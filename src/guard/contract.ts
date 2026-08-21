/**
 * M1 语义契约核心（P0-5，0.2.x 记录档）。
 *
 * 契约 = 插件作者/本地 agent（离线）为插件声明的「行为边界」：读/写/删哪些路径、
 * 连接哪些主机、跑哪些命令。价值在两点：
 *   1. 校验：过宽/过松的契约被确定性拒载（/**、裸 *、通配主机等），N1 差分
 *      回落默认（声明 vs 观测），并出 m1:contract-rejected warning；
 *   2. 对账：运行时观测与契约对账 → 匹配记 info、越界记 yellow（record 档只记录，
 *      绝不拦截）。
 *
 * 纪律红线（ROADMAP P0-5，与全项目一致）：
 *   - 本模块零模型请求、零出站、纯本地、纯函数判定——LLM 只负责「写契约」，
 *     执法永远确定性；
 *   - 契约是「承诺」，不是「事实」。可信优先级恒为
 *       代码事实（静态扫描） > 运行时观测（T2） > 契约承诺（本模块）
 *     契约可以给观测降噪/对账，永远不能压过代码事实与观测（见 contractPriority）。
 *
 * 当前仅记录档：契约存在且校验通过时，vet 只记 m1:contract-* 观测，不改变既有
 * 报警面/拦截面（N7 相永不参与）。
 */

import { homedir } from 'node:os'
import { join } from 'node:path'

// ── 类型 ─────────────────────────────────────────────

export interface ContractScopeFs {
  /** 允许读取的路径模式（read/probe 面共用）。 */
  read: string[]
  /** 允许写入的路径模式。 */
  write: string[]
  /** 允许删除的路径模式（高危面：声明即触发额外审视，见校验规则）。 */
  destroy: string[]
}

export interface ContractScopeNet {
  /** 允许连接的主机：精确名（webhook.example.com）或单段后缀（*.example.com）。 */
  connect: string[]
  /** 可选：允许的端口白名单（缺省 = 允许范围内主机的任意声明端口）。 */
  ports?: number[]
}

export interface ContractScopeSpawn {
  /** 允许执行的命令：basename（git/sh）或完整路径（/usr/bin/git）。 */
  commands: string[]
}

export interface ContractScope {
  fs: ContractScopeFs
  network: ContractScopeNet
  spawn: ContractScopeSpawn
  /** 允许读取的环境变量名（敏感 env 面；缺省 = 不读任何 env）。 */
  env?: string[]
}

export interface ContractMeta {
  author?: string
  /** 契约生成来源：'agent'（本地 agent 离线生成）/ 'manual'/'template'。未知来源 → warn。 */
  generator?: string
  generatedAt?: string
}

export interface Contract {
  schema: number
  /** 插件包名（须与 vet 归因 map 的包名一致）。 */
  name: string
  scope: ContractScope
  meta?: ContractMeta
}

export type LaxityLevel = 'ok' | 'warn' | 'reject'

export interface ContractIssue {
  level: LaxityLevel
  field: string
  reason: string
}

export interface ContractValidation {
  /** 是否可载入（reject 级问题 > 0 → false，契约不生效，N1 回落默认）。 */
  ok: boolean
  issues: ContractIssue[]
}

/** 契约对账结果（record 档：只观测，不拦截）。 */
export type ContractCheck =
  | { kind: 'no-contract' }
  | { kind: 'rejected'; reason: string }
  | { kind: 'violation'; field: 'fs-read' | 'fs-write' | 'fs-destroy' | 'network' | 'spawn' | 'env'; detail: string }
  | { kind: 'within'; field: 'fs-read' | 'fs-write' | 'fs-destroy' | 'network' | 'spawn' | 'env' }

/** 三级优先级对账：代码事实 > 运行时观测 > 契约承诺（纯函数，可测）。 */
export type ContractPriority =
  | { outcome: 'code-fact-beats-contract' }
  | { outcome: 'observation-beats-contract'; within: boolean }
  | { outcome: 'contract-explains-observation'; within: boolean }
  | { outcome: 'ambiguous' }


// ── 校验常量 ─────────────────────────────────────────

const SCHEMA_VERSION = 1
const HOSTNAME_RE = /^[a-z0-9][a-z0-9.-]*$/i
const COMMAND_TOKEN_RE = /^[A-Za-z0-9._/-]+$/
/** 已知本地契约生成来源（未知 generator → warn，非拒载）。 */
const KNOWN_GENERATORS = new Set(['agent', 'manual', 'template'])

/** 过宽路径模式（**、裸 *、空串、含 ** 的全局递归）——直接拒载。 */
function isLaxPathPattern(p: string): boolean {
  const norm = p.trim()
  if (norm === '' || norm === '*' || norm === '**' || norm.startsWith('**')) return true
  if (!norm.includes('**')) return false
  // 含 **：仅「目录前缀 /<dir>/**」形态可接受（目录递归有界）；其余（a/**/b、尾部裸 **）拒载
  if (!norm.endsWith('/**')) return true
  const pre = norm.slice(0, -3)
  return pre === '' || pre === '/' || pre === '*' || pre.includes('**')
}

const BS = String.fromCharCode(92)

function normPath(s: string): string {
  return s.split(BS).join('/').replace(/\/{2,}/g, '/').replace(/\/$/, '')
}

/**
 * 解析模式是否「合法可匹配」：
 * - 字面路径：/home/u/data/x
 * - 目录前缀：/home/u/data/**（含目录本身及其下一切）
 * - 单段通配：/tmp/<seg>/out（每段仅一星，本实现按单段处理）
 * 返回 false = 模式无法被规则接受（校验拒载；匹配器按不匹配处理）。
 */
export function isValidPathPattern(p: string): boolean {
  const norm = p.trim().replace(/\\/g, '/')
  if (isLaxPathPattern(norm)) return false
  if (norm.startsWith('~/')) return false
  if (norm.startsWith('./') || norm === '/' || norm === '.') return false
  return true
}

/**
 * 路径模式匹配（纯函数，自实现无 glob 依赖）：
 * - 目录前缀 /** 结尾：命中前缀自身 + 其下一切；
 * - 含 *：单段通配（[^/]*，不跨 /）；
 * - 否则：规范化后字面相等。
 */
/** 编译缓存：规范模式 → RegExp（#4：含通配符模式在每次 fs 对账时复用，避免反复编译）。
 * 契约模式读写一次后不再变，Map 大小由契约内容决定（有界，无需 LRU）。 */
const patternReCache = new Map<string, RegExp>()

export function patternMatchPath(pattern: string, path: string): boolean {
  const P = normPath(pattern)
  const T = normPath(path)
  if (P === '' || P === '*' || P === '**') return false
  if (P.endsWith('/**')) {
    const pre = P.slice(0, -3).replace(/\/$/, '')
    if (pre === '' || pre === '*' || pre.includes('**')) return false
    return T === pre || T.startsWith(pre + '/')
  }
  if (P.includes('**')) return false
  if (!P.includes('*')) return T === P
  let re = patternReCache.get(P)
  if (re === undefined) {
    const reMeta = '.+*?^()[]{}|$' + BS
    const esc = (s: string): string => s.split('').map(ch => reMeta.includes(ch) ? BS + ch : ch).join('')
    re = new RegExp('^' + P.split('*').map(esc).join('[^/]*') + '$')
    patternReCache.set(P, re)
  }
  return re.test(T)
}

/**
 * 网络主机模式匹配：精确名，或 *.example.com（单段通配，匹配 example.com 及其任意子域）。
 * 裸 * 恒不匹配（宽松路径，校验应将其拒载）。
 */
export function patternMatchHost(pattern: string, hostname: string): boolean {
  const P = pattern.trim().toLowerCase().replace(/[.:]+$/, '')
  const H = hostname.toLowerCase()
  if (P === '' || P === '*') return false
  if (P.startsWith('*.')) {
    const suf = P.slice(2)
    if (suf === '' || !HOSTNAME_RE.test(suf)) return false
    return H === suf || H.endsWith('.' + suf)
  }
  if (!HOSTNAME_RE.test(P)) return false
  return H === P
}

/**
 * 命令模式匹配：声明 basename（git）或完整路径（/usr/bin/git）。
 * 对命令行任一 token 做 basename/字面比对。
 */
export function patternMatchCommand(pattern: string, command: string): boolean {
  const P = pattern.trim()
  if (P === '' || P === '*' || !COMMAND_TOKEN_RE.test(P)) return false
  const pBase = P.slice(P.lastIndexOf('/') + 1)
  const cTokens = command.trim().split(/\s+/).filter(Boolean)
  const cBases = cTokens.map((t: string) => t.slice(t.lastIndexOf('/') + 1))
  return cTokens.includes(P) || cBases.includes(P) || cTokens.includes(pBase) || cBases.includes(pBase)
}



// ── 解析 + 宽松度校验（确定性） ──────────────────────

/**
 * 解析 JSON 文本为契约：结构校验 + 宽松度校验。
 * @returns ok=false = 契约不可载入（N1 回落默认声明对账），并出 reject 原因。
 */
export function validateContract(raw: string): ContractValidation {
  const issues: ContractIssue[] = []
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch (error) {
    return { ok: false, issues: [{ level: 'reject', field: '$', reason: '不是合法 JSON：' + String(error) }] }
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    return { ok: false, issues: [{ level: 'reject', field: '$', reason: '契约必须是 JSON 对象' }] }
  }
  const c = obj as Record<string, unknown>

  if (c.schema !== SCHEMA_VERSION) {
    issues.push({ level: 'reject', field: 'schema', reason: 'schema 版本不支持（期望 ' + SCHEMA_VERSION + '，实际 ' + String(c.schema) + '）' })
  }
  if (typeof c.name !== 'string' || c.name.trim() === '') {
    issues.push({ level: 'reject', field: 'name', reason: '缺少插件包名 name' })
  }

  checkScope(c.scope, issues)
  checkMeta(c.meta, issues)

  const ok = !issues.some(i => i.level === 'reject')
  return { ok, issues }
}

/** 各 scope 段独立校验（guard-clause 早退，降低嵌套深度）。 */
function checkScope(scope: unknown, issues: ContractIssue[]): void {
  if (typeof scope !== 'object' || scope === null) {
    issues.push({ level: 'reject', field: 'scope', reason: '缺少 scope 段（fs/network/spawn 至少各一数组，可为空）' })
    return
  }
  const sc = scope as Record<string, unknown>
  checkFs(sc.fs, issues)
  checkNetwork(sc.network, issues)
  checkSpawn(sc.spawn, issues)
  checkEnv(sc.env, issues)
}

function checkFs(fs: unknown, issues: ContractIssue[]): void {
  if (typeof fs !== 'object' || fs === null) {
    issues.push({ level: 'reject', field: 'scope.fs', reason: 'scope.fs 段缺失（read/write/destroy 三数组，可为空）' })
    return
  }
  const f = fs as Record<string, unknown>
  checkPatterns(f.read, 'scope.fs.read', '路径模式', issues, 'path')
  checkPatterns(f.write, 'scope.fs.write', '路径模式', issues, 'path')
  checkPatterns(f.destroy, 'scope.fs.destroy', '路径模式', issues, 'path')
  const destroyArr = Array.isArray(f.destroy) ? f.destroy : []
  if (destroyArr.length > 0) {
    issues.push({ level: 'warn', field: 'scope.fs.destroy', reason: '声明了删除面——删除属不可逆高危操作，将按最高审视档记录' })
  }
}

function checkNetwork(net: unknown, issues: ContractIssue[]): void {
  if (typeof net !== 'object' || net === null) {
    issues.push({ level: 'reject', field: 'scope.network', reason: 'scope.network 段缺失（connect 数组，可为空）' })
    return
  }
  const n = net as Record<string, unknown>
  checkPatterns(n.connect, 'scope.network.connect', '主机名', issues, 'host')
  const ports = n.ports
  if (ports !== undefined && !(Array.isArray(ports) && ports.every((p: unknown) => Number.isInteger(p) && (p as number) > 0 && (p as number) < 65536))) {
    issues.push({ level: 'reject', field: 'scope.network.ports', reason: 'ports 必须是 1..65535 整数数组或省略' })
  }
}

function checkSpawn(spawn: unknown, issues: ContractIssue[]): void {
  if (typeof spawn !== 'object' || spawn === null) {
    issues.push({ level: 'reject', field: 'scope.spawn', reason: 'scope.spawn 段缺失（commands 数组，可为空）' })
    return
  }
  checkPatterns((spawn as Record<string, unknown>).commands, 'scope.spawn.commands', '命令', issues, 'cmd')
}

function checkEnv(env: unknown, issues: ContractIssue[]): void {
  if (env === undefined) return
  if (!(Array.isArray(env) && env.every((e: unknown) => typeof e === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(e as string)))) {
    issues.push({ level: 'reject', field: 'scope.env', reason: 'env 必须是环境变量名数组或省略' })
  }
}

function checkMeta(meta: unknown, issues: ContractIssue[]): void {
  if (meta === undefined) return
  const gen = (meta as Record<string, unknown>).generator
  if (typeof gen === 'string' && !KNOWN_GENERATORS.has(gen)) {
    issues.push({ level: 'warn', field: 'meta.generator', reason: '未知契约来源「' + gen + '」——建议由本地 agent/manual/template 生成' })
  }
}

function checkPatterns(
  arr: unknown,
  field: string,
  kind: string,
  issues: ContractIssue[],
  flavor: 'path' | 'host' | 'cmd',
): void {
  if (!Array.isArray(arr)) {
    issues.push({ level: 'reject', field, reason: field + ' 必须是数组（可为空）' })
    return
  }
  for (const item of arr) {
    if (typeof item !== 'string') {
      issues.push({ level: 'reject', field, reason: kind + '项必须是字符串' })
      continue
    }
    if (flavor === 'path') {
      if (!isValidPathPattern(item)) {
        issues.push({ level: 'reject', field, reason: '非法路径模式「' + item + '」——拒载（不允许 ** / 裸 * / 空串 / 家目录 ~ / 根 / 相对 ./）' })
      }
    } else if (flavor === 'host') {
      if (item.trim() === '' || item.trim() === '*') {
        issues.push({ level: 'reject', field, reason: '过宽主机名「' + item + '」——拒载（不允许裸 * / 空串）' })
      } else if (item.startsWith('*.')) {
        const suf = item.slice(2)
        if (suf === '' || !HOSTNAME_RE.test(suf)) {
          issues.push({ level: 'reject', field, reason: '非法通配主机「' + item + '」——通配仅限单段后缀 *.example.com 形态' })
        }
      } else if (!HOSTNAME_RE.test(item)) {
        issues.push({ level: 'reject', field, reason: '非法主机名「' + item + '」' })
      }
    } else {
      if (item.trim() === '' || item.trim() === '*' || !COMMAND_TOKEN_RE.test(item.trim())) {
        issues.push({ level: 'reject', field, reason: '过宽/非法命令「' + item + '」——拒载（仅 basename 或完整路径）' })
      }
    }
  }
}

// ── 范围判定（纯函数） ──────────────────────────────


export type FsScopeMode = 'read' | 'write' | 'destroy'

/** fs 目标是否在契约允许范围内（read/probe → read 面复用）。 */
export function fsWithinScope(path: string, fs: ContractScopeFs, mode: FsScopeMode): boolean {
  const list = mode === 'read' ? fs.read : mode === 'write' ? fs.write : fs.destroy
  return list.some(p => patternMatchPath(p, path))
}

/** 网络目标是否在契约允许范围内（含端口白名单）。 */
export function netWithinScope(hostname: string, port: number | undefined, net: ContractScopeNet): boolean {
  if (!net.connect.some(h => patternMatchHost(h, hostname))) return false
  if (port !== undefined && Array.isArray(net.ports) && net.ports.length > 0 && !net.ports.includes(port)) return false
  return true
}

/** 命令行是否在契约允许范围内。 */
export function spawnWithinScope(command: string, spawn: ContractScopeSpawn): boolean {
  return spawn.commands.some(p => patternMatchCommand(p, command))
}

/** env 变量名是否在契约允许读取范围内（缺省 = 一律越界）。 */
export function envWithinScope(variable: string, env: string[] | undefined): boolean {
  return Array.isArray(env) && env.includes(variable)
}

// ── 三级优先级（纯函数） ─────────────────────────────

/**
 * 「代码事实 > 运行时观测 > 契约承诺」对账（record 档判定）。
 * @param codeFact   该操作是否已有静态代码事实（扫描 manifest 命中，N1 侧）
 * @param observed   该操作是否正被运行时观测到（T2 报警/台账一路）
 * @param inContract 该操作是否落在契约允许范围内
 */
export function contractPriority(codeFact: boolean, observed: boolean, inContract: boolean): ContractPriority {
  if (codeFact && !inContract) return { outcome: 'code-fact-beats-contract' }
  if (observed) {
    return inContract
      ? { outcome: 'contract-explains-observation', within: true }
      : { outcome: 'observation-beats-contract', within: false }
  }
  if (codeFact && inContract) return { outcome: 'contract-explains-observation', within: true }
  return { outcome: 'ambiguous' }
}

// ── 存储加载（离线，测试可覆写目录） ──────────────────

const SNAPSHOT_CONTRACTS_DIR = process.env.DSH_PLUGIN_VET_CONTRACTS_DIR
let contractsDir: string | undefined = SNAPSHOT_CONTRACTS_DIR

/** 单测覆写契约存储目录（生产不调用；undefined 恢复默认）。 */
export function setContractsDirForTest(dir: string | undefined): void {
  contractsDir = dir
}

/** 当前契约存储目录（缺省 ~/.dsh/vet/contracts，env DSH_PLUGIN_VET_CONTRACTS_DIR 可覆盖）。 */
export function contractsRoot(): string | undefined {
  return contractsDir ?? SNAPSHOT_CONTRACTS_DIR ?? join(homedir(), '.dsh', 'vet', 'contracts')
}

/**
 * 载入某插件的契约：<root>/<name>.json（dirHint > 模块目录 > env > homedir 默认）。
 * 缺失 → no-contract；存在但不通过校验 → rejected（record 档记 warning）。
 */
export function loadContract(
  name: string,
  readFile: (p: string) => string | undefined,
  dirHint?: string,
): { kind: 'no-contract' } | { kind: 'rejected'; validation: ContractValidation } | { kind: 'loaded'; contract: Contract; validation: ContractValidation } {
  const root = dirHint !== undefined && dirHint !== '' ? dirHint : contractsRoot()
  if (root === undefined || name.trim() === '') return { kind: 'no-contract' }
  const path = root + '/' + name.replace(/[^A-Za-z0-9@._-]/g, '_') + '.json'
  const raw = readFile(path)
  if (raw === undefined) return { kind: 'no-contract' }
  const validation = validateContract(raw)
  if (!validation.ok) return { kind: 'rejected', validation }
  const contract = JSON.parse(raw) as Contract
  return { kind: 'loaded', contract, validation }
}

// ── 报警对账（纯函数：T2 报警 ↔ 契约范围） ──────────────

export type ContractAlarmField = 'fs-read' | 'fs-write' | 'fs-destroy' | 'network' | 'spawn'

/** T2 报警 kind → 契约字段（不可映射的种类返回 null，如 n3-/canary/key-leak 关联签名类）。 */
export function contractFieldOf(kind: string): ContractAlarmField | null {
  switch (kind) {
    case 'fs-read':
    case 'fs-probe':
      return 'fs-read'
    case 'fs-write':
    case 'persistence-write':
    case 'install-write':
      return 'fs-write'
    case 'fs-destroy':
    case 'integrity':
      return 'fs-destroy'
    case 'net-egress':
      return 'network'
    case 'spawn':
      return 'spawn'
    default:
      return null
  }
}

/**
 * 依据一条 T2 报警与契约对账：返回「字段 + 是否在承诺范围」。
 * 无法映射（关联签名类）或无 target → null（不产生 m1 记录）。
 * @param target HookAlarm.target——fs 为路径；network 为 host[:port]；spawn 为命令串。
 */
export function checkAlarmInContract(
  kind: string,
  target: string | undefined,
  contract: Contract,
): { field: ContractAlarmField; within: boolean } | null {
  const field = contractFieldOf(kind)
  if (field === null || target === undefined || target.trim() === '') return null
  if (field === 'network') {
    let host = target.trim()
    let port: number | undefined
    // 末尾「:数字」拆成 port（IPv6 括号形态先剥 []；从最后一个冒号切开，避开无端口主机名）
    const colon = host.lastIndexOf(':')
    const afterColon = host.slice(colon + 1)
    if (colon > 0 && /^\d{1,5}$/.test(afterColon)) {
      host = host.slice(0, colon)
      port = Number(afterColon)
    }
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)
    return { field, within: netWithinScope(host, port, contract.scope.network) }
  }
  if (field === 'spawn') {
    return { field, within: spawnWithinScope(target, contract.scope.spawn) }
  }
  const mode: FsScopeMode = field === 'fs-read' ? 'read' : field === 'fs-write' ? 'write' : 'destroy'
  return { field, within: fsWithinScope(target, contract.scope.fs, mode) }
}