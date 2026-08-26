/**
 * 盾牌数据通道（D22）：宿主 webServer 注册前缀路由 /vet：
 * - GET  /vet/status.json → { ...盾牌快照, runtimeGuard, metrics（内存/CPU/IO/子进程/fd） }
 * - POST /vet/runtime-guard { enable } → 写入 profile cordis.patch.yml 的 runtimeGuard 配置
 *   （持久化 + 即时生效——toggle hook 当前进程立即切换，不再等重启；0.4.1 事故修复）
 * - POST /vet/profile { tier } → 写入 vet 条目 profile 档位（持久化；守卫即时切换，
 *   档位预设其余扩展键在 apply 时展开——重启/热重载后生效；保留其他配置键）
 * webServer 是可选服务且可能晚于本插件就绪：注册带轮询重试（插件加载顺序无关）。
 * POST 同源校验（Origin 缺失或不同源 → 403），防止跨站触发。
 */
import type { Context } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync, writeFileSync, renameSync, rmSync, openSync, fsyncSync, closeSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as yaml from 'js-yaml'
import { VetStatus } from './status.js'
import { readHostMetrics, readMetricsHistory } from './metrics.js'
import { withVetSelfIo } from './runtime-hooks.js'
import type { VetConfig } from '../config.js'
import { PLUGIN_ENTRY_ID } from '../package-meta.js'
import { getStats } from './stats.js'
import { buildAuditSummary } from './audit-summary.js'
import { getScanSummary } from './scan-summaries.js'
import { label as capabilityLabel, history as diffHistory, type CapabilityLabel } from './version-diff.js'
import { hasAuditRecordBatch } from '../audit/archive.js'
import { confirmBlock } from './confirm-block.js'
import { isOfficial } from './runtime-attrib.js'

interface WebServerLike {
  register(route: {
    kind: 'exact' | 'prefix'
    path: string
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): () => void
}

/** 最小上下文形状（避免与 cordis Context 的 logger 类型冲突）。 */
interface ContextLike {
  get<T>(name: string, strict?: boolean): T | undefined
  effect(fn: () => unknown, label?: string): unknown
  baseUrl?: string
  logger?: { info(m: string): void; warn(m: string): void; error(m: string): void }
}

const RETRY_MS = 400
const RETRY_MAX = 150

function writeJson(res: ServerResponse, code: number, body: unknown): void {
  // M3：响应可能已被结束（413 后 destroy + 客户端 RST 触发 error 监听再写）——
  // 双写会在事件监听器里抛 ERR_HTTP_HEADERS_SENT → 未捕获 → 宿主进程退出。
  if (res.writableEnded) return
  try {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(JSON.stringify(body))
  } catch {
    // 写入已结束/连接已断：忽略，绝不向上抛
  }
}

/**
 * YAML 写入前校验（防御层）：解析合法才写。cordis 的 patch 允许 !!js 表达式（如
 * `port: !!js ctx.webStartup.port ?? 3456`）——js-yaml 默认 schema 不认 !!js tag 会抛
 * 「unknown tag」，把合法 DSH 文件误判为损坏（2026-08-26 事故根因）。校验 schema 扩展
 * !!js 与 !!js/function 两个 tag（按原样字符串保留，绝不执行；tagName 用规范长名
 * tag:yaml.org,2002:js 才能匹配 `!!js` 句柄），语法错误仍抛、坏文件仍拒写。
 */
const JS_TAGS = yaml.CORE_SCHEMA.withTags(
  yaml.defineScalarTag('tag:yaml.org,2002:js', {
    resolve: (source: string) => source,
    identify: () => false,
  }),
  yaml.defineScalarTag('tag:yaml.org,2002:js/function', {
    resolve: (source: string) => source,
    identify: () => false,
  }),
)
function validateYaml(content: string): void {
  yaml.load(content, { schema: JS_TAGS })
}

/**
 * 行级文本手术的兜底路径（旧对象重建语义，仅限坏文件）：yaml.load 失败（真语法损坏）
 * 时回退。输出只含 vet 条目的合法单文档（repaired=true 提示用户核对其余条目）。
 * 2026-08-26 事故后该路径不再承担常规写路径职责——常规文件一律走行级手术，绝不重排。
 * round-15 review：多文档（--- 分隔的合法 YAML stream）不再走此重建——多文档不是损坏，
 * 重建会把用户手写的其他文档整段抹掉（2026-08-26 !!js 事故同族的破坏面）。多文档 →
 * refused（拒绝写入，提示手动合并），reconstructVetOnly 只保留给真语法损坏的抢救。
 */
function reconstructVetOnly(content: string, enable: boolean, key?: string, value?: string): { content: string; repaired: boolean; refused?: boolean } {
  // round-15 review：多文档（合法 YAML stream）拒绝重建——`---` 分隔的多文档在 YAML 里
  // 合法（用户手写合并配置的形态），重建会把其余文档整段抹掉（2026-08-26 !!js 事故
  // 同族的破坏面）；这不是损坏文件，无需抢救。refused → 调用方拒绝写入并提示手动合并。
  if (/^---\s*$/m.test(content)) {
    return { content, repaired: false, refused: true }
  }
  let entries: unknown[] = []
  let parsed: unknown
  try {
    parsed = yaml.load(content)
    if (parsed === null || parsed === undefined) {
      entries = []
    } else if (Array.isArray(parsed)) {
      entries = parsed
    } else {
      entries = []
    }
  } catch {
    entries = []
  }
  const existingVetConfig: Record<string, unknown> = {}
  let captured = false
  const others = entries.filter((e: unknown) => {
    if (typeof e !== 'object' || e === null) return true
    const id = (e as Record<string, unknown>).id
    const isVet = id === PLUGIN_ENTRY_ID || id === '@jieai/dsh-plugin-vet'
    if (isVet && !captured) {
      const config = (e as Record<string, unknown>).config
      if (config && typeof config === 'object') {
        Object.assign(existingVetConfig, config)
        if (key !== undefined && value !== undefined) existingVetConfig[key] = value
        else if (enable) existingVetConfig.runtimeGuard = 'watch'
        else delete existingVetConfig.runtimeGuard
      }
      captured = true
    }
    return !isVet
  })
  let out: unknown[]
  if (key !== undefined && value !== undefined) {
    out = [...others, { id: PLUGIN_ENTRY_ID, config: existingVetConfig }]
  } else if (enable) {
    out = [...others, { id: PLUGIN_ENTRY_ID, config: { ...existingVetConfig, runtimeGuard: 'watch' } }]
  } else if (Object.keys(existingVetConfig).length > 0) {
    out = [...others, { id: PLUGIN_ENTRY_ID, config: existingVetConfig }]
  } else {
    out = others
  }
  if (out.length === 0) return { content: '[]', repaired: true }
  return { content: yaml.dump(out, { indent: 2, lineWidth: -1 }), repaired: true }
}

/** 新条目块（标准 2/4 缩进；写路径唯一建档格式）。0.3.1 联动：开启守卫 ≡ 中级防御。 */
const VET_ENTRY_BLOCK = '- id: plugin-vet\n  config:\n    runtimeGuard: watch\n    profile: hardened\n'

/** 块内查找：返回 lines[start..end) 中首个匹配行下标，无则 -1。 */
function findInBlock(lines: string[], start: number, end: number, re: RegExp): number {
  for (let i = start; i < end; i++) {
    if (re.test(lines[i])) return i
  }
  return -1
}

/**
 * 档位中文标签（服务端 note 文案用——客户端 i18n 与「hardened/paranoid 档」这类
 * 术语不得进用户可见文案，用户 2026-08-26 明确过）。
 */
const TIER_LABEL: Record<string, string> = { standard: '轻度防御', hardened: '中级防御', paranoid: '高级防御' }

/** 读 vet 条目块内 profile 行值（未写 → undefined）。只读助手，不改文件。 */
function readProfileInPatch(content: string): string | undefined {
  const lines = content.split('\n')
  const start = lines.findIndex(isVetEntryLine)
  if (start === -1) return undefined
  let end = lines.length
  for (let i = start + 1; i < lines.length; i++) {
    if (/^-\s/.test(lines[i])) {
      end = i
      break
    }
  }
  const idx = findInBlock(lines, start, end, /^\s*profile:\s*\S/)
  if (idx === -1) return undefined
  const m = lines[idx]?.match(/^\s*profile:\s*(\S+)/)
  return m === null || m === undefined ? undefined : m[1]
}

/**
 * 行级手术：只动 vet 条目的 runtimeGuard 行，文件其余行（注释头、!!js 表达式、
 * 其他插件条目、insert 列表）原样保留。这是 2026-08-26 事故的根治：旧实现用
 * js-yaml load + dump 全量重排，遇到 !!js 抛异常后把整个 patch 重写成只剩 vet 条目，
 * 抹掉 webserver/insert 等配置 → DSH watcher 应用后 LAN 服务异常。
 * 无法安全行级操作的形态（多文档 --- / 损坏 / config 内联表达式）回退 reconstructVetOnly；
 * 多文档在 reconstructVetOnly 内被 refused（拒绝写入，不重排不破坏）。
 */
function spliceRuntimeGuardText(content: string, enable: boolean): { content: string; repaired: boolean; refused?: boolean } {
  if (/^---\s*$/m.test(content)) return reconstructVetOnly(content, enable)
  const lines = content.split('\n')
  const start = lines.findIndex(isVetEntryLine)
  if (start === -1) {
    if (!enable) return { content, repaired: false }
    // 空文件 / DSH boot 空数组（[]）形态：直接生成新条目文件
    if (lines.length === 1 && lines[0].trim() === '') return { content: VET_ENTRY_BLOCK + '\n', repaired: false }
    if (content.trim() === '[]') return { content: VET_ENTRY_BLOCK + '\n', repaired: false }
    const tail = content.endsWith('\n') ? '' : '\n'
    return { content: content + tail + VET_ENTRY_BLOCK + '\n', repaired: false }
  }
  // 块边界：下一个顶格条目（含 - id / - insert 等）
  let end = lines.length
  for (let i = start + 1; i < lines.length; i++) {
    if (/^-\s/.test(lines[i])) {
      end = i
      break
    }
  }
  const idIndent = (lines[start]?.match(/^\s*/) ?? [''])[0]
  const ruIdx = findInBlock(lines, start, end, /^\s*runtimeGuard:\s*\S/)
  if (enable) {
    // 规范 id 行（旧形态 "@jieai/dsh-plugin-vet" 自愈为 plugin-vet）
    lines[start] = idIndent + '- id: ' + PLUGIN_ENTRY_ID
    if (ruIdx !== -1) {
      lines[ruIdx] = lines[ruIdx].replace(/^(\s*)runtimeGuard:.*$/, '$1runtimeGuard: watch')
    } else {
      const cfgIdx = findInBlock(lines, start, end, /^\s*config:\s*$/)
      if (cfgIdx !== -1) {
        const indent = (lines[cfgIdx]?.match(/^\s*/) ?? [''])[0]
        lines.splice(cfgIdx + 1, 0, indent + '  runtimeGuard: watch')
      } else if (findInBlock(lines, start, end, /^\s*config:\s*\S/) !== -1) {
        // config 为内联表达式：无法安全插入子键，回退
        return reconstructVetOnly(content, true)
      } else {
        // 条目只有 id（无 config）：补 config 容器 + runtimeGuard
        lines.splice(start + 1, 0, idIndent + '  config:', idIndent + '    runtimeGuard: watch')
      }
    }
  } else {
    if (ruIdx === -1) return { content, repaired: false }
    lines.splice(ruIdx, 1)
    // 空壳判定：删 rg 后块内只剩 id 行与 config 容器行（注释/空行不算）→ 移除整块
    const blockEnd = end - 1 // ruIdx 已删，块长度同步减一
    const meaningful = lines.slice(start, blockEnd).filter(l => l.trim() !== '' && !l.trim().startsWith('#'))
    const shellOnly = meaningful.every(l => /^-\s*id:/.test(l) || /^\s*config:\s*$/.test(l))
    if (shellOnly) {
      lines.splice(start, blockEnd - start)
    } else {
      lines[start] = idIndent + '- id: ' + PLUGIN_ENTRY_ID
    }
  }
  let out = lines.join('\n')
  if (out.trim() === '') return { content: '[]', repaired: false }
  if (!out.endsWith('\n')) out += '\n'
  return { content: out, repaired: false }
}

/**
 * 行级手术（通用键）：改/插入 vet 条目内单个标量键（档位 profile 等）。
 * 与 spliceRuntimeGuardText 同纪律：其余行原样保留。key/value 来自内部常量
 * （'profile' / standard|hardened|paranoid），无正则特殊字符、无需引号转义。
 * 0.3.1 联动语义：value === 'standard'（默认值）→ 删行而非替换——「轻度防御 = 无显式
 * 档位」的干净形态，保证守卫 关→开 往返字节一致；删后成空壳（只剩 id+config）→ 整块移除。
 */
function spliceVetEntryKeyText(content: string, key: string, value: string): { content: string; repaired: boolean; refused?: boolean } {
  if (/^---\s*$/m.test(content)) return reconstructVetOnly(content, false, key, value)
  const lines = content.split('\n')
  const start = lines.findIndex(isVetEntryLine)
  if (start === -1) {
    if (value === 'standard') return { content, repaired: false }
    if (lines.length === 1 && lines[0].trim() === '') return { content: '- id: plugin-vet\n  config:\n    ' + key + ': ' + value + '\n', repaired: false }
    if (content.trim() === '[]') return { content: '- id: plugin-vet\n  config:\n    ' + key + ': ' + value + '\n', repaired: false }
    const tail = content.endsWith('\n') ? '' : '\n'
    return { content: content + tail + '- id: plugin-vet\n  config:\n    ' + key + ': ' + value + '\n', repaired: false }
  }
  let end = lines.length
  for (let i = start + 1; i < lines.length; i++) {
    if (/^-\s/.test(lines[i])) {
      end = i
      break
    }
  }
  const keyRe = new RegExp('^\\s*' + key + ':\\s*\\S')
  const keyIdx = findInBlock(lines, start, end, keyRe)
  if (keyIdx === -1) {
    if (value === 'standard') return { content, repaired: false }
    const cfgIdx = findInBlock(lines, start, end, /^\s*config:\s*$/)
    if (cfgIdx !== -1) {
      const indent = (lines[cfgIdx]?.match(/^\s*/) ?? [''])[0]
      lines.splice(cfgIdx + 1, 0, indent + '  ' + key + ': ' + value)
    } else if (findInBlock(lines, start, end, /^\s*config:\s*\S/) !== -1) {
      return reconstructVetOnly(content, false, key, value)
    } else {
      const idIndent = (lines[start]?.match(/^\s*/) ?? [''])[0]
      lines.splice(start + 1, 0, idIndent + '  config:', idIndent + '    ' + key + ': ' + value)
    }
  } else if (value === 'standard') {
    // 0.3.1：档位回默认 → 删行（与 rg 删除同纪律；空壳块整体移除）
    lines.splice(keyIdx, 1)
    const blockEnd = end - 1 // keyIdx 已删，块长度同步减一
    const meaningful = lines.slice(start, blockEnd).filter(l => l.trim() !== '' && !l.trim().startsWith('#'))
    const shellOnly = meaningful.every(l => /^-\s*id:/.test(l) || /^\s*config:\s*$/.test(l))
    if (shellOnly) lines.splice(start, blockEnd - start)
    let out = lines.join('\n')
    if (out.trim() === '') return { content: '[]', repaired: false }
    if (!out.endsWith('\n')) out += '\n'
    return { content: out, repaired: false }
  } else {
    lines[keyIdx] = lines[keyIdx].replace(new RegExp('^(\\s*)' + key + ':.*$'), '$1' + key + ': ' + value)
  }
  let out = lines.join('\n')
  if (out.trim() === '') return { content: '[]', repaired: false }
  if (!out.endsWith('\n')) out += '\n'
  return { content: out, repaired: false }
}

/**
 * M2：原子写 patch 文件——先写同目录 .tmp，再 rename 覆盖（POSIX 同文件系统 rename 原子）。
 * 崩溃中途不会留下半写的主文件；.bak.latest 是改动前固定快照名（防 Date.now 碰撞/无限堆积）。
 * 写入前强制 YAML 校验：拼错的字符串不会落到磁盘（DSH 启动解析失败会崩溃）。
 * round-16 review（S7）：rename 前 fsync tmp 内容——ext4 等延迟分配下不 fsync 直接 rename，
 * 断电/崩溃可能留下空块（配置被清空 → DSH 重载后守卫配置丢失且无任何提示）。
 */
function atomicWritePatch(patchPath: string, content: string, previousContent: string): void {
  validateYaml(content)
  const tmp = patchPath + '.tmp'
  const backup = patchPath + '.bak.latest'
  try {
    // 改动前快照（固定名，供人工回滚）
    writeFileSync(backup, previousContent, { mode: 0o600 })
  } catch {
    // 快照失败不阻断主写入
  }
  writeFileSync(tmp, content, { mode: 0o600 })
  // fsync 需要可写句柄（'r' 只读句柄在 Windows 上 fsync 报 EPERM）；失败降级不阻断
  // 写入（fsync 是掉电/崩溃持久性保障，非正确性前提——rename 仍保证原子替换）。
  try {
    const fd = openSync(tmp, 'r+')
    try {
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
  } catch {
    // fsync 不可用（如某些文件系统/平台）→ 跳过持久化刷盘
  }
  renameSync(tmp, patchPath)
  // tmp 残留清理（rename 成功后不应存在，防异常残留）
  try {
    rmSync(tmp, { force: true })
  } catch {
    // 无害
  }
}

/** L3：提示语里的配置文件名（不泄露绝对路径）。 */
function profileName(): string {
  return 'cordis.patch.yml'
}

/** 同源校验（POST 用）：Origin 缺失或与 Host 不符 → 拒绝（跨站/无浏览器上下文 POST 防护）。
 * round-15 review（scheme 补漏）：旧实现只比 host——`https://` Origin 可被 `http://` Host
 * 接受（协议降级面：DSH web 即便 http 部署，跨协议 POST 也应收紧）。现要求协议一致：
 * Origin 的 scheme 必须与请求 URL 的 scheme 相同（file: 面板场景除外的普通 http/https）。
 */
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin
  if (origin === undefined) return false
  const host = req.headers.host
  if (host === undefined) return false
  try {
    const o = new URL(origin)
    // 协议比对：req.url 是路径（/vet/...），无法直接取 scheme——用标准端口推断不安全；
    // 稳妥做法：Origin scheme 必须是 http/https 之一（file: 服务桌面面板的 Origin 仅测试用），
    // 且 host 精确匹配（包含端口）。Host 头本身由 HTTP 栈保证与请求目标一致。
    if (o.protocol !== 'http:' && o.protocol !== 'https:') return false
    return o.host === host
  } catch {
    return false
  }
}

/**
 * 在 profile 的 cordis.patch.yml 写入/移除 plugin-vet 的 runtimeGuard 配置。
 * 用户点按钮触发（alarm-only 不冲突：是用户的操作，vet 只按指令写自己的配置）。
 * @returns ok + 给用户的提示语。
 */
/**
 * DSH 的 ctx.baseUrl 可能是 file: URL（如 file:/home/user/.dsh/profiles/web）
 * 或普通目录路径，统一规整成文件系统路径（path.join 不认 URL）。
 */
function resolveProfileDir(baseUrl: string): string {
  if (baseUrl.startsWith('file:')) {
    try {
      return fileURLToPath(baseUrl)
    } catch {
      // 解析失败退回字面量，由后续 IO 报错，避免吞掉真实原因
    }
  }
  return baseUrl
}

/** vet 条目的历史形态：早期误写成了包名 id（DSH 曾自动加引号），统一识别为 vet 条目。 */
const VET_ENTRY_RE = /^-\s*id:\s*(?:["']?@?jieai\/dsh-plugin-vet["']?|plugin-vet)\s*$/

/**
 * vet 条目判定（P2-8 统一规则）：只认顶格条目——VET_ENTRY_RE 锚定行首，缩进的
 * （如嵌在别的插件 insert/group 列表里）不是 vet 顶层条目。strip / extract / read
 * 三处此前规则不一致（后两者用 trim 匹配）→ 缩进嵌套条目被误读/摘不掉；现全部走本函数。
 */
function isVetEntryLine(line: string): boolean {
  return VET_ENTRY_RE.test(line)
}

/** 读 patch 文件里 vet 条目实际配置的 runtimeGuard（'watch' | 'off'）。 */
export function readPatchRuntimeGuard(ctx: ContextLike): 'watch' | 'off' {
  // 先取局部变量再判空：闭包内 TS 对属性访问不保留 narrowing（ctx.baseUrl 可能被外部改写）
  const baseUrl = ctx.baseUrl
  if (baseUrl === undefined) return 'off'
  // P2-6：vet 自读 patch（盾牌 5s 轮询）在 .dsh 敏感段下会自报警——vetSelfIo 直通
  return withVetSelfIo(() => {
    try {
      const content = readFileSync(join(resolveProfileDir(baseUrl), 'cordis.patch.yml'), 'utf8')
      const lines = content.split('\n')
      const start = lines.findIndex(isVetEntryLine)
      if (start === -1) return 'off'
      for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i]
        // P2-8 条目边界：下一条顶格条目（或文件尾）即 vet 条目结束——绝不能越界扫到
        // 其他插件的 config（别的插件也可能有 runtimeGuard 键，缩进匹配会误读）
        if (/^-\s/.test(line)) break
        const m = /^\s*runtimeGuard:\s*(\S+)/.exec(line)
        if (m !== null) return m[1] === 'watch' ? 'watch' : 'off'
      }
      return 'off'
    } catch {
      return 'off'
    }
  })
}

/** 读取 vet 条目在 patch 中显式写入的配置键（0.3 档位合并用：patch 写入 = 用户显式意图，预设不覆盖）。
 * 只取「键: 非空值」标量行（config: / rules: 等容器行不算）；自读 patch 走 vetSelfIo 直通，不触发 .dsh 敏感段自报警。 */
export function readPatchVetKeys(ctx: ContextLike): Set<string> {
  const baseUrl = ctx.baseUrl
  if (baseUrl === undefined) return new Set()
  return withVetSelfIo(() => {
    try {
      const content = readFileSync(join(resolveProfileDir(baseUrl), 'cordis.patch.yml'), 'utf8')
      const lines = content.split('\n')
      const start = lines.findIndex(isVetEntryLine)
      if (start === -1) return new Set()
      const keys = new Set<string>()
      for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i]
        if (/^-\s/.test(line)) break // 下一个顶格条目 = 本条目结束
        const m = /^(\s*)([A-Za-z_][A-Za-z0-9_]*):\s*\S/.exec(line)
        if (m !== null) keys.add(m[2])
      }
      return keys
    } catch {
      return new Set()
    }
  })
}

/**
 * 守卫开关写入（0.3.1 联动：守卫 ↔ 防御等级绑定）。
 * 开启：runtimeGuard: watch + 档位升到 hardened（当前已是 hardened/paranoid 则保持，绝不降级）；
 * 关闭：移除 runtimeGuard 行 + 档位回 standard（删 profile 行，「轻度防御 = 无显式档位」）。
 * profile 字段：写后生效档位（standard/hardened/paranoid），供客户端即时更新徽标。
 */
export function writeRuntimeGuardConfig(ctx: ContextLike, enable: boolean): { ok: boolean; note: string; profile?: string } {
  if (ctx.baseUrl === undefined) {
    return { ok: false, note: '无法定位 profile 配置目录（ctx.baseUrl 缺失）' }
  }
  const patchPath = join(resolveProfileDir(ctx.baseUrl), 'cordis.patch.yml')
  // P2-6：vet 自写自己的 patch 配置（用户点按钮触发）——vetSelfIo 直通，不自报警
  return withVetSelfIo(() => {
    let content: string
    try {
      content = readFileSync(patchPath, 'utf8')
    } catch (error) {
      if (!enable) return { ok: true, note: '当前未开启', profile: 'standard' }
      // 首次开启时 cordis.patch.yml 可能还不存在 → 直接新建
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        return { ok: false, note: `无法读取 ${profileName()}` }
      }
      // 文件不存在：行级手术直接生成新文件（含档位行：开启守卫 ≡ 中级防御）
      const { content: newContent } = spliceRuntimeGuardText('', true)
      const { content: withProfile } = spliceVetEntryKeyText(newContent, 'profile', 'hardened')
      try {
        atomicWritePatch(patchPath, withProfile, '')
      } catch (writeError) {
        return { ok: false, note: `写入失败：${String(writeError)}` }
      }
      return { ok: true, note: `已写入 ${profileName()}，防御等级：中级防御（配置已持久化）`, profile: 'hardened' }
    }
    // 文件存在：行级手术（只动 runtimeGuard/profile 行，其余行原样保留）
    // 顺序：profile 手术在前、rg 手术在后——两者都缺失时 rg 插在 config 行后、
    // profile 被顺延，最终行序 = [config, runtimeGuard, profile]，与 VET_ENTRY_BLOCK/
    // 往返字节一致（profile 在前会把 rg 挤到后面，破坏关→开往返字节相等）。
    let working = content
    let tier = 'standard'
    let repaired = false
    let refused = false
    if (enable) {
      // 联动：当前档位 standard/未写 → 中级（升级）；已是 中/高级 → 保持（绝不降级）
      const cur = readProfileInPatch(content)
      if (cur === undefined || cur === 'standard') {
        const sp = spliceVetEntryKeyText(content, 'profile', 'hardened')
        working = sp.content
        repaired = sp.repaired
        refused = sp.refused === true
        tier = 'hardened'
      } else {
        tier = cur
      }
      const rg = spliceRuntimeGuardText(working, true)
      working = rg.content
      repaired = repaired || rg.repaired
      refused = refused || rg.refused === true
    } else {
      // 联动：关闭守卫 ≡ 轻度防御（profile 行删除）
      const sp = spliceVetEntryKeyText(content, 'profile', 'standard')
      working = sp.content
      repaired = sp.repaired
      refused = sp.refused === true
      const rg = spliceRuntimeGuardText(working, false)
      working = rg.content
      repaired = repaired || rg.repaired
      refused = refused || rg.refused === true
    }
    // round-15 review：多文档（refused）→ 拒绝写入，绝不重排破坏用户手写的其他文档
    // （须在 working===content 短路判定之前——多文档时 splice 原样返回，先命中「无配置变化」）
    if (refused) {
      return { ok: false, note: `${profileName()} 含多文档（--- 分隔），无法安全写入——请手动合并为单文档后重试（vet 不修改多文档补丁）` }
    }
    // 检查是否真的需要写入（避免无意义的文件修改）
    if (working === content && !repaired) {
      return { ok: true, note: enable ? '已开启（无配置变化）' : '当前未开启', profile: tier }
    }
    try {
      atomicWritePatch(patchPath, working, content)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    if (repaired) {
      return { ok: true, note: `${profileName()} 已损坏并已修复（其余条目已丢失，请核对）`, profile: tier }
    }
    return {
      ok: true,
      note: enable
        ? `已写入 ${profileName()}，防御等级：${TIER_LABEL[tier] ?? tier}（配置已持久化）`
        : `已移除 runtimeGuard 配置，防御等级：轻度防御（配置已持久化）`,
      profile: tier,
    }
  })
}

const VET_TIERS = ['standard', 'hardened', 'paranoid'] as const

/**
 * 安全档位写入（0.3.1 联动：档位 ↔ 守卫绑定）。
 * 把 tier 写进 vet 条目 config.profile（行级手术），并同步守卫：
 * 轻度防御 ⇔ 守卫关（删 profile 行 + 移除 runtimeGuard 行）；中级/高级防御 ⇔ 守卫开
 * （写档位行 + 保证 runtimeGuard: watch）。requireAudit 等既有键与其他条目原样保留。
 */
export function writeVetTierConfig(ctx: ContextLike, tier: string): { ok: boolean; note: string; profile?: string } {
  if (!VET_TIERS.includes(tier as (typeof VET_TIERS)[number])) {
    return { ok: false, note: `非法档位：${tier}（可选 standard/hardened/paranoid）` }
  }
  if (ctx.baseUrl === undefined) {
    return { ok: false, note: '无法定位 profile 配置目录（ctx.baseUrl 缺失）' }
  }
  const patchPath = join(resolveProfileDir(ctx.baseUrl), 'cordis.patch.yml')
  // P2-6：vet 自写自己的 patch 配置（用户点按钮触发）——vetSelfIo 直通，不自报警
  return withVetSelfIo(() => {
    let content: string
    try {
      content = readFileSync(patchPath, 'utf8')
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        return { ok: false, note: `无法读取 ${profileName()}` }
      }
      content = '[]'
    }
    // 档位行手术在前，守卫行手术在后（插入顺序：profile 在 config 下、rg 更内层）
    const { content: tierContent, repaired: tierRepaired, refused: tierRefused } = spliceVetEntryKeyText(content, 'profile', tier)
    let working = tierContent
    if (tier === 'standard') {
      working = spliceRuntimeGuardText(working, false).content
    } else {
      working = spliceRuntimeGuardText(working, true).content
    }
    const repaired = tierRepaired
    // round-15 review：多文档 → 拒绝写入（与 writeRuntimeGuardConfig 同纪律；须在
    // working===content 短路判定之前）
    if (tierRefused === true) {
      return { ok: false, note: `${profileName()} 含多文档（--- 分隔），无法安全写入——请手动合并为单文档后重试（vet 不修改多文档补丁）` }
    }
    if (working === content && !repaired) {
      return { ok: true, note: `防御等级已是${TIER_LABEL[tier] ?? tier}（无配置变化）`, profile: tier }
    }
    try {
      atomicWritePatch(patchPath, working, content)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    if (repaired) {
      return { ok: true, note: `${profileName()} 已损坏并已修复（其余条目已丢失，请核对）：防御等级=${TIER_LABEL[tier] ?? tier}`, profile: tier }
    }
    return { ok: true, note: `已切换防御等级：${TIER_LABEL[tier] ?? tier}（配置已持久化）`, profile: tier }
  })
}

function handleTier(req: IncomingMessage, res: ServerResponse, ctx: ContextLike): void {
  if (!sameOrigin(req)) {
    writeJson(res, 403, { ok: false, note: '跨源请求被拒绝' })
    return
  }
  const chunks: Buffer[] = []
  let total = 0
  req.on('data', (c: Buffer) => {
    total += c.length
    if (total > 8192) {
      writeJson(res, 413, { ok: false, note: '请求体过大' })
      req.destroy()
      return
    }
    chunks.push(c)
  })
  req.on('end', () => {
    let tier: unknown
    try {
      tier = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').tier
    } catch {
      writeJson(res, 400, { ok: false, note: '请求体不是合法 JSON' })
      return
    }
    if (typeof tier !== 'string') {
      writeJson(res, 400, { ok: false, note: '缺少字符串字段 tier' })
      return
    }
    const result = writeVetTierConfig(ctx, tier)
    if (!result.ok) {
      writeJson(res, 400, result)
      return
    }
    // 0.3.1 联动即时装配：换档即时切换守卫（配置已持久化，进程内同步生效）
    const label = TIER_LABEL[tier] ?? tier
    if (guardToggleHook !== undefined) {
      const imm = guardToggleHook(tier !== 'standard')
      if (imm.ok) {
        writeJson(res, 200, {
          ok: true,
          profile: tier,
          note: tier === 'standard'
            ? `已切换防御等级：轻度防御，运行时守卫已即时关闭`
            : `已切换防御等级：${label}，运行时守卫已即时开启`,
        })
        return
      }
      writeJson(res, 200, {
        ok: true,
        profile: tier,
        note: `已切换防御等级：${label}（守卫即时切换失败：${imm.note ?? '未知错误'}，随 DSH 配置重载生效）`,
      })
      return
    }
    writeJson(res, 200, { ...result, profile: tier })
  })
  req.on('error', () => {
    writeJson(res, 400, { ok: false, note: '请求体读取失败' })
  })
}

/** 即时装配钩子（index.ts 装上生产实现：写配置后立刻在当前进程切换守卫，不必等 DSH 重启）。
 * 未注入时写路径只做持久化（测试/旧行为兼容）。 */
type GuardToggleHook = (enable: boolean) => { ok: boolean; note?: string }
let guardToggleHook: GuardToggleHook | undefined
export function setGuardToggleHook(hook: GuardToggleHook | undefined): void {
  guardToggleHook = hook
}

function handleToggle(req: IncomingMessage, res: ServerResponse, ctx: ContextLike): void {
  if (!sameOrigin(req)) {
    writeJson(res, 403, { ok: false, note: '跨源请求被拒绝' })
    return
  }
  const chunks: Buffer[] = []
  let total = 0
  req.on('data', (c: Buffer) => {
    total += c.length
    if (total > 8192) {
      writeJson(res, 413, { ok: false, note: '请求体过大' })
      req.destroy()
      return
    }
    chunks.push(c)
  })
  req.on('end', () => {
    // enable 必须是显式布尔：空 body / 缺字段 / 非布尔 → 400 拒绝，绝不默认当「关闭」误关守卫
    let enable: unknown
    try {
      enable = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').enable
    } catch {
      writeJson(res, 400, { ok: false, note: '请求体不是合法 JSON' })
      return
    }
    if (typeof enable !== 'boolean') {
      writeJson(res, 400, { ok: false, note: '缺少布尔字段 enable' })
      return
    }
    const result = writeRuntimeGuardConfig(ctx, enable)
    if (!result.ok) {
      writeJson(res, 500, result)
      return
    }
    const profile = result.profile ?? (enable ? 'hardened' : 'standard')
    // 即时装配：配置已持久化，再在当前进程切换守卫（用户无需重启 DSH）
    if (guardToggleHook !== undefined) {
      const imm = guardToggleHook(enable)
      if (imm.ok) {
        writeJson(res, 200, {
          ok: true,
          profile,
          note: enable
            ? `运行时守卫已即时开启（防御等级：${TIER_LABEL[profile] ?? profile}）`
            : '运行时守卫已即时关闭（防御等级：轻度防御）',
        })
      } else {
        writeJson(res, 200, {
          ok: true,
          profile,
          note: '配置已持久化；即时生效失败：' + (imm.note ?? '未知错误') + '（随 DSH 配置重载生效）',
        })
      }
      return
    }
    writeJson(res, 200, { ...result, profile })
  })
  req.on('error', () => {
    writeJson(res, 400, { ok: false, note: '请求体读取失败' })
  })
}

/** 最近一次升级差分（P4 浮动 diff 卡数据源）：从活跃报警找 N6 事件，附上能力差分摘要。 */
function lastUpgradeDiffOf(alarms: ReturnType<VetStatus['snapshot']>['alarms']): {
  plugin: string
  severity: 'yellow' | 'red' | 'info'
  at: number
  from: string | null
  to: string | null
  added: string[]
} | undefined {
  const alarm = alarms.find(a => a.kind === 'upgrade-diff' || a.kind === 'upgrade-cold')
  if (alarm?.pluginHint === undefined) return undefined
  let from: string | null = null
  let to: string | null = null
  let added: string[] = []
  try {
    const h = diffHistory(alarm.pluginHint)
    if (h.diff !== null) {
      from = h.diff.from
      to = h.diff.to
      added = describeAdded(h.diff.added)
    }
    if (added.length === 0 && alarm.kind === 'upgrade-cold') {
      // 冷启动无旧版可差分：给出声明面提示（exec+network 双高）
      added = ['首次记录：执行 + 网络 双高能力（无旧版本可差分）']
    }
  } catch { /* fail-open：卡片降级为纯报警文本 */ }
  return {
    plugin: alarm.pluginHint,
    severity: alarm.severity,
    at: alarm.at,
    from,
    to,
    added,
  }
}

/** ManifestDelta → 展示串列表（hosts/fsPaths/spawn/imports/ghost 摘要，上限 6 条）。 */
function describeAdded(delta: { hosts: string[]; fsPaths: string[]; spawnCmds: string[]; imports?: string[]; ghostDeps?: string[] }): string[] {
  const out: string[] = []
  if (delta.hosts.length > 0) out.push('网络主机 +' + delta.hosts.slice(0, 3).join('、') + (delta.hosts.length > 3 ? ` 等 ${delta.hosts.length} 个` : ''))
  if (delta.fsPaths.length > 0) out.push('文件访问 +' + delta.fsPaths.slice(0, 3).join('、') + (delta.fsPaths.length > 3 ? ` 等 ${delta.fsPaths.length} 个` : ''))
  if (delta.spawnCmds.length > 0) out.push('子进程 +' + delta.spawnCmds.slice(0, 2).join('、'))
  if ((delta.ghostDeps ?? []).length > 0) out.push('幽灵依赖 +' + (delta.ghostDeps ?? []).length + ' 个')
  if ((delta.imports ?? []).length > 0 && out.length < 4) out.push('导入 +' + (delta.imports ?? []).length + ' 项')
  return out.slice(0, 6)
}

/**
 * GET /vet/plugin?name=<pkg>（P2，只读）：插件详情页数据聚合。
 * 组装：扫描摘要（规则墙/OSV/时间）+ 能力标签（营养标签/雷达）+ 版本史差分 + 审计态。
 * 校验：name 必填、≤214 字符、无路径分隔符/控制字符；未见过 → 404。fail-closed on 校验。
 */
function handlePluginDetail(req: IncomingMessage, res: ServerResponse): void {
  void req
  let name: unknown
  try {
    name = new URL(req.url ?? '/vet/plugin', 'http://localhost').searchParams.get('name')
  } catch {
    writeJson(res, 400, { ok: false, note: '查询参数解析失败' })
    return
  }
  if (typeof name !== 'string' || name === '') {
    writeJson(res, 400, { ok: false, note: '缺少 name 参数' })
    return
  }
  // 校验（0.3.1 修复）：作用域包名合法含 '/'（@scope/name）——旧正则把 '/' 当非法字符，
  // 导致所有真实插件详情一律 400（前端显示为「没有信息」）。仍拒：控制字符、反斜杠、
  // '..' 路径穿越串、头尾空白。
  if (name.length > 214 || /[\u0000-\u001f\\]/.test(name) || name.includes('..') || name !== name.trim()) {
    writeJson(res, 400, { ok: false, note: 'name 非法' })
    return
  }

  const summary = getScanSummary(name)
  const cap: CapabilityLabel = capabilityLabel(name)
  const present = summary !== undefined || cap.present
  if (!present) {
    writeJson(res, 404, { ok: false, note: 'vet 未见过该包（未被自动扫描/gate 扫描过）' })
    return
  }

  const version = summary?.version ?? cap.latest ?? undefined
  const auditMap = hasAuditRecordBatch([{ name, ...(version !== undefined ? { version } : {}) }])
  const dh = diffHistory(name)
  writeJson(res, 200, {
    ok: true,
    plugin: {
      name,
      ...(version !== undefined ? { version } : {}),
      present: true,
      scan: summary === undefined ? undefined : {
        version: summary.version,
        at: summary.at,
        verdict: summary.verdict,
        staticScore: summary.staticScore,
        ruleCodes: summary.ruleCodes,
        sourceCount: summary.sourceCount,
        ...(summary.osv !== undefined ? { osv: summary.osv } : {}),
      },
      capabilities: cap.manifest,
      versions: cap.records,
      diffSummary: cap.diffSummary === null && dh.diff !== null
        ? { from: dh.diff.from, to: dh.diff.to, added: describeAdded(dh.diff.added) }
        : cap.diffSummary,
      audited: auditMap[name] === true,
      blocked: confirmBlock.isFamily1Blocked(name),
      // round-18：官方/受信包标记（随 DSH 分发）——详情页展示「官方插件」chip，
      // 不再因无人工审计档案而显得「未审核的陌生包」。
      official: isOfficial(name),
      note: summary === undefined
        ? '该包只有能力清单记录，尚无扫描摘要留档（留档启用前的旧包）'
        : undefined,
    },
  })
}

/** 单次注册尝试（可测试）：webServer 就绪即注册成功。 */
export function registerStatusRouteOnce(
  ctx: ContextLike,
  config: VetConfig,
  status: VetStatus,
): boolean {
  void config // 部分字段（runtimeGuard/profile）在 status.json 供盾牌展示生效值（post-档位展开）；config 对象本身由调用方长期持有
  let ws: WebServerLike | undefined
  try {
    ws = ctx.get('webServer')
  } catch {
    return false
  }
  if (ws === undefined) return false
  ctx.effect(
    () => ws!.register({
      kind: 'prefix',
      path: '/vet',
      handler: (req, res) => {
        const pathname = (req.url ?? '').split('?')[0]
        if (req.method === 'POST' && pathname.endsWith('/vet/dismiss')) {
          handleDismiss(req, res, status, false)
          return
        }
        if (req.method === 'POST' && pathname.endsWith('/vet/restore')) {
          handleDismiss(req, res, status, true)
          return
        }
        if (req.method === 'POST' && pathname.endsWith('/vet/runtime-guard')) {
          handleToggle(req, res, ctx)
          return
        }
        if (req.method === 'POST' && pathname.endsWith('/vet/profile')) {
          handleTier(req, res, ctx)
          return
        }
        if (req.method !== 'GET' || !pathname.endsWith('/vet/status.json')) {
          if (req.method === 'GET' && pathname.endsWith('/vet/plugin')) {
            handlePluginDetail(req, res)
            return
          }
          writeJson(res, 404, { ok: false, note: 'not found' })
          return
        }
        // M5：runtimeGuard = 档位展开后的生效值（盾牌按它显示开关状态）；patchRuntimeGuard =
        // 文件级实际状态（面板外编辑/写入 pending 时给用户看差异）；0.1.20：防御统计；
        // P2：metricsHistory（火花线）+ audit（审计&蜜罐中心/最近插件索引）+ lastUpgradeDiff（浮动卡）
        const snap = status.snapshot()
        const alarmsAll = [...snap.alarms, ...snap.dismissed]
        writeJson(res, 200, {
          ...snap,
          profile: config.profile,
          runtimeGuard: config.runtimeGuard,
          patchRuntimeGuard: readPatchRuntimeGuard(ctx),
          metrics: readHostMetrics(),
          metricsHistory: readMetricsHistory(),
          stats: getStats(),
          audit: buildAuditSummary({
            alarms: alarmsAll,
            honeypotArmed: config.honeypot?.enabled === true && config.runtimeGuard === 'watch',
            isBlocked: name => confirmBlock.isFamily1Blocked(name),
          }),
          lastUpgradeDiff: lastUpgradeDiffOf(snap.alarms),
        })
      },
    }),
    'vet: shield status route',
  )
  return true
}

/** 读取 POST JSON body 的 { id }（统一大小/解析错误处理；超大 body 413 断连）。 */
function readIdBody(req: IncomingMessage, res: ServerResponse, onId: (id: string | undefined) => void): void {
  const chunks: Buffer[] = []
  let total = 0
  req.on('data', (c: Buffer) => {
    total += c.length
    if (total > 8192) {
      writeJson(res, 413, { ok: false, note: '请求体过大' })
      req.destroy()
      return
    }
    chunks.push(c)
  })
  req.on('end', () => {
    let id: unknown
    try {
      id = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').id
    } catch {
      writeJson(res, 400, { ok: false, note: '请求体不是合法 JSON' })
      return
    }
    // round-5 review（B-A15）：纯空白 id 一并拒绝——'   ' 此前通过校验进入
    // dismissedIds 垃圾键永不命中，与 handleTier/handleToggle 的输入校验不一致。
    if (typeof id !== 'string' || id.trim() === '') {
      writeJson(res, 400, { ok: false, note: '缺少报警 id' })
      return
    }
    onId(id)
  })
  req.on('error', () => {
    writeJson(res, 400, { ok: false, note: '请求体读取失败' })
  })
}

/**
 * 用户忽略/恢复一条报警：只改 vet 自己的内存聚合（不删记录、不碰插件），
 * 面板下一轮轮询即生效。同源校验与 guard 开关一致（M4）。
 */
function handleDismiss(req: IncomingMessage, res: ServerResponse, status: VetStatus, restore: boolean): void {
  if (!sameOrigin(req)) {
    writeJson(res, 403, { ok: false, note: '跨源请求被拒绝' })
    return
  }
  readIdBody(req, res, (id) => {
    if (id === undefined) return
    if (restore) status.restore(id)
    else status.dismiss(id)
    writeJson(res, 200, { ok: true })
  })
}

/**
 * 安装盾牌状态路由：webServer 可能晚于本插件就绪（fiber 未 ACTIVE 时
 * ctx.get 返回 undefined），轮询重试直到注册成功；超时只告警不阻断。
 */
export function installStatusRoute(ctx: Context, config: VetConfig, status: VetStatus): void {
  const c = ctx as unknown as ContextLike
  if (registerStatusRouteOnce(c, config, status)) return
  const timer = setInterval(() => {
    if (registerStatusRouteOnce(c, config, status)) {
      clearInterval(timer)
      // round-5 review（B-A16）：注册成功后 60s 告警定时器也要清——此前成功路径
      // 只清轮询，60s 后仍会打一条误导的「webServer 60s 内未就绪」warn。
      clearTimeout(timeout)
    }
  }, RETRY_MS)
  timer.unref?.()
  ctx.effect(() => () => clearInterval(timer), 'vet: status route waiter')
  const timeout = setTimeout(() => {
    if (typeof c.logger?.warn === 'function') {
      c.logger.warn('vet: webServer 60s 内未就绪，盾牌状态路由未注册（非 web profile 属正常）')
    }
  }, RETRY_MS * RETRY_MAX)
  timeout.unref?.()
}