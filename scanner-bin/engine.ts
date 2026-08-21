/**
 * Scan orchestration: code-string mode, files mode with per-file budget and
 * content-hash cache. Pure logic — the stdio wrapper is index.ts.
 * @module dsh-plugin-vet/scanner-engine
 */
import { readFileSync, statSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { parseSource } from './ast.js'
import { extractCapabilities, aggregateCapabilities } from './capability.js'
import { collectDecodedLiterals } from './decode.js'
import { executeRules } from './rules/index.js'
import { runPackageJson } from './rules/supply-chain.js'
import { runContract } from './rules/contract.js'
import { NON_JS_SCRIPT_EXT, runNonJsScript } from './rules/non-js-scripts.js'
import { computeScore, computeVerdict } from './score.js'
import { cacheKey, readCached, writeCached, cacheDirFor } from './cache.js'
import { ENGINE_VERSION } from './protocol.js'
import { queryOsv, type OsvVuln } from './osv.js'
import type { CapabilityManifest, Finding, ScanReport, ScanRequest, ScanResponse } from './protocol.js'

const SCANNABLE_EXT = new Set(['js', 'ts', 'mjs', 'cjs'])

/** 大文件预检上限（技术债偿还）：超过该大小的源码文件不做整文件 readFileSync——
 * 直接产出 R8-scan-skipped info（规则扫不到≠干净，但绝不让大文件把引擎内存打爆）。 */
const PRE_FILE_SIZE_LIMIT = 8 * 1024 * 1024

/** Extension of a path (without dot), or undefined when none. */
function extOf(file: string): string | undefined {
  const dot = file.lastIndexOf('.')
  return dot === -1 ? undefined : file.slice(dot + 1)
}

/** Read a file as UTF-8, returning '' when unreadable. */
function readOrDefault(file: string): string {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

/** R8-skip 触发后仍需时间写出报告并退出——必须早于宿主 kill 的余量。 */
const ENGINE_KILL_MARGIN_MS = 1500

// ── P0-2 #9（R16）：幽灵/僵尸依赖健康审计 ──────────────────────────────────
// 依赖声明（package.json）↔ 代码引用（capabilities.imports）↔ 实际安装（node_modules）三方对账：
// - 幽灵依赖（ghost）：代码引用但 package.json 未声明——靠传递依赖提升侥幸可解析，升级即可能断供/换源；
// - 僵尸依赖（zombie）：package.json 声明但 node_modules 找不到——陈旧/伪造声明，运行到即崩溃。
// 纪律（产品红线）：info 级观测（WEIGHTS.info=0 不扣分）、heuristic 置信（不改 verdict）、零出站；
// @deepseek-ai/* 宿主信任边界两端都不列（与 OSV 直接依赖核对的跳过规则一致，避免 DSH 插件宿主 SDK 误报）。
const R16_DEP_CAP = 20
/** 从包根向上的 node_modules 查找层数上限（npm hoisting/工作区常见 2-4 层；8 层已超出常规 monorepo）。 */
const R16_ROOT_WALK = 8

export interface DepsInfo {
  /** 声明侧直接依赖（dependencies/devDependencies/peerDependencies/optionalDependencies；去 @deepseek-ai/*、排序去重）。 */
  declared: string[]
  /** declared 中实际安装的子集；null = 本地无 node_modules，僵尸判定不可用。 */
  installed: string[] | null
  /** 参与缓存 key 的指纹（声明/node_modules 变化 → 缓存失效重扫，保证幽灵/僵尸结果不陈旧）。 */
  fingerprint: string
}

function declaredDepsOf(pkg: Record<string, unknown>): string[] {
  const out = new Set<string>()
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const) {
    const deps = pkg[key]
    if (typeof deps !== 'object' || deps === null) continue
    for (const name of Object.keys(deps as Record<string, unknown>)) {
      if (name.startsWith('@deepseek-ai/')) continue
      out.add(name)
    }
  }
  return [...out].sort()
}

/** 从包根向上（含本层）收集现有 node_modules 目录（hoisting 到工作区根的情况也能找到）。 */
function nodeModulesRoots(pkgRoot: string): string[] {
  const roots: string[] = []
  let dir = pkgRoot
  for (let i = 0; i <= R16_ROOT_WALK; i++) {
    try {
      if (statSync(join(dir, 'node_modules')).isDirectory()) roots.push(join(dir, 'node_modules'))
    } catch {
      // 无此目录/不可读：跳过该层
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return roots
}

/** 某依赖是否在任一 node_modules 根下实际安装（scoped 包拆两段路径）。 */
function isInstalledDep(name: string, roots: string[]): boolean {
  const parts = name.split('/')
  for (const root of roots) {
    const p = parts.length === 2 ? join(root, parts[0], parts[1]) : join(root, name)
    try {
      if (statSync(p).isDirectory()) return true
    } catch {
      // 缺失：继续找下一个根
    }
  }
  return false
}

/** 构建依赖健康审计上下文（无 package.json / 坏 package.json → null，静默跳过）。 */
export function buildDepsInfo(files: string[] | undefined): DepsInfo | null {
  if (files === undefined) return null
  const pkgFile = files.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return null
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(readOrDefault(pkgFile)) as Record<string, unknown>
  } catch {
    return null
  }
  const declared = declaredDepsOf(pkg)
  const roots = nodeModulesRoots(dirname(pkgFile))
  if (roots.length === 0) {
    return { declared, installed: null, fingerprint: JSON.stringify({ declared }) }
  }
  const installed = declared.filter(d => isInstalledDep(d, roots))
  return { declared, installed, fingerprint: JSON.stringify({ declared, installed }) }
}

/** R16 info 观测（不给分、不改 verdict——WEIGHTS.info=0 & heuristic 恒 0.5 但 info 权重为 0）。 */
function depsFindings(ghost: string[], zombie: string[]): Finding[] {
  const out: Finding[] = []
  for (const d of ghost) {
    out.push({
      rule: 'R16', severity: 'info', confidence: 'heuristic',
      message: '幽灵依赖：代码引用 ' + d + ' 但 package.json 未声明（靠传递依赖提升侥幸可解析，升级可能断供/换源）',
      evidence: d, file: 'package.json',
    })
  }
  for (const d of zombie) {
    out.push({
      rule: 'R16', severity: 'info', confidence: 'heuristic',
      message: '僵尸依赖：package.json 声明了 ' + d + ' 但 node_modules 中不存在（陈旧/伪造声明，运行到即失败）',
      evidence: d, file: 'package.json',
    })
  }
  return out
}

/**
 * 从 package.json 内容解析包形态（round-7，P4）：bin 声明（字符串或对象）→ 应用型包
 * （appShape，R3 按能力触达面降级）；bin 值对应文件 → CLI 入口（cliFiles，R2/R3/R9 按
 * 通用代码判定）。engine 只见文件 basename，bin 路径统一归一为 basename 匹配。
 */
function packageShape(content: string): { cliFiles: Set<string>; appShape: boolean } {
  const cliFiles = new Set<string>()
  let appShape = false
  try {
    const pkg = JSON.parse(content) as Record<string, unknown>
    const bin = pkg.bin
    const entries: string[] = []
    if (typeof bin === 'string' && bin !== '') entries.push(bin)
    else if (typeof bin === 'object' && bin !== null) {
      for (const v of Object.values(bin)) {
        if (typeof v === 'string' && v !== '') entries.push(v)
      }
    }
    appShape = entries.length > 0
    for (const e of entries) {
      const name = basename(e.replace(/^\.\//, ''))
      if (name !== '' && name !== '.') cliFiles.add(name)
    }
  } catch {
    // 坏 package.json：无形态证据（保守不降级）
  }
  return { cliFiles, appShape }
}

/**
 * Total scan budget: min(files × 2s, host-timeout − margin), floor 1s.
 * P2-1：宿主 kill 超时（report min(…,60s) / deny min(…,30s) / 工具 60s）比 files×2s 先到的话，
 * 子进程在 R8-skip 触发前被杀 → ok:false（deny fail-closed 误拦合法大包、report 误报 scan-fail）。
 * 引入宿主计划超时（request.timeoutMs，client 写入）后：budget = min(files×2s, timeout−ENGINE_KILL_MARGIN_MS)，
 * R8-skip 恒先于 kill 触发——优雅降级结构上可达。timeoutMs 缺省（直调 engine 的测试）维持旧行为。
 * round-4：移除 DSH_PLUGIN_VET_SCAN_BUDGET_MS env 覆盖——设大值会绕过宿主对齐再次让
 * R8-skip 不可达（子进程被杀 → deny fail-closed 误拦）；测试用 timeoutMs 参数控制预算。
 */
function budgetMs(fileCount: number, timeoutMs?: number): number {
  const byFiles = fileCount * 2000
  const byHost = timeoutMs !== undefined && Number.isFinite(timeoutMs)
    ? timeoutMs - ENGINE_KILL_MARGIN_MS
    : byFiles
  return Math.max(1000, Math.min(byFiles, byHost))
}

/** Meta finding emitted when a file exceeds the scan budget (R8-scan-skipped). */
function skipFinding(file: string): Finding {
  return {
    rule: 'R8',
    severity: 'info',
    confidence: 'heuristic',
    message: '扫描超时/文件过大跳过（R8-scan-skipped）',
    evidence: '',
    file: basename(file),
  }
}

/** Assemble the final report (score + verdict) for a request. */
function buildReport(
  request: ScanRequest,
  findings: Finding[],
  sourceCount: number,
  capabilities?: CapabilityManifest,
): ScanReport {
  const report: ScanReport = {
    engine: ENGINE_VERSION,
    sourceCount,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
  // N1：能力清单仅 files 模式产出（code 模式无插件身份）
  if (capabilities !== undefined) report.capabilities = capabilities
  return report
}

/** Scan one in-memory code string. */
function scanCode(request: ScanRequest): ScanResponse {
  if (request.code === undefined || request.language === undefined) {
    return { ok: false, error: 'code 模式需要 language 与 code' }
  }
  const sf = parseSource(request.code, `input.${request.language}`, request.language)
  // N2：解码预处理（code 模式同样受益：scan_plugin dynamic-code 对混淆片段输出解码命中）
  const decodedLiterals = collectDecodedLiterals(sf, `input.${request.language}`)
  const findings = executeRules(sf, { request, runtime: request.runtime ?? 'host', decodedLiterals })
  return { ok: true, report: buildReport(request, findings, 1) }
}

/** Scan a file list with a total budget and content-hash cache (files mode). */
function scanFiles(request: ScanRequest): ScanResponse {
  if (request.files === undefined || request.files.length === 0) {
    return { ok: false, error: 'files 模式需要非空 files 列表' }
  }
  const runtime = request.runtime ?? 'host'
  // round-7：package.json 内容参与缓存 hash（bin 形态变化 → 缓存自然失效），无需额外 context
  const pkgJson = request.files.find(f => basename(f) === 'package.json')
  const shape = pkgJson === undefined ? undefined : packageShape(readOrDefault(pkgJson))
  // P0-2 #9（R16）：依赖健康上下文（幽灵/僵尸对账 + 缓存指纹）
  const depsInfo = buildDepsInfo(request.files)
  // R8-skip 先于缓存散列：超过 PRE_FILE_SIZE_LIMIT 的文件不会进入扫描循环（stat 先行跳过），
  // 缓存 key 不再整读它们——旧实现 key 阶段对全部文件 readOrDefault，大文件被全量读入 → 内存峰值。
  // 超限文件用 stat 尺寸做 key 占位（超大文件内容从不参与判定，尺寸即"未扫描"的充分表示）。
  const key = cacheKey(
    request.files.map(file => {
      try {
        const st = statSync(file)
        if (st.size > PRE_FILE_SIZE_LIMIT) return { path: file, content: 'vet-skipped:size=' + st.size }
      } catch {
        // stat 失败 → 走 readOrDefault 的空串兜底
      }
      return { path: file, content: readOrDefault(file) }
    }),
    request.rules,
    {
      targetKind: request.targetKind,
      runtime,
      scanBasis: request.scanBasis,
      // P0-2 #9（R16）：声明/node_modules 变化 → key 变化 → 缓存失效重扫；规则关掉则不参与 key
      deps: request.rules?.['R16'] === false ? undefined : depsInfo?.fingerprint,
    },
  )
  // C3（0.1.16 加固）：目录与 nonce 均来自宿主注入（cacheDirFor 缺省回退 env/tmpdir）
  const cacheDir = cacheDirFor(request.cacheDir)
  const cached = readCached(key, cacheDir, request.cacheNonce ?? '')
  if (cached !== undefined) return { ok: true, report: cached }

  const findings: Finding[] = []
  const manifests: CapabilityManifest[] = []
  let sourceCount = 0
  const deadline = Date.now() + budgetMs(request.files.length, request.timeoutMs)
  for (let i = 0; i < request.files.length; i++) {
    const file = request.files[i]
    if (i > 0 && Date.now() > deadline) {
      findings.push(skipFinding(file))
      break
    }
    // R10/R12: package.json manifests are JSON, not source; scan them directly.
    if (basename(file) === 'package.json') {
      const json = readOrDefault(file)
      if (json === '') continue
      if (request.rules?.['R10'] !== false) {
        findings.push(...runPackageJson(json, 'package.json', request.targetKind))
      }
      // R12: Cordis/DSH bundle 契约（P-2 计划项）——入口/patch 声明等确定性检查
      if (request.rules?.['R12'] !== false) {
        findings.push(...runContract(json, file, request.targetKind, request.scanBasis))
      }
      continue
    }
    const ext = extOf(file)
    // R14: non-JS script files (shell/PowerShell/batch) get a deterministic
    // text scan for download-and-exec primitives — the AST rules do not see them.
    if (ext !== undefined && NON_JS_SCRIPT_EXT.has(ext)) {
      if (request.rules?.['R14'] !== false) {
        const script = readOrDefault(file)
        if (script !== '') {
          findings.push(...runNonJsScript(script, basename(file), request.targetKind))
        }
      }
      continue
    }
    if (ext === undefined || !SCANNABLE_EXT.has(ext)) continue
    // 大文件预检（技术债偿还）：readFileSync 前先 stat，超限即 R8-skip（不整读、不 OOM）
    try {
      const st = statSync(file)
      if (st.size > PRE_FILE_SIZE_LIMIT) {
        findings.push(skipFinding(file))
        continue
      }
    } catch {
      // stat 失败（文件消失/不可读）：走 readOrDefault 的空串兜底
    }
    const code = readOrDefault(file)
    if (code === '') continue
    const language = ext === 'ts' ? 'ts' : 'js'
    const sf = parseSource(code, basename(file), language)
    // N2：解码预处理（每文件独立采集，结果并入 R13/R7/R11 语料）
    const decodedLiterals = collectDecodedLiterals(sf, basename(file))
    const fileFindings = executeRules(sf, {
      request,
      runtime,
      cliFiles: shape?.cliFiles,
      appShape: shape?.appShape,
      filePath: file,
      decodedLiterals,
    })
    for (const f of fileFindings) {
      if (f.file === undefined) f.file = basename(file)
      findings.push(f)
    }
    // N1：每文件能力提取 → 聚合（files 模式才有插件身份；code 模式不产出）
    manifests.push(extractCapabilities(sf))
    sourceCount++
  }
  const capabilities = aggregateCapabilities(manifests)
  // P0-2 #9（R16）：幽灵/僵尸依赖三方对账——写入能力清单 + info 观测（files 模式 + 有 package.json 才生效；
  // info/heuristic 不计分不改 verdict，纯数据面与提示面）
  if (depsInfo !== null && request.rules?.['R16'] !== false) {
    const declaredSet = depsInfo.declared
    const ghost = capabilities.imports
      .filter(i => !i.startsWith('@deepseek-ai/') && !declaredSet.includes(i))
      .slice(0, R16_DEP_CAP)
    const installed = depsInfo.installed
    const zombie = installed === null
      ? []
      : declaredSet.filter(d => !installed.includes(d)).slice(0, R16_DEP_CAP)
    if (ghost.length > 0) capabilities.ghostDeps = ghost
    if (zombie.length > 0) capabilities.zombieDeps = zombie
    findings.push(...depsFindings(ghost, zombie))
  }
  const report = buildReport(request, findings, sourceCount, capabilities)
  writeCached(key, report, cacheDir, request.cacheNonce ?? '')
  return { ok: true, report }
}

/**
 * Run one scan request (pure logic; the stdio wrapper lives in index.ts).
 * kind='code': scan one source string. kind='files': scan a path list with
 * per-file 2s budget and total budget files×2s (R8-scan-skipped on timeout),
 * cached by content hash.
 */
export function scan(request: ScanRequest): ScanResponse {
  try {
    return request.kind === 'code' ? scanCode(request) : scanFiles(request)
  } catch (error) {
    return { ok: false, error: String(error) }
  }
}

export interface OsvCheckOptions {
  /** 跨源去重（OSV ↔ upstream-radar 共享）：同漏洞 id 只报一次（曾各自 seenVuln → 重复 finding）。 */
  seenVuln?: Set<string>
  /** upstream-radar 实现注入（测试用）：默认走本地 execFile CLI；返回 null 视为未安装/失败降级。 */
  radarImpl?: (packageRoot: string, timeoutMs: number) => Promise<UpstreamRadarResult | null>
  osvTimeoutMs?: number
  /** P2-10：OSV 总预算（宿主超时余量）。提供时逐查询超时按剩余预算动态收窄且 OSV 总耗时不超过预算，
   * 避免超出宿主 kill 超时 → 子进程被 SIGKILL → 扫描失败（deny 模式 fail-closed 误拦合法包）。
   * 直调引擎（无 timeoutMs）时不提供，沿用旧的每查询固定超时、无总预算行为。 */
  osvBudgetMs?: number
  fetchImpl?: typeof fetch
}

/**
 * 取 package.json 的直接依赖（dependencies + peerDependencies），用于 OSV 依赖核对。
 * P3-10：跳过 @deepseek-ai/*（官方包与 vet 同一信任边界，查询是噪声）；上限 8 个（有界网络面）。
 */
const OSV_MAX_DIRECT_DEPS = 8

/**
 * P3-1/P3-3：OSV 只做精确版本查询。*、>=1.0.0、^1 等 range 原样传给 OSV 会被当精确版本
 * 匹配——误返回或报错被吞。非精确（含 undefined）一律跳过该目标查询；主包无 version
 * 也不查全量历史（陈旧漏洞全是误报）。判定：以数字开头、含至少一个点、无 range 符号。
 */
function isExactVersion(v: unknown): v is string {
  if (typeof v !== 'string' || v.length === 0) return false
  const first = v.charCodeAt(0)
  if (first < 48 || first > 57) return false
  const dot = v.indexOf('.')
  if (dot <= 0 || dot === v.length - 1) return false
  for (let i = 0; i < v.length; i++) {
    const code = v.charCodeAt(i)
    const ok = (code >= 48 && code <= 57) || (code >= 97 && code <= 122) || (code >= 65 && code <= 90)
      || v[i] === '-' || v[i] === '+' || v[i] === '_' || v[i] === '.'
    if (!ok) return false
  }
  return true
}

function directDepsOf(pkg: Record<string, unknown>): { name: string; version?: string }[] {
  const out: { name: string; version?: string }[] = []
  const seen = new Set<string>()
  for (const key of ['dependencies', 'peerDependencies'] as const) {
    const deps = pkg[key]
    if (typeof deps !== 'object' || deps === null) continue
    for (const [name, ver] of Object.entries(deps as Record<string, unknown>)) {
      if (name.startsWith('@deepseek-ai/')) continue
      if (seen.has(name)) continue
      seen.add(name)
      // round-7（P2）：range（^/~/*/>= 等）原样保留，不再剥前缀——isExactVersion 只放行
      // 精确版本，range 一律跳过查询（README 宣称行为）。此前 ^2.4.2 被剥成下界 "2.4.2"
      // 发给 OSV：下界在受影响区间而上界已修复（实际装到 2.8.x）时会误报已知漏洞。
      out.push({ name, version: typeof ver === 'string' ? ver : undefined })
    }
    if (out.length >= OSV_MAX_DIRECT_DEPS) break
  }
  return out.slice(0, OSV_MAX_DIRECT_DEPS)
}

/**
 * OSV 已知漏洞核对（R10 补漏）：仅 files 模式 + package.json 有 name 时执行。
 * P3-10：核对面从插件自身扩展到直接依赖（上限 8 个）——插件生态的主要风险在依赖树；
 * 每项独立查询、独立超时，网络失败只跳过该项（静默降级，不影响静态判定）。
 * 间接传递树超出 OSV v1 范围与扫描预算，README 已记录边界。
 */
async function checkOsv(request: ScanRequest, opts: OsvCheckOptions = {}): Promise<Finding[]> {
  if (request.osv !== true) return []
  const pkgFile = request.files?.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return []
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(readOrDefault(pkgFile)) as Record<string, unknown>
  } catch {
    return []
  }
  if (typeof pkg.name !== 'string' || pkg.name === '') return []
  const targets: { name: string; version?: string }[] = [
    { name: pkg.name, version: typeof pkg.version === 'string' ? pkg.version : undefined },
    ...directDepsOf(pkg),
  ].filter(t => isExactVersion(t.version)) // filter: only exact versions take part in OSV checks
  const vulns: OsvVuln[] = []
  // 透传的外部集合（checkSupplyChain 跨源共享）或孤立集合——dedup 按 id 生效
  const seenVuln = opts.seenVuln ?? new Set<string>()
  // P2-10：OSV 总预算（宿主超时余量）——逐查询超时按「剩余预算 / 剩余目标数」动态收窄（下限
  // 500ms、上限 4000ms），并保证 OSV 总耗时不超过预算，提前 break 避免超出宿主 kill 超时
  // 导致子进程被 SIGKILL → 扫描失败（deny 模式 fail-closed 误拦合法包 / report 误报 scan-fail）。
  const budgetEnd = opts.osvBudgetMs !== undefined ? Date.now() + opts.osvBudgetMs : undefined
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i]
    if (budgetEnd !== undefined && Date.now() >= budgetEnd) break
    const remaining = budgetEnd !== undefined ? budgetEnd - Date.now() : undefined
    const perQuery = remaining !== undefined
      ? Math.max(500, Math.min(4000, Math.floor(remaining / (targets.length - i))))
      : (opts.osvTimeoutMs ?? 4000)
    let found: OsvVuln[]
    try {
      // F15：带 version 查询——OSV 服务端按 affected ranges 过滤，已修复版本不再误报
      found = await queryOsv(target.name, {
        timeoutMs: perQuery,
        fetchImpl: opts.fetchImpl,
        version: target.version,
      })
    } catch {
      continue // 网络失败/超时：静默降级，不影响静态判定
    }
    for (const v of found) {
      if (seenVuln.has(v.id)) continue
      seenVuln.add(v.id)
      vulns.push(v)
    }
    if (vulns.length >= 10) break
  }
  return vulns.slice(0, 10).map(v => ({
    rule: 'OSV',
    severity: 'high',
    confidence: 'certain', // 漏洞库命中是事实（非启发式），verdict 可据此抬升
    message: '已知漏洞 ' + v.id + (v.aliases.length > 0 ? '（' + v.aliases[0] + '）' : '') + '：' + (v.summary ?? 'npm 生态已知漏洞').slice(0, 110),
    evidence: '',
    file: 'package.json',
  }))
}

/**
 * scan + OSV 核对（异步，含网络调用）：静态判定（含缓存）与 OSV 结果分离——
 * 缓存只存静态报告，OSV 每次扫描实时查询（保持数据新鲜）。OSV 命中追加 high
 * findings 并重算 score/verdict；网络失败静默降级为纯静态结果。
 */
export async function scanWithOsv(request: ScanRequest, opts: OsvCheckOptions = {}): Promise<ScanResponse> {
  const start = Date.now()
  const base = scan(request)
  if (!base.ok || base.report === undefined) return base
  // P2-10：从宿主超时推导 OSV 总预算，确保 OSV 网络相位不超出宿主 kill 超时（见 checkOsv）。
  // 预算 = 宿主超时 - 静态扫描耗时 - 引擎余量 - 输出余量；缺省（直调引擎、无 timeoutMs）不改行为。
  let osvBudgetMs = opts.osvBudgetMs
  if (osvBudgetMs === undefined && typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)) {
    osvBudgetMs = Math.max(1000, request.timeoutMs - (Date.now() - start) - ENGINE_KILL_MARGIN_MS - 500)
  }
  const supplyChainFindings = await checkSupplyChain(request, { ...opts, osvBudgetMs })
  if (supplyChainFindings.length === 0) return base
  const findings = [...base.report.findings, ...supplyChainFindings]
  const report: ScanReport = {
    ...base.report,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
  return { ok: true, report }
}

// ── 传递依赖扫描（P1 特性）─────────────────────────────────────

import { execFile } from 'node:child_process'

export interface UpstreamRadarResult {
  vulnerabilities: { id: string; package: string; severity: string; source: string }[]
}

// 创建 require 函数（ESM 模块中需要 createRequire）
const require = createRequire(import.meta.url)

// v5 修订（专家1 #5）：不使用 npx 自动安装，先探测本地安装路径
async function queryUpstreamRadar(
  packageRoot: string,
  timeoutMs: number = 15_000
): Promise<UpstreamRadarResult | null> {
  // 优先使用本地安装的 upstream-radar（避免 npx 自动安装的供应链风险）
  let radarPath: string | null = null
  try {
    radarPath = require.resolve('upstream-radar/bin/upstream-radar.js', { paths: [packageRoot] })
  } catch {
    // 未安装：静默降级
    return null
  }
  
  return new Promise((resolve) => {
    execFile(radarPath!, ['scan', packageRoot, '--json'], {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,  // v5 修订（专家2 #10）：增加到 10MB
    }, (err, stdout) => {
      if (err !== null || stdout === '') {
        resolve(null)  // 超时/失败：静默降级
        return
      }
      try {
        resolve(JSON.parse(stdout) as UpstreamRadarResult)
      } catch {
        resolve(null)
      }
    })
  })
}

let upstreamRadarWarned = false

/** 单测辅助：重置模块级 warn 标志（进程内测试隔离；生产每次扫描为独立子进程，天然每次只警告一次）。 */
export function resetUpstreamRadarWarned(): void {
  upstreamRadarWarned = false
}

/**
 * 供应链检查：直接依赖 OSV + 传递依赖 upstream-radar。
 */
async function checkSupplyChain(
  request: ScanRequest,
  opts: OsvCheckOptions & { transitiveDeps?: boolean }
): Promise<Finding[]> {
  // 1. 现有逻辑：插件自身 + 直接依赖 OSV 查询（osvBudgetMs 随 opts 透传，约束 OSV 总预算）
  //    跨源去重：与 upstream-radar 共享同一 seenVuln，同 id CVE 不重复报告（#8 修复）
  const crossSourceSeen = new Set<string>()
  const directFindings = await checkOsv(request, { ...opts, seenVuln: crossSourceSeen })

  // 2. 新增：传递依赖扫描（调用 upstream-radar CLI）
  if (request.transitiveDeps !== true) return directFindings
  const pkgFile = request.files?.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return directFindings
  const pkgRoot = dirname(pkgFile)

  // P2-10：传递依赖 CLI 超时同样受 OSV 总预算约束（缺省 15s），避免拖垮宿主 kill 超时
  const radarTimeout = opts.osvBudgetMs !== undefined
    ? Math.min(opts.osvBudgetMs, opts.osvTimeoutMs ?? 15_000)
    : (opts.osvTimeoutMs ?? 15_000)
  const radarResult = opts.radarImpl !== undefined
    ? await opts.radarImpl(pkgRoot, radarTimeout)
    : await queryUpstreamRadar(pkgRoot, radarTimeout)
  if (radarResult === null) {
    // v5 修订（专家2 #9）：首次调用时给出友好提示
    if (!upstreamRadarWarned) {
      console.warn('[vet] transitiveDeps enabled but upstream-radar not installed or failed, skipping transitive dependency scan')
      upstreamRadarWarned = true
    }
    return directFindings  // 未安装/超时：静默降级
  }

  // 形状校验：确保 vulnerabilities 字段存在且为数组
  if (!Array.isArray(radarResult.vulnerabilities)) {
    return directFindings  // 输出格式不符合预期，静默降级
  }

  const transitiveFindings: Finding[] = []

  // 与 OSV 共享去重集合：同一漏洞在 OSV 与 upstream-radar 间只报一条（曾各用各的
  // seenVuln → 同一 CVE 出 rule=OSV 与 rule=OSV-T 两条 finding）。
  for (const vuln of radarResult.vulnerabilities.slice(0, 20)) {
    if (crossSourceSeen.has(vuln.id)) continue
    crossSourceSeen.add(vuln.id)
    transitiveFindings.push({
      rule: 'OSV-T',  // 新规则名：传递依赖已知漏洞
      severity: 'medium',  // v5 修订（专家1 #7 + 专家2 #11）：传递依赖利用面小于直接依赖，权重降为 medium
      confidence: 'certain',
      message: `传递依赖已知漏洞 ${vuln.id}（${vuln.package}，来源 ${vuln.source}）`,
      evidence: '',
      file: 'package.json',
    })
  }

  return [...directFindings, ...transitiveFindings]
}