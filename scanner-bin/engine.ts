/**
 * Scan orchestration: code-string mode, files mode with per-file budget and
 * content-hash cache. Pure logic — the stdio wrapper is index.ts.
 * @module dsh-plugin-vet/scanner-engine
 */
import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import { parseSource } from './ast.js'
import { executeRules } from './rules/index.js'
import { runPackageJson } from './rules/supply-chain.js'
import { runContract } from './rules/contract.js'
import { computeScore, computeVerdict } from './score.js'
import { cacheKey, readCached, writeCached } from './cache.js'
import { ENGINE_VERSION } from './protocol.js'
import { queryOsv, type OsvVuln } from './osv.js'
import type { Finding, ScanReport, ScanRequest, ScanResponse } from './protocol.js'

const SCANNABLE_EXT = new Set(['js', 'ts', 'mjs', 'cjs'])

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
function buildReport(request: ScanRequest, findings: Finding[], sourceCount: number): ScanReport {
  return {
    engine: ENGINE_VERSION,
    sourceCount,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
}

/** Scan one in-memory code string. */
function scanCode(request: ScanRequest): ScanResponse {
  if (request.code === undefined || request.language === undefined) {
    return { ok: false, error: 'code 模式需要 language 与 code' }
  }
  const sf = parseSource(request.code, `input.${request.language}`, request.language)
  const findings = executeRules(sf, { request, runtime: request.runtime ?? 'host' })
  return { ok: true, report: buildReport(request, findings, 1) }
}

/** Scan a file list with a total budget and content-hash cache (files mode). */
function scanFiles(request: ScanRequest): ScanResponse {
  if (request.files === undefined || request.files.length === 0) {
    return { ok: false, error: 'files 模式需要非空 files 列表' }
  }
  const runtime = request.runtime ?? 'host'
  const key = cacheKey(
    request.files.map(file => ({ path: file, content: readOrDefault(file) })),
    request.rules,
    { targetKind: request.targetKind, runtime },
  )
  const cached = readCached(key)
  if (cached !== undefined) return { ok: true, report: cached }

  const findings: Finding[] = []
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
        findings.push(...runContract(json, file, request.targetKind))
      }
      continue
    }
    const ext = extOf(file)
    if (ext === undefined || !SCANNABLE_EXT.has(ext)) continue
    const code = readOrDefault(file)
    if (code === '') continue
    const language = ext === 'ts' ? 'ts' : 'js'
    const sf = parseSource(code, basename(file), language)
    const fileFindings = executeRules(sf, { request, runtime })
    for (const f of fileFindings) {
      if (f.file === undefined) f.file = basename(file)
      findings.push(f)
    }
    sourceCount++
  }
  const report = buildReport(request, findings, sourceCount)
  writeCached(key, report)
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
  osvTimeoutMs?: number
  fetchImpl?: typeof fetch
}

/**
 * 取 package.json 的直接依赖（dependencies + peerDependencies），用于 OSV 依赖核对。
 * P3-10：跳过 @deepseek-ai/*（官方包与 vet 同一信任边界，查询是噪声）；
 * 版本去掉 ^/~ 前缀（OSV 按 affected ranges 匹配精确版本）；上限 8 个（有界网络面）。
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
      out.push({ name, version: typeof ver === 'string' ? ver.replace(/^[~^]/, '') : undefined })
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
async function checkOsv(request: ScanRequest, opts: OsvCheckOptions): Promise<Finding[]> {
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
  const seenVuln = new Set<string>()
  for (const target of targets) {
    let found: OsvVuln[]
    try {
      // F15：带 version 查询——OSV 服务端按 affected ranges 过滤，已修复版本不再误报
      found = await queryOsv(target.name, {
        timeoutMs: opts.osvTimeoutMs,
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
  const base = scan(request)
  if (!base.ok || base.report === undefined) return base
  const osvFindings = await checkOsv(request, opts)
  if (osvFindings.length === 0) return base
  const findings = [...base.report.findings, ...osvFindings]
  const report: ScanReport = {
    ...base.report,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
  return { ok: true, report }
}