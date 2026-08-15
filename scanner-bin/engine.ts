/**
 * Scan orchestration: code-string mode, files mode with per-file budget and
 * content-hash cache (PLAN.md §4.5). Pure logic — the stdio wrapper is index.ts.
 * @module dsh-plugin-vet/scanner-engine
 */
import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import { parseSource } from './ast.js'
import { executeRules } from './rules/index.js'
import { runPackageJson } from './rules/supply-chain.js'
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

/** Total scan budget: files × 2s, min 1s; env override for tests. */
function budgetMs(fileCount: number): number {
  const env = Number(process.env.DSH_PLUGIN_VET_SCAN_BUDGET_MS)
  return Number.isFinite(env) && env >= 0 ? env : Math.max(1000, fileCount * 2000)
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
  const deadline = Date.now() + budgetMs(request.files.length)
  for (let i = 0; i < request.files.length; i++) {
    const file = request.files[i]
    if (i > 0 && Date.now() > deadline) {
      findings.push(skipFinding(file))
      break
    }
    // R10: package.json manifests are JSON, not source; scan them directly.
    if (basename(file) === 'package.json') {
      if (request.rules?.['R10'] !== false) {
        const json = readOrDefault(file)
        if (json !== '') findings.push(...runPackageJson(json, 'package.json', request.targetKind))
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
 * cached by content hash per PLAN.md §4.5.
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

/** OSV 已知漏洞核对（R10 补漏，PLAN.md §14.6）：仅 files 模式 + package.json 有 name 时执行。 */
async function checkOsv(request: ScanRequest, opts: OsvCheckOptions): Promise<Finding[]> {
  if (request.osv !== true) return []
  const pkgFile = request.files?.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return []
  let pkg: { name?: unknown; version?: unknown }
  try {
    pkg = JSON.parse(readOrDefault(pkgFile)) as { name?: unknown; version?: unknown }
  } catch {
    return []
  }
  if (typeof pkg.name !== 'string' || pkg.name === '') return []
  let vulns: OsvVuln[]
  try {
    // F15：带 version 查询——OSV 服务端按 affected ranges 过滤，已修复版本不再误报
    vulns = await queryOsv(pkg.name, {
      timeoutMs: opts.osvTimeoutMs,
      fetchImpl: opts.fetchImpl,
      version: typeof pkg.version === 'string' ? pkg.version : undefined,
    })
  } catch {
    return [] // 网络失败/超时：静默降级，不影响静态判定
  }
  return vulns.slice(0, 5).map(v => ({
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