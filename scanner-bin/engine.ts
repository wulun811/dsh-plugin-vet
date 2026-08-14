/**
 * Scan orchestration: code-string mode, files mode with per-file budget and
 * content-hash cache (PLAN.md §4.5). Pure logic — the stdio wrapper is index.ts.
 * @module dsh-plugin-vet/scanner-engine
 */
import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import { parseSource } from './ast.js'
import { executeRules } from './rules/index.js'
import { computeScore, computeVerdict } from './score.js'
import { cacheKey, readCached, writeCached } from './cache.js'
import { ENGINE_VERSION } from './protocol.js'
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
  const key = cacheKey(request.files.map(file => ({ path: file, content: readOrDefault(file) })), request.rules)
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
