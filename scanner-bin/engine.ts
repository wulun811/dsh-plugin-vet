import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import ts from 'typescript'
import { parseSource } from './ast.js'
import { executeRules } from './rules/index.js'
import { computeScore, computeVerdict } from './score.js'
import { cacheKey, readCached, writeCached } from './cache.js'
import { ENGINE_VERSION } from './protocol.js'
import type { Finding, ScanReport, ScanRequest, ScanResponse } from './protocol.js'

const SCANNABLE_EXT = new Set(['js', 'ts', 'mjs', 'cjs'])

function extOf(file: string): string | undefined {
  const dot = file.lastIndexOf('.')
  return dot === -1 ? undefined : file.slice(dot + 1)
}

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

function buildReport(request: ScanRequest, findings: Finding[], sourceCount: number): ScanReport {
  return {
    engine: ENGINE_VERSION,
    sourceCount,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
}

/**
 * Run one scan request (pure logic; the stdio wrapper lives in index.ts).
 * kind='code': scan one source string. kind='files': scan a path list with
 * per-file 2s budget and a total budget of files × 2s (R8-scan-skipped on
 * timeout), cached by content hash per PLAN.md §4.5.
 */
export function scan(request: ScanRequest): ScanResponse {
  try {
    if (request.kind === 'code') {
      if (request.code === undefined || request.language === undefined) {
        return { ok: false, error: 'code 模式需要 language 与 code' }
      }
      const sf = parseSource(request.code, `input.${request.language}`, request.language)
      const findings = executeRules(sf, { request, runtime: request.runtime ?? 'host' })
      return { ok: true, report: buildReport(request, findings, 1) }
    }

    if (request.files === undefined || request.files.length === 0) {
      return { ok: false, error: 'files 模式需要非空 files 列表' }
    }
    const runtime = request.runtime ?? 'host'

    // content-hash cache (files mode only)
    const cacheables: { path: string; content: string }[] = []
    for (const file of request.files) {
      try {
        cacheables.push({ path: file, content: readFileSync(file, 'utf8') })
      } catch {
        cacheables.push({ path: file, content: '' })
      }
    }
    const key = cacheKey(cacheables, request.rules)
    const cached = readCached(key)
    if (cached !== undefined) return { ok: true, report: cached }

    const budgetEnv = Number(process.env.DSH_PLUGIN_VET_SCAN_BUDGET_MS)
    const budgetMs = Number.isFinite(budgetEnv) && budgetEnv >= 0
      ? budgetEnv
      : Math.max(1000, request.files.length * 2000)
    const start = Date.now()
    const findings: Finding[] = []
    let sourceCount = 0

    for (let i = 0; i < request.files.length; i++) {
      const file = request.files[i]
      if (i > 0 && Date.now() - start > budgetMs) {
        findings.push(skipFinding(file))
        break
      }
      const ext = extOf(file)
      if (ext === undefined || !SCANNABLE_EXT.has(ext)) continue
      let code: string
      try {
        code = readFileSync(file, 'utf8')
      } catch {
        continue // unreadable file: skip silently (per-file cache entry also empty)
      }
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
  } catch (error) {
    return { ok: false, error: String(error) }
  }
}
