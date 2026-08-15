import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ENGINE_VERSION } from './protocol.js'
import type { ScanReport } from './protocol.js'

export interface CachedFile {
  path: string
  content: string
}

function cacheDir(): string {
  return process.env.DSH_PLUGIN_VET_CACHE_DIR ?? join(tmpdir(), 'dsh-plugin-vet-cache')
}

const VERDICTS = new Set(['critical', 'suspicious', 'clean'])

/** 严格形状校验：防本地伪造缓存报告（F26）——verdict/engine/findings 形状不符即视为无效。 */
function validReport(report: unknown): report is ScanReport {
  if (typeof report !== 'object' || report === null) return false
  const r = report as Record<string, unknown>
  if (r.engine !== ENGINE_VERSION) return false
  if (typeof r.staticScore !== 'number' || !Number.isFinite(r.staticScore)) return false
  if (typeof r.verdict !== 'string' || !VERDICTS.has(r.verdict)) return false
  if (typeof r.sourceCount !== 'number') return false
  if (!Array.isArray(r.findings)) return false
  for (const f of r.findings) {
    if (typeof f !== 'object' || f === null) return false
    const ff = f as Record<string, unknown>
    if (typeof ff.rule !== 'string' || typeof ff.severity !== 'string' || typeof ff.message !== 'string' || typeof ff.confidence !== 'string') return false
  }
  return true
}

/**
 * Cache key covers engine version, rules config, target kind, runtime, and full
 * content of every file. targetKind/runtime change verdict semantics (R2/R3/R9/R10
 * downgrade for generic) — omitting them lets one context's cached verdict poison
 * another (F1: deny gate used a strict scan that hit a generic-cached report).
 */
export function cacheKey(
  files: CachedFile[],
  rules: Record<string, boolean> | undefined,
  context: { targetKind?: 'plugin' | 'generic'; runtime?: string } = {},
): string {
  const body = files.map(f => `${f.path}\u0000${f.content}`).join('\u0001')
  const ctx = `tk:${context.targetKind ?? ''}|rt:${context.runtime ?? ''}`
  return createHash('sha256').update(`${ENGINE_VERSION}|${ctx}|${JSON.stringify(rules ?? {})}|${body}`).digest('hex')
}

export function readCached(key: string): ScanReport | undefined {
  try {
    const file = join(cacheDir(), `${key}.json`)
    if (!existsSync(file)) return undefined
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { report: ScanReport }
    if (!validReport(parsed.report)) return undefined
    return parsed.report
  } catch {
    return undefined
  }
}

export function writeCached(key: string, report: ScanReport): void {
  try {
    const dir = cacheDir()
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    // 防本地其他用户读扫描报告/伪造缓存（F26）：文件 0600
    writeFileSync(join(dir, `${key}.json`), JSON.stringify({ report, ts: Date.now() }), { mode: 0o600 })
  } catch {
    // cache must never fail a scan
  }
}