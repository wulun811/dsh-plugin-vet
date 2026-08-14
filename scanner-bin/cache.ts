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

/** Cache key covers engine version, rules config, and full content of every file. */
export function cacheKey(files: CachedFile[], rules: Record<string, boolean> | undefined): string {
  const body = files.map(f => `${f.path}\u0000${f.content}`).join('\u0001')
  return createHash('sha256').update(`${ENGINE_VERSION}|${JSON.stringify(rules ?? {})}|${body}`).digest('hex')
}

export function readCached(key: string): ScanReport | undefined {
  try {
    const file = join(cacheDir(), `${key}.json`)
    if (!existsSync(file)) return undefined
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { report: ScanReport }
    if (parsed.report === undefined || parsed.report.engine !== ENGINE_VERSION) return undefined
    return parsed.report
  } catch {
    return undefined
  }
}

export function writeCached(key: string, report: ScanReport): void {
  try {
    const dir = cacheDir()
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, `${key}.json`), JSON.stringify({ report, ts: Date.now() }))
  } catch {
    // cache must never fail a scan
  }
}
