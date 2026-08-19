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

/**
 * 缓存目录解析（C3，0.1.16 加固）：宿主注入的 request.cacheDir 优先——宿主在模块加载时快照
 * env（vet 先于第三方插件加载），进程内插件改动 process.env 无法重定向缓存；无注入时回退
 * 本进程 env / 默认 tmpdir（测试直调引擎场景）。
 */
export function cacheDirFor(requestDir?: string): string {
  if (requestDir !== undefined && requestDir !== '') return requestDir
  const env = process.env.DSH_PLUGIN_VET_CACHE_DIR
  if (env !== undefined && env !== '') return env
  return join(tmpdir(), 'dsh-plugin-vet-cache')
}

const VERDICTS = new Set(['critical', 'suspicious', 'clean'])

/**
 * N1（round-9）：capabilities 形状校验——report 若带 capabilities，必须是
 * CapabilityManifest 形状（字段名/类型/数组），否则视为无效缓存（防本地伪造/旧版毒缓存）。
 */
function validCapabilities(c: unknown): boolean {
  if (typeof c !== 'object' || c === null) return false
  const m = c as Record<string, unknown>
  for (const key of ['hosts', 'fsPaths', 'spawnCmds', 'imports']) {
    if (!Array.isArray(m[key])) return false
    if (!(m[key] as unknown[]).every(v => typeof v === 'string')) return false
  }
  // C2（0.1.16）：esmNamedBuiltins 可选布尔（旧条目无此字段也合法；形状校验不拒绝未知键）
  if (m.esmNamedBuiltins !== undefined && typeof m.esmNamedBuiltins !== 'boolean') return false
  return typeof m.hasNetwork === 'boolean' && typeof m.hasExec === 'boolean'
}

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
  // N1：capabilities 可选但形状必须校验
  if (r.capabilities !== undefined && !validCapabilities(r.capabilities)) return false
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
  context: { targetKind?: 'plugin' | 'generic'; runtime?: string; scanBasis?: 'git' | 'npm' } = {},
): string {
  const body = files.map(f => `${f.path}\u0000${f.content}`).join('\u0001')
  const ctx = `tk:${context.targetKind ?? ''}|rt:${context.runtime ?? ''}|sb:${context.scanBasis ?? ''}`
  return createHash('sha256').update(`${ENGINE_VERSION}|${ctx}|${JSON.stringify(rules ?? {})}|${body}`).digest('hex')
}

export function readCached(key: string, dir?: string, nonce?: string): ScanReport | undefined {
  try {
    const file = join(cacheDirFor(dir), `${key}.json`)
    if (!existsSync(file)) return undefined
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { report: ScanReport; nonce?: string }
    // C3（0.1.16 加固）：写入时嵌宿主 nonce，读时校验——无 nonce 的旧条目/伪造条目全部视为无效自动重扫
    if (nonce !== undefined && nonce !== '' && parsed.nonce !== nonce) return undefined
    if (!validReport(parsed.report)) return undefined
    return parsed.report
  } catch {
    return undefined
  }
}

export function writeCached(key: string, report: ScanReport, dir?: string, nonce?: string): void {
  try {
    const cacheRoot = cacheDirFor(dir)
    mkdirSync(cacheRoot, { recursive: true, mode: 0o700 })
    // 防本地其他用户读扫描报告/伪造缓存（F26）：文件 0600
    writeFileSync(join(cacheRoot, `${key}.json`), JSON.stringify({ report, ts: Date.now(), nonce: nonce ?? '' }), { mode: 0o600 })
  } catch {
    // cache must never fail a scan
  }
}