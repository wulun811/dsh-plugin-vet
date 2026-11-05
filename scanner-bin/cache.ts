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
  // 0.5.3：esmNamedBuiltinModules 可选字符串数组（v27 前的缓存没有此字段，消费方按「不知哪几个面」降级）
  if (m.esmNamedBuiltinModules !== undefined) {
    if (!Array.isArray(m.esmNamedBuiltinModules) || !(m.esmNamedBuiltinModules as unknown[]).every(v => typeof v === 'string')) return false
  }
  // P0-2 #9（round-11，0.1.21）：ghostDeps/zombieDeps 可选字符串数组（旧条目无此字段也合法）
  for (const key of ['ghostDeps', 'zombieDeps'] as const) {
    if (m[key] !== undefined) {
      if (!Array.isArray(m[key]) || !(m[key] as unknown[]).every(v => typeof v === 'string')) return false
    }
  }
  // C4（0.3.8）：hasNativeBinary 可选布尔、nativeBinaries 可选字符串数组（旧缓存条目无字段合法；
  // v21 起 engine 必产出，但缓存失效已由 validReport 的 engine 严格比对兜住）
  if (m.hasNativeBinary !== undefined && typeof m.hasNativeBinary !== 'boolean') return false
  if (m.nativeBinaries !== undefined) {
    if (!Array.isArray(m.nativeBinaries) || !(m.nativeBinaries as unknown[]).every(v => typeof v === 'string')) return false
  }
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
 * Cache key covers engine version, rules config, target kind, runtime, official-family
 * grading, and full content of every file. targetKind/runtime change verdict semantics
 * (R2/R3/R9/R10 downgrade for generic) — omitting them lets one context's cached verdict
 * poison another (F1: deny gate used a strict scan that hit a generic-cached report).
 * officialFamily likewise changes severities (0.3.13 artifact fold) → must enter the key,
 * or an official scan's folded report would be served to a third-party scan of the same bytes.
 */
export function cacheKey(
  files: CachedFile[],
  rules: Record<string, boolean> | undefined,
  context: { targetKind?: 'plugin' | 'generic'; runtime?: string; scanBasis?: 'git' | 'npm'; deps?: string; surface?: { configFiles?: boolean; instructionFiles?: boolean }; officialFamily?: boolean; dshVersion?: string } = {},
): string {
  // round-15 review：哈希改为增量 update + 每段长度前缀——
  // 1) 旧实现先 map+join 出整条 body（全量文件内容的第二份拷贝）再整体 update，
  //    大文件集（~1000×8MB）内存峰值 ≈ 2× 总字节；增量 update 不再复制内容。
  // 2) 无长度 framing 时 `path\u0000content` 拼接可被构造出二阶碰撞（不同文件集
  //    拼出相同串），长度前缀根除该碰撞面（路径与内容都带长度）。
  const h = createHash('sha256')
  for (const f of files) {
    h.update(String(f.path.length))
    h.update(':')
    h.update(f.path)
    h.update('\u0000')
    h.update(String(f.content.length))
    h.update(':')
    h.update(f.content)
    h.update('\u0001')
  }
  // surface 改变输出形状（R17/R18 是否参与）→ 必须入 key，否则开关切换会命中旧形状缓存
  const sf = context.surface
  const surface = sf !== undefined ? `cf:${sf.configFiles !== false ? 1 : 0}|if:${sf.instructionFiles !== false ? 1 : 0}` : 'cf:1|if:1'
  // 0.5.10（不变式 9）：`targetKind` 的协议默认值就是 'plugin'，规则侧一律判 `=== 'generic'`，
  // 所以「省略」与「显式 plugin」是同一个语义。键里按语义归槽，而不是按调用方的书写形式——
  // 否则同一份字节、同一个判定会分裂成两条缓存（工具面一条、加载前扫描一条），而且一旦有人
  // 把默认值写显，存量缓存会整体失效、几百个包在下次启动重扫一遍。
  const targetKind = context.targetKind === 'generic' ? 'generic' : ''
  // 0.5.24：`dshVersion` 改变 R12 需求闸门的判定（同一个包在不同 DSH 上结论不同）→ 必须入 key，
  // 否则升级后仍会命中旧版本的结论。代价是每次 DSH 升级全量重扫一次——那正是应该重扫的时刻。
  const ctx = `tk:${targetKind}|rt:${context.runtime ?? ''}|sb:${context.scanBasis ?? ''}|deps:${context.deps ?? ''}|of:${context.officialFamily === true ? 1 : 0}|dv:${context.dshVersion ?? ''}|${surface}`
  h.update(`${ENGINE_VERSION}|${ctx}|${JSON.stringify(rules ?? {})}|`)
  return 'sha256:' + h.digest('hex')
}

/**
 * 缓存条目文件名（Windows 兼容）：key 含 `sha256:` 前缀，冒号在 Windows 文件名里非法
 * （Linux 合法——vet1 开发环境未暴露）。统一替换为 `_`，读写两侧对称。
 */
function cacheEntryFile(key: string): string {
  return key.replace(/[:]/g, '_') + '.json'
}

export function readCached(key: string, dir?: string, nonce?: string): ScanReport | undefined {
  try {
    const file = join(cacheDirFor(dir), cacheEntryFile(key))
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
    writeFileSync(join(cacheRoot, cacheEntryFile(key)), JSON.stringify({ report, ts: Date.now(), nonce: nonce ?? '' }), { mode: 0o600 })
  } catch {
    // cache must never fail a scan
  }
}