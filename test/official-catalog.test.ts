import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import {
  isOfficialPackageName, normalizePackageName, refreshOfficialCatalogFromRegistry,
  setCatalogAutoRefresh, setOfficialCatalogDirForTest, officialCatalogPath,
} from '../lib/guards/official-catalog.js'
import { computePackageHash, setBaselineDirForTest, refreshBaseline } from '../lib/guards/content-baseline.js'
import { setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { isOfficialTrusted, resetOfficialTrustForTest } from '../lib/guard/runtime-attrib.js'
import { VetStatus } from '../lib/guard/status.js'
import type { VetConfig } from '../lib/config.js'

const execFileAsync = promisify(execFile)

const REPO_ROOT = join(import.meta.dirname, '..')
const IN_CATALOG = '@deepseek-ai/dsh-atomic-write'   // 真实官方包名（种子内）
const OUT_CATALOG = '@deepseek-ai/evil-not-real'     // 目录外官方名

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report', autoScan: true,
  scannerTimeoutMs: 15_000,
  rules: {}, denyOn: 'critical', allowlist: [],
  runtimeGuard: 'off', runtimeIntervalMs: 2000, runtimeMemLimitMb: 2048,
  runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
  contentBaseline: true, acknowledgedPackageHashes: {},
  ...over,
})

class FakeCtx {
  handlers = new Map<string, Function[]>()
  baseUrl = REPO_ROOT
  logger = { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} }
  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

/** 在临时 profile 的 node_modules 下重建 IN_CATALOG 名的夹具包（0.3.5 审查修正：
 * 原先直接写仓库 node_modules/@deepseek-ai 并 afterAll 无条件清理——若未来仓库引入该
 * 依赖会被误删；改为 profile 隔离夹具，随 profile 一起清理，零污染）。 */
function makePkg(profile: string): string {
  const unscoped = IN_CATALOG.split('/')[1]
  const pkg = join(profile, 'node_modules', '@deepseek-ai', unscoped)
  rmSync(pkg, { recursive: true, force: true })
  mkdirSync(pkg, { recursive: true })
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: IN_CATALOG, version: '9.9.9', main: 'index.js' }))
  writeFileSync(join(pkg, 'index.js'), 'module.exports = { ok: true }\n')
  return pkg
}

/** npm 布局 tarball（package/ 前缀）——快照夹具目录内容。 */
async function makeTgz(pkg: string): Promise<Buffer> {
  const stage = mkdtempSync(join(tmpdir(), 'vet-ocat-'))
  const pkgDir = join(stage, 'package')
  mkdirSync(pkgDir, { recursive: true })
  for (const f of ['package.json', 'index.js']) {
    const src = join(pkg, f)
    if (existsSync(src)) writeFileSync(join(pkgDir, f), readFileSync(src))
  }
  const out = join(stage, 'p.tgz')
  await execFileAsync('tar', ['-czf', out, '-C', stage, 'package'])
  const buf = readFileSync(out)
  rmSync(stage, { recursive: true, force: true })
  return buf
}

describe('official-catalog：官方全集判据（M1）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-ocat-store-'))
    setOfficialCatalogDirForTest(join(dir, 'store'))
  })
  afterAll(() => {
    setOfficialCatalogDirForTest(undefined)
    setCatalogAutoRefresh(true)
    vi.unstubAllGlobals()
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
  })

  it('规一化：@scope/name/subpath → @scope/name；本地路径原样', () => {
    expect(normalizePackageName('@deepseek-ai/dsh-tool-subagent/list-agents')).toBe('@deepseek-ai/dsh-tool-subagent')
    expect(normalizePackageName('@deepseek-ai/dsh-settings-file')).toBe('@deepseek-ai/dsh-settings-file')
    expect(normalizePackageName('/path/to/file.mjs')).toBe('/path/to/file.mjs')
    expect(normalizePackageName('name/sub')).toBe('name')
  })

  it('种子成员：真实官方包在目录内（含警报涉及的三个包名）', () => {
    expect(isOfficialPackageName('@deepseek-ai/dsh-session-persistence-jsonl')).toBe(true)
    expect(isOfficialPackageName('@deepseek-ai/dsh-settings-file')).toBe(true)
    expect(isOfficialPackageName('@deepseek-ai/dsh-atomic-write')).toBe(true)
    expect(isOfficialPackageName('@deepseek-ai/dsh-tools')).toBe(true)
  })

  it('目录外官方名：不在目录内（"多出来的那个"）', () => {
    expect(isOfficialPackageName(OUT_CATALOG)).toBe(false)
    expect(isOfficialPackageName('@deepseek-ai/evil-official')).toBe(false)
  })

  it('registry 核对：scope 枚举发现的官方名并入目录并落盘覆盖层（重启后仍生效）', async () => {
    const discovered = ['@deepseek-ai/dsh-brand-new-2026', '@deepseek-ai/another-new']
    vi.stubGlobal('fetch', vi.fn(async () => {
      const body = JSON.stringify({ objects: discovered.map(n => ({ package: { name: n } })) })
      return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
    }))
    const merged = await refreshOfficialCatalogFromRegistry()
    expect(merged.has('@deepseek-ai/dsh-brand-new-2026')).toBe(true)
    expect(isOfficialPackageName('@deepseek-ai/dsh-brand-new-2026')).toBe(true)
    // 覆盖层已落盘 + 缓存失效后重载仍认识
    expect(existsSync(officialCatalogPath())).toBe(true)
    setOfficialCatalogDirForTest(join(dir, 'store'))
    expect(isOfficialPackageName('@deepseek-ai/dsh-brand-new-2026')).toBe(true)
  })

  it('核对失败 fail-open：网络异常/非 JSON 响应 → 目录维持现状（绝不误伤）', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline') }))
    const merged = await refreshOfficialCatalogFromRegistry()
    expect(merged.has(OUT_CATALOG)).toBe(false)
    expect(isOfficialPackageName('@deepseek-ai/dsh-atomic-write')).toBe(true)
    vi.stubGlobal('fetch', vi.fn(async () => new Response('not-json', { status: 200, headers: { 'content-length': '8' } })))
    const merged2 = await refreshOfficialCatalogFromRegistry()
    expect(merged2.has(OUT_CATALOG)).toBe(false)
  })

  it('auto-refresh 关闭（测试钩子）：不发起核对、不落盘', async () => {
    setCatalogAutoRefresh(false)
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-length': '2' } }))
    vi.stubGlobal('fetch', fetchSpy)
    const merged = await refreshOfficialCatalogFromRegistry(fetchSpy)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(existsSync(officialCatalogPath())).toBe(false)
    setCatalogAutoRefresh(true)
  })

  it('分页：官方名压过单页 250 上限 → 逐页取完（不足整页即停）', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      calls.push(u)
      const from = Number.parseInt(new URL(u).searchParams.get('from') ?? '0', 10)
      const mkPage = (n: number, official: string): Response => {
        const objects = Array.from({ length: n }, (_, i) => ({
          package: { name: i === 0 ? official : `search-noise-${from}-${i}` },
        }))
        const body = JSON.stringify({ objects })
        return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
      }
      if (from === 0) return mkPage(250, '@deepseek-ai/page-one-pkg')
      if (from === 250) return mkPage(250, '@deepseek-ai/page-two-pkg')
      return mkPage(3, '@deepseek-ai/page-three-pkg')
    }))
    const merged = await refreshOfficialCatalogFromRegistry()
    // 跨页官方名全部并入（首见首页 201/231 的实测形态：尾部包在 from=250 之后）
    expect(merged.has('@deepseek-ai/page-two-pkg')).toBe(true)
    expect(merged.has('@deepseek-ai/page-three-pkg')).toBe(true)
    // 第 3 页不足整页（搜索已穷尽）→ 不再取第 4 页
    expect(calls.length).toBe(3)
    expect(calls[1]).toContain('from=250')
  })

  it('覆盖层超大（>8MB）→ fail-open 回种子（拒绝整读撑内存）', () => {
    mkdirSync(join(dir, 'store'), { recursive: true })
    writeFileSync(officialCatalogPath(), JSON.stringify({ names: ['@deepseek-ai/x'], refreshedAt: 1 }).padEnd(9 * 1024 * 1024, ' '))
    setOfficialCatalogDirForTest(join(dir, 'store')) // 同目录重设 → 缓存失效重载
    expect(isOfficialPackageName('@deepseek-ai/x')).toBe(false)
    expect(isOfficialPackageName('@deepseek-ai/dsh-atomic-write')).toBe(true) // 种子兜底不受影响
  })
})

describe('official-catalog × internal-plugin（M2 扫描侧接线）', () => {
  let sandbox: string
  beforeEach(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vet-ocat-guard-'))
    setBaselineDirForTest(join(sandbox, 'baseline'))
    setCapabilitiesDirForTest(join(sandbox, 'caps'))
    setSummariesDirForTest(join(sandbox, 'summaries'))
    setOfficialCatalogDirForTest(join(sandbox, 'ocat'))
    setCatalogAutoRefresh(false) // 测试环境禁止真实出网
    resetOfficialTrustForTest()  // 信任锚是进程级全局 Set——跨用例清空，避免前一用例入锚残留
  })
  afterAll(() => {
    setBaselineDirForTest(undefined)
    setCapabilitiesDirForTest(undefined)
    setSummariesDirForTest(undefined)
    setOfficialCatalogDirForTest(undefined)
    setCatalogAutoRefresh(true)
    vi.unstubAllGlobals()
    if (sandbox !== undefined) rmSync(sandbox, { recursive: true, force: true })
  })

  it('目录外官方名 → 黄牌 official-not-in-catalog 观察（不拦、不入锚）', async () => {
    const status = new VetStatus()
    const ctx = new FakeCtx()
    const profile = mkdtempSync(join(tmpdir(), 'vet-ocat-prof-'))
    const unscoped = OUT_CATALOG.split('/')[1]
    const pkg = join(profile, 'node_modules', '@deepseek-ai', unscoped)
    mkdirSync(pkg, { recursive: true })
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: OUT_CATALOG, version: '1.0.0', main: 'index.js' }))
    writeFileSync(join(pkg, 'index.js'), 'module.exports = 1')
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f1', entry: { options: { name: OUT_CATALOG } } })
    const kinds = status.snapshot().alarms.map(a => a.kind)
    expect(kinds).toContain('official-not-in-catalog')
    expect(isOfficialTrusted(OUT_CATALOG)).toBe(false) // 目录外不入内容信任锚
    rmSync(profile, { recursive: true, force: true })
  })

  it('目录内官方包 first-seen：registry 字节一致 → 首见即入锚（official-verified info），不再等二次 match', async () => {
    const profile = mkdtempSync(join(tmpdir(), 'vet-ocat-prof2-'))
    const pkg = makePkg(profile)
    const localHash = computePackageHash(pkg)!.hash
    const tgz = await makeTgz(pkg)
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.includes('/-/v1/search')) {
        return new Response('{"objects":[]}', { status: 200, headers: { 'content-length': '14' } })
      }
      if (u.endsWith('/9.9.9')) {
        const body = JSON.stringify({ dist: { tarball: 'https://registry.npmjs.org/x.tgz' } })
        return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
      }
      return new Response(new Uint8Array(tgz), { status: 200, headers: { 'content-length': String(tgz.length) } })
    }))
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f2', entry: { options: { name: IN_CATALOG } } })
    // 异步 verifyFirstSeenOfficial：轮询等待入锚
    for (let i = 0; i < 60 && !isOfficialTrusted(IN_CATALOG); i++) {
      await new Promise(r => setTimeout(r, 50))
    }
    expect(localHash.length).toBeGreaterThan(0)
    expect(isOfficialTrusted(IN_CATALOG)).toBe(true)
    expect(status.snapshot().alarms.some(a => a.kind === 'official-verified')).toBe(true)
    expect(status.snapshot().alarms.some(a => a.kind === 'official-not-in-catalog')).toBe(false)
    rmSync(profile, { recursive: true, force: true })
  })

  it('目录内官方包 first-seen：registry 字节不一致 → 黄牌 official-verify-mismatch（不红、不入锚）', async () => {
    const profile = mkdtempSync(join(tmpdir(), 'vet-ocat-prof3-'))
    const pkg = makePkg(profile)
    const officialSnapshot = await makeTgz(pkg)   // registry 快照：不含随后的本机改动
    writeFileSync(join(pkg, 'index.js'), '// local modification\n')
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.includes('/-/v1/search')) {
        return new Response('{"objects":[]}', { status: 200, headers: { 'content-length': '14' } })
      }
      if (u.endsWith('/9.9.9')) {
        const body = JSON.stringify({ dist: { tarball: 'https://registry.npmjs.org/x.tgz' } })
        return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
      }
      return new Response(new Uint8Array(officialSnapshot), { status: 200, headers: { 'content-length': String(officialSnapshot.length) } })
    }))
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f3', entry: { options: { name: IN_CATALOG } } })
    for (let i = 0; i < 60 && !status.snapshot().alarms.some(a => a.kind === 'official-verify-mismatch'); i++) {
      await new Promise(r => setTimeout(r, 50))
    }
    const hit = status.snapshot().alarms.find(a => a.kind === 'official-verify-mismatch')
    expect(hit?.severity).toBe('yellow')
    expect(isOfficialTrusted(IN_CATALOG)).toBe(false)
    // 0.3.5 审查加固：疑标持久化——同字节二次加载 match 不入锚 + official-match-suspected 黄牌
    ctx.logger.info.mockClear?.()
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f4', entry: { options: { name: IN_CATALOG } } })
    expect(isOfficialTrusted(IN_CATALOG)).toBe(false)
    expect(status.snapshot().alarms.some(a => a.kind === 'official-match-suspected')).toBe(true)
    rmSync(profile, { recursive: true, force: true })
  })

  it('疑标 + acknowledged 登记 → match 照常入锚（用户声明负责；黄牌提示）', async () => {
    const profile = mkdtempSync(join(tmpdir(), 'vet-ocat-prof4-'))
    const pkg = makePkg(profile)
    const officialSnapshot = await makeTgz(pkg)
    writeFileSync(join(pkg, 'index.js'), '// local modification\n')
    const localHash = computePackageHash(pkg)!.hash
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.includes('/-/v1/search')) {
        return new Response('{"objects":[]}', { status: 200, headers: { 'content-length': '14' } })
      }
      if (u.endsWith('/9.9.9')) {
        const body = JSON.stringify({ dist: { tarball: 'https://registry.npmjs.org/x.tgz' } })
        return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
      }
      return new Response(new Uint8Array(officialSnapshot), { status: 200, headers: { 'content-length': String(officialSnapshot.length) } })
    }))
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f5', entry: { options: { name: IN_CATALOG } } })
    for (let i = 0; i < 60 && !status.snapshot().alarms.some(a => a.kind === 'official-verify-mismatch'); i++) {
      await new Promise(r => setTimeout(r, 50))
    }
    expect(isOfficialTrusted(IN_CATALOG)).toBe(false) // 首见：不入锚
    // 用户登记补丁后二次加载：match + 疑标 + ack → 入锚
    const status2 = new VetStatus()
    const ctx2 = new FakeCtx()
    ctx2.baseUrl = profile
    installInternalPluginGuard(ctx2 as never, cfg({ acknowledgedPackageHashes: { [`${IN_CATALOG}@9.9.9`]: [localHash] } }), status2)
    ctx2.handlers.get('internal/plugin')![0]({ uid: 'f6', entry: { options: { name: IN_CATALOG } } })
    expect(isOfficialTrusted(IN_CATALOG)).toBe(true)
    const ackAlarm = status2.snapshot().alarms.find(a => a.kind === 'baseline-patch-ack')
    expect(ackAlarm).toBeDefined()
    expect(ackAlarm?.severity).toBe('info') // 0.3.13：已声明补丁降为观察档
    expect(status2.snapshot().alarms.some(a => a.kind === 'official-match-suspected')).toBe(false)
    rmSync(profile, { recursive: true, force: true })
  })
})