import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * 0.3.14（用户实测回归）：官方包扫描失败不该压黄盾牌。
 *
 * 背景：重启后 live 报
 * 「vet: 扫描失败 @deepseek-ai/dsh-mcp-client：scanner timeout after 15000ms」黄牌。
 * 引擎侧真因见 osv-budget.test.ts（OSV 网络相位缺硬护栏：fetch 不响应 abort 时挂死）
 * 与 scanner-bin/index.ts（报告写出后进程不退出 → 宿主等 close 到 kill 超时）。
 * 本文件钉住宿主侧口径：官方家族（官方目录成员 + 字节可信）的 scan-fail 降为 info 观察
 * ——不计 alarmCount/盾牌，工具侧事件仍进 logger.error；第三方保持 yellow（扫描失败 =
 * 覆盖缺口），deny 模式 fail-closed 语义不变。
 *
 * 扫描器用 mock 强制失败：真实引擎很难被逼到失败（超时预算随文件数放大，超时前会 R8-skip）。
 */
vi.mock('../lib/scanner/client.js', () => {
  const fail = (): { ok: false; error: string } => ({ ok: false, error: 'scanner timeout after 15000ms' })
  return {
    scan: vi.fn(async () => fail()),
    scanSync: vi.fn(() => fail()),
    scanBudget: (files: number, explicitMs?: number, capMs?: number) => {
      const base = explicitMs !== undefined && Number.isFinite(explicitMs) && explicitMs > 0 ? explicitMs : 15_000
      return Math.min(Math.max(base, files * 2000), capMs ?? 60_000)
    },
  }
})

import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { setCatalogAutoRefresh } from '../lib/guards/official-catalog.js'
import { VetStatus } from '../lib/guard/status.js'
import type { VetConfig } from '../lib/config.js'

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
  baseUrl = ''
  logger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }
  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

/** 临时 profile：node_modules/<name>/ 最小包（resolvePackageRoot 按 ctx.baseUrl 解析）。 */
function makeProfile(name: string): string {
  const profile = mkdtempSync(join(tmpdir(), 'vet-scanfail-'))
  const pkg = join(profile, 'node_modules', name)
  mkdirSync(pkg, { recursive: true })
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name, version: '9.9.9', main: 'index.js' }))
  writeFileSync(join(pkg, 'index.js'), 'module.exports = {}\n')
  return profile
}

const fiber = (name: string) => ({
  uid: 1, state: 0, dispose: vi.fn(async () => {}), entry: { options: { name } },
})

const OFFICIAL = '@deepseek-ai/dsh-tools' // 官方目录 seed 成员
const THIRD = 'vet-third-party-fixture'

describe('scan-fail 档位（0.3.14）：官方家族 info / 第三方 yellow', () => {
  let sandbox: string
  const profiles: string[] = []
  beforeEach(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vet-scanfail-sb-'))
    setBaselineDirForTest(join(sandbox, 'baseline'))
    setCapabilitiesDirForTest(join(sandbox, 'caps'))
    setSummariesDirForTest(join(sandbox, 'summaries'))
    setCatalogAutoRefresh(false)
    // 首见入锚验证（verifyFirstSeenOfficial）会查 npm registry——测试禁止真实出网
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline') }))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })
  afterAll(() => {
    setBaselineDirForTest(undefined)
    setCapabilitiesDirForTest(undefined)
    setSummariesDirForTest(undefined)
    setCatalogAutoRefresh(true)
    for (const p of profiles) rmSync(p, { recursive: true, force: true })
    if (sandbox !== undefined) rmSync(sandbox, { recursive: true, force: true })
  })

  it('官方目录成员（首见，字节可信）扫描失败 → info 观察，盾牌不被压黄', async () => {
    const profile = makeProfile(OFFICIAL)
    profiles.push(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    await ctx.handlers.get('internal/plugin')![0](fiber(OFFICIAL))

    const snap = status.snapshot()
    const alarm = snap.alarms.find(a => a.kind === 'scan-fail')
    expect(alarm).toBeDefined()
    expect(alarm?.severity).toBe('info')
    expect(alarm?.message).toContain('scanner timeout')
    expect(snap.alarmCount).toBe(0)
    expect(snap.level).toBe('green')
    expect(ctx.logger.error).toHaveBeenCalled() // 工具侧事件照旧进日志（不静默）
  })

  it('第三方包扫描失败 → yellow（覆盖缺口），盾牌黄', async () => {
    const profile = makeProfile(THIRD)
    profiles.push(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    await ctx.handlers.get('internal/plugin')![0](fiber(THIRD))

    const snap = status.snapshot()
    expect(snap.alarms.find(a => a.kind === 'scan-fail')?.severity).toBe('yellow')
    expect(snap.level).toBe('yellow')
  })

  it('deny 模式：官方家族扫描失败不拦截（不抛错、不 dispose）', () => {
    const profile = makeProfile(OFFICIAL)
    profiles.push(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg({ mode: 'deny' }), status)
    const f = fiber(OFFICIAL)
    expect(() => ctx.handlers.get('internal/plugin')![0](f)).not.toThrow()
    expect(f.dispose).not.toHaveBeenCalled()
    expect(status.snapshot().alarms.find(a => a.kind === 'scan-fail')?.severity).toBe('info')
  })

  it('deny 模式：第三方扫描失败仍 fail-closed（抛错 + dispose，档位不影响拦截）', () => {
    const profile = makeProfile(THIRD)
    profiles.push(profile)
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg({ mode: 'deny' }), new VetStatus())
    const f = fiber(THIRD)
    expect(() => ctx.handlers.get('internal/plugin')![0](f)).toThrow(/fail-closed/)
    expect(f.dispose).toHaveBeenCalled()
  })
})
