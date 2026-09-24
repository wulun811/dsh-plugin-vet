import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * 0.3.15：M7 存储自检的**归因分流**。
 *
 * 事故背景（2026-09-24 用户 live 黄牌 vet-store-tamper）：旧口径「字节与自写不符 =
 * 疑似进程内插件篡改」在多进程写路径下必然误判——那次真因是 vet 自己的测试进程写进了
 * 真实存储（夹具记录，见 store-root.test.ts）。
 *
 * 0.3.15 起每次落盘在存储文件里盖 writer 戳（工具 + 版本 + pid + 时间），读回时分流：
 *   - 戳为**别的 pid** 且工具标记为 dsh-plugin-vet → info `vet-store-foreign-write`
 *     （已知多进程写路径：vet CLI / 测试 / 第二个 DSH 实例）
 *   - 无戳 / 戳为本进程 pid → yellow `vet-store-tamper`（进程内篡改，M7 真正要抓的形态）
 *
 * 本文件同时钉住「落盘必带戳」与宿主侧档位（端到端：扫描器 mock 为成功，走 finish 路径）。
 */
vi.mock('../lib/scanner/client.js', () => ({
  scan: vi.fn(async () => ({
    ok: true,
    report: {
      engine: 'static-v26', sourceCount: 1, findings: [], staticScore: 100, verdict: 'clean',
      capabilities: { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false },
    },
  })),
  scanSync: vi.fn(() => ({ ok: false, error: 'unused' })),
  scanBudget: (files: number, explicitMs?: number, capMs?: number) => {
    const base = explicitMs !== undefined && Number.isFinite(explicitMs) && explicitMs > 0 ? explicitMs : 15_000
    return Math.min(Math.max(base, files * 2000), capMs ?? 60_000)
  },
}))

import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import {
  setBaselineDirForTest, saveBaseline, loadBaseline, consumeBaselineTamper, baselinePath,
} from '../lib/guards/content-baseline.js'
import {
  setCapabilitiesDirForTest, saveCapabilities, loadCapabilities, consumeCapabilitiesTamper, capabilitiesPath,
} from '../lib/guard/version-diff.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { setCatalogAutoRefresh } from '../lib/guards/official-catalog.js'
import { classifyStoreRewrite, currentWriter, readWriter, selfVersion, STORE_TOOL } from '../lib/guard/store-stamp.js'
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

function makeProfile(name: string): string {
  const profile = mkdtempSync(join(tmpdir(), 'vet-tamper-'))
  const pkg = join(profile, 'node_modules', name)
  mkdirSync(pkg, { recursive: true })
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name, version: '9.9.9', main: 'index.js' }))
  writeFileSync(join(pkg, 'index.js'), 'module.exports = {}\n')
  return profile
}

const fiber = (name: string) => ({
  uid: 1, state: 0, dispose: vi.fn(async () => {}), entry: { options: { name } },
})

const THIRD = 'vet-third-party-fixture'

/** 外来 vet 进程的戳（pid 必然不是本进程）。 */
const foreignWriter = () => ({ tool: STORE_TOOL, version: '0.3.13', pid: process.pid + 1, at: Date.now() })

function rewriteStore(path: string, body: unknown): void {
  writeFileSync(path, JSON.stringify(body, null, 2))
}

describe('store-stamp（0.3.15）：落盘自写标记', () => {
  let sandbox: string
  beforeEach(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vet-stamp-'))
    setCapabilitiesDirForTest(join(sandbox, 'caps'))
    setBaselineDirForTest(join(sandbox, 'baseline'))
  })
  afterEach(() => { rmSync(sandbox, { recursive: true, force: true }) })
  afterAll(() => {
    setCapabilitiesDirForTest(undefined)
    setBaselineDirForTest(undefined)
  })

  it('saveCapabilities 落盘必带 writer 戳（工具/版本/pid/时间）', () => {
    saveCapabilities({ records: {} })
    const raw = JSON.parse(readFileSync(capabilitiesPath(), 'utf8')) as { writer?: Record<string, unknown> }
    expect(raw.writer?.tool).toBe(STORE_TOOL)
    expect(raw.writer?.pid).toBe(process.pid)
    expect(raw.writer?.version).toBe(selfVersion())
    expect(Number.isFinite(raw.writer?.at)).toBe(true)
  })

  it('自写后读回：无篡改证据', () => {
    saveCapabilities({ records: {} })
    loadCapabilities()
    expect(consumeCapabilitiesTamper()).toBeNull()
  })

  it('另一个 vet 进程改写 → 证据带外来戳（归因 foreign-vet）', () => {
    saveCapabilities({ records: {} })
    rewriteStore(capabilitiesPath(), { writer: foreignWriter(), records: {} })
    loadCapabilities()
    const tamper = consumeCapabilitiesTamper()
    expect(tamper).not.toBeNull()
    expect(tamper?.file).toBe(capabilitiesPath())
    expect(tamper?.foreign?.pid).toBe(process.pid + 1)
    expect(classifyStoreRewrite(tamper?.foreign ?? null, process.pid)).toMatchObject({ kind: 'foreign-vet' })
    // 一次消费
    expect(consumeCapabilitiesTamper()).toBeNull()
  })

  it('无戳改写 → 无归因（unexplained，yellow 形态）', () => {
    saveCapabilities({ records: {} })
    rewriteStore(capabilitiesPath(), { records: {} })
    loadCapabilities()
    const tamper = consumeCapabilitiesTamper()
    expect(tamper?.foreign).toBeNull()
    expect(classifyStoreRewrite(tamper?.foreign ?? null, process.pid).kind).toBe('unexplained')
  })

  it('戳为本进程 pid 但字节不符 → unexplained（进程内篡改形态：照抄戳改内容）', () => {
    saveCapabilities({ records: {} })
    const cur = JSON.parse(readFileSync(capabilitiesPath(), 'utf8')) as { writer?: unknown }
    rewriteStore(capabilitiesPath(), { writer: cur.writer, records: { 'evil@1.0.0': { name: 'evil' } } })
    loadCapabilities()
    const tamper = consumeCapabilitiesTamper()
    expect(tamper?.foreign?.pid).toBe(process.pid)
    expect(classifyStoreRewrite(tamper?.foreign ?? null, process.pid).kind).toBe('unexplained')
  })

  it('存储损坏（非 JSON）→ 无戳证据（unexplained）', () => {
    saveCapabilities({ records: {} })
    writeFileSync(capabilitiesPath(), '{ not json')
    loadCapabilities()
    const tamper = consumeCapabilitiesTamper()
    expect(tamper?.file).toBe(capabilitiesPath())
    expect(tamper?.foreign).toBeNull()
  })

  it('baseline 同款：外来戳 → foreign-vet；无戳 → unexplained', () => {
    saveBaseline({ records: {} })
    const raw = JSON.parse(readFileSync(baselinePath(), 'utf8')) as { writer?: Record<string, unknown> }
    expect(raw.writer?.tool).toBe(STORE_TOOL)
    loadBaseline()
    expect(consumeBaselineTamper()).toBeNull()

    rewriteStore(baselinePath(), { writer: foreignWriter(), records: {} })
    loadBaseline()
    const foreign = consumeBaselineTamper()
    expect(classifyStoreRewrite(foreign?.foreign ?? null, process.pid).kind).toBe('foreign-vet')

    rewriteStore(baselinePath(), { records: {} })
    loadBaseline()
    expect(classifyStoreRewrite(consumeBaselineTamper()?.foreign ?? null, process.pid).kind).toBe('unexplained')
  })

  it('readWriter 形状守卫 / classifyStoreRewrite 边界', () => {
    expect(readWriter(undefined)).toBeNull()
    expect(readWriter('x')).toBeNull()
    expect(readWriter({ tool: STORE_TOOL, pid: 'nope', at: 1 })).toBeNull()
    expect(readWriter({ tool: STORE_TOOL, pid: 7, at: 1 })?.version).toBe('unknown')
    // 工具标记不是 vet（别的写者照抄了形状）→ 不给「另一个 vet 进程」的归因
    expect(classifyStoreRewrite({ tool: 'other', version: '1', pid: 999, at: 1 }, process.pid).kind).toBe('unexplained')
    expect(classifyStoreRewrite(null, process.pid).kind).toBe('unexplained')
    expect(currentWriter().pid).toBe(process.pid)
  })
})

describe('宿主侧档位（0.3.15）：外来 vet 写 → info 观察 / 无归因 → yellow', () => {
  let sandbox: string
  const profiles: string[] = []
  beforeEach(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'vet-tamper-tier-'))
    setBaselineDirForTest(join(sandbox, 'baseline'))
    setCapabilitiesDirForTest(join(sandbox, 'caps'))
    setSummariesDirForTest(join(sandbox, 'summaries'))
    setCatalogAutoRefresh(false)
    // 首见入锚验证会查 npm registry——测试禁止真实出网
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline') }))
    // 清掉可能残留的自检证据
    consumeCapabilitiesTamper()
    consumeBaselineTamper()
  })
  afterEach(() => { vi.unstubAllGlobals() })
  afterAll(() => {
    setBaselineDirForTest(undefined)
    setCapabilitiesDirForTest(undefined)
    setSummariesDirForTest(undefined)
    setCatalogAutoRefresh(true)
    for (const p of profiles) rmSync(p, { recursive: true, force: true })
    if (sandbox !== undefined) rmSync(sandbox, { recursive: true, force: true })
  })

  async function runGuard(): Promise<VetStatus> {
    const profile = makeProfile(THIRD)
    profiles.push(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx()
    ctx.baseUrl = profile
    installInternalPluginGuard(ctx as never, cfg(), status)
    await ctx.handlers.get('internal/plugin')![0](fiber(THIRD))
    return status
  }

  it('另一个 vet 进程改写存储 → info 观察（不压盾牌），消息点名 pid/版本/文件', async () => {
    saveCapabilities({ records: {} })
    rewriteStore(capabilitiesPath(), { writer: foreignWriter(), records: {} })

    const snap = (await runGuard()).snapshot()
    const alarm = snap.alarms.find(a => a.kind === 'vet-store-foreign-write')
    expect(alarm).toBeDefined()
    expect(alarm?.severity).toBe('info')
    expect(alarm?.message).toContain(String(process.pid + 1))
    expect(alarm?.message).toContain('0.3.13')
    expect(alarm?.message).toContain(capabilitiesPath())
    // 旧口径的 yellow 不再出现
    expect(snap.alarms.find(a => a.kind === 'vet-store-tamper')).toBeUndefined()
    expect(snap.alarmCount).toBe(0)
    expect(snap.level).toBe('green')
  })

  it('无戳改写存储 → yellow vet-store-tamper（进程内篡改保持）', async () => {
    saveCapabilities({ records: {} })
    rewriteStore(capabilitiesPath(), { records: {} })

    const snap = (await runGuard()).snapshot()
    const alarm = snap.alarms.find(a => a.kind === 'vet-store-tamper')
    expect(alarm).toBeDefined()
    expect(alarm?.severity).toBe('yellow')
    expect(alarm?.message).toContain(capabilitiesPath())
    expect(snap.alarms.find(a => a.kind === 'vet-store-foreign-write')).toBeUndefined()
    expect(snap.alarmCount).toBe(1)
    expect(snap.level).toBe('yellow')
  })

  it('自写未被改写 → 无任何存储警报（静默）', async () => {
    saveCapabilities({ records: {} })
    const snap = (await runGuard()).snapshot()
    expect(snap.alarms.find(a => a.kind === 'vet-store-tamper')).toBeUndefined()
    expect(snap.alarms.find(a => a.kind === 'vet-store-foreign-write')).toBeUndefined()
    expect(snap.alarmCount).toBe(0)
  })
})
