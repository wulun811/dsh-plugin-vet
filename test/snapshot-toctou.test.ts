import { afterAll, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { VetStatus } from '../lib/guard/status.js'
import { captureSnapshot, detectDrift } from '../lib/guard/snapshot.js'
import { diffManifests, isEmptyDiff, manifestDigest, toScopedSnapshot } from '../lib/domain/snapshot.js'
import type { VetConfig } from '../lib/config.js'

/**
 * 步骤 4 的第一半：快照与 TOCTOU（C02 反例）。
 *
 * 要证的不是「函数返回了什么」，而是：**扫描判定过的字节，不是加载时读到的字节**这件事
 * 会被发现。0.4.2 里没有任何东西把两者绑在一起——扫描器读一遍、加载器再读一遍，
 * 中间换了内容，报告照样放行（施工图 §6 步骤 4 的 C02）。
 */

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report',
  autoScan: true,
  scannerTimeoutMs: 15_000,
  rules: {},
  denyOn: 'critical',
  allowlist: [],
  runtimeGuard: 'off',
  runtimeIntervalMs: 2000,
  runtimeMemLimitMb: 2048,
  runtimeForkBurstN: 5,
  runtimeFdLimit: 512,
  runtimeGrowthMb: 256,
  runtimeGrowthWindowMs: 600_000,
  contentBaseline: true,
  acknowledgedPackageHashes: {},
  thirdPartyBaseline: false,
  domainProjection: 'shadow',
  ...over,
})

class FakeCtx {
  handlers = new Map<string, ((fiber: unknown) => unknown)[]>()
  baseUrl: string
  logger = { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} }
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }
  on(event: string, handler: (fiber: unknown) => unknown): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

const NAME = '@acme/toctou-fixture'
const dirs: string[] = []

/** 在临时 profile 下造一个第三方插件包（不走官方豁免，才会被捕获快照）。 */
function makeThirdParty(profile: string): string {
  const pkg = join(profile, 'node_modules', '@acme', 'toctou-fixture')
  mkdirSync(pkg, { recursive: true })
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: NAME, version: '1.0.0', main: 'index.js' }))
  writeFileSync(join(pkg, 'index.js'), 'module.exports = { ok: true }\n')
  return pkg
}

function makeProfile(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-toctou-'))
  dirs.push(dir)
  return dir
}

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
})

describe('C02：扫描到加载之间内容被替换', () => {
  it('report 模式：替换后产生 snapshot-drift 红牌，点名被改写的文件', async () => {
    const profile = makeProfile()
    const pkg = makeThirdParty(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx(profile)
    installInternalPluginGuard(ctx as never, cfg(), status)
    const listener = ctx.handlers.get('internal/plugin')![0]

    // 监听器内部**同步**捕获快照，随后才去 spawn 扫描子进程；改写在捕获之后 → 必然漂移。
    const done = listener({ uid: 'f-1', entry: { options: { name: NAME } } }) as Promise<unknown>
    writeFileSync(join(pkg, 'index.js'), 'module.exports = { ok: true, injected: "x".repeat(200) }\n')
    await done

    const alarms = status.snapshot().alarms
    const drift = alarms.find((a) => a.kind === 'snapshot-drift')
    expect(drift, `未产生漂移证据，实际告警：${alarms.map((a) => a.kind).join(',') || '(无)'}`).toBeDefined()
    expect(drift!.severity).toBe('red')
    expect(drift!.message).toContain('index.js')
    expect(drift!.target).toBe(NAME)
  }, 60_000)

  it('内容未变：不产生任何漂移证据（噪声为零）', async () => {
    const profile = makeProfile()
    makeThirdParty(profile)
    const status = new VetStatus()
    const ctx = new FakeCtx(profile)
    installInternalPluginGuard(ctx as never, cfg(), status)
    await ctx.handlers.get('internal/plugin')![0]({ uid: 'f-2', entry: { options: { name: NAME } } })
    expect(status.snapshot().alarms.map((a) => a.kind)).not.toContain('snapshot-drift')
  }, 60_000)
})

describe('快照：清单与漂移判定', () => {
  it('同一目录两次捕获一致；改一个字节即漂移并点名文件', () => {
    const profile = makeProfile()
    const pkg = makeThirdParty(profile)
    const first = captureSnapshot(pkg)
    expect(first.ok).toBe(true)
    if (!first.ok) return

    expect(detectDrift(first, pkg).drifted).toBe(false)

    writeFileSync(join(pkg, 'index.js'), 'module.exports = { ok: false }\n')
    const verdict = detectDrift(first, pkg)
    expect(verdict.drifted).toBe(true)
    expect(verdict.detail).toContain('index.js')
  })

  it('新增/删除文件也算漂移', () => {
    const profile = makeProfile()
    const pkg = makeThirdParty(profile)
    const before = captureSnapshot(pkg)
    if (!before.ok) throw new Error('capture failed')
    writeFileSync(join(pkg, 'extra.js'), 'module.exports = 1\n')
    expect(detectDrift(before, pkg).drifted).toBe(true)
    rmSync(join(pkg, 'extra.js'))
    expect(detectDrift(before, pkg).drifted).toBe(false)
  })

  it('排除项有理由、且不参与摘要（排除策略变了才该改摘要）', () => {
    const profile = makeProfile()
    const pkg = makeThirdParty(profile)
    mkdirSync(join(pkg, 'node_modules', 'dep'), { recursive: true })
    writeFileSync(join(pkg, 'node_modules', 'dep', 'index.js'), 'x')
    writeFileSync(join(pkg, '.hidden'), 'x')
    writeFileSync(join(pkg, 'README.md'), '# x')
    const captured = captureSnapshot(pkg)
    if (!captured.ok) throw new Error('capture failed')
    const reasons = new Map(captured.snapshot.snapshot.excluded.map((e) => [e.path, e.reason]))
    expect(reasons.get('node_modules')).toBe('node_modules')
    expect(reasons.get('.hidden')).toBe('hidden')
    expect(reasons.get('README.md')).toBe('doc')
    // 排除项改内容不影响摘要：它们本来就不在被承诺的范围里
    writeFileSync(join(pkg, '.hidden'), 'yyy')
    expect(detectDrift(captured, pkg).drifted).toBe(false)
  })

  it('目录不可读：captureSnapshot 返回原因，detectDrift 不谎报漂移', () => {
    const missing = join(tmpdir(), 'vet-toctou-does-not-exist-' + Date.now())
    const captured = captureSnapshot(missing)
    expect(captured.ok).toBe(true) // 空目录 + 一条 excluded（unreadable-dir）
    if (captured.ok) {
      expect(captured.snapshot.snapshot.complete).toBe(false)
      expect(captured.snapshot.snapshot.excluded.some((e) => e.reason.startsWith('unreadable'))).toBe(true)
    }
    expect(detectDrift(null, missing).drifted).toBe(false)
  })

  it('清单摘要与遍历顺序无关：同一批条目换序得同一摘要', () => {
    const a = [
      { path: 'a.js', size: 1, digest: 'aa' },
      { path: 'b.js', size: 2, digest: 'bb' },
    ]
    const b = [...a].reverse()
    expect(manifestDigest('p', a)).toBe(manifestDigest('p', b))
    expect(manifestDigest('p', a)).not.toBe(manifestDigest('q', a)) // 策略进摘要
  })

  it('diffManifests：策略变了返回 null（不可比，不是「没变」）', () => {
    const one = toScopedSnapshot([{ path: 'a', size: 1, digest: 'x' }], [], true, 'p1')
    const two = toScopedSnapshot([{ path: 'a', size: 1, digest: 'x' }], [], true, 'p2')
    expect(diffManifests(one, two)).toBeNull()
    expect(diffManifests(one, one)).not.toBeNull()
    expect(isEmptyDiff(diffManifests(one, one)!)).toBe(true)
  })
})
