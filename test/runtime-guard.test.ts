import { describe, expect, it } from 'vitest'
import { VetStatus } from '../src/guard/status.js'
import { analyzeSample, detectGrowth, type ProcSample, type RssSample, type WatchConfig } from '../src/guard/runtime-watch.js'
import {
  classifyOp, isSensitivePath, patchModule, pluginFromStack, DEFAULT_HOOK_CONFIG,
} from '../src/guard/runtime-hooks.js'
import { readHostMetrics } from '../src/guard/metrics.js'
import { registerStatusRouteOnce, writeRuntimeGuardConfig } from '../src/guard/status-route.js'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const CFG: WatchConfig = { intervalMs: 2000, memLimitMb: 1024, forkBurstN: 5, fdLimit: 512, growthMb: 256, growthWindowMs: 600_000 }

function sample(partial: Partial<ProcSample>): ProcSample {
  return { rssKb: 512 * 1024, childCount: 0, fdCount: 10, at: Date.now(), ...partial }
}

describe('VetStatus（盾牌聚合器）', () => {
  it('green 初始态', () => {
    const s = new VetStatus()
    const snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarmCount).toBe(0)
  })

  it('yellow 报警 → yellow；同 id 窗口内去重', () => {
    const s = new VetStatus({ dedupeWindowMs: 60_000 })
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: Date.now() }
    expect(s.record(alarm)).toBe('new')
    expect(s.record({ ...alarm, at: Date.now() + 1000 })).toBe('deduped')
    expect(s.snapshot().level).toBe('yellow')
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('red 报警压过 yellow → red', () => {
    const s = new VetStatus()
    s.record({ id: 'a', severity: 'yellow', source: 't2', kind: 'fs-write', message: 'y', at: Date.now() })
    s.record({ id: 'b', severity: 'red', source: 't1', kind: 'mem', message: 'r', at: Date.now() })
    expect(s.snapshot().level).toBe('red')
  })

  it('窗口外的同 id 重新报警', () => {
    const s = new VetStatus({ dedupeWindowMs: 10 })
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: Date.now() - 1000 }
    expect(s.record(alarm)).toBe('new')
    expect(s.record({ ...alarm, at: Date.now() })).toBe('new')
    expect(s.snapshot().alarmCount).toBe(2)
  })

  it('alarmMax 环形截断', () => {
    const s = new VetStatus({ alarmMax: 3, dedupeWindowMs: 0 })
    for (let i = 0; i < 5; i++) {
      s.record({ id: `a${i}`, severity: 'yellow', source: 't2', kind: 'fs-write', message: `m${i}`, at: Date.now() + i })
    }
    expect(s.snapshot().alarmCount).toBe(3)
    expect(s.snapshot().alarms[0].id).toBe('a4')
  })

  it('noteScan suspicious → yellow 抬升', () => {
    const s = new VetStatus()
    expect(s.snapshot().level).toBe('green')
    s.noteScan({ pluginName: 'evil', verdict: 'suspicious', staticScore: 40, at: Date.now() })
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: 'good', verdict: 'clean', staticScore: 100, at: Date.now() })
    expect(s.snapshot().level).toBe('green')
  })
})

describe('analyzeSample（T1 差分判定）', () => {
  it('内存超限 → red', () => {
    const alarms = analyzeSample(null, sample({ rssKb: 2048 * 1024 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'mem' })
  })

  it('fork 突增 → red（prev 为 null 不误报）', () => {
    expect(analyzeSample(null, sample({ childCount: 20 }), CFG)).toHaveLength(0)
    const alarms = analyzeSample(sample({ childCount: 1 }), sample({ childCount: 20 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'fork' })
  })

  it('fd 超限 → yellow', () => {
    const alarms = analyzeSample(null, sample({ fdCount: 600 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'yellow', kind: 'fd' })
  })

  it('稳态无报警', () => {
    expect(analyzeSample(sample({}), sample({}), CFG)).toHaveLength(0)
  })
})

describe('detectGrowth（持续膨胀/疑似泄漏检测）', () => {
  const gcfg = { growthMb: 256, growthWindowMs: 600_000 }
  const s = (rssMb: number, at: number): RssSample => ({ rssKb: rssMb * 1024, at })

  it('窗口内净增长 < 阈值 → 不报警', () => {
    const samples = [s(200, 0), s(300, 60_000), s(400, 120_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('净增长越过 1 倍 → yellow growth，倍数更新', () => {
    const samples = [s(200, 0), s(300, 60_000), s(500, 120_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(1)
    expect(r.alarms[0]).toMatchObject({ severity: 'yellow', kind: 'growth' })
    expect(r.alarms[0].message).toContain('持续膨胀')
    expect(r.multiples).toBe(1)
  })

  it('同倍数不重复报警（去重）', () => {
    const r = detectGrowth([s(200, 0), s(500, 120_000)], gcfg, 1)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(1)
  })

  it('回落归零重置倍数', () => {
    const r = detectGrowth([s(500, 0), s(200, 120_000)], gcfg, 2)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('窗口外的旧样本不参与（起点取窗口内）', () => {
    const samples = [s(900, 0), s(300, 700_000), s(600, 720_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.multiples).toBe(1)
  })
})

describe('isSensitivePath / classifyOp（T2 分类）', () => {
  it('敏感路径判定', () => {
    expect(isSensitivePath('/etc/passwd', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etc', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etcetera/foo', DEFAULT_HOOK_CONFIG)).toBe(false)
    expect(isSensitivePath('/home/user/.ssh/id_rsa', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/.env.local', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/project/src/index.ts', DEFAULT_HOOK_CONFIG)).toBe(false)
  })

  it('敏感路径删除 → red fs-destroy', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rmSync', args: ['/etc/hosts'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red', kind: 'fs-destroy' })
  })

  it('敏感路径写入 → yellow fs-write', () => {
    const alarm = classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/.npmrc', 'x'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-write' })
  })

  it('敏感路径读取 → yellow fs-read', () => {
    const alarm = classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/user/.ssh/id_ed25519'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-read' })
  })

  it('普通路径写入不报警', () => {
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/a.txt', 'x'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('child_process spawn 一律 yellow', () => {
    const alarm = classifyOp({ module: 'child_process', op: 'exec', args: ['curl http://x'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'spawn' })
  })

  it('对象参数取 path', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rm', args: [{ path: '/etc/passwd', recursive: true }] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red' })
  })
})

describe('pluginFromStack（栈归因）', () => {
  it('file:// 帧命中插件根 → 包名', () => {
    const roots = new Map([['/app/node_modules/evil-plugin/lib', 'evil-plugin']])
    const stack = 'Error\n    at wrapper (/app/node_modules/evil-plugin/lib/index.js:10:5)\n    at Object.<anonymous> (/app/main.js:1:1)'
    expect(pluginFromStack(stack, roots)).toBe('evil-plugin')
  })

  it('裸路径帧命中 → 包名；未命中 → undefined', () => {
    const roots = new Map([['/x/lib', '@scope/pkg']])
    expect(pluginFromStack('Error\n    at foo (/x/lib/a.js:1:1)', roots)).toBe('@scope/pkg')
    expect(pluginFromStack('Error\n    at foo (/other/b.js:1:1)', roots)).toBeUndefined()
  })

  it('空映射 / 空栈 → undefined', () => {
    expect(pluginFromStack(undefined, new Map())).toBeUndefined()
    expect(pluginFromStack('Error', new Map([['/x', 'x']]))).toBeUndefined()
  })
})

describe('patchModule（包装 + 恢复）', () => {
  it('危险操作报警、普通操作直通、disposer 恢复', () => {
    const calls: string[] = []
    const fake = {
      writeFile: (p: string) => { calls.push(`write:${p}`) },
      readFile: (p: string) => { calls.push(`read:${p}`) },
    }
    const alarms: string[] = []
    const dispose = patchModule(
      fake as unknown as Record<string, unknown>,
      'fs',
      DEFAULT_HOOK_CONFIG,
      a => { alarms.push(a.kind) },
      () => new Map(),
    )
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/home/user/.env')
    ;(fake as unknown as { readFile: (p: string) => void }).readFile('/home/user/a.txt')
    expect(alarms).toEqual(['fs-write'])
    expect(calls).toEqual(['write:/home/user/.env', 'read:/home/user/a.txt'])

    dispose()
    const restored = fake as unknown as Record<string, unknown>
    expect(restored.writeFile).toBeTypeOf('function')
    // 恢复后调用不再报警
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/etc/x')
    expect(alarms).toEqual(['fs-write'])
  })
})

describe('readHostMetrics（宿主实时指标）', () => {
  it('Linux 下返回完整形状且字段在界内', () => {
    const m = readHostMetrics()
    expect(m.rssMb).toBeGreaterThanOrEqual(0)
    expect(m.cpuPct).toBeGreaterThanOrEqual(0)
    expect(m.ioReadMb).toBeGreaterThanOrEqual(0)
    expect(m.ioWriteMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpRssMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpCount).toBeGreaterThanOrEqual(0)
    expect(m.childCount).toBeGreaterThanOrEqual(-1)
    expect(m.fdCount).toBeGreaterThanOrEqual(-1)
    expect(m.at).toBeGreaterThan(0)
  })
})

describe('writeRuntimeGuardConfig（profile 配置写入）', () => {
  const mkCtx = (baseUrl: string): { baseUrl: string; logger?: undefined } => ({ baseUrl })

  it('enable 追加条目 + 幂等保护 + disable 移除', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n  config:\n    watch: false\n')

    const ctx = mkCtx(dir)
    const r1 = writeRuntimeGuardConfig(ctx, true)
    expect(r1.ok).toBe(true)
    const content1 = readFileSync(patch, 'utf8')
    expect(content1).toContain('- id: @jieai/dsh-plugin-vet')
    expect(content1).toContain('runtimeGuard: watch')

    const r2 = writeRuntimeGuardConfig(ctx, true)
    expect(r2.ok).toBe(false) // 幂等：已存在

    const r3 = writeRuntimeGuardConfig(ctx, false)
    expect(r3.ok).toBe(true)
    const content3 = readFileSync(patch, 'utf8')
    expect(content3).not.toContain('plugin-vet')

    rmSync(dir, { recursive: true, force: true })
  })

  it('未配置时 disable 返回 ok', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })

  it('baseUrl 为 file: URL 时正常读写（DSH web profile 实际形态）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx('file:' + dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('runtimeGuard: watch')
    const r2 = writeRuntimeGuardConfig(mkCtx('file:' + dir), false)
    expect(r2.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).not.toContain('plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 enable 直接新建', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('- id: @jieai/dsh-plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 disable 视为未开启', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })
})

describe('registerStatusRouteOnce（webServer 就绪重试）', () => {
  it('webServer 未就绪 → false，不注册', () => {
    const routes: unknown[] = []
    const ctx = {
      baseUrl: '/tmp',
      get: () => undefined,
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'off' } as never, new VetStatus())
    expect(ok).toBe(false)
    expect(routes).toHaveLength(0)
  })

  it('webServer 就绪 → true，注册 /vet 前缀路由', () => {
    let handler: unknown
    const routes: unknown[] = []
    const ws = { register: (r: unknown) => { routes.push(r); return () => {} } }
    const ctx = {
      baseUrl: '/tmp',
      get: (name: string) => (name === 'webServer' ? ws : undefined),
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'watch' } as never, new VetStatus())
    expect(ok).toBe(true)
    expect(routes).toHaveLength(1)
    expect((routes[0] as { path: string }).path).toBe('/vet')
  })
})
