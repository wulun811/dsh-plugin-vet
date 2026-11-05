/**
 * 0.5.22：T1 启动暖机 + 内存持续判定。
 *
 * 用户实测（2026-11-05 重启宿主后）：一次性收到 4 条「宿主进程内存超限：4413 MB（阈值 4096 MB）」。
 * 宿主冷启动要加载 bundle、在进程内构建 client 包，RSS 会短时冲高到一个只有启动期才有的峰值；
 * 同一台机器随后稳态是 ~2.1 GB（`ps` 实测）。也就是说这个"超限"是启动波形，不是内存炸弹。
 * 两条修正：
 *   1. 暖机窗口（默认 180 s）内不产生任何 T1 报警——采样照做，窗口结束后逐拍判定恢复；
 *   2. 内存越线必须**连续**满 memSustainMs（默认 30 s）才报——4 拍（≈8 s）的尖峰不再算数。
 * 这里同时钉住默认值三处一致（config 默认 / schema 默认 / 哨兵默认），避免像 0.5.21 那样
 * 只改了一处、其余两处继续按旧值跑。
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { VET_CONFIG_DEFAULTS, VetConfigSchema } from '../lib/config.js'
import {
  DEFAULT_WATCH_CONFIG, analyzeSample, sidecarMain, sustainReached,
  type CmdRunner, type ProcSample, type WatchConfig,
} from '../lib/guard/runtime-watch.js'

const sample = (over: Partial<ProcSample> = {}): ProcSample =>
  ({ rssKb: 1024, childCount: 0, fdCount: 10, at: 0, ...over })
const cfg = (over: Partial<WatchConfig> = {}): WatchConfig => ({ ...DEFAULT_WATCH_CONFIG, ...over })

describe('0.5.22 默认值：config 默认 / schema 默认 / 哨兵默认三处一致', () => {
  it('暖机 180 s、内存持续判定 30 s', () => {
    expect(DEFAULT_WATCH_CONFIG.warmupMs).toBe(180_000)
    expect(DEFAULT_WATCH_CONFIG.memSustainMs).toBe(30_000)
    expect(VET_CONFIG_DEFAULTS.runtimeWarmupMs).toBe(DEFAULT_WATCH_CONFIG.warmupMs)
    expect(VET_CONFIG_DEFAULTS.runtimeMemSustainMs).toBe(DEFAULT_WATCH_CONFIG.memSustainMs)
    const parsed = VetConfigSchema({})
    expect(parsed.runtimeWarmupMs).toBe(DEFAULT_WATCH_CONFIG.warmupMs)
    expect(parsed.runtimeMemSustainMs).toBe(DEFAULT_WATCH_CONFIG.memSustainMs)
  })

  it('两个键都允许 0（= 关闭暖机 / 关闭持续判定），其它 T1 数值键仍是 ≥1', () => {
    const parsed = VetConfigSchema({ runtimeWarmupMs: 0, runtimeMemSustainMs: 0 })
    expect(parsed.runtimeWarmupMs).toBe(0)
    expect(parsed.runtimeMemSustainMs).toBe(0)
    expect(() => VetConfigSchema({ runtimeIntervalMs: 0 })).toThrow()
  })
})

describe('sustainReached（纯函数）', () => {
  it('从未越线（null）→ false', () => {
    expect(sustainReached(null, 100, 0)).toBe(false)
  })

  it('持续时长从第一次越线算起：29.999 s 不报、30 s 报', () => {
    expect(sustainReached(0, 29_999, 30_000)).toBe(false)
    expect(sustainReached(0, 30_000, 30_000)).toBe(true)
  })

  it('sustainMs=0 → 当拍即报（显式关掉持续判定）', () => {
    expect(sustainReached(5, 5, 0)).toBe(true)
  })
})

describe('analyzeSample 的 skipMem（只压内存行，不压 fork/fd）', () => {
  it('越线但 skipMem → 没有 mem 行', () => {
    const out = analyzeSample(null, sample({ rssKb: 5000 * 1024 }), cfg(), { skipMem: true })
    expect(out.filter(a => a.kind === 'mem')).toEqual([])
  })

  it('skipMem 时 fork / fd 照常判定（持续判定只管内存）', () => {
    const out = analyzeSample(
      sample({ childCount: 1 }),
      sample({ rssKb: 5000 * 1024, childCount: 20, fdCount: 600 }),
      cfg({ memLimitMb: 4096 }),
      { skipMem: true },
    )
    expect(out.map(a => a.kind).sort()).toEqual(['fd', 'fork'])
  })

  it('不传 options → 与 0.5.21 行为一致（越线即报）', () => {
    const out = analyzeSample(null, sample({ rssKb: 5000 * 1024 }), cfg())
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({ severity: 'red', kind: 'mem' })
  })

  it('mem 文案说明「连续超限 ≥30 秒」——否则读的人不知道这是一条持续判定', () => {
    const [alarm] = analyzeSample(null, sample({ rssKb: 5000 * 1024 }), cfg())
    expect(alarm!.message).toContain('阈值 4096 MB')
    expect(alarm!.message).toContain('连续超限 ≥30 秒')
  })
})

/**
 * 端到端：用 darwin 分派 + 注入 fake run（不碰 /proc，跨平台可跑），假时钟推进真实 tick。
 * 这条用例存在的理由：纯函数各自绿了、tick 里的门忘了接，是 0.5.20「标准变更没有生产者」
 * 的同一个失败模式。
 */
describe('sidecarMain 端到端：暖机与持续判定真的接在 tick 上', () => {
  /** 每个用例注册的清理（断言抛错时也要恢复 stdout 与定时器，否则污染后续用例）。 */
  let cleanups: (() => void)[] = []
  afterEach(() => {
    for (const c of cleanups.splice(0)) c()
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  interface Harness {
    advance: (ms: number) => void
    alarms: () => { kind?: string; severity?: string }[]
  }

  /** 以假时钟跑 sidecarMain；默认 fake run 恒报 3 GB RSS（任何 memLimitMb ≤ 3000 都越线）。
   * `rssAt` 可按「距启动的毫秒数」给出当时的 RSS，用来演冷启动冲高又回落的波形。 */
  const start = (watchCfg: WatchConfig, rssAt?: (elapsedMs: number) => number): Harness => {
    vi.useFakeTimers()
    const t0 = new Date('2026-11-05T20:00:00Z').getTime()
    vi.setSystemTime(t0)
    const raw: string[] = []
    const orig = process.stdout.write.bind(process.stdout)
    ;(process.stdout as unknown as { write: (s: string) => boolean }).write = (s: string) => { raw.push(s); return true }
    const host = process.ppid
    const run: CmdRunner = (cmd) => {
      if (cmd === 'lsof') return 'p1\nf0r\n'
      const rssKb = rssAt === undefined ? 3145728 : rssAt(Date.now() - t0)
      // self 行给出 ppid=host：否则哨兵按「被收养」判定宿主已死而 exit(0)
      return `${host} 1 ${rssKb}\n${process.pid} ${host} 9000\n`
    }
    const timer = sidecarMain(watchCfg, { platform: 'darwin', run })
    cleanups.push(() => {
      clearInterval(timer)
      process.stdout.write = orig as typeof process.stdout.write
    })
    return {
      advance: (ms) => vi.advanceTimersByTime(ms),
      alarms: () => raw.map(l => JSON.parse(l) as { kind?: string; severity?: string }),
    }
  }

  it('暖机窗口内越线 → 零报警；窗口一结束就恢复判定（延后，不是遮蔽）', () => {
    const h = start(cfg({ intervalMs: 1000, memLimitMb: 1000, warmupMs: 180_000, memSustainMs: 0 }))
    h.advance(179_000)
    expect(h.alarms()).toEqual([])
    h.advance(1_000) // t=180_000：第一拍非暖机
    expect(h.alarms().map(a => a.kind)).toContain('mem')
  })

  it('冷启动只冲高 8 秒（用户实测 4 拍 4413 MB）后回落到 2.1 GB → 全程零报警', () => {
    // sustain 关掉：这一条验的是暖机本身——只靠持续判定也能压住 8 秒尖峰，靠暖机则完全看不见。
    const h = start(
      cfg({ intervalMs: 2000, memLimitMb: 4096, warmupMs: 180_000, memSustainMs: 0 }),
      (elapsed) => (elapsed <= 8_000 ? 4413 * 1024 : 2100 * 1024),
    )
    h.advance(300_000)
    expect(h.alarms()).toEqual([])
  })

  it('持续判定：越线 29 拍不报，第 30 拍报', () => {
    const h = start(cfg({ intervalMs: 1000, memLimitMb: 1000, warmupMs: 0, memSustainMs: 30_000 }))
    h.advance(29_000)
    expect(h.alarms()).toEqual([])
    h.advance(1_000)
    expect(h.alarms().map(a => a.kind)).toContain('mem')
  })

  it('门是串联的：先满 3 秒暖机，再满 30 秒持续——第 32 拍之前出声就是漏判', () => {
    const h = start(cfg({ intervalMs: 1000, memLimitMb: 1000, warmupMs: 3_000, memSustainMs: 30_000 }))
    h.advance(32_000)
    expect(h.alarms()).toEqual([])
    h.advance(1_000)
    expect(h.alarms().map(a => a.kind)).toContain('mem')
  })
})
