/**
 * 0.5.21（用户实测原话）：「内存持续膨胀 260 MB（窗口 10 分钟），这个都要警报，你这个算法太烦人啦。
 * 10 分钟超过 2G 再报告吧」。
 *
 * 这不是调参洁癖问题。一台装着插件、跑着任务的 DSH 宿主，十分钟涨两百多 MB 是常态；在那个阈值下，
 * 报警报的是**正常工作**。而一条对正常工作发的警报，最确定的后果不是让人去查泄漏，是让人学会忽略
 * 这一类警报——之后真泄漏时，那条黄牌就混在同一堆噪音里。
 *
 * 所以这里钉三件事：
 * 1. 出厂值是 2048 MB / 10 分钟（配置、schema、sidecar 兜底三处一致）；
 * 2. 用户报的那个数（260 MB / 10 分钟）**不再**报警，卡在 2047 也不报，2048 才报；
 * 3. 文案自己说出门槛——看到「涨了 X MB」的人，第一个问题永远是「那涨多少才算」。
 */
import { describe, expect, it } from 'vitest'
import { VET_CONFIG_DEFAULTS, VetConfigSchema } from '../lib/config.js'
import { DEFAULT_WATCH_CONFIG, detectGrowth, type RssSample } from '../lib/guard/runtime-watch.js'

const WINDOW = 600_000
const CFG = { growthMb: 2048, growthWindowMs: WINDOW }

/** 起止两个采样点，跨度正好一个完整窗口（检测要求 ≥ 90% 窗口）。 */
function span(fromMb: number, toMb: number): RssSample[] {
  return [
    { rssKb: fromMb * 1024, at: 0 },
    { rssKb: toMb * 1024, at: WINDOW },
  ]
}

describe('持续膨胀的出厂阈值（0.5.21）', () => {
  it('配置默认值与 schema 默认值都是 2048 MB / 10 分钟', () => {
    expect(VET_CONFIG_DEFAULTS.runtimeGrowthMb).toBe(2048)
    expect(VET_CONFIG_DEFAULTS.runtimeGrowthWindowMs).toBe(600_000)
    expect(VetConfigSchema({}).runtimeGrowthMb).toBe(2048)
    expect(VetConfigSchema({}).runtimeGrowthWindowMs).toBe(600_000)
  })

  it('sidecar 自己的兜底值与配置默认值一致（不一致就会看配置行事的是宿主，看兜底行事的是哨兵）', () => {
    expect(DEFAULT_WATCH_CONFIG.growthMb).toBe(VET_CONFIG_DEFAULTS.runtimeGrowthMb)
    expect(DEFAULT_WATCH_CONFIG.growthWindowMs).toBe(VET_CONFIG_DEFAULTS.runtimeGrowthWindowMs)
  })
})

describe('阈值落在行为上，而不只是数字上', () => {
  it('用户报的那一例：10 分钟涨 260 MB → 不再报警', () => {
    expect(detectGrowth(span(400, 660), CFG, 0).alarms).toEqual([])
  })

  it('差一点：2047 MB 不报，2048 才报（阈值是「达到」，不是「超过」）', () => {
    expect(detectGrowth(span(400, 2447), CFG, 0).alarms).toEqual([])
    const hit = detectGrowth(span(400, 2448), CFG, 0)
    expect(hit.alarms).toHaveLength(1)
    expect(hit.multiples).toBe(1)
  })

  it('文案里写出门槛：读者第一句话是「涨多少才算」', () => {
    const msg = detectGrowth(span(400, 3000), CFG, 0).alarms[0]?.message ?? ''
    expect(msg).toContain('2048 MB')
    expect(msg).toContain('10 分钟')
  })

  it('跨过整数倍不刷屏：一个窗口只报新跨过的那一档', () => {
    // 涨 5000 MB = 跨过两档；本轮报一次、multiples=2，下一轮同样涨到 5000 不再报
    const first = detectGrowth(span(400, 5400), CFG, 0)
    expect(first.alarms).toHaveLength(1)
    expect(first.multiples).toBe(2)
    expect(detectGrowth(span(400, 5400), CFG, first.multiples).alarms).toEqual([])
  })
})
