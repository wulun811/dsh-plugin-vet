/**
 * P2 指标历史环形缓冲（metrics history）测试：
 * - recordMetricsSample 环形上限 64、非有限值拒收；
 * - readHostMetrics 每次调用自动追加采样（平台容差：非 Linux fd=-1 也入列）；
 * - readMetricsHistory 返回副本（外部改动不影响内部缓冲）。
 */
import { describe, it, expect } from 'vitest'
import {
  recordMetricsSample,
  readMetricsHistory,
  readHostMetrics,
  type MetricsHistoryPoint,
} from '../lib/guard/metrics.js'

const point = (over: Partial<MetricsHistoryPoint> = {}): MetricsHistoryPoint => ({
  at: Date.now(),
  rssTotalMb: 100,
  cpuPct: 1,
  fdCount: 64,
  ...over,
})

describe('metrics history', () => {
  it('环形上限 64：超出淘汰最旧', () => {
    // 前置：清不掉了？readMetricsHistory 只读——这里用相对量断言，避免依赖模块内初始态
    const before = readMetricsHistory().length
    for (let i = 0; i < 70; i++) {
      recordMetricsSample(point({ at: i }))
    }
    const hist = readMetricsHistory()
    expect(hist.length).toBe(Math.min(before + 70, 64))
    expect(hist.length).toBeLessThanOrEqual(64)
    // 最旧的被挤掉：末尾 64 个的 at 连续
    expect(hist[hist.length - 1]?.at).toBe(69)
    if (before === 0) expect(hist[0]?.at).toBe(6)
  })

  it('非有限值拒收', () => {
    const before = readMetricsHistory().length
    recordMetricsSample(point({ rssTotalMb: Number.NaN }))
    recordMetricsSample(point({ cpuPct: Number.POSITIVE_INFINITY }))
    expect(readMetricsHistory().length).toBe(before)
  })

  it('返回副本：外部 push 不影响内部缓冲', () => {
    const before = readMetricsHistory().length
    const copy = readMetricsHistory()
    copy.push(point({ at: 999_999 }))
    expect(readMetricsHistory().length).toBe(before)
  })

  it('readHostMetrics 自动采样一次（跨进程总口径 = rss+mcp+vet）', () => {
    const before = readMetricsHistory().length
    const m = readHostMetrics()
    const hist = readMetricsHistory()
    // 缓冲未满则 +1，已满（64）则保持——但内容必是新采样
    expect(hist.length).toBe(Math.min(before + 1, 64))
    const last = hist[hist.length - 1]
    const expected = Math.round((m.rssMb + m.mcpRssMb + m.vetRssMb) * 10) / 10
    expect(last?.rssTotalMb).toBe(expected)
    expect(last?.cpuPct).toBe(m.cpuPct)
    expect(last?.fdCount).toBe(m.fdCount)
  })
})
