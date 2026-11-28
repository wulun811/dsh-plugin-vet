/**
 * 宿主指标面板 Windows 支持（metrics.ts win32 分支）：`process.cpuUsage()` 差分。
 * 用注入 `platform`/`now` 驱动；`process.cpuUsage` 是真实 Node API（Linux CI 上同样可用），
 * 用一小段忙等制造真实 CPU 时间，验证第二拍得到 >0 且有限的 cpuPct——防止回归成
 * 「win32 直接落到回退 0、面板 CPU 环恒显示 0%」。
 */
import { describe, it, expect } from 'vitest'
import { readHostMetrics } from '../lib/guard/metrics.js'

describe('readHostMetrics win32（process.cpuUsage 差分）', () => {
  it('首拍无基线 → 0；忙等后第二拍 >0；child/fd/io 仍如实回退（画 —，不伪装 0）', () => {
    let fakeNow = 1_000_000
    const deps = { platform: 'win32' as const, now: () => fakeNow }

    const first = readHostMetrics(deps)
    expect(first.cpuPct).toBe(0)

    // 真实忙等 ~80ms：process.cpuUsage 无法注入，只能烧掉真实 CPU 时间。
    const spinUntil = Date.now() + 80
    while (Date.now() < spinUntil) {
      /* busy-wait: burn real CPU time */
    }

    fakeNow += 200
    const second = readHostMetrics(deps)
    expect(Number.isFinite(second.cpuPct)).toBe(true)
    expect(second.cpuPct).toBeGreaterThan(0)

    // win32 仍无低开销数据源：child/fd/io 必须如实回退（面板画 —）
    expect(second.childCount).toBe(-1)
    expect(second.fdCount).toBe(-1)
    expect(second.ioReadMb).toBe(-1)
    expect(second.ioWriteMb).toBe(-1)
  })
})
