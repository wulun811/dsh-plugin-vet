import { describe, expect, it } from 'vitest'
import { _withScanSlotForTest } from '../lib/scanner/client.js'

const sleep = (ms: number): Promise<void> => new Promise(r => setTimeout(r, ms))

/**
 * 三轮审查回归：MAX_CONCURRENT_SCANS 排队路径记账。
 * 修复前排队分支不增减 activeScans，pump 一口气放空队列，8 任务实测并发峰值 7（上限 2）。
 */
describe('scanner 并发上限（三轮审查回归）', () => {
  it('排队任务计入 activeScans，真实并发不超过 MAX_CONCURRENT_SCANS=2', async () => {
    let cur = 0
    let peak = 0
    await Promise.all(Array.from({ length: 8 }, () =>
      _withScanSlotForTest(async () => {
        cur++
        peak = Math.max(peak, cur)
        await sleep(25)
        cur--
      })
    ))
    expect(peak).toBeLessThanOrEqual(2)
  })
})