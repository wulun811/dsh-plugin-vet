import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { VetStatus } from '../lib/guard/status.js'
import { setDismissedFileForTest, persistentlyDismiss, restorePersistentDismissal, getPersistentDismissedList } from '../lib/guard/dismissed-alerts.js'

/**
 * round-15 review：持久化忽略跨 session 可恢复性修复。
 * 旧行为（0.2.1）：VetStatus.record 对已持久化忽略的 id 短路不入列 → 重启后该报警
 * 永不出现、已忽略区无条目、面板无恢复入口（0.2.1 文档承诺的「已忽略分区可恢复」
 * 跨 session 失效，且被忽略的报警再次真实发生时完全不可见）。
 * 新行为：照常入列，snapshot 按 isDismissed（内存 ∪ 持久化）折叠进 dismissed 区——
 * 不参与 level/alarmCount，但可见、可恢复；mergeKey 聚合最坏量级=一条。
 */

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vet-dismiss-'))
  setDismissedFileForTest(join(dir, 'dismissed.json'))
})

afterEach(() => {
  setDismissedFileForTest(join(dir, 'dismissed.json'))
  rmSync(dir, { recursive: true, force: true })
})

describe('持久化忽略跨 session 可恢复（round-15）', () => {
  it('持久化忽略后同 id 再触发 → 入列但折叠进 dismissed 区（可恢复）', () => {
    persistentlyDismiss('n3-key-leak-pem::abc')
    const status = new VetStatus()
    // 模拟跨 session：新 VetStatus 实例（内存 dismissedIds 空），但持久化记录在
    status.record({
      id: 'n3-key-leak-pem::abc',
      severity: 'red',
      source: 't2',
      kind: 'n3-key-leak',
      message: '密钥外泄确认',
      at: Date.now(),
    })
    const snap = status.snapshot()
    // 折叠进 dismissed：不进 active、不计 level/alarmCount
    expect(snap.dismissed.length).toBe(1)
    expect(snap.dismissed[0]!.id).toBe('n3-key-leak-pem::abc')
    expect(snap.alarmCount).toBe(0)
    expect(snap.level).toBe('green')
    // 恢复入口（面板 restore 按钮走同款 restorePersistentDismissal）→ 再触发进 active
    restorePersistentDismissal('n3-key-leak-pem::abc')
    status.record({
      id: 'n3-key-leak-pem::abc',
      severity: 'red',
      source: 't2',
      kind: 'n3-key-leak',
      message: '密钥外泄确认',
      at: Date.now(),
    })
    const snap2 = status.snapshot()
    expect(snap2.alarmCount).toBe(1)
    expect(snap2.level).toBe('red')
    expect(snap2.dismissed).toEqual([])
  })

  it('未持久化忽略的报警照常 active（回归：不误折叠）', () => {
    const status = new VetStatus()
    status.record({
      id: 'some-other-alarm',
      severity: 'yellow',
      source: 't1',
      kind: 'sentinel',
      message: 'T1 哨兵退出',
      at: Date.now(),
    })
    const snap = status.snapshot()
    expect(snap.alarmCount).toBe(1)
    expect(snap.dismissed).toEqual([])
  })

  it('mergeKey 聚合的报警按 mergeKey 持久化→折叠整组（count 累积展示一条）', () => {
    persistentlyDismiss('t2:n3-key-leak:plugin-a')
    const status = new VetStatus()
    // 同 mergeKey 的两个不同 id → 折叠为一条（count=2），且被持久化忽略 → 进 dismissed
    status.record({ id: 'n3-key-leak-pem::x', severity: 'red', source: 't2', kind: 'n3-key-leak', pluginHint: 'plugin-a', mergeKey: 't2:n3-key-leak:plugin-a', at: Date.now() })
    status.record({ id: 'n3-key-leak-aws::y', severity: 'red', source: 't2', kind: 'n3-key-leak', pluginHint: 'plugin-a', mergeKey: 't2:n3-key-leak:plugin-a', at: Date.now() })
    const snap = status.snapshot()
    expect(snap.dismissed.length).toBe(1)
    expect(snap.dismissed[0]!.count).toBe(2)
    expect(snap.alarmCount).toBe(0)
  })

  it('恢复后持久化磁盘记录同步清除（restorePersistentDismissal 写盘）', () => {
    persistentlyDismiss('alarm-persisted')
    expect(getPersistentDismissedList()).toContain('alarm-persisted')
    restorePersistentDismissal('alarm-persisted')
    expect(getPersistentDismissedList()).not.toContain('alarm-persisted')
  })
})