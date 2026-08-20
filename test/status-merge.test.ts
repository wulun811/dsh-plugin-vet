import { describe, it, expect } from 'vitest'
import { VetStatus } from '../src/guard/status'

describe('VetStatus 合并去重（事件风暴降噪）', () => {
  it('同 (kind,plugin) 跨 target 的关联签名折叠为一条并累计 count', () => {
    const s = new VetStatus({ dedupeWindowMs: 60_000 })
    // n3-spawn-net-match 按主机设 target——三个不同主机应是三条独立 id，但 mergeKey 相同
    const mk = (host: string) => ({
      id: `t2:n3-spawn-net-match:${host}:evil`,
      severity: 'red' as const,
      source: 't2' as const,
      kind: 'n3-spawn-net-match',
      message: `spawn+net ${host}`,
      target: host,
      pluginHint: 'evil',
      mergeKey: 't2:n3-spawn-net-match:evil',
      at: Date.now(),
    })
    expect(s.record(mk('a.com'))).toBe('new')
    expect(s.record(mk('b.com'))).toBe('deduped')
    expect(s.record(mk('c.com'))).toBe('deduped')
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(1) // 折叠为一条
    expect(snap.alarms[0].count).toBe(3) // 累计次数
    expect(snap.alarms[0].target).toBe('c.com') // 保留最近一次 target
  })

  it('未设 mergeKey 的报警仍按精确 id 去重（T2 hook 报警不被合并）', () => {
    const s = new VetStatus({ dedupeWindowMs: 0 })
    // fs-destroy 到不同文件：id 不同、无 mergeKey → 各自独立行
    s.record({ id: 't2:fs-destroy:/a:x', severity: 'red', source: 't2', kind: 'fs-destroy', message: 'del /a', target: '/a', pluginHint: 'x', at: Date.now() })
    s.record({ id: 't2:fs-destroy:/b:x', severity: 'red', source: 't2', kind: 'fs-destroy', message: 'del /b', target: '/b', pluginHint: 'x', at: Date.now() })
    expect(s.snapshot().alarmCount).toBe(2) // 不合并
    expect(s.snapshot().alarms.every(a => (a.count ?? 1) === 1)).toBe(true)
  })

  it('窗口外同 mergeKey 重发重置 count（replace 语义，不常驻单条）', () => {
    const s = new VetStatus({ dedupeWindowMs: 10 })
    const base = {
      id: 't2:n3-key-leak:evil:K1',
      severity: 'red' as const,
      source: 't2' as const,
      kind: 'n3-key-leak',
      message: 'key K1',
      target: 'K1',
      pluginHint: 'evil',
      mergeKey: 't2:n3-key-leak:evil',
      at: Date.now() - 1000,
    }
    expect(s.record(base)).toBe('new')
    // 窗口外再发（不同密钥，但 mergeKey 同）——先移除旧副本再入列，count 归 1
    expect(s.record({ ...base, id: 't2:n3-key-leak:evil:K2', target: 'K2', at: Date.now() })).toBe('new')
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms[0].count).toBe(1) // 新 episode，计数重置
    expect(snap.alarms[0].target).toBe('K2')
  })

  it('合并时严重度取高者（红压过黄）', () => {
    const s = new VetStatus({ dedupeWindowMs: 60_000 })
    const base = {
      id: 't2:n3-high-freq-read:evil',
      severity: 'yellow' as const,
      source: 't2' as const,
      kind: 'n3-high-freq-read',
      message: 'freq read',
      pluginHint: 'evil',
      mergeKey: 't2:n3-high-freq-read:evil',
      at: Date.now(),
    }
    expect(s.record(base)).toBe('new')
    expect(s.record({ ...base, severity: 'red', id: 't2:n3-high-freq-read:evil:2' })).toBe('deduped')
    expect(s.snapshot().alarms[0].severity).toBe('red')
    expect(s.snapshot().alarms[0].count).toBe(2)
  })
})
