import { describe, it, expect } from 'vitest'
import { VetStatus } from '../lib/guard/status'

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

  it('0.3.3 P1 双层通道：info 观察不进 alarmCount、不抬 level，但保留在列表', () => {
    const s = new VetStatus()
    s.record({
      id: 'esm-guard-coverage:@deepseek-ai/a',
      severity: 'info',
      source: 'scan',
      kind: 'esm-guard-coverage',
      message: '官方包信息观察',
      target: '@deepseek-ai/a',
      pluginHint: '@deepseek-ai/a',
      mergeKey: 'scan:esm-guard-coverage:official',
      at: Date.now(),
    })
    s.record({
      id: 'esm-guard-coverage:@deepseek-ai/b',
      severity: 'info',
      source: 'scan',
      kind: 'esm-guard-coverage',
      message: '官方包信息观察',
      target: '@deepseek-ai/b',
      pluginHint: '@deepseek-ai/b',
      mergeKey: 'scan:esm-guard-coverage:official',
      at: Date.now(),
    })
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(0) // 信息观察不计入可行动风险数
    expect(snap.level).toBe('green') // 不抬盾牌
    expect(snap.alarms.length).toBe(1) // 列表保留（折叠一条）
    expect(snap.alarms[0].count).toBe(2)
    expect(snap.alarms[0].severity).toBe('info')
    // 叠加真黄色：alarmCount 只计黄色
    s.record({ id: 'x:1', severity: 'yellow', source: 't2', kind: 'fs-write', message: 'm', target: '/a', at: Date.now() })
    expect(s.snapshot().alarmCount).toBe(1)
    expect(s.snapshot().alarms.length).toBe(2)
  })
})

/**
 * retract 与 dismiss 的分工（0.5.28）：dismiss = 用户的答复（记录留着、进「已忽略」区、可恢复）；
 * retract = vet 自己的观察被证伪（命题不成立了，留着就是一条已知为假的黄牌）。
 * 典型场景：目录外出现官方名 → 黄牌 → registry 核对确认是官方包 → 黄牌撤下、补 info。
 */
describe('VetStatus.retract（证据推翻时撤下，而非折叠成「已忽略」）', () => {
  const yellow = (id: string) => ({
    id,
    severity: 'yellow' as const,
    source: 'scan' as const,
    kind: 'official-not-in-catalog',
    message: '目录外的官方名',
    target: 'x',
    at: Date.now(),
  })

  it('撤销存活行并返回 true；再次撤销返回 false（幂等，不误删别行）', () => {
    const s = new VetStatus()
    s.record(yellow('official-not-in-catalog:a'))
    s.record(yellow('official-not-in-catalog:b'))
    expect(s.retract('official-not-in-catalog:a')).toBe(true)
    expect(s.snapshot().alarms.map(a => a.id)).toEqual(['official-not-in-catalog:b'])
    expect(s.retract('official-not-in-catalog:a')).toBe(false)
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('已忽略的行照撤——忽略不等于同意把一个错误结论留在「已忽略」区', () => {
    const s = new VetStatus()
    s.record(yellow('official-not-in-catalog:c'))
    s.dismiss('official-not-in-catalog:c')
    // 忽略后不进可行动列表，但仍留在记录里（折叠进 snapshot().dismissed）
    expect(s.snapshot().alarms.length).toBe(0)
    expect(s.snapshot().dismissed?.length).toBe(1)
    expect(s.retract('official-not-in-catalog:c')).toBe(true)
    expect(s.snapshot().dismissed?.length ?? 0).toBe(0)
    // 忽略状态随记录一起失效：同名再次触发时是新的观察，不该继承旧的折叠
    s.record(yellow('official-not-in-catalog:c'))
    expect(s.isDismissed('official-not-in-catalog:c')).toBe(false)
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('撤下后盾牌回绿（level 只看存活的可行动报警）', () => {
    const s = new VetStatus()
    s.record({ ...yellow('official-not-in-catalog:d'), severity: 'yellow' })
    expect(s.snapshot().level).not.toBe('green')
    s.retract('official-not-in-catalog:d')
    expect(s.snapshot().level).toBe('green')
    expect(s.snapshot().alarmCount).toBe(0)
  })
})
