import { describe, expect, it } from 'vitest'
import { isShieldSnapshotShape } from '../lib/guard/shield-shape.js'

/** round-21：盾牌轮询的形状守卫（防可解析非快照 JSON 覆盖旧快照 → 假全绿）。 */
describe('isShieldSnapshotShape（快照线格式最小形状谓词）', () => {
  it('接受 status-route 200 快照形状（level + alarms 双硬依赖）', () => {
    expect(isShieldSnapshotShape({
      level: 'yellow',
      alarmCount: 1,
      alarms: [{ id: 'x', severity: 'yellow', source: 't2', kind: 'fs-read', message: 'm', at: 1 }],
      dismissed: [],
      metrics: { rssMb: 1 },
    })).toBe(true)
    // 空报警的 green 快照同样合法
    expect(isShieldSnapshotShape({ level: 'green', alarmCount: 0, alarms: [], dismissed: [] })).toBe(true)
  })

  it('拒绝 SEC-6 跨源 403 信封（真阳性回归：曾把盾牌刷成假全绿）', () => {
    expect(isShieldSnapshotShape({ ok: false, note: '跨源请求被拒绝' })).toBe(false)
  })

  it('拒绝非对象/数组/null 与判别字段缺失或类型漂移', () => {
    expect(isShieldSnapshotShape(null)).toBe(false)
    expect(isShieldSnapshotShape('not json object')).toBe(false)
    expect(isShieldSnapshotShape([1, 2])).toBe(false)
    expect(isShieldSnapshotShape({})).toBe(false)
    expect(isShieldSnapshotShape({ level: 'green' })).toBe(false) // alarms 缺
    expect(isShieldSnapshotShape({ alarms: [] })).toBe(false) // level 缺
    expect(isShieldSnapshotShape({ level: 1, alarms: [] })).toBe(false) // level 非字符串
    expect(isShieldSnapshotShape({ level: 'green', alarms: 'oops' })).toBe(false) // alarms 非数组
  })
})
