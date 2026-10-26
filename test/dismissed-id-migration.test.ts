import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  setDismissedFileForTest,
  isPersistentlyDismissed,
  migrateLegacyScanVerdictId,
  getPersistentDismissedList,
  persistentlyDismiss,
} from '../lib/guard/dismissed-alerts.js'

/**
 * 0.4.1：`scan-verdict` 的 id 加了类别结构位（`agg:` / `plugin:` / `tool:`）。
 *
 * 变更 id 格式的直接代价是**用户已点过的「忽略」全部失配**——实测本机存储里同一个 zod
 * 公告留下两把键（旧 `scan-verdict:osv:…` + 新 `scan-verdict:agg:osv:…`），用户被迫对
 * 同一条 CVE 再点一次忽略。本测试锁住「旧键迁移到新键」：升级后已忽略的公告不再复活。
 *
 * 迁移的另一半同样是契约：**有歧义就不迁移**。旧对象行 `scan-verdict:<name>:<digest>` 不
 * 区分 plugin/tool，猜错方向会把「工具执行结果被忽略」变成「同名插件的红牌被预批准」。
 */

let dir: string
let file: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vet-dismiss-migrate-'))
  file = join(dir, 'dismissed-alerts.json')
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

/** 写盘并在同一刻清缓存（setDismissedFileForTest 会清——缓存只服务本文件的路径）。 */
function seedDismissed(dismissed: Record<string, unknown>): void {
  writeFileSync(file, JSON.stringify({ dismissed }), 'utf8')
  setDismissedFileForTest(file)
}

describe('scan-verdict 旧 id 迁移（升级后已忽略的公告不复活）', () => {
  it('旧聚合行插入 agg 段；已迁移/对象行/其它来源一律原样', () => {
    // 旧聚合行（5 段）→ 新形态
    expect(migrateLegacyScanVerdictId('scan-verdict:osv:GHSA-mrhx-c7xc-m3w5:zod@4.4.3:suspicious'))
      .toBe('scan-verdict:agg:osv:GHSA-mrhx-c7xc-m3w5:zod@4.4.3:suspicious')
    // 新形态幂等
    expect(migrateLegacyScanVerdictId('scan-verdict:agg:osv:GHSA-x:zod@4.4.3:critical'))
      .toBe('scan-verdict:agg:osv:GHSA-x:zod@4.4.3:critical')
    // 旧对象行（3 段）：plugin/tool 有歧义，不迁移
    expect(migrateLegacyScanVerdictId('scan-verdict:foo:deadbeef')).toBe('scan-verdict:foo:deadbeef')
    // 段数不足的畸形形态：不猜结构
    expect(migrateLegacyScanVerdictId('scan-verdict:osv:a:b')).toBe('scan-verdict:osv:a:b')
    // 别的来源完全不相干
    expect(migrateLegacyScanVerdictId('n3-key-leak-pem::abc')).toBe('n3-key-leak-pem::abc')
  })

  it('盘上是旧键 → 新 id 直接命中已忽略（用户不需要再点一次）', () => {
    seedDismissed({
      'scan-verdict:osv:GHSA-mrhx-c7xc-m3w5:zod@4.4.3:suspicious': { dismissedAt: 1000 },
    })
    expect(isPersistentlyDismissed('scan-verdict:agg:osv:GHSA-mrhx-c7xc-m3w5:zod@4.4.3:suspicious')).toBe(true)
    // 迁移后的列表里不再有旧键（面板「已忽略」不重复列一行）
    expect(getPersistentDismissedList()).toEqual(['scan-verdict:agg:osv:GHSA-mrhx-c7xc-m3w5:zod@4.4.3:suspicious'])
  })

  it('新旧两把键并存 → 合并成一条，取较晚的 dismissedAt 并保留 reason', () => {
    seedDismissed({
      'scan-verdict:osv:GHSA-x:zod@4.4.3:suspicious': { dismissedAt: 1000, reason: 'early' },
      'scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious': { dismissedAt: 2000 },
    })
    expect(getPersistentDismissedList()).toEqual(['scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious'])
    // 触发一次写盘（迁移本身不写盘）：落盘的必须是合并后的单条，旧键消失
    persistentlyDismiss('another-alert')
    const store = JSON.parse(readFileSync(file, 'utf8')) as { dismissed: Record<string, { dismissedAt: number; reason?: string }> }
    expect(Object.keys(store.dismissed).sort()).toEqual(['another-alert', 'scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious'])
    // 较晚的时间 + 较早记录上的说明，两者都不丢
    expect(store.dismissed['scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious']).toEqual({ dismissedAt: 2000, reason: 'early' })
  })

  it('盘上条目是畸形值（null / 字符串）→ 原样带过，不连累其它忽略项', () => {
    seedDismissed({
      'scan-verdict:osv:GHSA-x:zod@4.4.3:suspicious': { dismissedAt: 1000 },
      'broken-null': null,
      'broken-string': 'oops',
    })
    // 关键断言：迁移遇到非对象条目不能让整张表回退成空（外层 catch 会那样）
    expect(isPersistentlyDismissed('scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious')).toBe(true)
    expect(getPersistentDismissedList().sort()).toEqual([
      'broken-null',
      'broken-string',
      'scan-verdict:agg:osv:GHSA-x:zod@4.4.3:suspicious',
    ])
  })
})
