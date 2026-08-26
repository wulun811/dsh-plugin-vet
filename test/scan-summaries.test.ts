/**
 * P2 扫描摘要库（scan-summaries）测试：
 * - 记录/读取、变化才落盘（verdict/版本/规则码集合）、LRU 上限淘汰；
 * - 损坏存储 fail-open（空库起家，不抛错）；
 * - 原子写：落盘后目录内无 .tmp 残件（P0 dismissed 同款纪律回归）。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  recordScanSummary,
  getScanSummary,
  listRecentScanSummaries,
  allScanSummaries,
  summariesPath,
  setSummariesDirForTest,
} from '../lib/guard/scan-summaries.js'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vet-scan-summaries-'))
  setSummariesDirForTest(dir)
})

afterEach(() => {
  setSummariesDirForTest(undefined)
  rmSync(dir, { recursive: true, force: true })
})

const summary = (over: Partial<Parameters<typeof recordScanSummary>[0]> = {}): Parameters<typeof recordScanSummary>[0] => ({
  name: '@scope/pkg',
  version: '1.0.0',
  at: Date.now(),
  verdict: 'clean',
  staticScore: 0.1,
  sourceCount: 5,
  ruleCodes: [],
  ...over,
})

describe('scan-summaries', () => {
  it('记录后可读回（单包单条=最新）', () => {
    recordScanSummary(summary())
    const got = getScanSummary('@scope/pkg')
    expect(got?.verdict).toBe('clean')
    expect(got?.version).toBe('1.0.0')
    // 文件确实落盘
    expect(existsSync(summariesPath())).toBe(true)
  })

  it('同版同结论重扫不覆写（at 不变）；verdict 变化才刷新', () => {
    const t0 = 1_000
    recordScanSummary(summary({ at: t0 }))
    recordScanSummary(summary({ at: t0 + 5_000 }))
    expect(getScanSummary('@scope/pkg')?.at).toBe(t0)
    // verdict 变 → 刷新
    recordScanSummary(summary({ at: t0 + 9_000, verdict: 'suspicious' }))
    const got = getScanSummary('@scope/pkg')
    expect(got?.at).toBe(t0 + 9_000)
    expect(got?.verdict).toBe('suspicious')
    // 回到 clean（规则码集合变化）→ 也算变化
    recordScanSummary(summary({ at: t0 + 12_000, verdict: 'clean', ruleCodes: ['R5'] }))
    expect(getScanSummary('@scope/pkg')?.ruleCodes).toEqual(['R5'])
  })

  it('版本变化视为变化', () => {
    recordScanSummary(summary({ version: '1.0.0' }))
    recordScanSummary(summary({ version: '2.0.0' }))
    expect(getScanSummary('@scope/pkg')?.version).toBe('2.0.0')
  })

  it('LRU：超出上限按 at 淘汰最旧', () => {
    // 上限 200：写入 205 包，最旧的 5 个被淘汰
    for (let i = 0; i < 205; i++) {
      recordScanSummary(summary({ name: `pkg-${String(i).padStart(3, '0')}`, at: 10_000 + i }))
    }
    const all = allScanSummaries()
    expect(all.length).toBe(200)
    expect(getScanSummary('pkg-000')).toBeUndefined()
    expect(getScanSummary('pkg-004')).toBeUndefined()
    expect(getScanSummary('pkg-005')?.name).toBe('pkg-005')
    expect(getScanSummary('pkg-204')).toBeDefined()
  })

  it('listRecentScanSummaries 按 at 倒序取前 N（D7 最近插件列表口径）', () => {
    for (let i = 0; i < 30; i++) {
      recordScanSummary(summary({ name: `p-${i}`, at: 1_000 + i }))
    }
    const recent = listRecentScanSummaries(20)
    expect(recent.length).toBe(20)
    expect(recent[0]?.name).toBe('p-29')
    expect(recent[19]?.name).toBe('p-10')
  })

  it('损坏存储 fail-open：坏 JSON → 空库起家，随后可正常写入', () => {
    const path = join(dir, 'scan-summaries.json')
    writeFileSync(path, '{ not json !!!', 'utf8')
    expect(getScanSummary('x')).toBeUndefined()
    recordScanSummary(summary())
    expect(getScanSummary('@scope/pkg')?.verdict).toBe('clean')
  })

  it('残缺单条记录被丢弃，不影响其他条目', () => {
    recordScanSummary(summary())
    // 手工注入一条缺 ruleCodes 的坏记录
    const path = summariesPath()
    const raw = JSON.parse(readFileSync(path, 'utf8')) as { records: Record<string, unknown> }
    raw.records['bad-entry'] = { name: 'bad-entry', at: 1 }
    writeFileSync(path, JSON.stringify(raw), 'utf8')
    expect(getScanSummary('bad-entry')).toBeUndefined()
    expect(getScanSummary('@scope/pkg')?.verdict).toBe('clean')
  })

  it('原子写无 tmp 残件', () => {
    recordScanSummary(summary())
    const leftovers = readdirSync(dir).filter(f => f.includes('.tmp'))
    expect(leftovers).toEqual([])
  })
})
