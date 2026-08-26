/**
 * P2 审计&蜜罐聚合器（audit-summary）测试：
 * - seen 并集口径（capabilities ∪ scan-summaries）；
 * - 待审 = 见过 ∩ 无档案；新装 = 72h 内首见且无档案；
 * - 批量审计探测（hasAuditRecordBatch 一次 readdir）；
 * - 蜜罐触碰从报警流聚合（kind='honeypot'，count 累计、lastTouch 取最新）；
 * - blocked 标记走 confirmBlock.isFamily1Blocked；
 * - fail-open：内部抛错 → EMPTY 结构。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { saveCapabilities, setCapabilitiesDirForTest, type CapabilityStore, type CapabilityManifest } from '../lib/guard/version-diff.js'
import { recordScanSummary, setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { setArchiveDirForTest } from '../lib/audit/archive.js'
import { hasAuditRecordBatch } from '../lib/audit/archive.js'
import { buildAuditSummary } from '../lib/guard/audit-summary.js'
import { confirmBlock } from '../lib/guard/confirm-block.js'
import type { VetAlarm } from '../lib/guard/status.js'

let dir: string

const emptyManifest = (): CapabilityManifest => ({
  hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false,
})

const alarm = (over: Partial<VetAlarm> = {}): VetAlarm => ({
  id: 'a1',
  severity: 'red',
  source: 't2',
  kind: 'honeypot',
  message: '蜜罐命中',
  at: Date.now(),
  ...over,
})

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vet-audit-summary-'))
  mkdirSync(join(dir, 'caps'), { recursive: true })
  mkdirSync(join(dir, 'summaries'), { recursive: true })
  mkdirSync(join(dir, 'audits'), { recursive: true })
  setCapabilitiesDirForTest(join(dir, 'caps'))
  setSummariesDirForTest(join(dir, 'summaries'))
  setArchiveDirForTest(join(dir, 'audits'))
})

afterEach(() => {
  setCapabilitiesDirForTest(undefined)
  setSummariesDirForTest(undefined)
  setArchiveDirForTest('/nonexistent-vet-audit-reset')
  confirmBlock.clear()
  rmSync(dir, { recursive: true, force: true })
})

describe('audit-summary', () => {
  it('seen 并集：capabilities 与 summaries 同包合并（firstSeen 取早、结论跟随新）', () => {
    const now = Date.now()
    const store: CapabilityStore = {
      records: {
        '@a/old@1.0.0': { name: '@a/old', version: '1.0.0', recordedAt: now - 10_000, capabilities: emptyManifest() },
      },
    }
    saveCapabilities(store)
    recordScanSummary({ name: '@a/old', version: '2.0.0', at: now, verdict: 'clean', staticScore: 0.2, ruleCodes: [] })

    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    const entry = snap.plugins.find(p => p.name === '@a/old')
    expect(entry?.version).toBe('2.0.0')
    expect(entry?.at).toBe(now)
    // 只有一条记录（同包合并不重复）
    expect(snap.plugins.filter(p => p.name === '@a/old').length).toBe(1)
  })

  it('待审与新装：无档案的近期包进两个清单；有档案的不进', () => {
    const now = Date.now()
    const store: CapabilityStore = {
      records: {
        'audited@1.0.0': { name: 'audited', version: '1.0.0', recordedAt: now - 5_000, capabilities: emptyManifest() },
        'fresh@1.0.0': { name: 'fresh', version: '1.0.0', recordedAt: now - 1_000, capabilities: emptyManifest() },
      },
    }
    saveCapabilities(store)
    // audited 有档案
    writeFileSync(
      join(dir, 'audits', 'audited-1.0.0-' + '20260825-120000' + '.md'),
      '# ok', 'utf8',
    )
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    expect(snap.pendingAudits.some(p => p.name === 'fresh')).toBe(true)
    expect(snap.pendingAudits.some(p => p.name === 'audited')).toBe(false)
    expect(snap.newPlugins.some(n => n.name === 'fresh')).toBe(true)
    expect(snap.newPlugins.some(n => n.name === 'audited')).toBe(false)
    const idx = snap.plugins.find(p => p.name === 'audited')
    expect(idx?.audited).toBe(true)
  })

  it('老包（>72h 首见）不进新装清单，但仍算待审欠账', () => {
    const now = Date.now()
    const old = now - 80 * 60 * 60 * 1000
    const store: CapabilityStore = {
      records: { 'veteran@1.0.0': { name: 'veteran', version: '1.0.0', recordedAt: old, capabilities: emptyManifest() } },
    }
    saveCapabilities(store)
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    expect(snap.newPlugins.length).toBe(0)
    expect(snap.pendingAudits.some(p => p.name === 'veteran')).toBe(true)
  })

  it('round-19：官方包整体移出走廊（待审/新装/索引都不出现）；第三方照常进', () => {
    const now = Date.now()
    const store: CapabilityStore = {
      records: {
        '@deepseek-ai/dsh-tools@0.1.1-rc.2': { name: '@deepseek-ai/dsh-tools', version: '0.1.1-rc.2', recordedAt: now - 1_000, capabilities: emptyManifest() },
        'third-party@1.0.0': { name: 'third-party', version: '1.0.0', recordedAt: now - 1_000, capabilities: emptyManifest() },
      },
    }
    saveCapabilities(store)
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    // 待审：官方包不进（门槛=内容基线+静态扫描，非人工档案）；第三方照常待审
    expect(snap.pendingAudits.some(p => p.name === 'third-party')).toBe(true)
    expect(snap.pendingAudits.some(p => p.name === '@deepseek-ai/dsh-tools')).toBe(false)
    // 新装：官方包不进（随 DSH 分发，不是「新出现的陌生包」）；第三方照常进
    expect(snap.newPlugins.some(n => n.name === '@deepseek-ai/dsh-tools')).toBe(false)
    expect(snap.newPlugins.some(n => n.name === 'third-party')).toBe(true)
    // 索引：官方包不占格子（走廊只展示第三方，20 格让位给真正要审的包）
    expect(snap.plugins.some(p => p.name === '@deepseek-ai/dsh-tools')).toBe(false)
    expect(snap.plugins.some(p => p.name === 'third-party')).toBe(true)
  })

  it('蜜罐：touches 按 count 累计，lastTouch 取最新；armed 透传', () => {
    const now = Date.now()
    const snap = buildAuditSummary({
      alarms: [
        alarm({ kind: 'honeypot', pluginHint: 'evil-a', target: '~/.dsh/.local/fake-key-001', at: now - 5_000, count: 2 }),
        alarm({ kind: 'honeypot', pluginHint: 'evil-b', target: '~/.dsh/.local/fake-key-002', at: now }),
        alarm({ kind: 'fs-read', pluginHint: 'other', count: 9 }),
      ],
      honeypotArmed: true,
      isBlocked: () => false,
    })
    expect(snap.honeypot.armed).toBe(true)
    expect(snap.honeypot.touches).toBe(3)
    expect(snap.honeypot.lastTouch?.plugin).toBe('evil-b')
  })

  it('blocked 标记来自 confirmBlock 族 1 名单', () => {
    const now = Date.now()
    const store: CapabilityStore = {
      records: { 'bad@1.0.0': { name: 'bad', version: '1.0.0', recordedAt: now, capabilities: emptyManifest() } },
    }
    saveCapabilities(store)
    confirmBlock.markFamily1('bad')
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: n => confirmBlock.isFamily1Blocked(n) })
    expect(snap.plugins.find(p => p.name === 'bad')?.blocked).toBe(true)
  })

  it('hasAuditRecordBatch：一次调用判多个包（命中/未命中混合）', () => {
    writeFileSync(join(dir, 'audits', 'yes-1.0.0-20260825-120000.md'), '# ok', 'utf8')
    writeFileSync(join(dir, 'audits', 'nope-foo-20260825-120000.md'), '# 伪造前缀（版本段非数字开头）', 'utf8')
    const map = hasAuditRecordBatch([{ name: 'yes', version: '1.0.0' }, { name: 'nope' }, { name: 'ghost' }])
    expect(map['yes']).toBe(true)
    expect(map['nope']).toBe(false)
    expect(map['ghost']).toBe(false)
  })

  it('fail-open：目录全部不可用时返回空结构而非抛错', () => {
    setCapabilitiesDirForTest(join(dir, 'missing-caps'))
    setSummariesDirForTest(join(dir, 'missing-sum'))
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    expect(snap.honeypot.armed).toBe(false)
    expect(snap.plugins).toEqual([])
    expect(snap.pendingAudits).toEqual([])
    expect(snap.newPlugins).toEqual([])
  })

  it('round-21：索引上限 200——第三方较多时不截断（旧 50 会把第 51 个起藏掉）', () => {
    const now = Date.now()
    const records: CapabilityStore['records'] = {}
    for (let i = 0; i < 120; i++) {
      records[`pkg-${i}@1.0.0`] = { name: `pkg-${i}`, version: '1.0.0', recordedAt: now - i, capabilities: emptyManifest() }
    }
    saveCapabilities({ records })
    const snap = buildAuditSummary({ alarms: [], honeypotArmed: false, isBlocked: () => false })
    // 120 个第三方全部进入索引（≤ LIMIT 不截断；超出才按 LIST_CAP=200 兜底）
    expect(snap.plugins.length).toBe(120)
    expect(snap.plugins.some(p => p.name === 'pkg-119')).toBe(true)
    expect(snap.pendingAudits.length).toBe(120)
  })
})
