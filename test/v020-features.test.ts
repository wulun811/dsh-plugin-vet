/**
 * 0.1.20 新功能测试：防御统计、启动校验、esm 去重、upgrade-cold 联审计。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { existsSync, readFileSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('0.1.20 新功能', () => {
  let testDir: string

  beforeEach(() => {
    testDir = join(tmpdir(), 'vet-test-' + Date.now() + '-' + Math.random().toString(36).slice(2))
    mkdirSync(testDir, { recursive: true })
  })

  afterEach(() => {
    try { rmSync(testDir, { recursive: true, force: true }) } catch {}
  })

  describe('stats 模块', () => {
    it('loadStats: 文件不存在返回默认值', async () => {
      const { loadStats, setStatsDirForTest } = await import('../src/guard/stats.js')
      setStatsDirForTest(testDir)
      const stats = loadStats()
      expect(stats.scannedCount).toBe(0)
      expect(stats.alarmsRecorded).toBe(0)
      expect(stats.blockedCount).toBe(0)
      expect(stats.activeDefenseCount).toBe(0)
    })

    it('saveStats + loadStats: 原子写后读回', async () => {
      const { loadStats, saveStats, setStatsDirForTest } = await import('../src/guard/stats.js')
      setStatsDirForTest(testDir)
      saveStats({ scannedCount: 5, alarmsRecorded: 3, blockedCount: 1, activeDefenseCount: 2, updatedAt: 0 })
      const loaded = loadStats()
      expect(loaded.scannedCount).toBe(5)
      expect(loaded.alarmsRecorded).toBe(3)
      expect(loaded.blockedCount).toBe(1)
      expect(loaded.activeDefenseCount).toBe(2)
      expect(loaded.updatedAt).toBeGreaterThan(0)
    })

    it('incrementScanned/AlarmsRecorded/Blocked: 自增计数', async () => {
      const { incrementScanned, incrementAlarmsRecorded, incrementBlocked, loadStats, getStats, setStatsDirForTest } = await import('../src/guard/stats.js')
      setStatsDirForTest(testDir)
      incrementScanned()
      incrementScanned()
      incrementAlarmsRecorded()
      incrementBlocked()
      getStats() // 落盘刷新（生产由盾牌 5s 轮询触发）
      const stats = loadStats()
      expect(stats.scannedCount).toBe(2)
      expect(stats.alarmsRecorded).toBe(1)
      expect(stats.blockedCount).toBe(1)
    })

    it('setActiveDefenseCount + getActiveDefenseCount: 内存态不持久化', async () => {
      const { setActiveDefenseCount, getActiveDefenseCount, getStats, loadStats, setStatsDirForTest } = await import('../src/guard/stats.js')
      setStatsDirForTest(testDir)
      setActiveDefenseCount(7)
      expect(getActiveDefenseCount()).toBe(7)
      const stats = getStats()
      expect(stats.activeDefenseCount).toBe(7)
      // 内存态不写入文件
      const stats2 = loadStats()
      expect(stats2.activeDefenseCount).toBe(0)
    })
  })

  describe('upgrade-cold 联审计', () => {
    it('recordScan: 冷启动 + 有审计档案 → 不报 upgrade-cold', async () => {
      const { recordScan, setCapabilitiesDirForTest } = await import('../src/guard/version-diff.js')
      const { setArchiveDirForTest } = await import('../src/audit/archive.js')
      setCapabilitiesDirForTest(testDir)
      setArchiveDirForTest(testDir)
      // 创建审计档案
      const archiveName = 'test-plugin-1.0.0-20260101-120000.md'
      const { writeFileSync } = await import('node:fs')
      writeFileSync(join(testDir, archiveName), '# audit')
      const outcome = recordScan('test-plugin', '1.0.0', { hasNetwork: true, hasExec: true })
      // 有审计档案 → 不报 upgrade-cold
      expect(outcome.alarm).toBeNull()
    })

    it('recordScan: 冷启动 + 无审计档案 → 报 upgrade-cold', async () => {
      const { recordScan, setCapabilitiesDirForTest } = await import('../src/guard/version-diff.js')
      const { setArchiveDirForTest } = await import('../src/audit/archive.js')
      setCapabilitiesDirForTest(testDir)
      setArchiveDirForTest(testDir)
      const outcome = recordScan('test-plugin', '1.0.0', { hasNetwork: true, hasExec: true })
      // 无审计档案 → 报 upgrade-cold
      expect(outcome.alarm).not.toBeNull()
      expect(outcome.alarm?.kind).toBe('upgrade-cold')
    })
  })

  describe('升级差分 red 级别文案', () => {
    it('buildUpgradeAlarm: red 级别提示用户重新审计', async () => {
      // 通过 recordScan 间接测试
      const { recordScan, setCapabilitiesDirForTest } = await import('../src/guard/version-diff.js')
      const { setArchiveDirForTest } = await import('../src/audit/archive.js')
      setCapabilitiesDirForTest(testDir)
      setArchiveDirForTest(testDir)
      // 先记录旧版本
      recordScan('test-plugin', '1.0.0', { hasNetwork: false, hasExec: false })
      // 升级到新版本，新增 exec + network → red
      const outcome = recordScan('test-plugin', '2.0.0', { hasNetwork: true, hasExec: true })
      expect(outcome.alarm).not.toBeNull()
      expect(outcome.alarm?.severity).toBe('red')
      expect(outcome.alarm?.message).toContain('vet-audit-protocol')
      expect(outcome.alarm?.message).toContain('审查完成后警报自动解除')
    })
  })
})
