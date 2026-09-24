import { afterAll, describe, expect, it, vi } from 'vitest'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, sep } from 'node:path'
import {
  VET_STORE_DIR_ENV, isTestRuntime, resolveStoreRoot, setStoreRootForTest, testStoreRoot,
  vetIntegrityRoot, vetStoreRoot,
} from '../lib/guard/store-root.js'
import { capabilitiesPath } from '../lib/guard/version-diff.js'
import { baselinePath } from '../lib/guards/content-baseline.js'
import { summariesPath } from '../lib/guard/scan-summaries.js'
import { statsPath } from '../lib/guard/stats.js'
import { knownBoundariesPath } from '../lib/guard/known-boundaries.js'
import { officialCatalogPath } from '../lib/guards/official-catalog.js'
import { forensicsRoot } from '../lib/guard/forensics.js'
import { contractsRoot } from '../lib/guard/contract.js'
import { archiveDir } from '../lib/audit/archive.js'

/**
 * 0.3.15（用户实测事故回归）：vet 存储根目录统一解析 + 测试运行时 fail-closed。
 *
 * 事故：0.3.14 及以前，**忘记** setXDirForTest 的测试直接写用户真实存储——实测 vitest
 * 把 6 条夹具记录写进 ~/.dsh/vet/capabilities.json、8 条写进 scan-summaries.json，另有
 * stats.json 与 forensics/evil-plugin-*.jsonl；随后被 M7 自检如实报成 vet-store-tamper
 * 黄牌（用户 live 面板可见）。逐测试纪律已补过两轮仍在复发，故改成默认 fail-closed：
 * 测试运行时的默认存储根永远不是真实家目录。
 */
describe('store-root（0.3.15）：统一解析 + 测试运行时 fail-closed', () => {
  afterAll(() => { setStoreRootForTest(undefined) })

  it('纯解析：生产默认 = <home>/.dsh/vet；env 口子优先；空串忽略', () => {
    // Windows 兼容：期望值用 join（resolveStoreRoot 内部用 join，win32 分隔符为 \）
    const probeRoot = join('/home/probe', '.dsh', 'vet')
    expect(resolveStoreRoot({ env: {}, home: '/home/probe', isTestRuntime: false })).toBe(probeRoot)
    expect(resolveStoreRoot({
      env: { [VET_STORE_DIR_ENV]: '/srv/vet-state' }, home: '/home/probe', isTestRuntime: false,
    })).toBe('/srv/vet-state')
    expect(resolveStoreRoot({
      env: { [VET_STORE_DIR_ENV]: '   ' }, home: '/home/probe', isTestRuntime: false,
    })).toBe(probeRoot)
  })

  it('纯解析：测试运行时默认落进程私有临时目录（env 口子仍优先）', () => {
    const root = resolveStoreRoot({ env: {}, home: '/home/probe', isTestRuntime: true })
    expect(root).toBe(testStoreRoot())
    expect(root.startsWith(tmpdir())).toBe(true)
    expect(root).not.toContain('/home/probe')
    expect(resolveStoreRoot({
      env: { [VET_STORE_DIR_ENV]: '/srv/vet-state' }, home: '/home/probe', isTestRuntime: true,
    })).toBe('/srv/vet-state')
  })

  it('isTestRuntime：VITEST / NODE_ENV=test 都算', () => {
    expect(isTestRuntime({})).toBe(false)
    expect(isTestRuntime({ VITEST: 'true' })).toBe(true)
    expect(isTestRuntime({ NODE_ENV: 'test' })).toBe(true)
  })

  it('事故回归：测试进程的默认存储根**不是**真实家目录', () => {
    // 本文件存在的理由：0.3.14 时 vetStoreRoot() 恒为 ~/.dsh/vet，测试夹具直写用户生产状态
    expect(vetStoreRoot()).toBe(testStoreRoot())
    expect(vetStoreRoot()).not.toBe(join(homedir(), '.dsh', 'vet'))
    expect(vetStoreRoot().startsWith(tmpdir() + sep)).toBe(true)
  })

  it('所有 vet 状态路径都在存储根之下（单一真源）', () => {
    const root = vetStoreRoot()
    const paths: [string, string | undefined][] = [
      ['capabilities', capabilitiesPath()],
      ['baseline', baselinePath()],
      ['scan-summaries', summariesPath()],
      ['stats', statsPath()],
      ['known-boundaries', knownBoundariesPath()],
      ['official-catalog', officialCatalogPath()],
      ['forensics', forensicsRoot()],
      ['contracts', contractsRoot()],
    ]
    // audits 另有 DSH_PLUGIN_VET_ARCHIVE_DIR 口子：设了就不在存储根下（生产显式迁移）
    if (process.env.DSH_PLUGIN_VET_ARCHIVE_DIR === undefined) paths.push(['audits', archiveDir()])
    for (const [name, p] of paths) {
      expect(p, name).toBeDefined()
      expect(String(p).startsWith(root + sep), name).toBe(true)
    }
  })

  it('完整性金丝雀根 = 存储根父目录（生产 ~/.dsh；测试不写真实家目录）', () => {
    expect(vetIntegrityRoot()).toBe(dirname(vetStoreRoot()))
    expect(vetIntegrityRoot()).not.toBe(join(homedir(), '.dsh'))
  })

  it('setStoreRootForTest：立即改 vetStoreRoot，且只对之后加载的模块生效（加载时快照）', async () => {
    const override = join(tmpdir(), 'vet-store-root-override-probe')
    setStoreRootForTest(override)
    try {
      // 同一模块实例：立即生效（含派生的完整性金丝雀根）
      expect(vetStoreRoot()).toBe(override)
      expect(vetIntegrityRoot()).toBe(tmpdir())
      // 已加载模块（文件顶部静态导入）保持加载时快照——C3 纪律：运行期覆盖不改已装路径
      expect(capabilitiesPath()).toBe(join(testStoreRoot(), 'capabilities.json'))
      // 之后加载的模块（fresh 注册表）按新覆盖解析
      vi.resetModules()
      const freshRoot = await import('../lib/guard/store-root.js')
      freshRoot.setStoreRootForTest(override)
      const fresh = await import('../lib/guard/version-diff.js')
      expect(fresh.capabilitiesPath()).toBe(join(override, 'capabilities.json'))
      freshRoot.setStoreRootForTest(undefined)
    } finally {
      setStoreRootForTest(undefined)
    }
  })
})
