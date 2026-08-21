
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  recordScan,
  label,
  capabilitiesPath,
  setCapabilitiesDirForTest,
  type CapabilityManifest,
} from '../lib/guard/version-diff.js'

const manifest = (o: Partial<CapabilityManifest> = {}): CapabilityManifest => ({
  hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, ...o,
})

describe('M2：vet_label 营养标签查询（只读本地能力清单历史）', () => {
  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-label-'))
    setCapabilitiesDirForTest(testDir)
  })

  afterEach(() => {
    setCapabilitiesDirForTest(undefined)
    rmSync(testDir, { recursive: true, force: true })
  })

  it('无任何本地记录 → present=false，友好提示（不抛错）', () => {
    const v = label('@never/scanned')
    expect(v.present).toBe(false)
    expect(v.latest).toBeNull()
    expect(v.manifest).toBeNull()
    expect(v.note).toContain('尚未被 vet 自动扫描')
  })

  it('冷启动单条记录 → present=true，manifest 正确，无升级差分', () => {
    recordScan('@x/p', '1.0.0', manifest({
      hosts: ['api.github.com'], fsPaths: ['src/', '~/.aws/credentials'],
      spawnCmds: ['git'], imports: ['axios'], hasNetwork: true,
    }))
    const v = label('@x/p')
    expect(v.present).toBe(true)
    expect(v.latest).toBe('1.0.0')
    expect(v.manifest?.hosts).toEqual(['api.github.com'])
    expect(v.manifest?.fsPaths).toEqual(['src/', '~/.aws/credentials'])
    expect(v.manifest?.spawnCmds).toEqual(['git'])
    expect(v.manifest?.imports).toEqual(['axios'])
    expect(v.manifest?.hasNetwork).toBe(true)
    expect(v.diffSummary).toBeNull()
    expect(v.note).toContain('仅一条版本记录')
  })

  it('多版本 → 取 recordedAt 最晚者为最新清单，并产出升级差分摘要', () => {
    recordScan('@x/p', '1.0.0', manifest({ hosts: ['old.com'] }))
    recordScan('@x/p', '1.0.1', manifest({ hosts: ['old.com', 'evil-cdn.com'], hasExec: true }))
    const v = label('@x/p')
    expect(v.latest).toBe('1.0.1')
    expect(v.manifest?.hosts).toContain('evil-cdn.com')
    expect(v.manifest?.hasExec).toBe(true)
    expect(v.diffSummary?.from).toBe('1.0.0')
    expect(v.diffSummary?.to).toBe('1.0.1')
    expect(v.diffSummary?.added).toContain('网络主机 evil-cdn.com')
    expect(v.diffSummary?.added).toContain('执行能力')
  })

  it('ESM 具名导入盲区标记传入 manifest（esmNamedBuiltins）', () => {
    recordScan('@x/p', '1.0.0', manifest({ esmNamedBuiltins: true }))
    expect(label('@x/p').manifest?.esmNamedBuiltins).toBe(true)
  })

  it('存储损坏 → fail-open，present=false，不抛错（降级为空记录）', () => {
    // loadCapabilities 对损坏 JSON 返回空 store，label 因此得到"无记录"——fail-open、不抛错
    writeFileSync(capabilitiesPath(), '{broken', 'utf8')
    const v = label('@x/p')
    expect(v.present).toBe(false)
    expect(v.manifest).toBeNull()
    expect(v.note).toContain('尚未被 vet 自动扫描')
  })
})
