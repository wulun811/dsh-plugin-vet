
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { arm, record, isArmed, resetForensics, setForensicsDirForTest, forensicsRoot } from '../lib/guard/forensics.js'

describe('P0-2 取证模式（forensics）', () => {
  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-forensics-'))
    resetForensics()
    setForensicsDirForTest(testDir)
  })

  afterEach(() => {
    setForensicsDirForTest(undefined)
    resetForensics()
    rmSync(testDir, { recursive: true, force: true })
  })

  it('arm 前 record 是 no-op（不建桶不落盘）', () => {
    record('@x/p', { module: 'fs', op: 'readFileSync', target: '/etc/passwd' })
    expect(readdirSync(testDir)).toHaveLength(0)
  })

  it('arm 后写取证文件 + 记录微小操作（fail-open）', () => {
    arm('@x/p')
    expect(isArmed('@x/p')).toBe(true)
    record('@x/p', { module: 'fs', op: 'readFileSync', target: '/etc/shadow', sensitive: true })
    record('@x/p', { module: 'net', op: 'request', target: 'evil.com:443' })
    const files = readdirSync(testDir)
    expect(files.length).toBe(1)
    const path = join(testDir, files[0])
    const lines = readFileSync(path, 'utf8').trim().split('\n')
    // 首行是 forensics-start 标记
    expect(JSON.parse(lines[0]).kind).toBe('forensics-start')
    expect(JSON.parse(lines[0]).plugin).toBe('@x/p')
    // 后续是操作记录
    const evt1 = JSON.parse(lines[1])
    expect(evt1.op).toBe('readFileSync')
    expect(evt1.target).toBe('/etc/shadow')
    expect(evt1.sensitive).toBe(true)
    const evt2 = JSON.parse(lines[2])
    expect(evt2.op).toBe('request')
    expect(evt2.target).toBe('evil.com:443')
  })

  it('未武装插件的 record 不落盘（选择性取证）', () => {
    arm('@bad/one')
    record('@innocent/two', { module: 'fs', op: 'writeFileSync', target: '/tmp/x' })
    const files = readdirSync(testDir)
    expect(files.length).toBe(1)
    const content = readFileSync(join(testDir, files[0]), 'utf8')
    expect(content).not.toContain('@innocent/two')
  })

  it('arm 幂等：重复 arm 只落一次 start 标记', () => {
    arm('@x/p')
    arm('@x/p')
    const files = readdirSync(testDir)
    const content = readFileSync(join(testDir, files[0]), 'utf8')
    expect(content.trim().split('\n').length).toBe(1)
  })

  it('resetForensics 清空武装集（测试/热重载隔离）；record 不再追加（已落盘文件保留）', () => {
    arm('@x/p')
    resetForensics()
    expect(isArmed('@x/p')).toBe(false)
    const before = readdirSync(testDir)
    expect(before.length).toBe(1) // arm 时落盘的 forensics-start 标记保留（内存重置不删盘）
    record('@x/p', { module: 'fs', op: 'rmSync', target: '/etc/passwd' })
    // 未武装 → record no-op，文件内容不再增长
    expect(readdirSync(testDir)).toHaveLength(1)
    expect(readFileSync(join(testDir, before[0]), 'utf8').trim().split('\n').length).toBe(1)
  })

  it('forensicsRoot 用测试覆盖目录', () => {
    expect(forensicsRoot()).toBe(testDir)
  })

  it('写盘失败 fail-open：锁目录不存在空跑不抛错', () => {
    expect(() => record('@x/p', { module: 'fs', op: 'x' })).not.toThrow()
  })
})
