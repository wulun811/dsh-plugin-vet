import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isKnownBoundary, markKnownBoundary, setKnownBoundariesDirForTest, knownBoundariesPath } from '../lib/guard/known-boundaries.js'

/**
 * P3（0.3.3 用户警报疲劳反馈）：coverage 类边界提示的持久化状态化去重。
 * (kind, pkg, version, capabilitiesHash) 落盘——版本/能力未变不重报；任意变化即
 * 自动吊销（重新报警）；fail-open：存储不可写/损坏 → 按未知处理（宁可重复提示，
 * 不可静默失明）。
 */
describe('known-boundaries（P3 状态化去重）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-known-'))
    setKnownBoundariesDirForTest(dir)
  })
  afterEach(() => {
    setKnownBoundariesDirForTest(undefined)
    rmSync(dir, { recursive: true, force: true })
  })

  it('未记录 → false；mark 后同 (version, hash) → true', () => {
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(false)
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(true)
  })

  it('版本变化 → 自动吊销（false，重报）', () => {
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '2.0.0', 'abc')).toBe(false)
  })

  it('能力差分变化（capabilitiesHash 变）→ 自动吊销（N6 同变化源）', () => {
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abd')).toBe(false)
  })

  it('kind 隔离：同包不同 kind 互不影响', () => {
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    expect(isKnownBoundary('other-kind', '@x/p', '1.0.0', 'abc')).toBe(false)
  })

  it('跨进程持久化：重读盘（同一目录新模块实例语义）仍已知', () => {
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    // 直接读盘验证落盘内容，再模拟「新进程」重载（路径相同 → loadStore 重读）
    expect(existsSync(knownBoundariesPath())).toBe(true)
    const raw = JSON.parse(readFileSync(knownBoundariesPath(), 'utf8'))
    expect(raw.records['esm-guard-coverage:@x/p'].version).toBe('1.0.0')
    expect(raw.records['esm-guard-coverage:@x/p'].firstAt).toBeGreaterThan(0)
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(true)
    // mark 刷新（能力同但重报过一次）保持 firstAt、刷新 lastAt
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    const raw2 = JSON.parse(readFileSync(knownBoundariesPath(), 'utf8'))
    expect(raw2.records['esm-guard-coverage:@x/p'].firstAt).toBe(raw.records['esm-guard-coverage:@x/p'].firstAt)
    expect(raw2.records['esm-guard-coverage:@x/p'].lastAt).toBeGreaterThanOrEqual(raw.records['esm-guard-coverage:@x/p'].lastAt)
  })

  it('损坏/残缺记录丢弃（fail-open → 未知，不静默）', () => {
    markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')
    // 手工破坏：缺 capabilitiesHash → 该条目被丢弃，判定回未知
    const path = knownBoundariesPath()
    const store = JSON.parse(readFileSync(path, 'utf8'))
    delete store.records['esm-guard-coverage:@x/p'].capabilitiesHash
    writeFileSync(path, JSON.stringify(store))
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(false)
    // 文件整体损坏 → 空库（未知）
    writeFileSync(path, '{oops')
    expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(false)
  })

  it.skipIf(process.platform === 'win32')('写失败静默：下次按未知处理（安全方向：宁可重复提示，不可静默）', () => {
    // 只读目录（无写权限）→ mark 不抛、isKnown 恒 false。
    // Windows：POSIX 权限位不生效（chmod 0o500 不真正移除写权限），仅 POSIX 可测。
    const ro = join(dir, 'ro')
    mkdirSync(ro, { recursive: true })
    chmodSync(ro, 0o500)
    try {
      setKnownBoundariesDirForTest(ro)
      expect(() => markKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).not.toThrow()
      expect(isKnownBoundary('esm-guard-coverage', '@x/p', '1.0.0', 'abc')).toBe(false)
    } finally {
      chmodSync(ro, 0o700)
      rmSync(ro, { recursive: true, force: true })
    }
  })

  it('空 version/hash → 拒绝记录与判定（防脏键）', () => {
    expect(isKnownBoundary('k', 'p', '', 'h')).toBe(false)
    expect(isKnownBoundary('k', 'p', 'v', '')).toBe(false)
    expect(() => markKnownBoundary('k', 'p', '', 'h')).not.toThrow()
    expect(isKnownBoundary('k', 'p', '1.0.0', 'xxx')).toBe(false)
  })
})