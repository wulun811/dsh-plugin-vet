/**
 * round-16 批次 2 回归（运行时 + 安全修复）：
 * - SA2-2：spawn 相对敏感裸 token 组合判定（rm -rf .ssh；cp/mv 排除防备份误报）
 * - SA2-3：status 环形缓冲裁剪保护红色报警
 * - SA2-4/5：confirm-block 成对路径目标侧覆盖凭据 + open 写标志
 * - SA2-7：capability-diff 观测集/插件数上限
 * - SEC-4：scan-summaries records 键劫持防护（__proto__/constructor）
 * - SEC-5：writeTmpExclusive 排他落盘（预置符号链接不跟随、victim 不被写穿）
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, readFileSync, lstatSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { classifyOp } from '../lib/guard/runtime-classify.js'
import { DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { VetStatus } from '../lib/guard/status.js'
import { decideBlock, setCredentialHomeForTest } from '../lib/guard/confirm-block.js'
import { recordScanSummary, getScanSummary, listRecentScanSummaries, setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { writeTmpExclusive } from '../lib/guard/path-utils.js'
import { capabilityDiff } from '../lib/guard/capability-diff.js'

const YELLOW = (id: string) => ({ id, severity: 'yellow' as const, source: 't2' as const, kind: 'k', message: id, at: Date.now() })

/** 符号链接能力探针：Windows 无开发者模式/非管理员时 symlinkSync 抛 EPERM——
 * 该环境无法物化「预置 symlink」场景，跳过对应用例（CI 特权 runner 与 POSIX 照常执行）。
 * 不用 skipIf(win32)：Windows CI 具备符号链接能力时不应丢覆盖。 */
const canSymlink = ((): boolean => {
  const d = mkdtempSync(join(tmpdir(), 'vet-symprobe-'))
  try {
    symlinkSync(join(d, 'a'), join(d, 'b'))
    return true
  } catch {
    return false
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
})()

describe('SA2-2：spawn 相对敏感裸 token（破坏头 rm/shred/…；cp/mv 排除）', () => {
  it('spawn("rm", ["-rf", ".ssh"]) → spawn 报警（裸相对敏感名此前漏报）', () => {
    const alarm = classifyOp({ module: 'child_process', op: 'spawn', args: ['rm', ['-rf', '.ssh']] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).not.toBeNull()
    expect(alarm!.kind).toBe('spawn')
  })

  it('exec("rm -rf id_rsa") 全字符串形态 → spawn 报警', () => {
    const alarm = classifyOp({ module: 'child_process', op: 'exec', args: ['rm', '-rf', 'id_rsa'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).not.toBeNull()
  })

  it('非敏感裸名（rm -rf .git）→ 不报警（保持常规清理零误报）', () => {
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['rm', ['-rf', '.git']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('cp/mv 裸敏感名（cp id_rsa.pub backup/）→ 不报警（备份形态误报护栏）', () => {
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['cp', ['-r', 'id_rsa.pub', 'backup']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['mv', ['id_rsa.pub', 'backup']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })
})

describe('SA2-3：status 环形缓冲裁剪保护红色报警', () => {
  it('黄色风暴不挤出红色（red 仍存活且缓冲 = alarmMax）', () => {
    const s = new VetStatus({ alarmMax: 3 })
    s.record({ id: 'red-1', severity: 'red', source: 't2', kind: 'k', message: 'red', at: Date.now() })
    for (const id of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) s.record(YELLOW(id))
    const snap = s.snapshot()
    expect(snap.alarms.some(a => a.id === 'red-1')).toBe(true)
    expect(snap.alarms.length).toBe(3)
    expect(snap.level).toBe('red')
  })

  it('全红风暴仍可收容新报警（退让最旧一条，无活锁）', () => {
    const s = new VetStatus({ alarmMax: 2 })
    for (const id of ['x', 'y', 'z']) {
      s.record({ id, severity: 'red', source: 't2', kind: 'k', message: id, at: Date.now() })
    }
    expect(s.snapshot().alarms.length).toBe(2)
  })
})

describe('SA2-4/5：confirm-block 成对路径目标侧 + open 写标志（族 2）', () => {
  let dir = ''
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), '.n7-pair-'))
    setCredentialHomeForTest(dir)  // 凭据清单基准覆写（与 n7-confirm-block 同款纪律）
  })
  afterEach(() => {
    setCredentialHomeForTest(undefined)
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* 清理失败不影响结果 */ }
  })

  it('copyFile/cp 目标侧 = 已存在凭据 → 族 2 拦截（src 侧是普通文件不拦）', () => {
    const npmrc = join(dir, '.npmrc')
    writeFileSync(npmrc, 'old')
    const d = decideBlock('evil', 'copyFile', ['/tmp/src', npmrc])
    expect(d?.family).toBe(2)
    expect(decideBlock('evil', 'cpSync', ['/tmp/src', npmrc])?.family).toBe(2)
    // 目标不存在的凭据形态（新建，可逆）→ 不拦
    expect(decideBlock('evil', 'copyFileSync', ['/tmp/src', join(dir, '.ssh', 'id_ed25519')])).toBeNull()
    // 源侧是凭据、目标普通文件：copyFile 不是 DESTROY_OPS，dst 非凭据 → 族 2 不触发
    expect(decideBlock('evil', 'copyFile', [npmrc, '/tmp/out'])).toBeNull()
  })

  it('rename 目标侧 = 已存在凭据 → 族 2 拦截', () => {
    const npmrc = join(dir, '.npmrc')
    writeFileSync(npmrc, 'old')
    expect(decideBlock('evil', 'rename', ['/tmp/src', npmrc])?.family).toBe(2)
  })

  it('open/openSync 写标志指向已存在凭据 → 族 2；只读标志 → 不拦', () => {
    const npmrc = join(dir, '.npmrc')
    writeFileSync(npmrc, 'old')
    expect(decideBlock('evil', 'open', [npmrc, 'w'])?.family).toBe(2)
    expect(decideBlock('evil', 'openSync', [npmrc, 'w+'])?.family).toBe(2)
    expect(decideBlock('evil', 'open', [npmrc, 'r'])).toBeNull()
    expect(decideBlock('evil', 'openSync', [npmrc, 'rs'])).toBeNull()
    // 'r+' = 读写句柄（含写能力，与 runtime-classify 同款 /[wax+]/ 语义）→ 族 2
    expect(decideBlock('evil', 'open', [npmrc, 'r+'])?.family).toBe(2)
    // 开辟式 wx：目标已存在时 open 本就失败，不构成覆盖写拦截面（新文件形态可逆不拦）
    expect(decideBlock('evil', 'open', [npmrc, 'wx'])).not.toBeNull() // 已存在 + 写标志 → 族 2（与覆盖读语义一致）
  })
})

describe('SA2-7：capability-diff 观测集上限', () => {
  afterEach(() => {
    // 单例无公开清空 API——测试包名隔离，互不污染
  })

  it('每（插件×类别）观测值上限 128（超出淘汰最旧）', () => {
    capabilityDiff.registerStatic('cap-cap-p', { imports: [], hasNetwork: false, hosts: [], hasExec: false, spawnCmds: [], fsPaths: [] })
    for (let i = 0; i < 300; i++) capabilityDiff.observeAndCheck({ plugin: 'cap-cap-p', kind: 'spawn', value: 'cmd-' + i })
    expect(capabilityDiff.observedSets('cap-cap-p').spawn.length).toBe(128)
    // 最旧 172 个被淘汰：'cmd-0' 已不在窗口内
    expect(capabilityDiff.observedSets('cap-cap-p').spawn).toContain('cmd-299')
    expect(capabilityDiff.observedSets('cap-cap-p').spawn).not.toContain('cmd-0')
  })

  it('插件数上限 200（超出淘汰最旧插件整行）', () => {
    for (let i = 0; i < 220; i++) {
      capabilityDiff.registerStatic('cap-plug-' + i, { imports: [], hasNetwork: false, hosts: [], hasExec: false, spawnCmds: [], fsPaths: [] })
      capabilityDiff.observeAndCheck({ plugin: 'cap-plug-' + i, kind: 'net', value: 'h' + i })
    }
    // 最旧 20 个被整体淘汰；最新 200 个保留
    expect(capabilityDiff.observedSets('cap-plug-0').net.length).toBe(0)
    expect(capabilityDiff.observedSets('cap-plug-219').net.length).toBe(1)
  })
})

describe('SEC-4：scan-summaries records 键劫持防护', () => {
  let dir = ''
  afterEach(() => {
    setSummariesDirForTest(undefined)
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* 清理失败不影响结果 */ }
  })

  it('__proto__/constructor/prototype 插件名写入读取一致，不污染原型', () => {
    dir = mkdtempSync(join(tmpdir(), '.sum-sec4-'))
    setSummariesDirForTest(dir)
    const at = Date.now()
    recordScanSummary({ name: '__proto__', verdict: 'clean', staticScore: 10, at, ruleCodes: [] })
    recordScanSummary({ name: 'constructor', verdict: 'suspicious', staticScore: 55, at, ruleCodes: ['R1'] })
    recordScanSummary({ name: 'prototype', verdict: 'clean', staticScore: 12, at, ruleCodes: [] })
    expect(getScanSummary('__proto__')?.verdict).toBe('clean')
    expect(getScanSummary('constructor')?.verdict).toBe('suspicious')
    expect(getScanSummary('prototype')?.verdict).toBe('clean')
    // 列表侧（Object.values）不因原型污染多出条目
    expect(listRecentScanSummaries(10).length).toBe(3)
  })
})

describe('SEC-5：writeTmpExclusive 排他落盘（预置符号链接不跟随）', () => {
  it.skipIf(!canSymlink)('预置 symlink 指向 victim：写入不穿链接，victim 内容不变，tmp 为全新普通文件', () => {
    const dir = mkdtempSync(join(tmpdir(), '.wx-sec5-'))
    try {
      const victim = join(dir, 'victim')
      writeFileSync(victim, 'keep')
      const tmp = join(dir, 'x.tmp.424242')
      symlinkSync(victim, tmp)
      writeTmpExclusive(tmp, 'data', 0o600)
      expect(readFileSync(victim, 'utf8')).toBe('keep')
      expect(readFileSync(tmp, 'utf8')).toBe('data')
      expect(lstatSync(tmp).isSymbolicLink()).toBe(false)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('普通 EEXIST（崩溃残留 tmp）→ unlink 后重试成功', () => {
    const dir = mkdtempSync(join(tmpdir(), '.wx-retry-'))
    try {
      const tmp = join(dir, 'y.tmp.777')
      writeFileSync(tmp, 'stale')
      writeTmpExclusive(tmp, 'fresh', 0o600)
      expect(readFileSync(tmp, 'utf8')).toBe('fresh')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
describe('round-22：T2 观测面参数上限（防「单串复用循环」观测放大）', () => {
  it('firstString/allStrings/pathArgValue 超长实参按 MAX_ARG_CHARS 截断', async () => {
    const { firstString, allStrings, pathArgValue, MAX_ARG_CHARS, joinCapped } = await import('../lib/guard/runtime-denoise.js')
    const giant = 'a'.repeat(MAX_ARG_CHARS * 2)
    expect(firstString([giant])!.length).toBe(MAX_ARG_CHARS)
    expect(firstString([giant])).toBe('a'.repeat(MAX_ARG_CHARS))
    // Buffer 路径形态同样有界（旧实现会把整块 Buffer utf8 解码进内存）
    const asPath = pathArgValue(Buffer.alloc(MAX_ARG_CHARS * 2, 'b'))
    expect(asPath!.length).toBe(MAX_ARG_CHARS)
    expect(asPath).toBe('b'.repeat(MAX_ARG_CHARS))
    // 参数数组（spawn argv 递归展开）逐元素截断
    const all = allStrings(['x', [giant], ['y']])
    expect(all.length).toBe(3)
    expect(all[1].length).toBe(MAX_ARG_CHARS)
  })

  it('joinCapped：总长封顶且保前缀（元素数 × 单参长均可放大时不再无界）', async () => {
    const { joinCapped } = await import('../lib/guard/runtime-denoise.js')
    const parts = ['bash', '-c', 'echo head', 'x'.repeat(10_000), 'y'.repeat(10_000)]
    const full = joinCapped(parts, 4096)
    expect(full.length).toBeLessThanOrEqual(4096)
    expect(full.startsWith('bash -c echo head')).toBe(true) // 前缀（命令头检测面）保留
    expect(joinCapped(['a'], 100)).toBe('a')
  })

  it('classifyOp：巨型命令实参不抛错、不产生假报警；恶意前缀仍在检测面内', async () => {
    const { classifyOp } = await import('../lib/guard/runtime-classify.js')
    const cfg = (await import('../lib/guard/runtime-hooks.js')).DEFAULT_HOOK_CONFIG
    // 巨型但无敏感内容（非 shell 命令；bash 等 shell 令牌本身必报警，不属此断言）：旧实现
    // 全量正则扫描（每事件 O(输入)），新实现有界后快速返回 null
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['node', ['-e', 'a'.repeat(2_000_000)]] }, cfg)).toBeNull()
    // 恶意前缀（破坏命令 + 敏感路径）在截断窗口内 → 照常报警（检测面不因截断丢失）
    const evil = 'rm -rf /home/u/.ssh ' + 'a'.repeat(2_000_000)
    const alarm = classifyOp({ module: 'child_process', op: 'exec', args: ['bash', '-c', evil] }, cfg)
    expect(alarm).not.toBeNull()
    expect(alarm!.kind).toBe('spawn')
    // fs 面：巨型路径（必然 ENAMETOOLONG）截断后照常判定（敏感前缀命中）
    const p = classifyOp({ module: 'fs', op: 'writeFileSync', args: ['/home/u/.ssh/' + 'a'.repeat(2_000_000), 'x'] }, cfg)
    expect(p).not.toBeNull()
    expect(p!.kind).toBe('fs-write')
  })
})
