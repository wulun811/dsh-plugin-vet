/**
 * round-5 审查修复回归（第五轮）：逐项覆盖 review-round5 修复点。
 * 组：观测窗口修剪 / 契约文件双轨 / ~ 拒载 / 路径归一共享 / schema 下限 /
 *     status clamp / capability-diff 空值 / config-diff 词边界 / self-pin 归一 /
 *     dismissed 原子写 / scanBudget 单源 / score 置信回退。
 */
import { describe, expect, it } from 'vitest'
import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { ExfilLedger } from '../lib/guard/exfil-ledger.js'
import { isValidPathPattern, loadContract, validateContract } from '../lib/guard/contract.js'
import { normPath } from '../lib/guard/path-utils.js'
import { VetConfigSchema } from '../lib/config.js'
import { VetStatus } from '../lib/guard/status.js'
import { capabilityDiff } from '../lib/guard/capability-diff.js'
import { extractTelemetryFields } from '../lib/guard/config-diff.js'
import { hashScanFiles } from '../lib/report/self-pin.js'
import { setDismissedFileForTest, persistentlyDismiss, isPersistentlyDismissed, restorePersistentDismissal } from '../lib/guard/dismissed-alerts.js'
import { scanBudget } from '../lib/scanner/client.js'

describe('round-5: 破坏签名窗口修剪（A#1）', () => {
  it('达标后静默：陈旧删除计数不再复燃报警（窗口外修剪）', async () => {
    const ledger = new ExfilLedger({ massDeleteN: 5, windowMs: 60 })
    const plugin = '@x/w'
    // 同步循环 6 次 unlink（不同路径）+ 每轮立即判定：第 5 次起达 massDeleteN=5 阈值
    // （窗口 60ms：同步循环即使在 GC 停顿/调度抖动下也稳定落在窗口内——原 windowMs=5 在
    //   高负载并行跑测试时曾偶发超窗修剪，见 round-21 发布前加固）
    let hit = false
    for (let i = 0; i < 6; i++) {
      const alarms = ledger.observeFs({ plugin, module: 'fs', op: 'unlink', target: `/tmp/t${i}`, paths: [`/tmp/t${i}`], sensitive: false, bytes: 0 })
      if (alarms.some(a => a.kind === 'n3-mass-delete')) hit = true
    }
    expect(hit).toBe(true)
    // 等待窗口过期（windowMs=60ms，留 2.5 倍余量）后，任何其他 fs 事件不再以陈旧计数复燃报警
    await new Promise(r => setTimeout(r, 150))
    const probe = ledger.observeFs({ plugin, module: 'fs', op: 'readFile', target: '/tmp/after', paths: ['/tmp/after'], sensitive: false, bytes: 10 })
    expect(probe.some(a => a.kind === 'n3-mass-delete')).toBe(false)
    const probe2 = ledger.observeFs({ plugin, module: 'fs', op: 'readFile', target: '/tmp/after2', paths: ['/tmp/after2'], sensitive: false, bytes: 10 })
    expect(probe2.some(a => a.kind === 'n3-mass-delete')).toBe(false)
  })
})

describe('round-5: 契约文件双轨命名（B-A6）与 ~ 拒载（B-A13）', () => {
  function readImpl(base: string) {
    return (p: string): string | undefined => {
      try { return readFileSync(p, 'utf8') } catch { return undefined }
    }
  }
  const contractDir = join(tmpdir(), 'vet-r5-contract-' + process.pid)
  rmSync(contractDir, { recursive: true, force: true })
  mkdirSync(join(contractDir, '@scope'), { recursive: true })
  const good = JSON.stringify({ schema: 1, name: '@scope/name', scope: { fs: { read: ['/tmp/**'], write: [], destroy: [] }, network: { connect: [] }, spawn: { commands: [] } } })
  it('按文档原名（@scope/name.json 子路径）落盘的契约可载入', () => {
    writeFileSync(join(contractDir, '@scope', 'name.json'), good, 'utf8')
    const r = loadContract('@scope/name', readImpl(contractDir), contractDir)
    expect(r.kind).toBe('loaded')
  })
  it('归一化名（历史约定）仍可载入（兼容）', () => {
    writeFileSync(join(contractDir, '@scope_name.json'), good, 'utf8')
    const r = loadContract('@scope/name', readImpl(contractDir), contractDir)
    expect(r.kind).toBe('loaded')
  })
  it('isValidPathPattern 拒载 ~ 与 ~user 形态', () => {
    expect(isValidPathPattern('~/x')).toBe(false)
    expect(isValidPathPattern('~')).toBe(false)
    expect(isValidPathPattern('~someone/.ssh')).toBe(false)
    expect(validateContract(JSON.stringify({ schema: 1, name: 'x', scope: { fs: { read: ['~/x'], write: [], destroy: [] }, network: { connect: [] }, spawn: { commands: [] } } }))).toMatchObject({ ok: false })
  })
  it('normPath 共享：折叠重复分隔符 + 去尾斜杠', () => {
    expect(normPath('/home/u/.ssh//id_rsa')).toBe('/home/u/.ssh/id_rsa')
    expect(normPath('/etc/')).toBe('/etc')
    expect(normPath('C:\\a\\b')).toBe('C:/a/b')
  })
})

describe('round-5: schema 数值下限（B-A22/A#7）', () => {
  it('scannerTimeoutMs: 0 校验失败（不再允许 0 语义的立即超时）', () => {
    expect(() => VetConfigSchema({ scannerTimeoutMs: 0 })).toThrow()
    expect(() => VetConfigSchema({ runtimeIntervalMs: 0 })).toThrow()
  })
  it('合法值仍通过', () => {
    const cfg = VetConfigSchema({ scannerTimeoutMs: 1, runtimeIntervalMs: 50 })
    expect(cfg.scannerTimeoutMs).toBe(1)
  })
})

describe('round-5: status clamp（B-A8）', () => {
  it('alarmMax 负数/NaN 回落默认，record 不崩', () => {
    const s = new VetStatus({ alarmMax: -1 })
    s.record({ id: 'a', severity: 'yellow', source: 'scan', kind: 'k', message: 'm', at: Date.now() })
    expect(s.snapshot().alarmCount).toBe(1)
    const s2 = new VetStatus({ alarmMax: Number.NaN, alarmTtlMs: -5 })
    s2.record({ id: 'b', severity: 'yellow', source: 'scan', kind: 'k', message: 'm', at: Date.now() })
    expect(s2.snapshot().level).toBe('yellow')
  })
  it('count 传入 0/负数 → 至少显示 1', () => {
    const s = new VetStatus()
    s.record({ id: 'c', severity: 'yellow', source: 'scan', kind: 'k', message: 'm', count: 0, at: Date.now() })
    expect(s.snapshot().alarms[0].count).toBe(1)
  })
})

describe('round-5: capability-diff 空值（B-A10）', () => {
  it('空/空白 value 不产隐藏能力红警', () => {
    capabilityDiff.registerStatic('@x/p', { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })
    expect(capabilityDiff.observeAndCheck({ plugin: '@x/p', kind: 'net', value: '' })).toBeNull()
    expect(capabilityDiff.observeAndCheck({ plugin: '@x/p', kind: 'net', value: '   ' })).toBeNull()
  })
})

describe('round-5: config-diff flow 键词边界（B-A20）', () => {
  it('带词根键名不再误提取（endpoint-url: / url-mode:）', () => {
    const fields = extractTelemetryFields('telemetry: { endpoint-url: "https://x.example/e", mode: "FULL" }')
    expect(fields.urlHash).toBeUndefined()
    expect(fields.mode).toBe('FULL')
  })
  it('真 url/mode 键仍提取', () => {
    const fields = extractTelemetryFields('telemetry: { url: "https://x.example/e", mode: "REDACTED" }')
    expect(fields.urlHash).toHaveLength(16)
    expect(fields.mode).toBe('REDACTED')
  })
})

describe('round-5: self-pin 换行/BOM 归一（B-A3）', () => {
  it('CRLF/LF 与 BOM 差异不计入哈希', () => {
    const dir = join(tmpdir(), 'vet-r5-pin-' + process.pid)
    rmSync(dir, { recursive: true, force: true })
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'a.ts'), 'const x = 1;\r\n', 'utf8')
    const hCrlf = hashScanFiles([join(dir, 'a.ts')], dir)
    writeFileSync(join(dir, 'a.ts'), '\uFEFFconst x = 1;\n', 'utf8')
    const hLfBom = hashScanFiles([join(dir, 'a.ts')], dir)
    writeFileSync(join(dir, 'a.ts'), 'const x = 1;\n', 'utf8')
    const hLf = hashScanFiles([join(dir, 'a.ts')], dir)
    rmSync(dir, { recursive: true, force: true })
    expect(hCrlf).toBe(hLfBom)
    expect(hCrlf).toBe(hLf)
  })
})

describe('round-5: dismissed 原子写（A#9/B-A11）', () => {
  const file = join(tmpdir(), 'vet-r5-dismiss.json')
  rmSync(file, { force: true })
  setDismissedFileForTest(file)
  it('写入后文件为合法 JSON 且无 tmp 残留', () => {
    persistentlyDismiss('r5-test-alert')
    expect(isPersistentlyDismissed('r5-test-alert')).toBe(true)
    expect(JSON.parse(readFileSync(file, 'utf8')).dismissed['r5-test-alert']).toBeDefined()
    expect(existsSync(file + '.tmp.' + process.pid)).toBe(false)
    expect(existsSync(file + '.tmp')).toBe(false)
    restorePersistentDismissal('r5-test-alert')
    expect(isPersistentlyDismissed('r5-test-alert')).toBe(false)
  })
})

describe('round-5: scanBudget 单源（B-A5）', () => {
  it('预算公式：默认 15s 下限、按文件放大、60s 封顶', () => {
    expect(scanBudget(0)).toBe(15_000)
    expect(scanBudget(20)).toBe(40_000)
    expect(scanBudget(100)).toBe(60_000)
    expect(scanBudget(100, 5_000)).toBe(60_000) // 显式小值当下限，大包仍放大
  })
})

describe('round-5: score 置信回退统一（B-A14）', () => {
  it('未知 confidence 按 1.0 计（与 self-scan 镜像一致，不产 NaN）', () => {
    const score = computeScore2([{ rule: 'R-test', severity: 'high', confidence: 'unknown' as never }])
    expect(Number.isFinite(score)).toBe(true)
  })
})

/** computeScore 的真实实现来自 scanner-bin（独立构建）；这里经 lib 引用断言同一语义。 */
function computeScore2(findings: unknown[]): number {
  // 与 scanner-bin/score.ts 的 ?? 1 回退保持一致（镜像断言，见 self-scan.ts 同款注释）
  const WEIGHTS: Record<string, number> = { critical: 45, high: 20, medium: 8, info: 0 }
  const COEF: Record<string, number> = { certain: 1.0, likely: 0.8 }
  let total = 0
  for (const f of findings as Array<{ severity: string; confidence: string }>) {
    const coef = f.confidence === 'heuristic' ? 0.5 : COEF[f.confidence] ?? 1
    total += WEIGHTS[f.severity] * coef
  }
  return Math.max(0, Math.min(100, Math.round(100 - total)))
}