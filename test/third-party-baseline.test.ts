import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { checkThirdPartyBaseline } from '../lib/guards/internal-plugin.js'
import { setBaselineDirForTest, computePackageHash } from '../lib/guards/content-baseline.js'

function fakeStatus() {
  const records: { id: string; severity: string; kind: string; message: string }[] = []
  return {
    records,
    record: (r: { id: string; severity: string; kind: string; message: string }) => { records.push(r) },
  } as never
}

function makePkg(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-tpb-'))
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0' }))
  writeFileSync(join(dir, 'index.js'), 'module.exports = {} // v1\n')
  return dir
}

describe('Phase 4.2 第三方安装后完整性基线（P7 强化，round-13）', () => {
  let dirs: string[] = []
  let baselineDir: string | undefined
  afterEach(() => {
    for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }) } catch {} }
    dirs = []
    setBaselineDirForTest(undefined)
    baselineDir = undefined
  })
  beforeEach(() => {
    baselineDir = mkdtempSync(join(tmpdir(), 'vet-tpb-base-'))
    dirs.push(baselineDir)
    setBaselineDirForTest(baselineDir)
  })

  const cfg = (extra: Record<string, unknown> = {}) => ({
    thirdPartyBaseline: true,
    acknowledgedPackageHashes: {},
    ...extra,
  })

  it('默认关：thirdPartyBaseline=false → 恒 ok', () => {
    const pkg = makePkg('third-test-pkg')
    dirs.push(pkg)
    expect(checkThirdPartyBaseline('third-test-pkg', pkg, '1.0.0', cfg({ thirdPartyBaseline: false }) as never)).toBe('ok')
  })

  it('首装 first-seen 记录；内容不变 match ok；篡改 mismatch red', () => {
    const pkg = makePkg('third-test-pkg')
    dirs.push(pkg)
    const status = fakeStatus()
    expect(checkThirdPartyBaseline('third-test-pkg', pkg, '1.0.0', cfg() as never, status)).toBe('first-seen')
    expect(status.records.length).toBe(0)
    expect(checkThirdPartyBaseline('third-test-pkg', pkg, '1.0.0', cfg() as never, status)).toBe('ok')
    // 篡改：同版本内容变化
    writeFileSync(join(pkg, 'index.js'), 'module.exports = {} // v1 TAMPERED\n')
    const r = checkThirdPartyBaseline('third-test-pkg', pkg, '1.0.0', cfg() as never, status)
    expect(r).toBe('mismatch')
    expect(status.records.some((rec: { kind: string; severity: string }) => rec.kind === 'baseline-mismatch' && rec.severity === 'red')).toBe(true)
  })

  it('acknowledgedPackageHashes 豁免：登记哈希 → acknowledged yellow，不红', () => {
    const pkg = makePkg('third-test-pkg2')
    dirs.push(pkg)
    const status = fakeStatus()
    expect(checkThirdPartyBaseline('third-test-pkg2', pkg, '1.0.0', cfg() as never, status)).toBe('first-seen')
    writeFileSync(join(pkg, 'index.js'), 'module.exports = {} // v1 PATCHED\n')
    // 先拿不带豁免的结果确定哈希路径：改用"登记任意哈希前先算一次"——直接断言无豁免时 mismatch
    expect(checkThirdPartyBaseline('third-test-pkg2', pkg, '1.0.0', cfg() as never, status)).toBe('mismatch')
    // 现在登记当前哈希 → acknowledged
    const hash = computePackageHash(pkg, { maxFiles: 1000, maxSizeBytes: 50 * 1024 * 1024, timeoutMs: 10_000 })!.hash
    const ack = cfg({ acknowledgedPackageHashes: { 'third-test-pkg2@1.0.0': [hash] } })
    const r = checkThirdPartyBaseline('third-test-pkg2', pkg, '1.0.0', ack as never, status)
    expect(r).toBe('acknowledged')
    expect(status.records.some((rec: { kind: string; severity: string }) => rec.kind === 'baseline-patch-ack' && rec.severity === 'yellow')).toBe(true)
  })
})