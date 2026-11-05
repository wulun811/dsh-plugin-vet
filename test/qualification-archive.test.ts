import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { probeQualification, setArchiveDirForTest } from '../lib/audit/archive.js'
import { computePackageHash } from '../lib/guards/content-baseline.js'
import { VetStatus } from '../lib/guard/status.js'
import type { VetConfig } from '../lib/config.js'

/**
 * 0.5.1 步骤 6 的验收之二：档案 → 资格 → 加载门槛。
 *
 * 这里要证的是**迁移不会造成大规模拒载**（施工图给的准出条件）：0.4.x 写下的档案没有内容摘要，
 * 升级后必须落 `qualified(basis=legacy)` 而不是 `unassessed`。同时要证新约定真的管用：
 * 档案声明了摘要而当前字节对不上时，不再「有文件就放行」。
 */

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report',
  autoScan: true,
  scannerTimeoutMs: 15_000,
  rules: {},
  denyOn: 'critical',
  allowlist: [],
  runtimeGuard: 'off',
  runtimeIntervalMs: 2000,
  runtimeMemLimitMb: 2048,
  runtimeForkBurstN: 5,
  runtimeFdLimit: 512,
  runtimeGrowthMb: 256,
  runtimeGrowthWindowMs: 600_000,
  contentBaseline: true,
  acknowledgedPackageHashes: {},
  thirdPartyBaseline: false,
  requireAudit: true,
  domainProjection: 'shadow',
  ...over,
})

class FakeCtx {
  handlers = new Map<string, ((fiber: unknown) => unknown)[]>()
  baseUrl: string
  logger = { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} }
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }
  on(event: string, handler: (fiber: unknown) => unknown): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

const NAME = '@acme/qual-fixture'
const files = `acme-qual-fixture-1.0.0-20260101-000000.md`

const dirs: string[] = []
function temp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  dirs.push(dir)
  return dir
}

function makePkg(profile: string): string {
  const pkg = join(profile, 'node_modules', '@acme', 'qual-fixture')
  mkdirSync(pkg, { recursive: true })
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: NAME, version: '1.0.0', main: 'index.js' }))
  writeFileSync(join(pkg, 'index.js'), 'module.exports = { ok: true }\n')
  return pkg
}

/** 假 fiber：deny 分支在抛错前会先 dispose，缺了它会掩盖真正的错误消息。 */
function fiber(uid: string): Record<string, unknown> {
  return { uid, entry: { options: { name: NAME } }, dispose: () => {} }
}

function writeArchive(dir: string, body: string): void {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, files), body)
}

/** 跑一次守卫。report 模式返回 promise（会真扫一遍），deny 模式在门槛处同步抛。 */
function run(profile: string, over: Partial<VetConfig> = {}): { status: VetStatus; done: unknown; listener: (f: unknown) => unknown } {
  const status = new VetStatus()
  const ctx = new FakeCtx(profile)
  installInternalPluginGuard(ctx as never, cfg(over), status)
  const listener = ctx.handlers.get('internal/plugin')![0]
  return { status, done: undefined, listener }
}

beforeEach(() => {
  setArchiveDirForTest(undefined)
})

afterAll(() => {
  setArchiveDirForTest(undefined)
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
})

describe('迁移：0.4.x 的旧档案不得造成拒载', () => {
  it('无摘要的老档案 → qualified(basis=legacy)，deny 模式不拦', async () => {
    const archive = temp('vet-qual-archive-')
    const profile = temp('vet-qual-prof-')
    makePkg(profile)
    writeArchive(archive, '# 健康档案\n\n审查结论：通过\n')
    setArchiveDirForTest(archive)

    const probe = probeQualification({ name: NAME, version: '1.0.0' })
    expect(probe.state.status).toBe('qualified')
    expect(probe.state.basis).toBe('legacy')

    // 迁移期最要紧的一条：deny 用户升级后，昨天的档案今天照样放行
    const { listener } = run(profile, { mode: 'deny' })
    expect(() => listener(fiber('f-legacy'))).not.toThrow()
  }, 60_000)

  it('没有档案 → unassessed → deny 拦截，消息说清「尚未完成审计」', () => {
    const archive = temp('vet-qual-archive-empty-')
    const profile = temp('vet-qual-prof-')
    makePkg(profile)
    setArchiveDirForTest(archive)

    expect(probeQualification({ name: NAME, version: '1.0.0' }).state.status).toBe('unassessed')
    const { listener } = run(profile, { mode: 'deny' })
    expect(() => listener(fiber('f-none'))).toThrow(/尚未完成审计/)
  })
})

describe('新约定：档案声明摘要后，字节对不上就不放行', () => {
  it('摘要一致 → qualified(basis=digest)', () => {
    const archive = temp('vet-qual-archive-hash-')
    const profile = temp('vet-qual-prof-')
    const pkg = makePkg(profile)
    const hash = computePackageHash(pkg)!.hash
    writeArchive(archive, `# 健康档案\n\nsubject_sha256: ${hash}\n审查结论：通过\n`)
    setArchiveDirForTest(archive)

    const probe = probeQualification({ name: NAME, version: '1.0.0', contentDigest: () => computePackageHash(pkg)?.hash })
    expect(probe.state.status).toBe('qualified')
    expect(probe.state.basis).toBe('digest')
  })

  it('摘要不一致 → recheck_required，deny 拦截且消息说明「档案不能用」而不是「没审过」', () => {
    const archive = temp('vet-qual-archive-drift-')
    const profile = temp('vet-qual-prof-')
    const pkg = makePkg(profile)
    writeArchive(archive, `# 健康档案\n\nsubject_sha256: ${'a'.repeat(64)}\n审查结论：通过\n`)
    setArchiveDirForTest(archive)

    const probe = probeQualification({ name: NAME, version: '1.0.0', contentDigest: () => computePackageHash(pkg)?.hash })
    expect(probe.state.status).toBe('recheck_required')

    const { listener } = run(profile, { mode: 'deny' })
    expect(() => listener(fiber('f-drift'))).toThrow(/不能作为当前放行依据/)
  })

  it('档案声明了摘要但算不出当前摘要（无根/超预算）→ 按旧档放行并记明理由，不因 IO 失败拒载', () => {
    const archive = temp('vet-qual-archive-nodigest-')
    writeArchive(archive, `# 健康档案\n\nsubject_sha256: ${'b'.repeat(64)}\n`)
    setArchiveDirForTest(archive)
    const probe = probeQualification({ name: NAME, version: '1.0.0' })
    expect(probe.state.status).toBe('qualified')
    expect(probe.state.basis).toBe('legacy')
    expect(probe.state.reasons).toContain('digest-unverifiable')
  })

  it('同版本多条档案取最新的一条（按文件名时间戳，18/19 位两种历史格式都排得对）', () => {
    const archive = temp('vet-qual-archive-multi-')
    mkdirSync(archive, { recursive: true })
    const oldHash = 'c'.repeat(64)
    writeFileSync(join(archive, 'acme-qual-fixture-1.0.0-20250101-000000.md'), `subject_sha256: ${oldHash}\n`)
    writeFileSync(join(archive, 'acme-qual-fixture-1.0.0-20260101-000000.md'), '审查结论：通过\n')
    setArchiveDirForTest(archive)
    const probe = probeQualification({ name: NAME, version: '1.0.0' })
    // 最新那条没有摘要 → legacy；若取错顺序会拿到旧的摘要 → 变成 recheck
    expect(probe.state.basis).toBe('legacy')
    expect(probe.recordPath).toContain('20260101')
  })

  it('版本不匹配的档案不参与（升级后必须重审，这是 0.4.x 已有语义）', () => {
    const archive = temp('vet-qual-archive-ver-')
    mkdirSync(archive, { recursive: true })
    writeFileSync(join(archive, 'acme-qual-fixture-0.9.0-20260101-000000.md'), '审查结论：通过\n')
    setArchiveDirForTest(archive)
    expect(probeQualification({ name: NAME, version: '1.0.0' }).state.status).toBe('unassessed')
  })
})

describe('report 模式：不能放行时给的是可行动的告警', () => {
  it('摘要不一致 → 黄牌且文案指出是档案不能作为依据', async () => {
    const archive = temp('vet-qual-archive-rep-')
    const profile = temp('vet-qual-prof-')
    makePkg(profile)
    writeArchive(archive, `subject_sha256: ${'d'.repeat(64)}\n`)
    setArchiveDirForTest(archive)

    const { status, listener } = run(profile, { mode: 'report' })
    await listener(fiber('f-rep'))
    const alarm = status.snapshot().alarms.find((a) => a.kind === 'audit-required')
    expect(alarm).toBeDefined()
    expect(alarm!.message).toContain('内容摘要与当前字节不一致')
  }, 60_000)
})
