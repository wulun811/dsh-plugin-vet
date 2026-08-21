import { afterAll, describe, expect, it, vi } from 'vitest'
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { hashPackTarball, verifyAgainstRegistry } from '../lib/guards/registry-verify.js'
import { computePackageHash, refreshBaseline, setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { VetStatus } from '../lib/guard/status.js'
import type { VetConfig } from '../lib/config.js'

const execFileAsync = promisify(execFile)

const REPO_ROOT = join(import.meta.dirname, '..')
const OFFICIAL_PKG = join(REPO_ROOT, 'node_modules', '@deepseek-ai', 'vet-fixture')
const NAME = '@deepseek-ai/vet-fixture'
const VERSION = '9.9.9'

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report', autoScan: true,
  scannerTimeoutMs: 15_000,
  rules: {}, denyOn: 'critical', allowlist: [],
  runtimeGuard: 'off', runtimeIntervalMs: 2000, runtimeMemLimitMb: 2048,
  runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
  contentBaseline: true, acknowledgedPackageHashes: {},
  ...over,
})

class FakeCtx {
  handlers = new Map<string, Function[]>()
  baseUrl = REPO_ROOT
  logger = { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} }
  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

/** 干净的官方命名空间夹具包（每次重建，清掉上个用例的 extra.js）。 */
function makePkg(): void {
  rmSync(OFFICIAL_PKG, { recursive: true, force: true })
  mkdirSync(OFFICIAL_PKG, { recursive: true })
  writeFileSync(join(OFFICIAL_PKG, 'package.json'), JSON.stringify({ name: NAME, version: VERSION, main: 'index.js' }))
  writeFileSync(join(OFFICIAL_PKG, 'index.js'), 'module.exports = { ok: true }\n')
}

/** npm 布局 tarball（package/ 前缀）——快照当前 OFFICIAL_PKG 内容。 */
async function makeTgz(): Promise<Buffer> {
  const stage = mkdtempSync(join(tmpdir(), 'vet-stage-'))
  const pkgDir = join(stage, 'package')
  mkdirSync(pkgDir, { recursive: true })
  for (const f of ['package.json', 'index.js', 'extra.js']) {
    const src = join(OFFICIAL_PKG, f)
    if (existsSync(src)) writeFileSync(join(pkgDir, f), readFileSync(src))
  }
  const out = join(stage, 'p.tgz')
  await execFileAsync('tar', ['-czf', out, '-C', stage, 'package'])
  const buf = readFileSync(out)
  rmSync(stage, { recursive: true, force: true })
  return buf
}

/** 预置陈旧基线（hash 全 0），确保与任何真实内容都不匹配。 */
function preloadStaleBaseline(): void {
  const dir = mkdtempSync(join(tmpdir(), 'vet-base-'))
  writeFileSync(join(dir, 'baseline.json'), JSON.stringify({
    records: { [`${NAME}@${VERSION}`]: { name: NAME, version: VERSION, hash: '0'.repeat(64), recordedAt: Date.now() } },
  }))
  setBaselineDirForTest(dir)
  refreshBaseline()
}

async function waitFor(status: VetStatus, kind: string): Promise<boolean> {
  for (let i = 0; i < 60; i++) {
    if (status.snapshot().alarms.some(a => a.kind === kind)) return true
    await new Promise(r => setTimeout(r, 50))
  }
  return status.snapshot().alarms.some(a => a.kind === kind)
}

describe('hashPackTarball（registry 对账的哈希管线）', () => {
  it('npm 布局 tarball 的哈希 == 对目录直接 computePackageHash；内容变化 → 哈希变化', async () => {
    makePkg()
    const tgz = await makeTgz()
    const h1 = await hashPackTarball(tgz)
    expect(h1).toBe(computePackageHash(OFFICIAL_PKG)?.hash ?? '')
    expect(await hashPackTarball(tgz)).toBe(h1)
    writeFileSync(join(OFFICIAL_PKG, 'index.js'), 'module.exports = { ok: false }\n')
    expect(await hashPackTarball(await makeTgz())).not.toBe(h1)
  })
})

describe('baseline-mismatch 定性（0.1.21：registry 对账 + 已声明补丁）', () => {
  afterAll(() => {
    setBaselineDirForTest(undefined)
    rmSync(OFFICIAL_PKG, { recursive: true, force: true })
    vi.unstubAllGlobals()
  })

  it('已登记补丁 → 豁免 + yellow baseline-patch-ack，无红警', async () => {
    makePkg()
    const realHash = computePackageHash(OFFICIAL_PKG)!.hash
    preloadStaleBaseline()
    const status = new VetStatus()
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg({
      acknowledgedPackageHashes: { [`${NAME}@${VERSION}`]: [realHash] },
    }), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f1', entry: { options: { name: NAME } } })
    const kinds = status.snapshot().alarms.map(a => a.kind)
    expect(kinds).toContain('baseline-patch-ack')
    expect(kinds).not.toContain('baseline-mismatch')
  })

  it('deny 模式未登记 → 同步红警（零网络），消息含登记指引', async () => {
    makePkg()
    preloadStaleBaseline()
    const status = new VetStatus()
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg({ mode: 'deny' }), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f2', entry: { options: { name: NAME } } })
    const red = status.snapshot().alarms.find(a => a.kind === 'baseline-mismatch')
    expect(red?.severity).toBe('red')
    expect(red?.message).toContain('acknowledged-package-hashes')
  })

  it('report 模式：本机字节 == registry → 基线刷新 + yellow，不记红', async () => {
    makePkg()
    preloadStaleBaseline()
    const tgz = await makeTgz()
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.endsWith(`/${VERSION}`)) {
        return new Response(JSON.stringify({ dist: { tarball: 'https://registry.npmjs.org/x.tgz' } }))
      }
      return new Response(new Uint8Array(tgz))
    }))
    const status = new VetStatus()
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f3', entry: { options: { name: NAME } } })
    expect(await waitFor(status, 'baseline-refreshed')).toBe(true)
    const kinds = status.snapshot().alarms.map(a => a.kind)
    expect(kinds).not.toContain('baseline-mismatch')
  })

  it('report 模式：本机字节 != registry → 红警坐实（措辞含 registry 不一致）', async () => {
    makePkg()
    const officialSnapshot = await makeTgz()   // registry 快照：不含随后的本机改动
    writeFileSync(join(OFFICIAL_PKG, 'extra.js'), '// local modification\n')
    preloadStaleBaseline()
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL) => {
      const u = String(url)
      if (u.endsWith(`/${VERSION}`)) {
        return new Response(JSON.stringify({ dist: { tarball: 'https://registry.npmjs.org/x.tgz' } }))
      }
      return new Response(new Uint8Array(officialSnapshot))
    }))
    const status = new VetStatus()
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg(), status)
    ctx.handlers.get('internal/plugin')![0]({ uid: 'f4', entry: { options: { name: NAME } } })
    expect(await waitFor(status, 'baseline-mismatch')).toBe(true)
    const red = status.snapshot().alarms.find(a => a.kind === 'baseline-mismatch')
    expect(red?.severity).toBe('red')
    expect(red?.message).toContain('官方 registry')
  })
})
