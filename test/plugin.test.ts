import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync, realpathSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { Context } from '@deepseek-ai/cordis'
import * as vetPlugin from '../lib/index.js'
import { apply } from '../lib/index.js'
import { scan } from '../lib/scanner-bin/engine.js'
import { buildRequest, createScanPluginTool, detectTargetKind } from '../lib/tools/scan-plugin.js'
import { installToolExecuteGuard } from '../lib/guards/tool-execute.js'
import { installInternalPluginGuard, classifyLocalEntry } from '../lib/guards/internal-plugin.js'
import { installInvariant, PACKAGE_NAME } from '../lib/invariant.js'
import { resolvePackageRoot } from '../lib/scanner/package-sources.js'
import { VetConfigSchema } from '../lib/config.js'
import { VetStatus } from '../lib/guard/status.js'
import { setArchiveDirForTest, hasAuditRecord, setArchiveIoWarn } from '../lib/audit/archive.js'
import { computePackageHash, setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { setCatalogAutoRefresh } from '../lib/guards/official-catalog.js'
import type { VetConfig } from '../lib/config.js'
import { explainScore, renderScorecard } from '../lib/report/render.js'

const ESCAPE = 'TextEncoder.constructor("return process")().cwd()'
const CLEAN = 'module.exports = { ok: true }'

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report', autoScan: true,
  scannerTimeoutMs: 15_000,
  rules: {}, denyOn: 'critical', allowlist: [],
  runtimeGuard: 'off', runtimeIntervalMs: 2000, runtimeMemLimitMb: 2048,
  runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
  ...over,
})

class FakeCtx {
  handlers = new Map<string, Function[]>()
  tools = { register: vi.fn() }
  logger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }
  invariants?: { register: vi.fn }
  effect = (fn: () => unknown): (() => void) => { fn(); return () => {} }

  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

const fakeExec = (name: string, args: unknown) => ({
  name,
  arguments: args,
  callId: 'call-1',
  rootCallId: 'call-1',
  token: Symbol('t'),
  signal: new AbortController().signal,
})

const okResult = { isError: false, value: {}, content: [{ type: 'text', text: 'OK' }] }

// 临时"已安装"恶意包：node_modules/@vet-test/evil（node_modules 已 gitignore）
const EVIL_PKG = join(import.meta.dirname, '..', 'node_modules', '@vet-test', 'evil')
const CLEAN_PKG = join(import.meta.dirname, '..', 'node_modules', '@vet-test', 'clean')

describe('resolvePackageRoot（符号链接/非 vet 安装目录解析）', () => {
  it('baseDir 指向独立 node_modules 时能解析该目录里的包（DSH profile 场景）', () => {
    // 模拟 dsh profile：包的 node_modules 在 profile 下，vet 自身不依赖它
    const profile = mkdtempSync(join(tmpdir(), 'vet-profile-'))
    const pkgDir = join(profile, 'node_modules', '@vet-test', 'remote')
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: '@vet-test/remote', version: '1.0.0', main: 'index.js' }))
    try {
      // 不传 baseDir（vet realpath 解析）→ 找不到
      expect(resolvePackageRoot('@vet-test/remote')).toBeUndefined()
      // 传 profile 目录 → 找到（resolvePackageRoot 经 createRequire realpath——macOS
      // /var → /private/var 符号链接，期望值同样 realpath 归一）
      expect(resolvePackageRoot('@vet-test/remote', profile)).toBe(realpathSync(join(profile, 'node_modules', '@vet-test', 'remote')))
    } finally {
      rmSync(profile, { recursive: true, force: true })
    }
  })

  it('file: URL baseDir 也能解析（ctx.baseUrl 的 file: 形态）', () => {
    const profile = mkdtempSync(join(tmpdir(), 'vet-profile-'))
    const pkgDir = join(profile, 'node_modules', '@vet-test', 'fileurl')
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: '@vet-test/fileurl', version: '1.0.0', main: 'index.js' }))
    try {
      expect(resolvePackageRoot('@vet-test/fileurl', 'file://' + profile)).toBe(realpathSync(join(profile, 'node_modules', '@vet-test', 'fileurl')))
    } finally {
      rmSync(profile, { recursive: true, force: true })
    }
  })

  it('vet 自身安装位置仍作为回退基准（历史行为）', () => {
    expect(resolvePackageRoot('@vet-test/evil')).toBe(EVIL_PKG)
  })
})

beforeAll(() => {
  for (const [dir, name, code] of [
    [EVIL_PKG, '@vet-test/evil', `module.exports = ${ESCAPE}`],
    [CLEAN_PKG, '@vet-test/clean', CLEAN],
  ] as const) {
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', type: 'module', main: 'index.js' }))
    writeFileSync(join(dir, 'index.js'), code)
  }
})
afterAll(() => {
  rmSync(join(import.meta.dirname, '..', 'node_modules', '@vet-test'), { recursive: true, force: true })
})

describe('config', () => {
  it('schemastery schema 可校验并补默认值（callable）', () => {
    const parsed = VetConfigSchema({}) as unknown as VetConfig
    expect(parsed.mode).toBe('report')
    expect(parsed.scannerTimeoutMs).toBe(15_000)
    expect(() => VetConfigSchema({ mode: 'bogus' })).toThrow()
  })
})

describe('scan_plugin tool', () => {
  it('dynamic-code 逃逸代码 → verdict critical', async () => {
    const tool = createScanPluginTool()
    const value = await tool.execute({ target: 'dynamic-code', source: ESCAPE }, fakeExec('scan_plugin', {}) as never)
    expect(value.static.verdict).toBe('critical')
  })

  it('dynamic-code 干净代码 → verdict clean', async () => {
    const tool = createScanPluginTool()
    const value = await tool.execute({ target: 'dynamic-code', source: CLEAN }, fakeExec('scan_plugin', {}) as never)
    expect(value.static.verdict).toBe('clean')
    expect(value.static.staticScore).toBeGreaterThanOrEqual(90)
  })

  it('package 模式扫描真实目录', async () => {
    const tool = createScanPluginTool()
    const value = await tool.execute({ target: 'package', packagePath: EVIL_PKG }, fakeExec('scan_plugin', {}) as never)
    expect(value.static.verdict).toBe('critical')
  })

  it('scanBasis 参数接线：git 语义的 package 扫描照常出评分卡（R12 降级由引擎层覆盖）', async () => {
    const tool = createScanPluginTool()
    const value = await tool.execute({ target: 'package', packagePath: EVIL_PKG, scanBasis: 'git' }, fakeExec('scan_plugin', {}) as never)
    expect(value.static.verdict).toBe('critical')
    // 能力块经 output schema 校验（additionalProperties: false + 新字段必须显式声明，R16 字段在列）
    expect(value.static.capabilities).toBeDefined()
  })

  it('render 输出评分卡文本', () => {
    const text = renderScorecard({
      pluginName: 'x', scannedAt: 'now',
      static: { verdict: 'clean', staticScore: 100, findings: [] },
    })
    expect(text).toContain('verdict: clean')
  })

  it('D3：file target 定界——拒绝相对路径/不存在/目录/设备/FIFO/符号链接', async () => {
    const tool = createScanPluginTool()
    const exec = fakeExec('scan_plugin', {}) as never
    await expect(tool.execute({ target: 'file', source: 'relative/x.js' }, exec)).rejects.toThrow(/绝对路径/)
    await expect(tool.execute({ target: 'file', source: '/definitely/not/exists-xyz.js' }, exec)).rejects.toThrow(/不存在/)
    if (process.platform !== 'win32') {
      // /dev/null 是 Linux 设备文件（Windows 上不存在 → 走"不存在"分支，语义不同）
      await expect(tool.execute({ target: 'file', source: '/dev/null' }, exec)).rejects.toThrow(/常规文件/)
    }
    const dir = mkdtempSync(join(tmpdir(), 'vet-filetarget-'))
    try {
      await expect(tool.execute({ target: 'file', source: dir }, exec)).rejects.toThrow(/常规文件/)
      writeFileSync(join(dir, 'linked.js'), CLEAN)
      // 符号链接 → 拒绝（与扫描面 walk 纪律一致）
      if (process.platform !== 'win32') {
        const outside = join(dir, '..', 'vet-filetarget-outside-' + Date.now() + '.js')
        writeFileSync(outside, CLEAN)
        try {
          symlinkSync(outside, join(dir, 'link.js'))
          await expect(tool.execute({ target: 'file', source: join(dir, 'link.js') }, exec)).rejects.toThrow(/常规文件/)
        } finally {
          rmSync(outside, { force: true })
        }
      }
      // FIFO（Linux）→ 拒绝（/dev/zero 同族：无限流/挂死面）
      if (process.platform === 'linux') {
        const fifo = join(dir, 'fifo.js')
        const mr = spawnSync('mkfifo', [fifo])
        if (mr.status === 0) {
          await expect(tool.execute({ target: 'file', source: fifo }, exec)).rejects.toThrow(/常规文件/)
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('D3：file target 常规文件照常扫描（插件形态识别 + 严重度正常）', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-filetarget2-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'evil-file', dependencies: { '@deepseek-ai/cordis': '^4' } }))
      writeFileSync(join(dir, 'evil.js'), ESCAPE)
      const tool = createScanPluginTool()
      const value = await tool.execute({ target: 'file', source: join(dir, 'evil.js') }, fakeExec('scan_plugin', {}) as never)
      expect(value.static.verdict).toBe('critical')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('tools/execute guard', () => {
  const install = (config: VetConfig) => {
    const ctx = new FakeCtx()
    installToolExecuteGuard(ctx as never, config)
    return { ctx, handler: ctx.handlers.get('tools/execute')![0] }
  }

  it('report 模式：run_code 逃逸代码 → 结果加 VET 前缀，不拦截', async () => {
    const { handler } = install(cfg())
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('run_code', { code: ESCAPE, description: 'x' }), next)
    expect(next).toHaveBeenCalled()
    expect(result.isError).toBe(false)
    expect(result.content[0].text).toMatch(/^VET run_code: critical/)
  })

  it('deny 模式 + verdict ≥ denyOn → isError 拦截，不调 next', async () => {
    const { handler } = install(cfg({ mode: 'deny', denyOn: 'critical' }))
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('run_code', { code: ESCAPE, description: 'x' }), next)
    expect(next).not.toHaveBeenCalled()
    expect(result.isError).toBe(true)
    expect(result.content[0].text).toMatch(/^VET BLOCKED/)
  })

  it('deny 模式 + 干净代码 → 放行', async () => {
    const { handler } = install(cfg({ mode: 'deny', denyOn: 'critical' }))
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('run_code', { code: CLEAN, description: 'x' }), next)
    expect(next).toHaveBeenCalled()
    expect(result.isError).toBe(false)
  })

  it('非目标工具（bash）→ 透传', async () => {
    const { handler } = install(cfg())
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('bash', { command: 'ls' }), next)
    expect(result.content[0].text).toBe('OK')
  })

  it('workflow 工具 script 参数也被拦截（A4）', async () => {
    const { handler } = install(cfg({ mode: 'deny', denyOn: 'critical' }))
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('workflow', { script: ESCAPE, meta: { name: 'w' } }), next)
    expect(result.isError).toBe(true)
  })

  it('S8：cordis_run 现行 schema 无 code 载荷 → 透传（守卫位 dormant，零误报）', async () => {
    const { handler } = install(cfg())
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('cordis_run', { pluginId: '@deepseek-ai/some-plugin', mode: 'run' }), next)
    expect(next).toHaveBeenCalled()
    expect(result.content[0].text).toBe('OK')
  })

  it('S8：cordis_run 未来 schema 携带 code 形载荷 → 立即进扫描面（tripwire）', async () => {
    const { handler } = install(cfg())
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('cordis_run', { pluginId: '@deepseek-ai/some-plugin', code: ESCAPE }), next)
    expect(next).toHaveBeenCalled()
    expect(result.content[0].text).toMatch(/^VET cordis_run: critical/)
  })

  it('S8：cordis_run tripwire deny 模式 → 拦截', async () => {
    const { handler } = install(cfg({ mode: 'deny', denyOn: 'critical' }))
    const next = vi.fn(async () => okResult)
    const result = await handler(fakeExec('cordis_run', { source: ESCAPE }), next)
    expect(next).not.toHaveBeenCalled()
    expect(result.isError).toBe(true)
    expect(result.content[0].text).toMatch(/^VET BLOCKED/)
  })
})

describe('internal/plugin guard', () => {
  const fiber = (over: Record<string, unknown>) => ({
    uid: 1, state: 0, dispose: vi.fn(async () => {}), ...over,
  })

  it('dispose 发射（uid null）与 entry-less 直接跳过', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg())
    const h = ctx.handlers.get('internal/plugin')![0]
    h(fiber({ uid: null }))
    h(fiber({ entry: undefined }))
    expect(ctx.logger.info).not.toHaveBeenCalled()
  })

  it('自身与 @deepseek-ai/* 豁免（内容基线关闭 = 用户显式选择 → 完全跳过）', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg({ contentBaseline: false }))
    const h = ctx.handlers.get('internal/plugin')![0]
    h(fiber({ entry: { options: { name: PACKAGE_NAME } } }))
    h(fiber({ entry: { options: { name: '@deepseek-ai/dsh-tools' } } }))
    expect(ctx.logger.info).not.toHaveBeenCalled()
  })

  it('决策 1：官方包 first-seen/match 也跑静态扫描，仅豁免 deny 升级（critical 不拦截）', async () => {
    const profile = mkdtempSync(join(tmpdir(), 'vet-official-'))
    const bdir = mkdtempSync(join(tmpdir(), 'vet-bl-'))
    const pkg = join(profile, 'node_modules', '@deepseek-ai', 'evil-official')
    mkdirSync(pkg, { recursive: true })
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@deepseek-ai/evil-official', version: '1.0.0', main: 'index.js' }))
    writeFileSync(join(pkg, 'index.js'), 'module.exports = ' + ESCAPE)
    setBaselineDirForTest(join(bdir, 'baseline'))
    try {
      const ctx = new FakeCtx()
      ctx.baseUrl = profile
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', denyOn: 'critical', contentBaseline: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      // first-seen：扫描跑（info 留档）但 deny 升级豁免（TOFU 窗口修复：扫描是唯一能识别
      // 冒名 tarball 的确定性检查；官方信任锚不因静态 verdict 拦截）
      const f = fiber({ entry: { options: { name: '@deepseek-ai/evil-official' } } })
      expect(() => h(f)).not.toThrow()
      expect(f.dispose).not.toHaveBeenCalled()
      expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @deepseek-ai/evil-official'))
      // match（内容一致）：同样扫描、同样不拦截
      ctx.logger.info.mockClear()
      const f2 = fiber({ entry: { options: { name: '@deepseek-ai/evil-official' } } })
      expect(() => h(f2)).not.toThrow()
      expect(f2.dispose).not.toHaveBeenCalled()
      expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @deepseek-ai/evil-official'))
    } finally {
      setBaselineDirForTest(undefined)
      rmSync(profile, { recursive: true, force: true })
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  it('0.3.13：catalog 内官方包的构建产物命中折 info（auto-scan verdict clean）；授权源码命中仍 critical', async () => {
    setCatalogAutoRefresh(false)
    const profile = mkdtempSync(join(tmpdir(), 'vet-ofscan-'))
    const bdir = mkdtempSync(join(tmpdir(), 'vet-ofbl-'))
    const official = join(profile, 'node_modules', '@deepseek-ai', 'dsh-tools')   // catalog 内真名
    const authored = join(profile, 'node_modules', '@deepseek-ai', 'dsh-session') // 同样 catalog 内真名
    mkdirSync(join(official, 'lib'), { recursive: true })
    mkdirSync(authored, { recursive: true })
    writeFileSync(join(official, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-tools', version: '9.9.9', main: 'lib/index.js' }))
    writeFileSync(join(official, 'lib', 'index.js'), 'module.exports = ' + ESCAPE)   // 构建产物里的逃逸形态
    writeFileSync(join(authored, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-session', version: '9.9.9', main: 'index.js' }))
    writeFileSync(join(authored, 'index.js'), 'module.exports = ' + ESCAPE)          // 授权源码里的同一形态
    setBaselineDirForTest(join(bdir, 'baseline'))
    try {
      const ctx = new FakeCtx()
      ctx.baseUrl = profile
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'report', contentBaseline: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      h(fiber({ entry: { options: { name: '@deepseek-ai/dsh-tools' } } }))
      h(fiber({ entry: { options: { name: '@deepseek-ai/dsh-session' } } }))
      // report 模式为异步 spawn 扫描：两次 auto-scan 各自完成后才打日志（实测约 1-2s）
      await vi.waitFor(() => {
        expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @deepseek-ai/dsh-tools → clean'))
        expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @deepseek-ai/dsh-session → critical'))
      }, { timeout: 10_000 })
    } finally {
      setBaselineDirForTest(undefined)
      setCatalogAutoRefresh(true)
      rmSync(profile, { recursive: true, force: true })
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  it('S10：官方包基线落盘失败 → yellow baseline-save-fail（不再静默）', async () => {
    setCatalogAutoRefresh(false)
    const profile = mkdtempSync(join(tmpdir(), 'vet-official2-'))
    const bdir = mkdtempSync(join(tmpdir(), 'vet-blfile-'))
    const blocker = join(bdir, 'not-a-dir')
    writeFileSync(blocker, 'file') // baselinePath 指向此文件路径 → mkdirSync 失败 → save 失败
    const pkg = join(profile, 'node_modules', '@deepseek-ai', 'official-x')
    mkdirSync(pkg, { recursive: true })
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@deepseek-ai/official-x', version: '1.0.0', main: 'index.js' }))
    writeFileSync(join(pkg, 'index.js'), 'module.exports = 1')
    setBaselineDirForTest(blocker)
    try {
      const ctx = new FakeCtx()
      ctx.baseUrl = profile
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ contentBaseline: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      await h(fiber({ entry: { options: { name: '@deepseek-ai/official-x' } } }))
      const kinds = status.snapshot().alarms.map(a => a.kind)
      expect(kinds).toContain('baseline-save-fail')
    } finally {
      setCatalogAutoRefresh(true)
      setBaselineDirForTest(undefined)
      rmSync(profile, { recursive: true, force: true })
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  it('S9：档案目录不可读 → 一次性 warn + 按无档案判定', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-archive-warn-'))
    const blockerFile = join(dir, 'not-a-dir')
    writeFileSync(blockerFile, 'x')
    const warns: string[] = []
    setArchiveIoWarn((m) => warns.push(m))
    setArchiveDirForTest(blockerFile)
    try {
      expect(hasAuditRecord('some-pkg')).toBe(false)
      expect(hasAuditRecord('some-pkg')).toBe(false) // 第二次不重复告警
      expect(warns.length).toBe(1)
      expect(warns[0]).toContain('不可读')
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
      setArchiveIoWarn(undefined)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('report 模式：第三方包自动扫描 → logger.info（异步，P0-4 不再同步阻塞）', async () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg())
    const h = ctx.handlers.get('internal/plugin')![0]
    await h(fiber({ entry: { options: { name: '@vet-test/clean' } } }))
    // round-16（QA-8，防抖）：扫描经子进程 spawn + 引擎预算在并行 CI 下有落地抖动——
    // 终态断言改 vi.waitFor（≤10s 轮询），断言语义不变：日志终态必须出现 auto-scan → clean
    await vi.waitFor(
      () => expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @vet-test/clean → clean')),
      { timeout: 10_000, interval: 100 },
    )
  })

  it('deny 模式 + critical → 同步抛错并 dispose（回滚挂载）', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', denyOn: 'critical' }))
    const h = ctx.handlers.get('internal/plugin')![0]
    const f = fiber({ entry: { options: { name: '@vet-test/evil' } } })
    expect(() => h(f)).toThrow(/vet: 拦截/)
    expect(f.dispose).toHaveBeenCalled()
  })

  it('allowlist 豁免', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', allowlist: ['@vet-test/evil'] }))
    const h = ctx.handlers.get('internal/plugin')![0]
    const f = fiber({ entry: { options: { name: '@vet-test/evil' } } })
    expect(() => h(f)).not.toThrow()
  })
  it('requireAudit deny：无档案 → 拦截并 dispose（D30 强制层）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-require-'))
    setArchiveDirForTest(join(dir, 'audits'))
    try {
      const ctx = new FakeCtx()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', requireAudit: true }))
      const h = ctx.handlers.get('internal/plugin')![0]
      const f = fiber({ entry: { options: { name: '@vet-test/needs-audit' } } })
      expect(() => h(f)).toThrow(/尚未完成审计/)
      expect(f.dispose).toHaveBeenCalled()
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    }
  })

  it('requireAudit：cordis builtin（cordis:group）豁免——不报警不拦截（D30 误报修复）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-require4-'))
    setArchiveDirForTest(join(dir, 'audits'))
    try {
      const ctx = new FakeCtx()
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'report', requireAudit: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      const f = fiber({ entry: { options: { name: 'cordis:group' } } })
      expect(() => h(f)).not.toThrow()
      expect(f.dispose).not.toHaveBeenCalled()
      expect(ctx.logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      expect(status.snapshot().alarmCount).toBe(0)
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    }
  })

  it('requireAudit report（watch）：无档案 → 只报警不拦截（alarm-only，D30）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-require3-'))
    setArchiveDirForTest(join(dir, 'audits'))
    try {
      const ctx = new FakeCtx()
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'report', requireAudit: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      const f = fiber({ entry: { options: { name: '@vet-test/no-audit' } } })
      expect(() => h(f)).not.toThrow()
      expect(f.dispose).not.toHaveBeenCalled()
      expect(ctx.logger.warn).toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      const snap = status.snapshot()
      expect(snap.alarmCount).toBe(1)
      expect(snap.alarms[0].kind).toBe('audit-required')
      expect(snap.alarms[0].severity).toBe('yellow')
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    }
  })

  it('requireAudit 有档案 → 正常加载（不拦截）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-require2-'))
    setArchiveDirForTest(join(dir, 'audits'))
    try {
      mkdirSync(join(dir, 'audits'), { recursive: true })
      writeFileSync(join(dir, 'audits', 'vet-test-needs-audit-1.0.0-20260815-120000.md'), '# VET 健康档案')
      const ctx = new FakeCtx()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', requireAudit: true }))
      const h = ctx.handlers.get('internal/plugin')![0]
      const f = fiber({ entry: { options: { name: '@vet-test/needs-audit' } } })
      expect(() => h(f)).not.toThrow()
      expect(f.dispose).not.toHaveBeenCalled()
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    }
  })

  it('M1：档案前缀伪造——lodash 不能因 lodash-foo 的档案通过；自身完整档案才通过', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-m1-'))
    setArchiveDirForTest(join(dir, 'audits'))
    try {
      mkdirSync(join(dir, 'audits'), { recursive: true })
      // 只有 lodash-foo 的档案 → lodash 不应命中（旧前缀匹配会误判）
      writeFileSync(join(dir, 'audits', 'lodash-foo-1.0.0-20260815-120000.md'), '# x')
      const ctx = new FakeCtx()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'deny', requireAudit: true }))
      const h = ctx.handlers.get('internal/plugin')![0]
      const f = fiber({ entry: { options: { name: 'lodash' } } })
      expect(() => h(f)).toThrow(/尚未完成审计/)
      // 补上 lodash 自己的完整档案 → 通过
      writeFileSync(join(dir, 'audits', 'lodash-4.17.21-20260815-120000.md'), '# y')
      const f2 = fiber({ entry: { options: { name: 'lodash' } } })
      expect(() => h(f2)).not.toThrow()
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    }
  })

  it('round-17：官方包（first-seen/match）不进 requireAudit 门槛——不报 audit-required（回归：官方包告警风暴）', async () => {
    setCatalogAutoRefresh(false)
    const profile = mkdtempSync(join(tmpdir(), 'vet-official3-'))
    const bdir = mkdtempSync(join(tmpdir(), 'vet-bl3-'))
    const pkg = join(profile, 'node_modules', '@deepseek-ai', 'ok-official')
    mkdirSync(pkg, { recursive: true })
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@deepseek-ai/ok-official', version: '1.0.0', main: 'index.js' }))
    writeFileSync(join(pkg, 'index.js'), 'module.exports = 1')
    setBaselineDirForTest(join(bdir, 'baseline'))
    setArchiveDirForTest(join(bdir, 'audits')) // 空档案目录：第三方必经门槛
    setSummariesDirForTest(join(bdir, 'summaries')) // 扫描留档改 tmp，不污染真实 ~/.dsh/vet
    setCapabilitiesDirForTest(join(bdir, 'caps'))
    try {
      const ctx = new FakeCtx()
      ctx.baseUrl = profile
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'report', requireAudit: true, contentBaseline: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      // first-seen：无档案也不报 audit-required（官方包门槛 = 内容哈希基线 + 静态扫描，非人工档案）
      const f = fiber({ entry: { options: { name: '@deepseek-ai/ok-official' } } })
      const p = h(f)
      await p // 等 report 异步扫描收尾（留档走 tmp 目录）
      expect(ctx.logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      // match（内容一致，二次加载）：同样不报
      await h(fiber({ entry: { options: { name: '@deepseek-ai/ok-official' } } }))
      expect(ctx.logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      expect(status.snapshot().alarms.map(a => a.kind)).not.toContain('audit-required')
      // 对照：第三方名（resolve 不到根 → not-official）同配置下仍被门槛命中
      expect(() => h(fiber({ entry: { options: { name: '@vet-test/needs-audit' } } }))).not.toThrow()
      expect(ctx.logger.warn).toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      expect(status.snapshot().alarms.map(a => a.kind)).toContain('audit-required')
    } finally {
      setCatalogAutoRefresh(true)
      setBaselineDirForTest(undefined)
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
      setSummariesDirForTest(undefined)
      setCapabilitiesDirForTest(undefined)
      rmSync(profile, { recursive: true, force: true })
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  // 0.3.7（DSH 0.1.5-rc.1 同步）：cordis 4.x loader 把 profile insert/本地插件条目规范成
  // `file:///…` URL（或保持 `link:/…`/裸路径形态）。此前 extractPackageName 把这类名字切成
  // `file:` 伪包名，requireAudit 下产出无法处置的永久黄牌 `audit-required:file:`。
  it('0.3.7：file: URL 条目不再产 audit-required，降为聚合蓝色观察', () => {
    const bdir = mkdtempSync(join(tmpdir(), 'vet-bl4-'))
    setArchiveDirForTest(join(bdir, 'audits'))
    setSummariesDirForTest(join(bdir, 'summaries'))
    setCapabilitiesDirForTest(join(bdir, 'caps'))
    try {
      const ctx = new FakeCtx()
      const status = new VetStatus()
      installInternalPluginGuard(ctx as never, cfg({ mode: 'report', requireAudit: true }), status)
      const h = ctx.handlers.get('internal/plugin')![0]
      const f1 = fiber({ entry: { options: { name: 'file:///home/u/.dsh/profiles/web/lan-uuid-polyfill.mjs' } } })
      expect(() => h(f1)).not.toThrow()
      expect(ctx.logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('尚未完成审计'))
      const snap = status.snapshot()
      const rows = snap.alarms.filter(a => a.kind === 'local-entry')
      expect(rows).toHaveLength(1)
      expect(rows[0].severity).toBe('info')
      expect(rows[0].message).toContain('/home/u/.dsh/profiles/web/lan-uuid-polyfill.mjs')
      expect(snap.alarms.map(a => a.kind)).not.toContain('audit-required')
      // 蓝行不参与警报计价：level 不因本地条目抬升
      expect(snap.alarmCount).toBe(0)
      // 第二个不同本地条目 → mergeKey 聚合成一行 ×2，仍无黄
      h(fiber({ entry: { options: { name: 'file:/home/u/.dsh/profiles/web/another.mjs' } } }))
      const snap2 = status.snapshot()
      const rows2 = snap2.alarms.filter(a => a.kind === 'local-entry')
      expect(rows2).toHaveLength(1)
      expect(rows2[0].count).toBe(2)
      expect(snap2.alarmCount).toBe(0)
    } finally {
      setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
      setSummariesDirForTest(undefined)
      setCapabilitiesDirForTest(undefined)
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  it('0.3.7：vet 本体 link: 豁免；裸路径计观察；classifyLocalEntry 不误伤包名', () => {
    const vetRoot = realpathSync(join(import.meta.dirname, '..'))
    const ctx = new FakeCtx()
    const status = new VetStatus()
    installInternalPluginGuard(ctx as never, cfg({ mode: 'report', requireAudit: true }), status)
    const h = ctx.handlers.get('internal/plugin')![0]
    h(fiber({ entry: { options: { name: 'link:' + vetRoot } } }))
    expect(status.snapshot().alarms).toHaveLength(0)
    // 裸绝对/相对路径同样按本地条目处理，不再落到伪包名黄牌路径
    h(fiber({ entry: { options: { name: '/home/u/plugins/mystery.js' } } }))
    const snap = status.snapshot()
    expect(snap.alarms.map(a => a.kind)).toContain('local-entry')
    expect(snap.alarms.map(a => a.kind)).not.toContain('audit-required')
    // helper 单测：正常包名与带子路径包名不误伤；file: URL 解出真实路径
    expect(classifyLocalEntry('@deepseek-ai/dsh-web-app')).toBeNull()
    expect(classifyLocalEntry('@deepseek-ai/dsh-tool-subagent-control/list-agents')).toBeNull()
    expect(classifyLocalEntry('some-plain-package')).toBeNull()
    expect(classifyLocalEntry('file:///a/b%20c.mjs')).toBe('/a/b c.mjs')
    expect(classifyLocalEntry('file:/a/b.mjs')).toBe('/a/b.mjs')
    expect(classifyLocalEntry('link:/x/y')).toBe('/x/y')
  })
})

describe('invariant', () => {
  it('注册并验证 scanner-bin 可执行（空扫 ok）', async () => {
    const register = vi.fn()
    const ctx = new FakeCtx()
    ctx.invariants = { register }
    installInvariant(ctx as never)
    expect(register).toHaveBeenCalledWith(PACKAGE_NAME, expect.any(Function))
    const installer = register.mock.calls[0][1] as (child: unknown, fail: (m: string) => never) => Promise<void>
    const fail = vi.fn()
    await installer({}, fail as never)
    expect(fail).not.toHaveBeenCalled()
  })
})

describe('apply 装配', () => {
  it('注册 scan_plugin + 两守卫 + invariant', () => {
    const ctx = new FakeCtx()
    ctx.invariants = { register: vi.fn() }
    apply(ctx as never, cfg())
    // 0.1.15 (N6)：scan_plugin + vet_diff；0.1.21 (M2)：+ vet_label —— 三个工具注册
    expect(ctx.tools.register).toHaveBeenCalledTimes(3)
    expect(ctx.tools.register).toHaveBeenCalledWith(expect.objectContaining({ name: 'scan_plugin' }))
    expect(ctx.tools.register).toHaveBeenCalledWith(expect.objectContaining({ name: 'vet_diff' }))
    expect(ctx.tools.register).toHaveBeenCalledWith(expect.objectContaining({ name: 'vet_label' }))
    expect(ctx.handlers.has('internal/plugin')).toBe(true)
    expect(ctx.handlers.has('tools/execute')).toBe(true)
    expect(ctx.invariants!.register).toHaveBeenCalledWith(PACKAGE_NAME, expect.any(Function))
  })
})

describe('真实 cordis harness 挂载（防启动崩溃回归，B3）', () => {
  it('提供全部 inject 服务后挂载 vet：apply 执行、双工具注册、无 invariants 服务不崩', async () => {
    const ctx = new Context()
    const registered: string[] = []
    ctx.provide('tools', { register: (t: { name: string }) => { registered.push(t.name) } } as never)
    ctx.provide('skills', { register: (reg: { name: string }) => { registered.push(reg.name) } } as never)
    let fiber: PromiseLike<unknown> | undefined
    expect(() => { fiber = ctx.plugin(vetPlugin) as PromiseLike<unknown> }).not.toThrow()
    await fiber
    expect(registered).toContain('scan_plugin')
    expect(registered).toContain('vet-audit-protocol')
    expect(registered.some(n => n === 'vet-audit-protocol')).toBe(true)

  })

  it('installInvariant：invariants 属性访问抛错（cordis proxy 未注入行为）时不崩', () => {
    const ctx = {
      get invariants(): never { throw new Error('service not injected') },
    }
    expect(() => installInvariant(ctx as never)).not.toThrow()
  })
})

describe('目标身份分级（targetKind，§14.3 边界落地）', () => {
  const tmpPkg = (files: Record<string, string>): string => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-kind-'))
    for (const [name, content] of Object.entries(files)) {
      const p = join(dir, name)
      mkdirSync(dirname(p), { recursive: true })
      writeFileSync(p, content)
    }
    return dir
  }

  it('普通 npm 包（无 DSH 依赖）：process 降级 info，verdict clean', () => {
    const dir = tmpPkg({ 'index.js': 'process.env.HOME' })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('generic')
      const res = scan(request)
      expect(res.ok).toBe(true)
      expect(res.report!.verdict).toBe('clean')
      const r3 = res.report!.findings.find(f => f.rule === 'R3')
      expect(r3).toBeDefined()
      expect(r3!.severity).toBe('info')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('DSH 插件包（依赖 @deepseek-ai/cordis）：严格，process.kill → high → suspicious（round-7.1：env/cwd 等只读成员已降 info）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'evil-plugin', dependencies: { '@deepseek-ai/cordis': '^4.0.1' } }),
      'index.js': "process.kill(1234, 'SIGTERM')",
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('plugin')
      const res = scan(request)
      expect(res.report!.verdict).toBe('suspicious')
      const r3 = res.report!.findings.find(f => f.rule === 'R3' && f.severity === 'high')
      expect(r3).toBeDefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('vet 自豁免按 realpath 验证（round-7.1 P-3）：自身目录 → generic；冒名包（同名不同目录）→ 最严格 plugin', () => {
    // 真实 vet 实例：当前运行代码所在包根 → 信任锚豁免 generic
    const selfRoot = join(import.meta.dirname, '..')
    expect(detectTargetKind(selfRoot)).toBe('generic')
    // 冒名包：本地 file: 安装无 registry 校验，tmp 目录里 name 写 PACKAGE_NAME → plugin 严格判定
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: PACKAGE_NAME, dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'index.js': 'process.execPath',
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('plugin')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('冒名 vet 包（无依赖也判 plugin）：原型污染按 high 报，不再 generic 降 info', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: PACKAGE_NAME }),
      'index.js': 'Object.prototype.polluted = true',
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('plugin')
      const res = scan(request)
      expect(res.report!.verdict).toBe('suspicious')
      const r4 = res.report!.findings.find(f => f.rule === 'R4' && f.severity === 'high')
      expect(r4).toBeDefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  // 0.3.13：官方包产物降噪位（officialFamily）只在「目录成员 + 字节未改动」时开启。
  // 用临时基线目录隔离（setBaselineDirForTest），以真实目录名 @deepseek-ai/dsh-tools
  // 走 first-seen → match → mismatch 三态。
  it('officialFamily 四态：首见开（升级主场景）/ match 开 / mismatch 关（字节偏离）/ 已登记补丁开', () => {
    const bdir = mkdtempSync(join(tmpdir(), 'vet-of-'))
    setBaselineDirForTest(join(bdir, 'baseline'))
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: '@deepseek-ai/dsh-tools', version: '9.9.9', main: 'lib/index.js' }),
      'lib/index.js': 'module.exports = () => process.kill(1, "SIGTERM")\n',
    })
    try {
      const first = buildRequest({ target: 'package', packagePath: dir })
      expect(first.request.officialFamily).toBe(true) // 首见：目录成员，享降噪
      const match = buildRequest({ target: 'package', packagePath: dir })
      expect(match.request.officialFamily).toBe(true) // 同字节 match：仍享
      // 本机改动字节 → mismatch：不享降噪（且 targetKind 退回严格 plugin）
      writeFileSync(join(dir, 'lib', 'index.js'), 'module.exports = () => process.kill(2, "SIGKILL")\n')
      const tampered = buildRequest({ target: 'package', packagePath: dir })
      expect(tampered.request.officialFamily).toBeUndefined()
      expect(tampered.request.targetKind).toBe('plugin')
      // 0.3.13（用户决策「纳入降噪」）：同一 mismatch，但当前字节的 hash 已在
      // acknowledged-package-hashes 登记（用户认领本机合法补丁）→ 产物降噪照给；
      // targetKind 仍是 plugin（身份层不因声明放松——登记只改规则档位，不改信任判定）
      const acked = buildRequest(
        { target: 'package', packagePath: dir },
        { '@deepseek-ai/dsh-tools@9.9.9': [computePackageHash(dir)!.hash] },
      )
      expect(acked.request.officialFamily).toBe(true)
      expect(acked.request.targetKind).toBe('plugin')
      // 端到端：登记补丁的 mismatch 真扫一遍——产物命中折 info（verdict clean）；未登记仍严格
      const ackedScan = scan(acked.request)
      expect(ackedScan.report!.verdict).toBe('clean')
      expect(ackedScan.report!.findings.find(f => f.rule === 'R3')!.message).toContain('构建产物（官方包降噪）：')
      expect(scan(tampered.request).report!.verdict).toBe('suspicious')
      // 登记的是别的内容（认领 hash ≠ 当前字节）→ 不降噪（防「登记一次终身免检」）
      const staleAck = buildRequest(
        { target: 'package', packagePath: dir },
        { '@deepseek-ai/dsh-tools@9.9.9': ['0'.repeat(64)] },
      )
      expect(staleAck.request.officialFamily).toBeUndefined()
      // 目录外的 @deepseek-ai/* 名字（冒充候选）：首见也不享降噪
      const impostor = tmpPkg({
        'package.json': JSON.stringify({ name: '@deepseek-ai/not-a-real-official-pkg', version: '1.0.0', main: 'index.js' }),
        'index.js': 'export {}\n',
      })
      try {
        expect(buildRequest({ target: 'package', packagePath: impostor }).request.officialFamily).toBeUndefined()
      } finally { rmSync(impostor, { recursive: true, force: true }) }
    } finally {
      setBaselineDirForTest(undefined)
      rmSync(dir, { recursive: true, force: true })
      rmSync(bdir, { recursive: true, force: true })
    }
  })

  it('generic 包：R2 require 降级 medium（官方 loader 功能，不进 verdict）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'loader-tool' }),
      'index.js': "const m = require('x')",
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('generic')
      const res = scan(request)
      expect(res.report!.verdict).toBe('clean')
      const r2 = res.report!.findings.find(f => f.rule === 'R2')
      expect(r2).toBeDefined()
      expect(r2!.severity).toBe('medium')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('generic 包：R10 postinstall 降级 info（官方包合法安装步骤）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'tool-with-hook', scripts: { postinstall: 'node build.js' } }),
      'index.js': 'module.exports = {}',
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      const res = scan(request)
      expect(res.report!.verdict).toBe('clean')
      const r10 = res.report!.findings.find(f => f.rule === 'R10')
      expect(r10!.severity).toBe('info')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('DSH 插件包：R2 require 保持 high（插件内真实能力触达）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'evil-plugin', dependencies: { '@deepseek-ai/cordis': '^4.0.1' } }),
      'index.js': "const m = require('child_process')",
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('plugin')
      const res = scan(request)
      const r2 = res.report!.findings.find(f => f.rule === 'R2')
      expect(r2!.severity).toBe('high')
      expect(res.report!.verdict).toBe('suspicious')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('P3-4：file 目标父目录有 package.json → 识别插件形态（不再恒 generic）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'evil-plugin', dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'index.js': 'process.exit(0)',
      'sub/x.js': '1+1',
    })
    try {
      const r = buildRequest({ target: 'file', source: join(dir, 'sub', 'x.js') })
      expect(r.request.targetKind).toBe('plugin')
      expect(r.pluginVersion).toBeUndefined() // fixture 无 version 字段
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
    // 父目录无 package.json → generic（普通文件审计）
    const plain = mkdtempSync(join(tmpdir(), 'vet-fileplain-'))
    try {
      writeFileSync(join(plain, 'y.js'), '1')
      expect(buildRequest({ target: 'file', source: join(plain, 'y.js') }).request.targetKind).toBe('generic')
    } finally {
      rmSync(plain, { recursive: true, force: true })
    }
  })

  it('P-2 计划：package 目标输出 pluginVersion（档案/版本核对用）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'ver-pkg', version: '2.3.4', dependencies: { '@deepseek-ai/dsh-tools': '^1' } }),
      'index.js': 'export const name = "ver-pkg"',
    })
    try {
      const { pluginVersion } = buildRequest({ target: 'package', packagePath: dir })
      expect(pluginVersion).toBe('2.3.4')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('分数构成解释（explainScore，clean+低分可读性）', () => {
  it('info 级命中构成：含 R3 info 明细与 verdict 说明', () => {
    const s = explainScore([
      { rule: 'R3', severity: 'info', confidence: 'certain' },
      { rule: 'R3', severity: 'info', confidence: 'certain' },
      { rule: 'R6', severity: 'info', confidence: 'heuristic' },
    ])
    expect(s).toContain('info 0') // info 级不扣分（评分模型修正后）
    expect(s).toContain('R3×2')
    expect(s).toContain('verdict 只由 critical/high 决定')
  })
  it('无发现 → 满分说明', () => {
    expect(explainScore([])).toContain('满分')
  })
})
describe('invariant watch 档位平台门（round-22）', () => {
  it('纯判定：平台支持但哨兵未启动 → fail 文案；其余组合 → null', async () => {
    const { watchInvariantMessage } = await import('../lib/invariant.js')
    // Windows 等不支持平台 + watch 档：T1 按设计跳过（runtime-guard 平台门）→ 不 fail
    expect(watchInvariantMessage('win32', false)).toBeNull()
    expect(watchInvariantMessage('freebsd', false)).toBeNull()
    // Linux/macOS 支持但哨兵未启动 → fail（真故障）
    expect(watchInvariantMessage('linux', false)).toEqual(expect.stringContaining('T1 哨兵未启动'))
    expect(watchInvariantMessage('darwin', false)).toEqual(expect.stringContaining('T1 哨兵未启动'))
    // 已启动 → 不 fail
    expect(watchInvariantMessage('linux', true)).toBeNull()
    expect(watchInvariantMessage('darwin', true)).toBeNull()
  })

  it('watch 档位装配：按平台门判定（平台支持且哨兵未启动 → fail；平台不支持 → 不 fail）', async () => {
    const { sidecarSupportedOn, setSidecarSpawned, sidecarSpawned } = await import('../lib/guard/runtime-sidecar.js')
    const { installInvariant } = await import('../lib/invariant.js')
    const prev = sidecarSpawned
    setSidecarSpawned(false)
    try {
      const register = vi.fn()
      const ctx = new FakeCtx()
      ctx.invariants = { register }
      installInvariant(ctx as never, { runtimeGuard: 'watch' } as never)
      expect(register).toHaveBeenCalledTimes(1)
      const installer = register.mock.calls[0][1] as (child: unknown, fail: (m: string) => never) => Promise<void>
      const fail = vi.fn()
      await installer({}, fail as never)
      if (sidecarSupportedOn(process.platform)) {
        expect(fail).toHaveBeenCalled()
      } else {
        expect(fail).not.toHaveBeenCalled()
      }
    } finally {
      setSidecarSpawned(prev)
    }
  })
})
