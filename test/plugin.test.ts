import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import * as vetPlugin from '../lib/index.js'
import { apply } from '../lib/index.js'
import { scan } from '../lib/scanner-bin/engine.js'
import { buildRequest, createScanPluginTool } from '../lib/tools/scan-plugin.js'
import { installToolExecuteGuard } from '../lib/guards/tool-execute.js'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { installInvariant, PACKAGE_NAME } from '../lib/invariant.js'
import { VetConfigSchema, validateConfig } from '../lib/config.js'
import type { VetConfig } from '../lib/config.js'
import { explainScore, renderScorecard } from '../lib/report/render.js'

const ESCAPE = 'TextEncoder.constructor("return process")().cwd()'
const CLEAN = 'module.exports = { ok: true }'

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report', autoScan: true, autoAudit: false,
  auditMaxTokens: 2048, auditTimeoutMs: 120_000, scannerTimeoutMs: 15_000,
  auditCacheTtlHours: 168, rules: {}, denyOn: 'critical', allowlist: [],
  ...over,
})

class FakeCtx {
  handlers = new Map<string, Function[]>()
  tools = { register: vi.fn() }
  logger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }
  invariants?: { register: vi.fn }

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
  it('provider/model 必须成对（fail-loud）', () => {
    expect(() => validateConfig(cfg({ provider: 'deepseek' }))).toThrow(/成对/)
    expect(() => validateConfig(cfg({ model: 'x' }))).toThrow(/成对/)
    expect(() => validateConfig(cfg({ provider: 'deepseek', model: 'deepseek-chat' }))).not.toThrow()
  })

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

  it('render 输出评分卡文本', () => {
    const text = renderScorecard({
      pluginName: 'x', scannedAt: 'now',
      static: { verdict: 'clean', staticScore: 100, findings: [] },
    })
    expect(text).toContain('verdict: clean')
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

  it('自身与 @deepseek-ai/* 豁免', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg())
    const h = ctx.handlers.get('internal/plugin')![0]
    h(fiber({ entry: { options: { name: PACKAGE_NAME } } }))
    h(fiber({ entry: { options: { name: '@deepseek-ai/dsh-tools' } } }))
    expect(ctx.logger.info).not.toHaveBeenCalled()
  })

  it('report 模式：第三方包自动扫描 → logger.info', () => {
    const ctx = new FakeCtx()
    installInternalPluginGuard(ctx as never, cfg())
    const h = ctx.handlers.get('internal/plugin')![0]
    h(fiber({ entry: { options: { name: '@vet-test/clean' } } }))
    expect(ctx.logger.info).toHaveBeenCalledWith(expect.stringContaining('auto-scan @vet-test/clean → clean'))
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
    expect(ctx.tools.register).toHaveBeenCalledTimes(2)
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
    ctx.provide('llm', {} as never)
    ctx.provide('sessions', {} as never)
    ctx.provide('sessionPersistence', { append: async () => {} } as never)
    let fiber: PromiseLike<unknown> | undefined
    expect(() => { fiber = ctx.plugin(vetPlugin) as PromiseLike<unknown> }).not.toThrow()
    await fiber
    expect(registered).toContain('scan_plugin')
    expect(registered).toContain('audit_plugin')
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

  it('DSH 插件包（依赖 @deepseek-ai/cordis）：严格，process high → suspicious', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'evil-plugin', dependencies: { '@deepseek-ai/cordis': '^4.0.1' } }),
      'index.js': 'process.env.HOME',
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('plugin')
      const res = scan(request)
      expect(res.report!.verdict).toBe('suspicious')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('vet 自身（PACKAGE_NAME）→ generic（信任锚豁免）', () => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: PACKAGE_NAME, dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'index.js': 'process.execPath',
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      expect(request.targetKind).toBe('generic')
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
