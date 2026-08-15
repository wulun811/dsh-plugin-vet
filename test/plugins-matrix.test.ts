import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { createScanPluginTool } from '../lib/tools/scan-plugin.js'
import { installToolExecuteGuard } from '../lib/guards/tool-execute.js'
import type { ScanRequest, ScanResponse } from '../lib/scanner-bin/protocol.js'
import type { VetConfig } from '../lib/config.js'

const scanCode = (code: string, language: 'js' | 'ts', runtime: 'host' | 'sandbox', kind: 'code' | 'files' = 'code'): ScanResponse => {
  if (kind === 'files') {
    // files 模式需要真实文件路径：写入临时文件再扫
    const dir = mkdtempSync(join(tmpdir(), 'vet-matrix-'))
    const file = join(dir, 'sample.js')
    writeFileSync(file, code)
    const res = scan({ kind: 'files', files: [file] })
    rmSync(dir, { recursive: true, force: true })
    return res
  }
  return scan({ kind, language, runtime, code } as ScanRequest)
}

interface Sample {
  name: string
  code: string
  language: 'js' | 'ts'
  runtime: 'host' | 'sandbox'
  kind?: 'code' | 'files'
  verdict: 'critical' | 'suspicious' | 'clean'
  rules: string[]
}

// 对抗矩阵：真实攻击形态 × 各规则 × 场景分级（PLAN.md §4.3/§9.1 扩展）
const SAMPLES: Sample[] = [
  // --- 构造器链逃逸（R1/R4，critical） ---
  { name: '动态插件 TextEncoder 构造器', code: `TextEncoder.constructor("return process")().cwd()`, language: 'js', runtime: 'sandbox', verdict: 'critical', rules: ['R1', 'R4'] },
  { name: 'workflow agent 构造器', code: `agent.constructor("return process")()`, language: 'js', runtime: 'sandbox', verdict: 'critical', rules: ['R1', 'R4'] },
  { name: 'workflow parallel 构造器', code: `parallel.constructor("return process")()`, language: 'js', runtime: 'sandbox', verdict: 'critical', rules: ['R1', 'R4'] },
  // --- process 直访（R3，runtime 分级） ---
  { name: 'run_code getBuiltinModule（host）', code: `return process.getBuiltinModule('child_process').spawnSync('ls')`, language: 'ts', runtime: 'host', verdict: 'critical', rules: ['R3'] },
  { name: '同代码 sandbox（降级 high）', code: `return process.getBuiltinModule('child_process').spawnSync('ls')`, language: 'ts', runtime: 'sandbox', verdict: 'suspicious', rules: ['R3'] },
  { name: 'process.exit（host）', code: `process.exit(1)`, language: 'js', runtime: 'host', verdict: 'critical', rules: ['R3'] },
  { name: 'process.env（files）', code: `const p = process.env.HOME`, language: 'js', runtime: 'host', kind: 'files', verdict: 'suspicious', rules: ['R3'] },
  { name: 'typeof process 探测', code: `if (typeof process !== 'undefined') {}`, language: 'js', runtime: 'sandbox', verdict: 'clean', rules: ['R3'] },
  // --- 动态执行（R2） ---
  { name: 'eval 动态执行', code: `const x = eval('process.exit()')`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R2'] },
  { name: 'new Function 含逃逸串', code: `const f = new Function('return process.env')`, language: 'js', runtime: 'host', verdict: 'critical', rules: ['R2'] },
  { name: 'new AsyncFunction', code: `const f = new AsyncFunction('return 1')`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R2'] },
  { name: 'vm.runInContext', code: `vm.runInContext('x', sandbox)`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R2'] },
  { name: 'require 危险模块（files→high）', code: `const cp = require('child_process')`, language: 'js', runtime: 'host', kind: 'files', verdict: 'suspicious', rules: ['R2'] },
  { name: '沙箱内顶级 const require（降噪）', code: `const fs = require('fs')`, language: 'js', runtime: 'sandbox', verdict: 'clean', rules: [] },
  // --- 硬编码密钥（R7） ---
  { name: 'sk- API key', code: `const k = 'sk-abcdefghijklmnopqrstuvwxyz1234567890'`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R7'] },
  { name: 'env 密钥赋值', code: `const KEY = 'DEEPSEEK_API_KEY=sk-123456789012345678901234567890'`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R7'] },
  // --- ctx 逃逸尝试（R5，medium 不升级 verdict） ---
  { name: 'ctx.plugin（withheld）', code: `ctx.plugin({})`, language: 'js', runtime: 'sandbox', verdict: 'clean', rules: ['R5'] },
  // --- 混淆（R6，info 不升级） ---
  { name: '拼接逃逸', code: `const s = "return " + "process"; X.constructor(s)()`, language: 'js', runtime: 'host', verdict: 'critical', rules: ['R1', 'R6'] },
  { name: 'fromCharCode 混淆', code: `const s = String.fromCharCode(114,101,116,117,114,110)`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R6'] },
  // --- 负例（不得误报） ---
  { name: '参数遮蔽 process', code: `function f(process) { return process.pid }`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '干净工具插件', code: `export function apply(ctx) { ctx.tools.register(defineTool({ name: 't' })) }`, language: 'ts', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '良性文件插件（files）', code: `module.exports = { apply(ctx) { ctx.on('ready', () => {}) } }`, language: 'js', runtime: 'host', kind: 'files', verdict: 'clean', rules: [] },
]

describe('对抗矩阵：不同插件形态识别', () => {
  for (const s of SAMPLES) {
    it(`${s.name} → ${s.verdict}`, () => {
      const res = scanCode(s.code, s.language, s.runtime, s.kind)
      expect(res.ok).toBe(true)
      const r = res.report!
      expect(r.verdict).toBe(s.verdict)
      for (const rule of s.rules) {
        expect(r.findings.some(f => f.rule === rule)).toBe(true)
      }
    })
  }
})

describe('多文件插件包（files 模式 + 文件归因）', () => {
  it('良性 index + 恶意 helper + 密钥 config → critical，findings 带文件', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-pkg-'))
    try {
      writeFileSync(join(dir, 'index.js'), `module.exports = { apply(ctx) { ctx.on('ready', () => {}) } }`)
      writeFileSync(join(dir, 'helper.js'), 'module.exports = TextEncoder.constructor("return process")().cwd()')
      writeFileSync(join(dir, 'config.js'), `const k = 'sk-123456789012345678901234567890'`)
      const res = scan({ kind: 'files', files: [join(dir, 'index.js'), join(dir, 'helper.js'), join(dir, 'config.js')] })
      expect(res.ok).toBe(true)
      const r = res.report!
      expect(r.verdict).toBe('critical')
      const r1 = r.findings.find(f => f.rule === 'R1')
      expect(r1).toBeDefined()
      expect(r1!.file).toBe('helper.js')
      const r7 = r.findings.find(f => f.rule === 'R7')
      expect(r7!.file).toBe('config.js')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('scan_plugin 工具（package 模式）→ 评分卡 critical', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-tool-'))
    try {
      writeFileSync(join(dir, 'index.js'), 'module.exports = { ok: true }')
      writeFileSync(join(dir, 'evil.js'), 'agent.constructor("return process")()')
      const tool = createScanPluginTool()
      const value = await tool.execute({ target: 'package', packagePath: dir }, { signal: new AbortController().signal } as never)
      expect(value.static.verdict).toBe('critical')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('真实 DSH 插件误报测试（官方包，不得误杀 critical）', () => {
  const REAL = [
    ['session-title-llm', '/home/chen/1q/plugin-vet/dsh-src/packages/session/session-title-llm/src'],
    ['timeout-policy', '/home/chen/1q/plugin-vet/dsh-src/packages/guard/timeout-policy/src'],
    ['tool-skill', '/home/chen/1q/plugin-vet/dsh-src/packages/skill/tool-skill/src'],
  ] as const
  for (const [name, dir] of REAL) {
    it(`${name} 无 false-critical`, () => {
      const res = scan({ kind: 'files', files: [dir] })
      expect(res.ok).toBe(true)
      const r = res.report!
      expect(r.verdict).not.toBe('critical')
      console.log(`  [真实插件] ${name}: verdict=${r.verdict} score=${r.staticScore} findings=${r.findings.length}`)
    })
  }
})

describe('guard 端到端：cordis_define 拦截（A4 路径）', () => {
  const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
    mode: 'report', autoScan: true, autoAudit: false, auditMaxTokens: 2048, auditTimeoutMs: 120_000,
    scannerTimeoutMs: 15_000, auditCacheTtlHours: 168, rules: {}, denyOn: 'critical', allowlist: [], ...over,
  })
  it('deny 模式：cordis_define 的 host 半含逃逸 → isError', async () => {
    const handlers = new Map<string, Function[]>()
    const ctx = {
      tools: { register: () => {} },
      logger: { info: () => {}, error: () => {} },
      on: (event: string, h: Function) => { handlers.set(event, [...(handlers.get(event) ?? []), h]) },
    }
    installToolExecuteGuard(ctx as never, cfg({ mode: 'deny', denyOn: 'critical' }))
    const handler = handlers.get('tools/execute')![0]
    const exec = {
      name: 'cordis_define',
      arguments: { name: 'x', purpose: 'y', code: { host: 'TextEncoder.constructor("return process")()' } },
      signal: new AbortController().signal,
    }
    const next = async () => ({ isError: false, value: {}, content: [{ type: 'text', text: 'OK' }] })
    const result = await handler(exec, next)
    expect(result.isError).toBe(true)
  })
})
