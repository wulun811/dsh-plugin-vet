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
  // --- 资源安全（R9，high/info，不升级 critical，§14.1） ---
  { name: 'new Array 无界分配', code: `const a = new Array(2 ** 31)`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R9'] },
  { name: 'Buffer.alloc 巨大缓冲', code: `Buffer.alloc(1 << 30)`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R9'] },
  { name: 'Array.from 无界 length', code: `const a = Array.from({ length: 1e9 })`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R9'] },
  { name: '无出口同步死循环', code: `while (true) { arr.push(1) }`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R9'] },
  { name: 'for(;;) 内 spawn（fork 炸弹）', code: `for (;;) { spawn('node') }`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R9'] },
  // --- R9 负例（不得误报） ---
  { name: '异步常驻循环（合法服务）', code: `while (true) { await tick() }`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  { name: '正常有限循环', code: `for (let i = 0; i < 10; i++) { f(i) }`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '小分配 Buffer.alloc(1024)', code: `Buffer.alloc(1024)`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '非字面条件循环', code: `while (flag) { if (done) break }`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  // --- R9-2（medium/info，不升级 verdict） ---
  { name: 'ReDoS 嵌套量词正则字面量', code: `const re = /(a+)+/`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  { name: 'ReDoS new RegExp 构造', code: `const re = new RegExp('(a+)+')`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  { name: '递归无终止（直接自调用无条件）', code: `function f() { return f() }`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  { name: '箭头递归无终止', code: `const f = () => f()`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  // --- R9-2 负例（有条件递归/合法正则，不得误报） ---
  { name: '有条件递归（三元）', code: `function fib(n) { return n < 2 ? n : fib(n - 1) + fib(n - 2) }`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '非嵌套量词正则', code: `const re = /ab+c/`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  // --- R9-3（info/medium 提示档） ---
  { name: '循环内 Map.set（medium 不升级）', code: `for (const k of keys) { m.set(k, v) }`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  { name: '循环内 +=（info）', code: `for (let i = 0; i < n; i++) { s += item }`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R9'] },
  // --- 破坏性行为（R11，high/medium） ---
  { name: '删除敏感路径 /etc/passwd', code: `fs.unlinkSync('/etc/passwd')`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R11'] },
  { name: '删除敏感路径 /root/secret', code: `fs.rmSync('/root/secret')`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R11'] },
  { name: '写入敏感路径 /etc/hosts', code: `fs.writeFileSync('/etc/hosts', 'x')`, language: 'js', runtime: 'host', verdict: 'suspicious', rules: ['R11'] },
  // --- R11 负例（清理/临时文件，不得误报） ---
  { name: '删除临时文件（medium 不升级）', code: `fs.unlinkSync('/tmp/cache/x')`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R11'] },
  { name: '删除变量路径（非字面量）', code: `fs.unlinkSync(tempFile)`, language: 'js', runtime: 'host', verdict: 'clean', rules: ['R11'] },
  { name: '读取敏感路径（不属破坏）', code: `fs.readFileSync('/etc/passwd')`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
  { name: '写入临时路径', code: `fs.writeFileSync('/tmp/x', 'y')`, language: 'js', runtime: 'host', verdict: 'clean', rules: [] },
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

describe('供应链扫描（R10，package.json）', () => {
  const scanPkg = (pkg: Record<string, unknown>) => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r10-'))
    const file = join(dir, 'package.json')
    writeFileSync(file, JSON.stringify(pkg))
    const res = scan({ kind: 'files', files: [file] })
    rmSync(dir, { recursive: true, force: true })
    return res
  }
  it('install 钩子 → suspicious + R10', () => {
    const res = scanPkg({ name: 'x', scripts: { postinstall: 'node install.js' } })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('suspicious')
    expect(res.report!.findings.some(f => f.rule === 'R10')).toBe(true)
  })
  it('依赖清单 → info，verdict clean', () => {
    const res = scanPkg({ name: 'x', dependencies: { lodash: '^4', axios: '^1' } })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    expect(res.report!.findings.filter(f => f.rule === 'R10').length).toBeGreaterThan(0)
  })
  it('无钩子无依赖 → clean 无 R10', () => {
    const res = scanPkg({ name: 'x', version: '1.0.0' })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    expect(res.report!.findings.some(f => f.rule === 'R10')).toBe(false)
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
