import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

function codeRequest(overrides: Partial<ScanRequest>): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string, severity?: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule && (severity === undefined || f.severity === severity))
}

/** 建临时目录返回文件列表（files 模式用）。 */
function tmpFiles(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-fix-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    writeFileSync(p, content)
  }
  return dir
}

describe('P1-9：isFactoryParamRequire 嵌套函数向上查找（factory 注入 require 不再误报 high）', () => {
  it('内层函数调用 require，外层 factory 有 require 形参 → info（不进 verdict）', () => {
    const code = `window.__ModuleLoader__.load({
      factory: (require) => {
        const helper = () => require('path')
        return helper()
      },
    })`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    const r2 = findingOf(res.report!, 'R2', 'info')
    expect(r2).toBeDefined()
    expect(r2!.message).toContain('factory 形参注入')
    expect(res.report!.verdict).toBe('clean')
  })

  it('无 factory 注入的模块级 require → files 模式保持 high（真实能力触达不丢）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-fix-r2-'))
    writeFileSync(join(dir, 'index.js'), "const helper = () => require('child_process')")
    try {
      const res = scan({ kind: 'files', files: [join(dir, 'index.js')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R2', 'high')).toBeDefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('P2-1：R2 eval/Function 局部遮蔽检查（const Function = safe 不误报 high）', () => {
  it('eval 被局部遮蔽 → 不报 high', () => {
    const code = `function run(eval) { return eval('x') }`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R2', 'high')).toBeUndefined()
  })

  it('Function 被 const 遮蔽 → 不报 high', () => {
    const code = `const Function = safeFn; Function('x')`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R2', 'high')).toBeUndefined()
  })

  it('真实 eval/Function 仍报 high（遮蔽检查不丢检测）', () => {
    const res = scan(codeRequest({ code: "eval('1+1')" }))
    expect(findingOf(res.report!, 'R2', 'high')).toBeDefined()
    const res2 = scan(codeRequest({ code: "Function('return 1')" }))
    expect(findingOf(res2.report!, 'R2', 'high')).toBeDefined()
  })
})

describe('P2-6：R11 fsBase 只认 fs/fs.promises（fsmap.rm 不误报）', () => {
  it('自定义对象 fsmap.rm() 不再误判为 fs 调用', () => {
    const dir = tmpFiles({ 'index.js': "const fsmap = { rm: () => {} }; fsmap.rm('/tmp/x')" })
    try {
      const res = scan({ kind: 'files', files: [join(dir, 'index.js')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R11')).toBeUndefined()
      expect(res.report!.verdict).toBe('clean')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('真 fs.rm 敏感路径仍报 high；fs 写集补全（copyFile 等）', () => {
    const dir = tmpFiles({
      'a.js': "const fs = require('fs'); fs.rm('/etc/hosts', { recursive: true })",
      'b.js': "const fs = require('fs'); fs.copyFileSync('/etc/hosts', '/tmp/stolen')",
    })
    try {
      const res = scan({ kind: 'files', files: [join(dir, 'a.js'), join(dir, 'b.js')] })
      expect(res.ok).toBe(true)
      const r11 = res.report!.findings.filter(f => f.rule === 'R11' && f.severity === 'high')
      expect(r11.length).toBeGreaterThanOrEqual(2)
      // copyFileSync 命中的是写集补全
      expect(r11.some(f => f.message.includes('copyFileSync'))).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('fs.promises 调用仍被识别（两段式 base）', () => {
    const dir = tmpFiles({ 'p.js': "const fs = require('fs'); fs.promises.unlink('/etc/hosts')" })
    try {
      const res = scan({ kind: 'files', files: [join(dir, 'p.js')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R11', 'high')).toBeDefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('round-7（外部第二轮实测）回归：R2 括号形态、R4 原型污染、R9 ReDoS/递归、应用型降级', () => {
  // P1: R2 new (Function) 括号形态漏检（外部对抗样本）
  it('R2: new (Function)("return process") 括号包裹 callee → critical（此前漏检）', () => {
    const res = scan(codeRequest({ code: "const f = new (Function)('return process')" }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('critical')
    expect(findingOf(res.report!, 'R2', 'critical')).toBeDefined()
  })
  it('R2: (async()=>{}).constructor 括号包裹 base → high', () => {
    const res = scan(codeRequest({ code: "(async()=>{}).constructor('return 1')" }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R2', 'high')).toBeDefined()
  })
  // P1: R4 宿主全局原型污染
  it('R4: 对抗样本 TextEncoder.prototype.encode 覆盖赋值 → R2+R4 critical（此前 verdict=clean）', () => {
    const code = "TextEncoder.prototype.encode = function(){ return new (Function)('return process')().mainModule.require('child_process').execSync('id') }"
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('critical')
    expect(findingOf(res.report!, 'R2', 'critical')).toBeDefined() // new (Function) 逃逸串
    expect(findingOf(res.report!, 'R4', 'critical')).toBeDefined() // 原型污染
  })
  it('R4: Object.prototype.polluted = true → code critical / files-plugin high / files-generic 也 high（round-7.1 P-3：污染语义与 targetKind 无关，不再降 info）', () => {
    const code = 'Object.prototype.polluted = true'
    const c = scan(codeRequest({ code }))
    expect(findingOf(c.report!, 'R4', 'critical')).toBeDefined()
    const dir = tmpFiles({
      'package.json': JSON.stringify({ name: 'p', dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'index.js': code,
    })
    try {
      const plugin = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'index.js')], targetKind: 'plugin' })
      const g = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'index.js')], targetKind: 'generic' })
      expect(findingOf(plugin.report!, 'R4', 'high')).toBeDefined()
      expect(findingOf(g.report!, 'R4', 'high')).toBeDefined()
      expect(findingOf(g.report!, 'R4', 'info')).toBeUndefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  it('R4: Object.defineProperty(TextEncoder.prototype, ...) 形态 → 也报', () => {
    const res = scan(codeRequest({ code: "Object.defineProperty(TextEncoder.prototype, 'encode', { value: fn })" }))
    expect(findingOf(res.report!, 'R4', 'critical')).toBeDefined()
  })
  // P3: R9 可选组 (https?:)? 误报（外部实测 dsh-wechat-mp markdown.js）
  it('R9: /^(https?:)?\/\//i 组后 ? → 不报 ReDoS（此前误报 medium）', () => {
    const res = scan(codeRequest({ code: 'const re = /^(https?:)?\/\//i' }))
    expect(res.ok).toBe(true)
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('ReDoS'))).toBe(false)
  })
  it('R9: (\\d+)+ 组后 + → 仍报 ReDoS', () => {
    const res = scan(codeRequest({ code: 'const re = /(\\d+)+$/' }))
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('ReDoS'))).toBe(true)
  })
  // P4d: R9 有界遍历递归（外部实测 dsh-tui zeroLayoutRecursive）
  it('R9: for-of 树遍历自调用 → 不报递归无终止（此前误报 medium）', () => {
    const res = scan(codeRequest({ code: 'function walk(node) { for (const c of node.children) { walk(c) } }' }))
    expect(res.ok).toBe(true)
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('递归无终止'))).toBe(false)
  })
  it('R9: while(true) 内自调用 → 仍报递归无终止', () => {
    const res = scan(codeRequest({ code: 'function f() { while (true) { f() } }' }))
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('递归无终止'))).toBe(true)
  })
  // P4a/P4c: 应用型包 + bin 入口降级（外部实测 dsh-tui/dsh-bridges/dsh-web-open）
  it('P4: 应用型包（bin 声明）process 访问全降 info；无 bin 插件包副作用成员（kill）保持 high', () => {
    const app = tmpFiles({
      'package.json': JSON.stringify({ name: 'tui-app', bin: { app: './cli.js' } }),
      'cli.js': 'process.exit(0)',
      'app.js': 'const home = process.env.HOME; process.stdout.write(home)',
    })
    const plain = tmpFiles({
      'package.json': JSON.stringify({ name: 'plain-plugin', dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'app.js': "process.kill(1234, 'SIGTERM')",
    })
    try {
      const r = scan({ kind: 'files', files: [join(app, 'package.json'), join(app, 'cli.js'), join(app, 'app.js')], targetKind: 'plugin' })
      expect(r.ok).toBe(true)
      expect(r.report!.verdict).toBe('clean')
      // bin 入口文件（CLI 面）+ 应用型包 app 代码全部降 info（env/stdout 只读成员本就 info）
      expect(r.report!.findings.filter(f => f.rule === 'R3' && f.severity === 'info').length).toBeGreaterThanOrEqual(3)
      expect(r.report!.findings.filter(f => f.rule === 'R3' && (f.severity === 'critical' || f.severity === 'high')).length).toBe(0)
      // 对照组：无 bin 的插件包 process.kill（副作用成员）→ 仍 high → suspicious
      const p = scan({ kind: 'files', files: [join(plain, 'package.json'), join(plain, 'app.js')], targetKind: 'plugin' })
      expect(p.report!.verdict).toBe('suspicious')
      expect(findingOf(p.report!, 'R3', 'high')).toBeDefined()
    } finally {
      rmSync(app, { recursive: true, force: true })
      rmSync(plain, { recursive: true, force: true })
    }
  })
  it('P-2: 拼接形态的 process.pid（原子写临时名，wechat-mp token.js 同款）→ info 不进 verdict', () => {
    const res = scan(codeRequest({ code: 'const temp = this.cacheFile + "." + process.pid + ".tmp"' }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    expect(findingOf(res.report!, 'R3', 'info')).toBeDefined()
    expect(findingOf(res.report!, 'R3', 'high')).toBeUndefined()
  })
  it('P-1: process.cwd/platform 只读成员（bridges 类无 bin 插件）→ info，verdict clean', () => {
    const dir = tmpFiles({
      'package.json': JSON.stringify({ name: 'bridge-tool', dependencies: { '@deepseek-ai/dsh-tools': '^0.1.0-rc.6' } }),
      'bridge.js': "const d = process.cwd(); const plat = process.platform; const v = process.versions.node",
    })
    try {
      const files = [join(dir, 'package.json'), join(dir, 'bridge.js')]
      const r = scan({ kind: 'files', files, targetKind: 'plugin' })
      expect(r.ok).toBe(true)
      expect(r.report!.verdict).toBe('clean')
      expect(r.report!.findings.filter(f => f.rule === 'R3' && f.severity === 'info').length).toBeGreaterThanOrEqual(3)
      expect(r.report!.findings.some(f => f.rule === 'R3' && f.severity === 'high')).toBe(false)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  it('P4c: bin 入口文件 require(child_process) → R2 medium（CLI 面）；非 bin 插件文件保持 high', () => {
    const dir = tmpFiles({
      'package.json': JSON.stringify({ name: 'hybrid', bin: { run: './run.js' } }),
      'run.js': "const cp = require('child_process'); cp.spawnSync('x')",
      'plugin.js': "const cp = require('child_process'); cp.spawn('y')",
    })
    try {
      const files = [join(dir, 'package.json'), join(dir, 'run.js'), join(dir, 'plugin.js')]
      const r = scan({ kind: 'files', files, targetKind: 'plugin' })
      expect(r.ok).toBe(true)
      const r2 = r.report!.findings.filter(f => f.rule === 'R2' && f.severity === 'medium')
      expect(r2.some(f => f.file === 'run.js' && (f.message || '').includes('CLI/bin 入口'))).toBe(true)
      expect(r.report!.findings.some(f => f.rule === 'R2' && f.severity === 'high' && f.file === 'plugin.js')).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  // P4b: R6 混淆组合证据（外部实测 dsh-tui 终端解析 42 条误报）
  it('P4b: charCodeAt 独立 → 无 R6 混淆；charCodeAt/fromCharCode + eval → R6 报', () => {
    const lone = scan(codeRequest({ code: 'function parse(s) { return s.charCodeAt(0) }' }))
    expect(lone.report!.findings.some(f => f.rule === 'R6' && (f.message || '').includes('混淆'))).toBe(false)
    const combo = scan(codeRequest({ code: 'const s = String.fromCharCode(114,101); eval(s)' }))
    expect(combo.report!.findings.some(f => f.rule === 'R6' && (f.message || '').includes('混淆'))).toBe(true)
  })
})

describe('P2-9：R7 占位符按段排除（真实 key 混 example 文本不再整段跳过）', () => {
  it('sk- 真实 key 与 example 文本同串 → 仍报 R7', () => {
    const code = `const k = 'sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c example'`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R7', 'high')).toBeDefined()
  })

  it('纯占位符（your-key / xxx）→ 不报', () => {
    const code = `const k = 'your-key-here-please'`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R7')).toBeUndefined()
  })

  it('占位符与 key 重叠段（sk-xxx...）→ 排除', () => {
    // xxx 与 sk- 段重叠：命中段落在占位符内 → 不报（防示例误报）
    const code = `const k = 'sk-xxxxx'`
    const res = scan(codeRequest({ code }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R7')).toBeUndefined()
  })
})
