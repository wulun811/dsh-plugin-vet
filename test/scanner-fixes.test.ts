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
