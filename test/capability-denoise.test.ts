import { describe, expect, it } from 'vitest'
import ts from 'typescript'
import { extractCapabilities } from '../lib/scanner-bin/capability.js'

function sf(code: string): ts.SourceFile {
  return ts.createSourceFile('x.ts', code, ts.ScriptTarget.Latest, true)
}

describe('capability 提取降噪（0.1.21）', () => {
  it('bundle 自带同名 fork/exec 辅助函数（无 child_process 引用）→ 不再误报执行能力', () => {
    const m = extractCapabilities(sf("function fork(x) { return x * 2 } function exec(s) { return s } const r = fork(1) + exec(2)"))
    expect(m.hasExec).toBe(false)
  })

  it('文件确实引用 child_process 时，裸 exec 标识符仍计为执行能力', () => {
    const m = extractCapabilities(sf("import { exec } from 'child_process'; exec('ls')"))
    expect(m.hasExec).toBe(true)
  })

  it('模板拼接残片主机名（如左方括号）被形状校验拒绝', () => {
    const m = extractCapabilities(sf("const u = `ws://[${host}]:${port}`"))
    expect(m.hosts).not.toContain('[')
  })

  it('注释样文本 / 报错文案 / 相对模块引用不再混入 fsPaths', () => {
    const m = extractCapabilities(sf([
      'const s = "// A windowed read keeps the file line numbers in the gutter."',
      'const msg = "surface replace: sourceEventSeqs must include every shadowed surface node"',
      'import x from "./api.ts"',
      'const y = "../rpc.ts"',
    ].join('\n')))
    expect(m.fsPaths).toEqual([])
  })

  it('真实路径字面量不受降噪影响', () => {
    const m = extractCapabilities(sf('const p = "/home/u/.ssh/id_rsa"; const q = "~/.aws/credentials"'))
    expect(m.fsPaths).toContain('/home/u/.ssh/id_rsa')
    expect(m.fsPaths).toContain('~/.aws/credentials')
  })

  it('realm 探测 shim（Function return this）不算动态执行；eval 仍算', () => {
    const m1 = extractCapabilities(sf('const g = Function("return this")()'))
    expect(m1.hasExec).toBe(false)
    const m2 = extractCapabilities(sf('eval("1+1")'))
    expect(m2.hasExec).toBe(true)
  })

  it('正常域名与 localhost 主机提取不受形状校验影响', () => {
    const m = extractCapabilities(sf('fetch("https://api.example.com/v1"); fetch("http://localhost:3000/x")'))
    expect(m.hosts).toContain('api.example.com')
    expect(m.hosts).toContain('localhost:3000')
  })
})
