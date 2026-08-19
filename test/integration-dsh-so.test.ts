import { afterEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'

function writeTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-dshso-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    mkdirSync(dirname(p), { recursive: true })
    writeFileSync(p, content)
  }
  return dir
}

describe('R3 测试/CI 文件上下文降级 (dsh.so 静态注册站)', () => {
  let dir: string | undefined
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  it('coverage.mjs 内 process.exit/kill 降 info，verdict clean', () => {
    dir = writeTree({ 'coverage.mjs': 'if (bad) process.exit(1)\nprocess.kill(1, "SIGTERM")\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'coverage.mjs')] })
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.verdict).toBe('clean')
    for (const f of r.findings.filter(f => f.rule === 'R3')) expect(f.severity).toBe('info')
  })

  it('*.test.* / *.e2e.* 同样降级', () => {
    dir = writeTree({ 'a.test.ts': 'process.exit(2)', 'b.e2e.mjs': 'process.kill(3)' })
    const res = scan({ kind: 'files', files: [join(dir, 'a.test.ts'), join(dir, 'b.e2e.mjs')] })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    for (const f of res.report!.findings.filter(f => f.rule === 'R3')) expect(f.severity).toBe('info')
  })

  it('test/ 子目录文件降级', () => {
    dir = writeTree({ 'test/runner.ts': 'process.exit(1)' })
    const res = scan({ kind: 'files', files: [join(dir, 'test/runner.ts')] })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    for (const f of res.report!.findings.filter(f => f.rule === 'R3')) expect(f.severity).toBe('info')
  })

  it('真实源码 (非测试文件) process.exit 仍 critical', () => {
    dir = writeTree({ 'src/server.js': 'function shutdown() { process.exit(1) }' })
    const res = scan({ kind: 'files', files: [join(dir, 'src/server.js')] })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('critical')
    const exit = res.report!.findings.find(f => f.rule === 'R3' && f.message.includes('exit'))
    expect(exit?.severity).toBe('critical')
  })

  it('scripts/ 目录是产品代码，process.exit 不降级（#5：scripts 曾是测试/CI 白名单）', () => {
    dir = writeTree({ 'scripts/build.mjs': 'if (!ok) process.exit(1) // 构建脚本属产品面' })
    const res = scan({ kind: 'files', files: [join(dir, 'scripts/build.mjs')] })
    expect(res.ok).toBe(true)
    const exit = res.report!.findings.find(f => f.rule === 'R3' && f.message.includes('exit'))
    expect(exit?.severity).toBe('critical')
  })
})

describe('R12 scanBasis git 降级 (dsh.so 静态注册站)', () => {
  let dir: string | undefined
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  const pluginPkg = JSON.stringify({
    name: 'demo-plugin',
    dependencies: { '@deepseek-ai/cordis': '^1.0.0' },
    main: 'lib/index.js',
  }, null, 2)

  it('git 基础：声明入口文件缺失降 info，verdict clean', () => {
    dir = writeTree({ 'package.json': pluginPkg })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json')], scanBasis: 'git' })
    expect(res.ok).toBe(true)
    const r12 = res.report!.findings.filter(f => f.rule === 'R12')
    expect(r12.length).toBeGreaterThan(0)
    for (const f of r12) expect(f.severity).toBe('info')
    expect(res.report!.verdict).toBe('clean')
  })

  it('npm 基础 (默认)：声明入口文件缺失仍 high，verdict suspicious', () => {
    dir = writeTree({ 'package.json': pluginPkg })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json')], scanBasis: 'npm' })
    expect(res.ok).toBe(true)
    const entryMissing = res.report!.findings.find(f => f.rule === 'R12' && f.message.includes('入口文件缺失'))
    expect(entryMissing?.severity).toBe('high')
    expect(res.report!.verdict).toBe('suspicious')
  })
})

describe('R3 只读成员 info 不进 verdict (dsh.so 静态注册站)', () => {
  it('同文件多次 process.env 只读访问均为 info，verdict 仍 clean（info 权重 0，纯能力触达面）', () => {
    const dir = writeTree({ 'app.js': [
      'const a = process.env.A',
      'const b = process.env.B',
      'const c = process.env.C',
      'const d = process.env.D',
      'const e = process.env.E',
    ].join('\n') })
    const res = scan({ kind: 'files', files: [join(dir, 'app.js')] })
    expect(res.ok).toBe(true)
    const envInfos = res.report!.findings.filter(f => f.rule === 'R3' && f.severity === 'info' && f.message.includes('只读'))
    expect(envInfos.length).toBe(5)
    expect(res.report!.verdict).toBe('clean')
    rmSync(dir, { recursive: true, force: true })
  })
})
