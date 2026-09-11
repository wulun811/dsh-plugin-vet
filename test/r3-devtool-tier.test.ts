import { afterEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import type { Finding } from '../lib/scanner-bin/protocol.js'

/**
 * R3 dev/ops 脚本中间态（0.3.11→0.3.12）。
 * 背景：0.3.9 收窄 appShape 降级后，根级 dev/ops 脚本里的 process.exit 全部判 critical，
 * 注册站 8/329 插件 verdict 被单条 dev-script exit 推上最高档（dsh-dingtalk-3 的一条
 * check-pr-title.mjs:7 把 clean 插件推成 critical）。
 * 处置（①+② 合体，均不牺牲反漏报立场）：
 *  - **包根平铺**（相对 package.json 所在目录深度 1）的明确开发/运维动词脚本
 *    （check-pr-title.mjs / dev-install.mjs / uninstall.mjs / docker-init.mjs /
 *    register-plugin.mjs 等）的 process.exit/reallyExit → high + message 标记
 *    「dev-script」（仍在 verdict/评分，至少 suspicious，不再推 critical 档）；
 *  - 不参与：getBuiltinModule/mainModule/module（真实能力逃逸成员）、运行时文件名
 *    （transport/cli/desktop/start-* 等）、嵌套目录（scripts/、lib/、src/ 等——scripts/
 *    是产品代码，0.3.9 立场保持，见 integration-dsh-so #5）、无 package.json 上下文
 *    （根级无法界定，保守不降）、code 模式、sandbox 运行时。
 */
const PKG = JSON.stringify({ name: 'devtree-test', version: '1.0.0', main: 'index.js' })

function writeTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r3dev-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    mkdirSync(dirname(p), { recursive: true })
    writeFileSync(p, content)
  }
  return dir
}

function exitFindings(r: { findings: Finding[] }): Finding[] {
  return r.findings.filter(f => f.rule === 'R3' && f.message.includes('exit'))
}

describe('R3 dev/ops 脚本中间态（0.3.12 根级修正）', () => {
  let dir: string | undefined
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  it('包根平铺 check-pr-title.mjs → process.exit 降 high + dev-script 标记，verdict 不再 critical', () => {
    dir = writeTree({ 'package.json': PKG, 'check-pr-title.mjs': 'if (!ok) process.exit(1)\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'check-pr-title.mjs')] })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('suspicious')
    const exit = exitFindings(res.report!)[0]
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('high')
    expect(exit!.message).toContain('dev-script')
  })

  it('包根平铺 uninstall.mjs（globalThis[\'process\'].exit 元素访问形态）→ 同样降 high', () => {
    dir = writeTree({ 'package.json': PKG, 'uninstall.mjs': 'globalThis["process"].exit(2)\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'uninstall.mjs')] })
    expect(res.ok).toBe(true)
    const exit = exitFindings(res.report!)[0]
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('high')
    expect(exit!.message).toContain('dev-script')
  })

  it('包根平铺 dev-install.mjs（解构成员 exit 形态）→ 同样降 high', () => {
    dir = writeTree({ 'package.json': PKG, 'dev-install.mjs': 'const { exit } = process; if (bad) exit(1)\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'dev-install.mjs')] })
    expect(res.ok).toBe(true)
    const exit = res.report!.findings.find(f => f.rule === 'R3' && f.message.includes('解构成员'))
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('high')
    expect(exit!.message).toContain('dev-script')
  })

  it('嵌套目录不命中（0.3.12 根级修正）：scripts/check-pr-title.mjs、lib/install.js、src/dev-tool.mjs 保持 critical', () => {
    dir = writeTree({
      'package.json': PKG,
      'scripts/check-pr-title.mjs': 'if (!ok) process.exit(1)\n',
      'lib/install.js': 'if (!ok) process.exit(1)\n',
      'src/dev-tool.mjs': 'process.exit(1)\n',
    })
    const res = scan({ kind: 'files', files: ['scripts/check-pr-title.mjs', 'lib/install.js', 'src/dev-tool.mjs'].map(n => join(dir, n)).concat(join(dir, 'package.json')) })
    expect(res.ok).toBe(true)
    for (const f of exitFindings(res.report!)) {
      expect(f.severity, f.file).toBe('critical')
    }
    expect(res.report!.verdict).toBe('critical')
  })

  it('无 package.json 上下文 → 根级无法界定，保守不降（critical）', () => {
    dir = writeTree({ 'check-pr-title.mjs': 'if (!ok) process.exit(1)\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'check-pr-title.mjs')] })
    expect(res.ok).toBe(true)
    const exit = exitFindings(res.report!)[0]
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('critical')
  })

  it('运行时文件名不命中：transport.js / cli.ts / desktop.ts / start-http.mjs 保持 critical', () => {
    dir = writeTree({
      'package.json': PKG,
      'transport.js': 'function stop() { process.exit(0) }\n',
      'cli.ts': 'process.exit(0)\n',
      'desktop.ts': 'if (err) process.exit(1)\n',
      'start-http.mjs': 'process.exit(1)\n',
    })
    const res = scan({ kind: 'files', files: Object.keys({ 'package.json': 0, 'transport.js': 1, 'cli.ts': 1, 'desktop.ts': 1, 'start-http.mjs': 1 }).map(n => join(dir, n)) })
    expect(res.ok).toBe(true)
    for (const f of exitFindings(res.report!)) {
      expect(f.severity, f.file).toBe('critical')
    }
    expect(res.report!.verdict).toBe('critical')
  })

  it('0.3.9 立场保持：scripts/ 目录与孤立 build 名不命中（脚本是产品代码）', () => {
    dir = writeTree({ 'package.json': PKG, 'scripts/build.mjs': 'if (!ok) process.exit(1)\n', 'build.mjs': 'if (!ok) process.exit(1)\n' })
    const res = scan({ kind: 'files', files: Object.keys({ 'package.json': 0, 'scripts/build.mjs': 1, 'build.mjs': 1 }).map(n => join(dir, n)) })
    expect(res.ok).toBe(true)
    for (const f of exitFindings(res.report!)) {
      expect(f.severity, f.file).toBe('critical')
    }
  })

  it('能力逃逸成员不降：dev 脚本里的 getBuiltinModule 仍 critical', () => {
    dir = writeTree({ 'package.json': PKG, 'check-pr-title.mjs': 'process.getBuiltinModule("child_process")\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'check-pr-title.mjs')] })
    expect(res.ok).toBe(true)
    const exit = res.report!.findings.find(f => f.rule === 'R3' && f.message.includes('getBuiltinModule'))
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('critical')
  })

  it('test/CI 降级优先于 dev/ops：check-pr-title.test.mjs → info', () => {
    dir = writeTree({ 'package.json': PKG, 'check-pr-title.test.mjs': 'if (!ok) process.exit(1)\n' })
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'check-pr-title.test.mjs')] })
    expect(res.ok).toBe(true)
    const exit = exitFindings(res.report!)[0]
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('info')
    expect(res.report!.verdict).toBe('clean')
  })

  it('code 模式不受 dev/ops 中间态影响：process.exit(1) 仍 critical', () => {
    const res = scan({ kind: 'code', language: 'js', runtime: 'host', code: 'process.exit(1)' })
    expect(res.ok).toBe(true)
    const exit = exitFindings(res.report!)[0]
    expect(exit).toBeDefined()
    expect(exit!.severity).toBe('critical')
    expect(res.report!.verdict).toBe('critical')
  })

  it('reporter 8 例基线：dev 五件套降 high，运行时三件套保持 critical', () => {
    dir = writeTree({
      'package.json': PKG,
      'check-pr-title.mjs': 'if (!ok) process.exit(1)\n',
      'dev-install.mjs': 'process.exit(1)\n',
      'uninstall.mjs': 'process.exit(1)\n',
      'docker-init.mjs': 'process.exit(1)\n',
      'register-plugin.mjs': 'process.exit(1)\n',
      'transport.js': 'function stop() { process.exit(0) }\n',
      'cli.ts': 'process.exit(0)\n',
      'desktop.ts': 'if (err) process.exit(1)\n',
    })
    const names = ['package.json', 'check-pr-title.mjs', 'dev-install.mjs', 'uninstall.mjs', 'docker-init.mjs', 'register-plugin.mjs', 'transport.js', 'cli.ts', 'desktop.ts']
    const res = scan({ kind: 'files', files: names.map(n => join(dir, n)) })
    expect(res.ok).toBe(true)
    const devNames = new Set(['check-pr-title.mjs', 'dev-install.mjs', 'uninstall.mjs', 'docker-init.mjs', 'register-plugin.mjs'])
    for (const f of exitFindings(res.report!)) {
      if (devNames.has(f.file!)) {
        expect(f.severity, f.file).toBe('high')
      } else {
        expect(f.severity, f.file).toBe('critical')
      }
    }
  })
})