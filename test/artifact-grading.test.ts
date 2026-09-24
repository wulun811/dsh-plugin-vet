import { describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan, artifactKind } from '../lib/scanner-bin/engine.js'
import type { ScanRequest } from '../lib/scanner-bin/protocol.js'

/**
 * 0.3.13（DSH 0.1.7-rc.1 同步）：非授权源码产物分类 + 官方包降噪。
 *
 * 背景：官方家族整体换版本后首见严格扫描把发布物里的机器产物（lib/** 编译输出、压缩
 * bundle、.d.ts）当人写源码判——实测 0.1.7-rc.1 首扫 277 个官方包 27 个 non-clean
 * （4 critical），live 自动扫描已记 5 个 suspicious 并把盾牌压成黄色。
 * 纪律：只对**官方目录成员**（request.officialFamily）折 critical/high → info；第三方包
 * 只加「构建产物：」标注、severity 全量保留；授权源码（src/**、根级脚本、package.json）
 * 不降噪；身份核验仍由哈希基线 + registry 对账负责。
 */

const CRITICAL_SOURCE = 'const f = process.getBuiltinModule("fs")\nmodule.exports = f\n'
const HIGH_SOURCE = 'module.exports = () => process.kill(1, "SIGTERM")\n'

function pkg(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-artifact-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    mkdirSync(dirname(p), { recursive: true })
    writeFileSync(p, content)
  }
  return dir
}

function scanPkg(dir: string, extra: Partial<ScanRequest> = {}) {
  const res = scan({ kind: 'files', files: listFiles(dir), cacheDir: join(dir, '.cache'), targetKind: 'plugin', ...extra })
  expect(res.ok).toBe(true)
  return res.report!
}

/** 递归列目录（测试内联，避免依赖宿主枚举的过滤策略）。 */
function listFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.cache') continue
    const p = join(dir, e.name)
    if (e.isDirectory()) listFiles(p, out)
    else out.push(p)
  }
  return out
}

describe('artifactKind：产物分类判据（0.3.13）', () => {
  it('.d.ts → 类型声明', () => {
    expect(artifactKind('/x/pkg/lib/types/a.d.ts', 'export type A = 1\n')).toBe('类型声明')
  })
  it('包根相对路径含构建输出目录 → 构建产物', () => {
    expect(artifactKind('/x/pkg/lib/index.js', 'export {}\n', '/x/pkg')).toBe('构建产物')
    expect(artifactKind('/x/pkg/dist/assets/index.js', 'export {}\n', '/x/pkg')).toBe('构建产物')
  })
  it('回归：绝对路径里的 npm 全局前缀 lib/ 不得误判（~/.npm-global/lib/node_modules/…）', () => {
    // 实测踩过的坑：按绝对路径段判定会把 /home/u/.npm-global/lib/… 下**整包**判成产物
    expect(artifactKind('/home/u/.npm-global/lib/node_modules/@s/p/src/utils.ts', 'export {}\n', '/home/u/.npm-global/lib/node_modules/@s/p')).toBeUndefined()
  })
  it('授权源码（src/**、根级脚本）→ undefined', () => {
    expect(artifactKind('/x/pkg/src/index.ts', 'export {}\n', '/x/pkg')).toBeUndefined()
    expect(artifactKind('/x/pkg/build.mjs', 'process.exit(1)\n', '/x/pkg')).toBeUndefined()
    expect(artifactKind('/x/pkg/index.js', 'export {}\n', '/x/pkg')).toBeUndefined()
  })
  it('压缩内容特征 → 压缩产物（单行 ≥1000 / ≥3 行超 500）', () => {
    expect(artifactKind('/x/pkg/bundle.js', 'var a=1;'.repeat(200) + '\n', '/x/pkg')).toBe('压缩产物')
    const threeLong = ('x'.repeat(600) + '\n').repeat(3)
    expect(artifactKind('/x/pkg/bundle.js', threeLong, '/x/pkg')).toBe('压缩产物')
    // 两行超长不算（避免把正常长行源码误判）
    expect(artifactKind('/x/pkg/normal.js', ('x'.repeat(600) + '\n').repeat(2), '/x/pkg')).toBeUndefined()
  })
})

describe('官方包产物降噪（request.officialFamily，0.3.13）', () => {
  it('lib/ 里的 critical → 官方折 info（带前缀），第三方保留 critical', () => {
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'lib/index.js' }), 'lib/index.js': CRITICAL_SOURCE })
    try {
      const off = scanPkg(dir)
      expect(off.verdict).toBe('critical')
      const offF = off.findings.find(f => f.rule === 'R3')!
      expect(offF.severity).toBe('critical')
      expect(offF.message).toContain('构建产物：')
      expect(offF.message).not.toContain('官方包降噪')

      const on = scanPkg(dir, { officialFamily: true })
      expect(on.verdict).toBe('clean')
      expect(on.staticScore).toBe(100)
      const onF = on.findings.find(f => f.rule === 'R3')!
      expect(onF.severity).toBe('info')
      expect(onF.message).toContain('构建产物（官方包降噪）：')
      // 命中内容与证据保留（只降档、不隐藏）
      expect(onF.message).toContain('process.getBuiltinModule')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('授权源码（src/）不降噪：官方包 src 命中仍进 verdict', () => {
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'src/index.js' }), 'src/index.js': HIGH_SOURCE })
    try {
      const on = scanPkg(dir, { officialFamily: true })
      expect(on.verdict).toBe('suspicious')
      const f = on.findings.find(x => x.rule === 'R3')!
      expect(f.severity).toBe('high')
      expect(f.message).not.toContain('构建产物')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('根级压缩 bundle（无 lib/）→ 压缩产物，官方折 info', () => {
    const minified = 'var a=1;'.repeat(200)
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'bundle.js' }), 'bundle.js': minified + ';process.kill(1,2)\n' })
    try {
      const on = scanPkg(dir, { officialFamily: true })
      const f = on.findings.find(x => x.rule === 'R3')!
      expect(f.severity).toBe('info')
      expect(f.message).toContain('压缩产物（官方包降噪）：')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('.d.ts 声明里的命中 → 类型声明降噪（官方），第三方只标注', () => {
    const decl = 'export declare const k: string\nexport const boom = () => process.kill(1, 2)\n'
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', types: 'lib/a.d.ts' }), 'lib/a.d.ts': decl })
    try {
      const off = scanPkg(dir)
      const offF = off.findings.find(x => x.rule === 'R3')!
      expect(offF.severity).toBe('high')
      expect(offF.message).toContain('类型声明：')
      const on = scanPkg(dir, { officialFamily: true })
      const onF = on.findings.find(x => x.rule === 'R3')!
      expect(onF.severity).toBe('info')
      expect(onF.message).toContain('类型声明（官方包降噪）：')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('缓存不串味：同字节同缓存目录，officialFamily 开关结果各自独立', () => {
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'lib/index.js' }), 'lib/index.js': HIGH_SOURCE })
    try {
      const a = scanPkg(dir, { officialFamily: true })
      const b = scanPkg(dir)
      expect(a.verdict).toBe('clean')
      expect(b.verdict).toBe('suspicious')
      const again = scanPkg(dir, { officialFamily: true })
      expect(again.verdict).toBe('clean')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('官方包的 install 钩子走 generic 清单语义（info 能力触达面）；第三方仍 high', () => {
    const manifest = JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node build.js' } })
    const dir = pkg({ 'package.json': manifest, 'index.js': 'export {}\n' })
    try {
      const off = scanPkg(dir)
      const offHook = off.findings.find(f => f.rule === 'R10' && f.message.includes('install 钩子'))!
      expect(offHook.severity).toBe('high')
      const on = scanPkg(dir, { officialFamily: true })
      const onHook = on.findings.find(f => f.rule === 'R10' && f.message.includes('install 钩子'))!
      expect(onHook.severity).toBe('info')
      expect(onHook.message).toContain('能力触达面')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('同名文件歧义不按 basename 归因：根 index.js（授权源码）不被 lib/index.js（产物）串味', () => {
    const dir = pkg({
      'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'index.js' }),
      'index.js': HIGH_SOURCE,
      'lib/index.js': 'export const built = 1\n',
    })
    try {
      const on = scanPkg(dir, { officialFamily: true })
      const f = on.findings.find(x => x.rule === 'R3')!
      // 命中在授权源码根 index.js → 不降档、不加产物前缀
      expect(f.severity).toBe('high')
      expect(f.message).not.toContain('构建产物')
      expect(on.verdict).toBe('suspicious')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('同名但同属产物 → 仍按 basename 归因（lib/index.js + lib/types/index.js）', () => {
    const dir = pkg({
      'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'lib/index.js' }),
      'lib/index.js': HIGH_SOURCE,
      'lib/types/index.js': 'export const t = 1\n',
    })
    try {
      const on = scanPkg(dir, { officialFamily: true })
      const f = on.findings.find(x => x.rule === 'R3')!
      expect(f.severity).toBe('info')
      expect(f.message).toContain('构建产物（官方包降噪）：')
      expect(on.verdict).toBe('clean')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('info 观测不加产物前缀（避免噪音）', () => {
    const dir = pkg({ 'package.json': JSON.stringify({ name: '@deepseek-ai/demo', version: '1.0.0', main: 'lib/index.js' }), 'lib/index.js': 'const x = 1\nfor (const y of [1]) { x += y }\n' })
    try {
      const r = scanPkg(dir, { officialFamily: true })
      for (const f of r.findings.filter(x => x.severity === 'info')) {
        expect(f.message).not.toContain('（官方包降噪）')
      }
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})
