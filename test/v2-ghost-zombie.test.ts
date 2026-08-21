import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan, buildDepsInfo } from '../lib/scanner-bin/engine.js'
import { diffManifests } from '../lib/guard/version-diff.js'
import { setCapabilitiesDirForTest, recordScan, label } from '../lib/guard/version-diff.js'
import type { CapabilityManifest, ScanRequest } from '../lib/scanner-bin/protocol.js'

/**
 * P0-2 #9：幽灵/僵尸依赖健康审计（R16）——声明（package.json）↔ 代码引用（imports）↔ 实际安装（node_modules）
 * 三方对账。确定性、零出站、info 级观测（不扣分不改 verdict）。
 */

let root: string

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vet-r16-'))
})

afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})

function writeFile(dir: string, name: string, content: string): string {
  const p = join(dir, name)
  writeFileSync(p, content)
  return p
}

function makeDepDir(dir: string, name: string): void {
  // node_modules/<name> 或 node_modules/<scope>/<name>
  mkdirSync(join(dir, 'node_modules', ...name.split('/')), { recursive: true })
  writeFileSync(join(dir, 'node_modules', ...name.split('/'), 'index.js'), 'module.exports = {}')
}

function scanPkg(req: Partial<ScanRequest> = {}) {
  return scan({
    kind: 'files',
    files: [join(root, 'package.json'), join(root, 'index.js')],
    targetKind: 'plugin',
    ...req,
  })
}

describe('R16 幽灵依赖（代码引用但 package.json 未声明）', () => {
  it('未声明且被代码引用 → ghostDeps + R16 info 观测；verdict 仍 clean、score 100 不扣分', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'safe-dep': '1.0.0' } }))
    // ESM import（非动态 require，避免 R2 medium 干扰评分断言）：能力面只来自 R16 info 观测
    writeFile(root, 'index.js', 'import safeDep from "safe-dep"; import ghostPkg from "ghost-pkg"; safeDep(); ghostPkg()')
    makeDepDir(root, 'safe-dep')
    makeDepDir(root, 'ghost-pkg')

    const res = scanPkg()
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.capabilities?.ghostDeps).toEqual(['ghost-pkg'])
    expect(r.capabilities?.zombieDeps).toBeUndefined() // 无缺失声明
    const r16 = r.findings.filter(f => f.rule === 'R16')
    expect(r16.some(f => f.message.includes('ghost-pkg'))).toBe(true)
    expect(r16.every(f => f.severity === 'info')).toBe(true)
    expect(r.verdict).toBe('clean')
    expect(r.staticScore).toBe(100)
  })

  it('scoped 未声明依赖 @scope/pkg 也识别为幽灵', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0' }))
    writeFile(root, 'index.js', 'require("@evil/thing")')
    const res = scanPkg()
    expect(res.ok).toBe(true)
    expect(res.report!.capabilities?.ghostDeps).toContain('@evil/thing')
  })

  it('@deepseek-ai/* 宿主信任边界不列幽灵（DSH 插件宿主 SDK 不误报）', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0' }))
    writeFile(root, 'index.js', 'require("@deepseek-ai/dsh-tools")')
    const res = scanPkg()
    expect(res.ok).toBe(true)
    expect(res.report!.capabilities?.ghostDeps).toBeUndefined()
    expect(res.report!.findings.filter(f => f.rule === 'R16')).toHaveLength(0)
  })

  it('dev/peer/optional 声明都算"已声明"，不误报幽灵', () => {
    writeFile(root, 'package.json', JSON.stringify({
      name: 'p', version: '1.0.0',
      devDependencies: { 'dev-dep': '1.0.0' },
      peerDependencies: { 'peer-dep': '1.0.0' },
      optionalDependencies: { 'opt-dep': '1.0.0' },
    }))
    writeFile(root, 'index.js', 'require("dev-dep"); require("peer-dep"); require("opt-dep")')
    const res = scanPkg()
    expect(res.ok).toBe(true)
    expect(res.report!.capabilities?.ghostDeps).toBeUndefined()
  })
})

describe('R16 僵尸依赖（package.json 声明但 node_modules 缺失）', () => {
  it('声明但未安装 → zombieDeps + R16 info 观测', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'present-dep': '1.0.0', 'missing-dep': '1.0.0' } }))
    writeFile(root, 'index.js', 'require("present-dep")')
    makeDepDir(root, 'present-dep') // 只装 present，missing 不装

    const res = scanPkg()
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.capabilities?.zombieDeps).toEqual(['missing-dep'])
    expect(r.findings.some(f => f.rule === 'R16' && f.message.includes('missing-dep'))).toBe(true)
  })

  it('无 node_modules → 僵尸判定不可用；幽灵仍可判定', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'x-dep': '1.0.0' } }))
    writeFile(root, 'index.js', 'require("ghost-pkg2")')
    const res = scanPkg()
    expect(res.ok).toBe(true)
    const c = res.report!.capabilities!
    expect(c.zombieDeps).toBeUndefined()
    expect(c.ghostDeps).toEqual(['ghost-pkg2'])
  })

  it('无 package.json → 不做依赖健康审计（无 ghost/zombie 字段、无 R16）', () => {
    writeFile(root, 'index.js', 'require("foo")')
    const res = scan({ kind: 'files', files: [join(root, 'index.js')], targetKind: 'plugin' })
    expect(res.ok).toBe(true)
    const c = res.report!.capabilities!
    expect(c.ghostDeps).toBeUndefined()
    expect(c.zombieDeps).toBeUndefined()
    expect(res.report!.findings.filter(f => f.rule === 'R16')).toHaveLength(0)
  })

  it('R16 关闭（rules: {R16:false}）→ 不产出字段也不报警', () => {
    writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'm-dep': '1.0.0' } }))
    writeFile(root, 'index.js', 'require("ghost-pkg3"); require("m-dep")')
    makeDepDir(root, 'm-dep')
    const res = scanPkg({ rules: { R16: false } })
    expect(res.ok).toBe(true)
    const c = res.report!.capabilities!
    expect(c.ghostDeps).toBeUndefined()
    expect(c.zombieDeps).toBeUndefined()
    expect(res.report!.findings.filter(f => f.rule === 'R16')).toHaveLength(0)
  })
})

describe('R16 缓存与指纹', () => {
  it('node_modules 变化 → deps 指纹进 cache key → 缓存失效重扫出最新僵尸', () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'vet-r16-cache-'))
    const nonce = 'r16-test-nonce'
    try {
      writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'a-dep': '1.0.0' } }))
      writeFile(root, 'index.js', 'require("a-dep")')
      makeDepDir(root, 'a-dep')
      const first = scan({ kind: 'files', files: [join(root, 'package.json'), join(root, 'index.js')], targetKind: 'plugin', cacheDir, cacheNonce: nonce })
      expect(first.report!.capabilities?.zombieDeps).toBeUndefined()

      // 第二次扫描后 b-dep 依存 node_modules 出现（模拟 npm install 补装）
      makeDepDir(root, 'b-dep')
      writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'a-dep': '1.0.0', 'b-dep': '1.0.0' } }))
      const second = scan({ kind: 'files', files: [join(root, 'package.json'), join(root, 'index.js')], targetKind: 'plugin', cacheDir, cacheNonce: nonce })
      expect(second.ok).toBe(true)
      expect(second.report!.capabilities?.zombieDeps).toBeUndefined() // b-dep 现在已装上
    } finally {
      rmSync(cacheDir, { recursive: true, force: true })
    }
  })

  it('fingerprint 变化才会重扫：只换声明不装包 → 新僵尸出现', () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'vet-r16-cache2-'))
    const nonce = 'r16-test-nonce2'
    try {
      const req = () => ({ kind: 'files' as const, files: [join(root, 'package.json'), join(root, 'index.js')], targetKind: 'plugin' as const, cacheDir, cacheNonce: nonce })
      writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'a-dep': '1.0.0' } }))
      writeFile(root, 'index.js', 'require("a-dep")')
      makeDepDir(root, 'a-dep')
      expect(scan(req()).report!.capabilities?.zombieDeps).toBeUndefined()

      // 声明加了一个没装的依赖：declared 变化 → fingerprint 变 → 缓存失效
      writeFile(root, 'package.json', JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { 'a-dep': '1.0.0', 'uninstalled-dep': '1.0.0' } }))
      const res = scan(req())
      expect(res.report!.capabilities?.zombieDeps).toEqual(['uninstalled-dep'])
    } finally {
      rmSync(cacheDir, { recursive: true, force: true })
    }
  })
})

describe('buildDepsInfo（单元）', () => {
  it('声明四段合并 + 去 @deepseek-ai + 排序', () => {
    writeFile(root, 'package.json', JSON.stringify({
      name: 'p', version: '1.0.0',
      dependencies: { 'z-pkg': '1.0.0', 'a-pkg': '1.0.0' },
      devDependencies: { '@deepseek-ai/dsh-tools': '^0.1.0' },
      peerDependencies: { 'peer-pkg': '1' },
      optionalDependencies: { 'opt-pkg': '1' },
    }))
    const info = buildDepsInfo([join(root, 'package.json'), join(root, 'index.js')])
    expect(info).not.toBeNull()
    expect(info!.declared).toEqual(['a-pkg', 'opt-pkg', 'peer-pkg', 'z-pkg'])
  })

  it('坏 package.json / 无 package.json → null（静默跳过）', () => {
    expect(buildDepsInfo([join(root, 'index.js')])).toBeNull()
    writeFile(root, 'package.json', 'not json{')
    expect(buildDepsInfo([join(root, 'package.json'), join(root, 'index.js')])).toBeNull()
  })
})

describe('R16 → N6/M2 差分接线', () => {
  it('diffManifests 把 ghost/zombie 变化记入 added/removed（展示用）', () => {
    const base: CapabilityManifest = { hosts: [], fsPaths: [], spawnCmds: [], imports: ['a'], hasNetwork: false, hasExec: false, ghostDeps: ['a'], zombieDeps: ['gone'] }
    const next: CapabilityManifest = { hosts: [], fsPaths: [], spawnCmds: [], imports: ['a', 'b'], hasNetwork: false, hasExec: false, ghostDeps: ['a', 'b'] }
    const { added, removed } = diffManifests(base, next)
    expect(added.ghostDeps).toEqual(['b'])
    expect(added.zombieDeps).toEqual([])
    expect(removed.zombieDeps).toEqual(['gone'])
    expect(added.imports).toEqual(['b'])
  })

  it('幽灵依赖变化进入 vet label 的 diffSummary 文案', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r16-label-'))
    try {
      setCapabilitiesDirForTest(dir)
      const mk = (ghost: string[]): CapabilityManifest & { ghostDeps?: string[] } => ({
        hosts: [], fsPaths: [], spawnCmds: [], imports: ghost, hasNetwork: false, hasExec: false, ghostDeps: ghost,
      })
      recordScan('pkg-x', '1.0.0', mk(['a']))
      recordScan('pkg-x', '1.1.0', mk(['a', 'b']))
      const v = label('pkg-x')
      expect(v.diffSummary).not.toBeNull()
      expect(v.diffSummary!.added.join(';')).toContain('幽灵依赖 b（未声明）')
    } finally {
      setCapabilitiesDirForTest(undefined)
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
