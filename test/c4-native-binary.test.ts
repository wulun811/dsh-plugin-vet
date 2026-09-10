import { describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { listSourceFiles } from '../lib/scanner/package-sources.js'
import { diffManifests, upgradeSeverity, hasAnyAddition } from '../lib/guard/version-diff.js'
import type { CapabilityManifest } from '../lib/scanner-bin/protocol.js'

/**
 * C4（0.3.8，DSH 0.1.5 同步）：原生二进制感知。
 * 背景：官方首发平台二进制包（@deepseek-ai/node-addon-system-linux-x64 携带 .node），
 * 而预编译二进制对 JS 规则面完全不可审——第三方插件夹带 .node 是经典恶意手法。
 * 纪律：文件面证据（扩展名 + ELF/PE/Mach-O/wasm 魔数复核）；只记名不解析、不入
 * sourceCount、不产 finding；组合升红只在「原生 + 网络/执行/敏感路径」同版新增时触发。
 */

const CLEAN_JS = 'module.exports = { greet: () => "hi" }\n'
const ELF = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60, 0)])
const WASM = Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), Buffer.alloc(56, 0)])

const tmp = () => mkdtempSync(join(tmpdir(), 'vet-c4-'))

describe('C4 engine：原生二进制取证（files 模式）', () => {
  it('.node 扩展命中：记名、不解析（不入 sourceCount）、verdict 不受影响', () => {
    const dir = tmp()
    try {
      mkdirSync(join(dir, 'build'), { recursive: true })
      writeFileSync(join(dir, 'index.js'), CLEAN_JS)
      writeFileSync(join(dir, 'build', 'addon.node'), ELF)
      const res = scan({
        kind: 'files',
        files: [join(dir, 'index.js'), join(dir, 'package.json'), join(dir, 'build', 'addon.node')],
        cacheDir: dir,
      })
      expect(res.ok).toBe(true)
      const cap = res.report!.capabilities!
      expect(cap.hasNativeBinary).toBe(true)
      expect(cap.nativeBinaries).toEqual(['addon.node'])
      // .node 不解析：sourceCount 只数真正的源码文件（index.js + package.json 不算）
      expect(res.report!.sourceCount).toBe(1)
      expect(res.report!.verdict).toBe('clean')
      expect(res.report!.findings.filter(f => f.file === 'addon.node')).toHaveLength(0)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('魔数复核：伪装成 .js 的 ELF 与 .wasm 二进制同样命中且不进 AST 面', () => {
    const dir = tmp()
    try {
      writeFileSync(join(dir, 'helper.js'), ELF)
      writeFileSync(join(dir, 'compute.wasm'), WASM)
      writeFileSync(join(dir, 'app.js'), CLEAN_JS)
      const res = scan({
        kind: 'files',
        files: [join(dir, 'helper.js'), join(dir, 'compute.wasm'), join(dir, 'app.js')],
        cacheDir: dir,
      })
      const cap = res.report!.capabilities!
      expect(cap.hasNativeBinary).toBe(true)
      expect(cap.nativeBinaries).toContain('helper.js')
      expect(cap.nativeBinaries).toContain('compute.wasm')
      expect(res.report!.sourceCount).toBe(1) // 只有 app.js 真被解析
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('假阳性守卫：纯文本不命中；"MZ" 开头的 JS 不被误判 PE；普通 clean 插件形状不变', () => {
    const dir = tmp()
    try {
      writeFileSync(join(dir, 'weird.js'), 'MZ = 1\nmodule.exports = {}\n')
      writeFileSync(join(dir, 'note.txt'), 'MZ at start of a text file is legal')
      const hit = scan({ kind: 'files', files: [join(dir, 'weird.js'), join(dir, 'note.txt')], cacheDir: dir })
      expect(hit.report!.capabilities!.hasNativeBinary).toBe(false)
      expect(hit.report!.capabilities!.nativeBinaries).toBeUndefined()
      // 「MZ」文本走正常 JS 解析（sourceCount=1；note.txt 无扩展名不在面内——枚举侧已滤）
      expect(hit.report!.sourceCount).toBe(1)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('缓存往返：含原生字段的报告写读一致（validCapabilities 不拒新形状）', () => {
    const dir = tmp()
    try {
      mkdirSync(join(dir, 'prebuilds', 'linux-x64'), { recursive: true })
      writeFileSync(join(dir, 'index.js'), CLEAN_JS)
      writeFileSync(join(dir, 'prebuilds', 'linux-x64', 'node-sys.node'), ELF)
      const req = { kind: 'files' as const, files: [join(dir, 'index.js'), join(dir, 'prebuilds', 'linux-x64', 'node-sys.node')], cacheDir: dir }
      const first = scan(req)
      const second = scan(req) // 命中缓存
      expect(second.ok).toBe(true)
      expect(second.report!.capabilities).toEqual(first.report!.capabilities)
      expect(second.report!.capabilities!.hasNativeBinary).toBe(true)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})

describe('C4 宿主枚举面（package-sources）', () => {
  it('原生扩展进扫描面（含大写扩展名回归：宿主侧大小写旁路修复）', () => {
    const dir = tmp()
    try {
      mkdirSync(join(dir, 'prebuilds'), { recursive: true })
      writeFileSync(join(dir, 'index.js'), CLEAN_JS)
      writeFileSync(join(dir, 'prebuilds', 'addon.node'), ELF)
      writeFileSync(join(dir, 'prebuilds', 'evil.NODE'), ELF)
      writeFileSync(join(dir, 'icon.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]))
      const files = listSourceFiles(dir)
      expect(files.some(f => f.endsWith('addon.node'))).toBe(true)
      expect(files.some(f => f.endsWith('evil.NODE'))).toBe(true)
      expect(files.some(f => f.endsWith('icon.png'))).toBe(false)
      expect(files.some(f => f.endsWith('index.js'))).toBe(true)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})

describe('C4 升级差分（version-diff）', () => {
  const m = (o: Partial<CapabilityManifest>): CapabilityManifest => ({
    hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, ...o,
  })
  const delta = (o: Record<string, unknown>) => ({
    hosts: [], fsPaths: [], spawnCmds: [], imports: [], ghostDeps: [], zombieDeps: [],
    hasNetwork: false, hasExec: false, hasNativeBinary: false, nativeBinaries: [], ...o,
  })

  it('新增布尔：prev 缺字段（0.3.8 前存量记录）→ 首次观察计入新增；prev 已有 true → 不重复报', () => {
    const legacyPrev = m({ hasNetwork: true }) // 无 hasNativeBinary 键
    const next = m({ hasNetwork: true, hasNativeBinary: true, nativeBinaries: ['a.node'] })
    const { added } = diffManifests(legacyPrev, next)
    expect(added.hasNativeBinary).toBe(true)
    expect(added.nativeBinaries).toEqual(['a.node'])
    const { added: again } = diffManifests(next, m({ hasNetwork: true, hasNativeBinary: true, nativeBinaries: ['a.node'] }))
    expect(again.hasNativeBinary).toBe(false)
  })

  it('移除：prev true → next 无 → removed.hasNativeBinary（不报警仅审计）', () => {
    const { removed } = diffManifests(m({ hasNativeBinary: true, nativeBinaries: ['a.node'] }), m({}))
    expect(removed.hasNativeBinary).toBe(true)
    expect(removed.nativeBinaries).toEqual(['a.node'])
  })

  it('严重度：单独新增原生 → info 蓝；原生+执行/网络/敏感路径同版新增 → red；纯原生不进 hasAnyAddition=false 之外', () => {
    expect(upgradeSeverity(delta({ hasNativeBinary: true, nativeBinaries: ['a.node'] }))).toBe('info')
    expect(upgradeSeverity(delta({ hasNativeBinary: true, nativeBinaries: ['a.node'], hasExec: true }))).toBe('red')
    expect(upgradeSeverity(delta({ hasNativeBinary: true, hasNetwork: true }))).toBe('red')
    expect(upgradeSeverity(delta({ hasNativeBinary: true, fsPaths: ['/home/u/.ssh/id_rsa'] }))).toBe('red')
    expect(hasAnyAddition(delta({ hasNativeBinary: true }))).toBe(true)
    expect(upgradeSeverity(delta({}))).toBeNull()
  })
})
