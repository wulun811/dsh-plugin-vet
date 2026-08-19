import { describe, expect, it, beforeEach, afterEach, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  confirmBlock, resetConfirmBlock, decideBlock, isPersistenceWriteTarget, isInstallWriteTarget,
  BLOCK_FS_OPS,
} from '../lib/guard/confirm-block.js'
import {
  DEFAULT_HOOK_CONFIG, patchModule, classifyOp, withVetSelfIo,
} from '../lib/guard/runtime-hooks.js'

/** patchModule 返回的 disposer 统一在 afterAll 清理（避免串测）。 */
const patches: (() => void)[] = []
afterAll(() => { for (const dispose of patches.splice(0)) { try { dispose() } catch { /* 清理失败不吞单测结果 */ } } })

describe('N7 decideBlock：族 2 凭据本体（精确文件级）', () => {
  const oldHome = process.env.HOME
  let dir = ''
  beforeEach(() => {
    resetConfirmBlock()
    dir = mkdtempSync(join(tmpdir(), '.n7-h-'))
    process.env.HOME = dir
  })
  afterEach(() => {
    if (oldHome === undefined) delete process.env.HOME
    else process.env.HOME = oldHome
    rmSync(dir, { recursive: true, force: true })
  })

  it('删除族：unlink/rm/rename 使源凭据消失 → 族 2 拦截', () => {
    expect(decideBlock('evil', 'unlink', [join(dir, '.ssh', 'id_rsa')])?.family).toBe(2)
    expect(decideBlock('evil', 'unlinkSync', [join(dir, '.ssh', 'id_ed25519')])?.family).toBe(2)
    expect(decideBlock('evil', 'rename', [join(dir, '.aws', 'credentials'), '/tmp/out'])?.family).toBe(2)
    expect(decideBlock('evil', 'rmSync', [join(dir, '.dsh', '.credentials.yaml')])?.family).toBe(2)
  })

  it('覆盖写：writeFile/truncate 到已存在凭据 → 族 2；到不存在文件（新建，可逆）→ 不拦', () => {
    const npmrc = join(dir, '.npmrc')
    writeFileSync(npmrc, 'old')
    expect(decideBlock('evil', 'writeFile', [npmrc, 'x'])?.family).toBe(2)
    expect(decideBlock('evil', 'writeFileSync', [npmrc, 'x'])?.family).toBe(2)
    expect(decideBlock('evil', 'writeFile', [join(dir, '.netrc'), 'x'])).toBeNull()
  })

  it('appendFile 可逆 → 不拦', () => {
    const sshDir = join(dir, '.ssh')
    mkdirSync(sshDir, { recursive: true })
    const ssh = join(sshDir, 'id_ed25519')
    writeFileSync(ssh, 'k')
    expect(decideBlock('evil', 'appendFile', [ssh, 'x'])).toBeNull()
  })

  it('族 2 降级路径：alarm/off 模式即使凭据本体存在也不拦（即时生效）', () => {
    const npmrc = join(dir, '.npmrc')
    writeFileSync(npmrc, 'old')
    confirmBlock.setMode('alarm')
    expect(decideBlock('evil', 'unlink', [npmrc])).toBeNull()
    expect(decideBlock('evil', 'writeFile', [npmrc, 'x'])).toBeNull()
    confirmBlock.setMode('off')
    expect(decideBlock('evil', 'rm', [join(dir, '.aws', 'credentials')])).toBeNull()
  })
})

describe('N7 decideBlock：族 1 破坏/勒索确认后拦截', () => {
  beforeEach(() => { resetConfirmBlock() })

  it('markFamily1 后破坏类操作 → 族 1；未标记插件 → 不拦', () => {
    confirmBlock.markFamily1('extorter')
    expect(decideBlock('extorter', 'writeFile', ['/home/u/doc.txt', 'x'])?.family).toBe(1)
    expect(decideBlock('extorter', 'unlink', ['/home/u/doc.txt'])?.family).toBe(1)
    expect(decideBlock('extorter', 'renameSync', ['/home/u/doc.txt', '/home/u/locked'])?.family).toBe(1)
    expect(decideBlock('other', 'writeFile', ['/home/u/doc.txt', 'x'])).toBeNull()
  })

  it('可逆写（appendFile）不在拦截面 → 不拦', () => {
    confirmBlock.markFamily1('extorter')
    expect(decideBlock('extorter', 'appendFile', ['/home/u/doc.txt', 'x'])).toBeNull()
  })

  it('alarm/off 模式 → 全部不拦（降级路径即时生效）', () => {
    confirmBlock.markFamily1('extorter')
    confirmBlock.setMode('alarm')
    expect(decideBlock('extorter', 'writeFile', ['/home/u/doc.txt', 'x'])).toBeNull()
    confirmBlock.setMode('off')
    expect(decideBlock('extorter', 'unlink', ['/home/u/doc.txt'])).toBeNull()
  })

  it('块操作集合与计划一致：破坏类全覆盖、appendFile 不在内', () => {
    const expected = ['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync',
      'rename', 'renameSync', 'cp', 'cpSync', 'copyFile', 'copyFileSync',
      'truncate', 'truncateSync', 'writeFile', 'writeFileSync', 'createWriteStream']
    for (const op of expected) expect(BLOCK_FS_OPS.has(op), op).toBe(true)
    expect(BLOCK_FS_OPS.has('appendFile')).toBe(false)
    expect(BLOCK_FS_OPS.has('appendFileSync')).toBe(false)
  })
})

describe('N7 族 3/4 谓词（alarm-only，永不拦截）', () => {
  it('isPersistenceWriteTarget：bashrc/cron/systemd/sudoers/autostart/authorized_keys/hosts/ssl', () => {
    expect(isPersistenceWriteTarget('/home/u/.bashrc')).toBe(true)
    expect(isPersistenceWriteTarget('/home/u/.zshrc')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/cron.d/backdoor')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/systemd/system/x.service')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/ld.so.preload')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/sudoers.d/evil')).toBe(true)
    expect(isPersistenceWriteTarget('/home/u/.config/autostart/x.desktop')).toBe(true)
    expect(isPersistenceWriteTarget('/home/u/.ssh/authorized_keys')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/hosts')).toBe(true)
    expect(isPersistenceWriteTarget('/etc/ssl/certs/x')).toBe(true)
    expect(isPersistenceWriteTarget('/home/u/documents/notes.txt')).toBe(false)
  })

  it('isInstallWriteTarget：node_modules 包文件 / cordis.patch.yml / cordis.yml / plugin.json', () => {
    expect(isInstallWriteTarget('/proj/node_modules/@foo/bar/index.js')).toBe(true)
    expect(isInstallWriteTarget('/proj/cordis.patch.yml')).toBe(true)
    expect(isInstallWriteTarget('/proj/plugins/plugin.json')).toBe(true)
    expect(isInstallWriteTarget('/proj/source/index.js')).toBe(false)
  })

  it('classifyOp：写持久化/安装态路径 → 黄 persistence-write / install-write（报警不拦）', () => {
    const p = classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/u/.bashrc', 'x'] }, DEFAULT_HOOK_CONFIG)
    expect(p?.kind).toBe('persistence-write')
    expect(p?.severity).toBe('yellow')
    const i = classifyOp({ module: 'fs', op: 'writeFile', args: ['/proj/node_modules/pkg/i.js', 'x'] }, DEFAULT_HOOK_CONFIG)
    expect(i?.kind).toBe('install-write')
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/u/notes.txt', 'x'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // cp/rename 是成对路径：写目标是 dst——覆盖 /etc/hosts（族 3）也要按持久化面报警
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/evil', '/etc/hosts'] }, DEFAULT_HOOK_CONFIG)?.kind).toBe('persistence-write')
    expect(classifyOp({ module: 'fs', op: 'rename', args: ['/tmp/new', '/proj/node_modules/pkg/i.js'] }, DEFAULT_HOOK_CONFIG)?.kind).toBe('install-write')
  })
})

describe('N7 接线：hooks 包装器拦截矩阵（每族三向）', () => {
  beforeEach(() => { resetConfirmBlock() })



  // 归因脚手架：测试文件自身路径前缀 → 模拟插件名（pluginFromStack 最长前缀匹配）
  const rootFor = (name: string): Map<string, string> =>
    new Map([[process.cwd() + '/test', name]])

  it('族 1 确认插件：破坏类写文件 → 抛错"vet 拦截" + 同步 red n7-block 报警', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('extorter')
    const sunk: string[] = []
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sunk.push(a.kind), () => rootFor('extorter')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).toThrow(/vet.*拦截/)
    expect(sunk).toContain('n7-block')
  })

  it('族 1 确认插件：appendFile（可逆）→ 不抛错、不拦', () => {
    const mod: Record<string, unknown> = { appendFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('extorter')
    const sunk: string[] = []
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sunk.push(a.kind), () => rootFor('extorter')))
    expect(() => (mod.appendFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).not.toThrow()
    expect(sunk).not.toContain('n7-block')
  })

  it('族 2 单次即时：凭据本体删除 → 抛错拦截（真实栈归因到测试路径）', () => {
    const dir = mkdtempSync(join(tmpdir(), '.n7-w-'))
    const oldHome = process.env.HOME
    process.env.HOME = dir
    try {
      const mod: Record<string, unknown> = { unlink: (p: string) => true }
      const sunk: string[] = []
      patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sunk.push(a.kind), () => rootFor('evil')))
      expect(() => (mod.unlink as (p: string) => unknown)(join(dir, '.ssh', 'id_rsa'))).toThrow(/vet.*拦截/)
      expect(sunk).toContain('n7-block')
    } finally {
      if (oldHome === undefined) delete process.env.HOME
      else process.env.HOME = oldHome
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('豁免 1：官方归因永不拦截（族 1 标记也不拦）', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('@deepseek-ai/evil')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('@deepseek-ai/evil')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).not.toThrow()
  })

  it('豁免 2：无主操作永不拦截（归因映射为空 → plugin undefined）', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('somehost')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => new Map()))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).not.toThrow()
  })

  it('豁免 3：vet 自身 IO（withVetSelfIo）永不拦截', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('extorter')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('extorter')))
    expect(() => withVetSelfIo(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x'))).not.toThrow()
  })

  it('降级路径：alarm 模式下确认插件也不抛错（同进程即时生效）', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.markFamily1('extorter')
    confirmBlock.setMode('alarm')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('extorter')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).not.toThrow()
  })

  it('合法插件写普通文件 → 不拦（零误拦核心）', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('legit')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/a.txt', 'x')).not.toThrow()
  })

  it('合法插件写 node_modules（安装态）→ 只报警 install-write，不抛错', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    const sunk: string[] = []
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sunk.push(a.kind), () => rootFor('legit')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/proj/node_modules/pkg/i.js', 'x')).not.toThrow()
    expect(sunk).toContain('install-write')
  })

  it('族 3 升级 block：显式开启后写持久化面 → 抛错；默认（未开启）只报警不拦', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.setFamilyModes('block', 'alarm')
    const sunk: string[] = []
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sunk.push(a.kind), () => rootFor('evil')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/.bashrc', 'x')).toThrow(/vet.*拦截/)
    expect(sunk).toContain('n7-block')
    // 未开启的族 4 目标：只报警 install-write，不抛错
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/proj/node_modules/pkg/i.js', 'x')).not.toThrow()
    expect(sunk).toContain('install-write')
  })

  it('族 3 升级 block 仍守护栏：可逆写 appendFile 与 vetSelfIo 不拦', () => {
    const mod: Record<string, unknown> = { appendFile: (p: string, d: string) => true, writeFileSync: (p: string, d: string) => true }
    confirmBlock.setFamilyModes('block', 'block')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('evil')))
    expect(() => (mod.appendFile as (p: string, d: string) => unknown)('/home/u/.bashrc', 'x')).not.toThrow()
    expect(() => withVetSelfIo(() => (mod.writeFileSync as (p: string, d: string) => unknown)('/home/u/.bashrc', 'x'))).not.toThrow()
  })

  it('族 3/4 升级遇整体 alarm/off 降级 → 不拦（全局降级优先）', () => {
    const mod: Record<string, unknown> = { writeFile: (p: string, d: string) => true }
    confirmBlock.setFamilyModes('block', 'block')
    confirmBlock.setMode('alarm')
    patches.push(patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => rootFor('evil')))
    expect(() => (mod.writeFile as (p: string, d: string) => unknown)('/home/u/.bashrc', 'x')).not.toThrow()
  })
})