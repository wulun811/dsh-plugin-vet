import { describe, expect, it } from 'vitest'
import { homedir } from 'node:os'
import { DEFAULT_HOOK_CONFIG, classifyOp, isSensitivePath, patchModule } from '../lib/guard/runtime-hooks.js'
import type { HookAlarm } from '../lib/guard/runtime-hooks.js'
import {
  DEFAULT_TEMP_ROOTS, isPlausibleTempRoot, isUnderTempRoot, resolveTempRoots,
} from '../lib/guard/runtime-denoise.js'
import { normPath, normalizePathForJudge, stripMacPrivatePrefix } from '../lib/guard/path-utils.js'
import type { HookConfig } from '../lib/guard/runtime-hooks.js'

/**
 * 0.4.2（用户反馈回归）：macOS 规范前缀 + OS 临时根。
 *
 * 现场：面板一次刷出 20 条 red fs-destroy，全部无主，target 落在 /private/tmp 与
 * /private/var/folders/<xx>/<yy>/T（DSH 原子写暂存目录、workspace-changes 的私有 git index）。
 * 根因两条：① sensitiveKeywords 含 'private'，而 macOS 规范路径把 /tmp、/var、/etc 呈现为
 * /private/*；② sensitiveRoots 的 '/var' 前缀判定对 /var/folders/<xx>/<yy>/T（os.tmpdir()）
 * 同样命中——那是系统每用户临时区，不是 /var/db 那类持久面。
 *
 * 修复：判定前先归一化（点段折叠 + macOS /private 折叠），写/删落在临时根下直接放行；
 * 读不豁免（/tmp/id_rsa 这类把密钥复制到临时区的侦察照旧可见）。
 */

const DARWIN = 'darwin' as const
const cfg = DEFAULT_HOOK_CONFIG

/** macOS 每用户临时区（os.tmpdir() 在 macOS 的形态）。 */
const MAC_TMP = '/var/folders/95/k3x9q0r1/T'
const cfgWithMacTmp: HookConfig = { ...DEFAULT_HOOK_CONFIG, tempRoots: ['/tmp', '/var/tmp', MAC_TMP] }

describe('stripMacPrivatePrefix / normalizePathForJudge', () => {
  it('只剥开头一段 /private/：本体与同名前缀不动', () => {
    expect(stripMacPrivatePrefix('/private/tmp/x')).toBe('/tmp/x')
    expect(stripMacPrivatePrefix('/private/etc/hosts')).toBe('/etc/hosts')
    expect(stripMacPrivatePrefix('/private')).toBe('/private') // 真实目录，不能映射成 '/'
    expect(stripMacPrivatePrefix('/privatex/tmp')).toBe('/privatex/tmp')
    expect(stripMacPrivatePrefix('/tmp/x')).toBe('/tmp/x')
  })

  it('平台闸门：只在 darwin 折叠；Linux/Windows 的 /private 是普通目录', () => {
    expect(normalizePathForJudge('/private/tmp/x', DARWIN)).toBe('/tmp/x')
    expect(normalizePathForJudge('/private/tmp/x', 'linux')).toBe('/private/tmp/x')
    expect(normalizePathForJudge('/private/tmp/x', 'win32')).toBe('/private/tmp/x')
    // 非 darwin 平台与旧 normPath 逐字一致（不含折叠）
    expect(normalizePathForJudge('/a//b/../c/', 'linux')).toBe(normPath('/a//b/../c/'))
  })

  it('darwin 同时折叠大小写（macOS 默认卷大小写不敏感），Linux 不折', () => {
    expect(normalizePathForJudge('/ETC/Hosts', DARWIN)).toBe('/etc/hosts')
    expect(normalizePathForJudge('/Users/A/.SSH/ID_RSA', DARWIN)).toBe('/users/a/.ssh/id_rsa')
    expect(normalizePathForJudge('/ETC/Hosts', 'linux')).toBe('/ETC/Hosts')
  })

  it('折叠发生在点段折叠之后：/private/tmp/../etc/hosts → /etc/hosts（不能借顺序洗白）', () => {
    expect(normalizePathForJudge('/private/tmp/../etc/hosts', DARWIN)).toBe('/etc/hosts')
    expect(normalizePathForJudge('/private/tmp/./../../etc/hosts', DARWIN)).toBe('/etc/hosts')
  })
})

describe('OS 临时根解析（tempRoots 默认值与可信性）', () => {
  it('默认含 /tmp 与 /var/tmp，去重且只保留绝对路径', () => {
    expect(DEFAULT_TEMP_ROOTS).toContain('/tmp')
    expect(DEFAULT_TEMP_ROOTS).toContain('/var/tmp')
    expect(new Set(DEFAULT_TEMP_ROOTS).size).toBe(DEFAULT_TEMP_ROOTS.length)
    // Windows 兼容：win32 的 os.tmpdir() 是盘符路径（C:/…Temp），「绝对」不等于「以 / 开头」。
    expect(DEFAULT_TEMP_ROOTS.every(r => r.startsWith('/') || /^[a-zA-Z]:\//.test(r))).toBe(true)
  })

  it('归一化候选：macOS /private 前缀与点段都折叠；非法候选丢弃', () => {
    expect(resolveTempRoots(['/private/tmp', '/tmp', '/var/tmp/', '/var/folders/95/k3x9q0r1/T']))
      .toEqual(['/tmp', '/var/tmp', '/var/folders/95/k3x9q0r1/T'])
    expect(resolveTempRoots(['/', '', '/var/../tmp'])).toEqual(['/tmp'])
    // 相对根（TMPDIR=tmp）永远匹配不上绝对事件路径，却在相对目标上制造「碰巧命中」→ 丢弃
    expect(resolveTempRoots(['tmp', 'temp', './tmp', '/tmp'])).toEqual(['/tmp'])
  })

  it('可信性：家目录里的 tmp（TMPDIR=$HOME/.ssh/tmp）不算临时根', () => {
    expect(isPlausibleTempRoot('/tmp')).toBe(true)
    expect(isPlausibleTempRoot('/var/tmp')).toBe(true)
    expect(isPlausibleTempRoot('/var/folders/95/k3x9q0r1/T')).toBe(true)
    expect(isPlausibleTempRoot('/data/tmp')).toBe(true)
    // Windows 兼容：homedir() 在 win32 含反斜杠；生产路径（resolveTempRoots）先归一化再校验，
    // 这里按同一口径传入，否则家目录前缀在 win32 永远比不相等。
    expect(isPlausibleTempRoot(normPath(`${homedir()}/.ssh/tmp`))).toBe(false)
    expect(isPlausibleTempRoot(normPath(`${homedir()}/project`))).toBe(false)
    expect(isPlausibleTempRoot('/var/db')).toBe(false)
  })

  it('isUnderTempRoot：含根本身，不做兄弟前缀误判（/tmpfoo 不在 /tmp 下）', () => {
    expect(isUnderTempRoot('/tmp', ['/tmp'])).toBe(true)
    expect(isUnderTempRoot('/tmp/x', ['/tmp'])).toBe(true)
    expect(isUnderTempRoot('/tmpfoo/x', ['/tmp'])).toBe(false)
  })
})

describe('isSensitivePath：macOS /private 临时面不报警（用户反馈现场 4 条）', () => {
  const staging = '/private/tmp/.writer.applescript.123.4b1c5d6e-1111-2222-3333-444455556666.tmpdir'

  it('4 条现场路径：写/删 → false（darwin）', () => {
    // 前两条在 /tmp（默认临时根），后两条在 macOS 的 os.tmpdir()（/var/folders/<xx>/<yy>/T）——
    // 后者在真机上是 DEFAULT_TEMP_ROOTS 的一员，CI（linux）上用 cfgWithMacTmp 复刻同一取值。
    for (const p of [
      staging,
      `${staging}/writer.applescript.tmp`,
    ]) {
      expect(isSensitivePath(p, cfg, 'mutate', DARWIN)).toBe(false)
    }
    for (const p of [
      '/private/var/folders/95/k3x9q0r1/T/dsh-workspace-changes-AbC123/index-XyZ789/index',
      '/private/var/folders/95/k3x9q0r1/T/dsh-workspace-changes-AbC123/index-XyZ789',
    ]) {
      expect(isSensitivePath(p, cfgWithMacTmp, 'mutate', DARWIN)).toBe(false)
    }
  })

  it('同一批路径在 Linux 判定下走旧的敏感词面（private 关键词）——平台闸门是刻意的', () => {
    // 非 darwin 平台没有 /private 规范前缀这回事；此断言钉住「不折叠」的边界，
    // 防止有人把平台闸门删成无条件折叠（会让 Linux 上的 /private 目录静默降级）。
    expect(isSensitivePath(staging, cfg, 'mutate', 'linux')).toBe(true)
  })

  it('大小写变体不再绕过系统根（darwin 折叠；linux 保持区分大小写）', () => {
    expect(isSensitivePath('/ETC/hosts', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/private/ETC/hosts', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/ETC/hosts', cfg, 'mutate', 'linux')).toBe(false)
  })

  it('收窄验证：/private/etc、/private/var/db、/var/log、凭据、穿越写法照旧敏感', () => {
    expect(isSensitivePath('/private/etc/hosts', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/private/var/db/x', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/var/log/system.log', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath(`${homedir()}/.dsh/.credentials.yaml`, cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/tmp/../etc/hosts', cfg, 'mutate', DARWIN)).toBe(true)
    expect(isSensitivePath('/private/tmp/../etc/hosts', cfg, 'mutate', DARWIN)).toBe(true)
  })

  it('读不豁免：临时区里的密钥拷贝（/private/tmp/id_rsa）仍是侦察信号', () => {
    expect(isSensitivePath('/private/tmp/id_rsa', cfg, 'read', DARWIN)).toBe(true)
    expect(isSensitivePath('/tmp/.ssh/id_rsa', cfg, 'read', DARWIN)).toBe(true)
    // 写/删落在临时根下按「可丢弃」放行
    expect(isSensitivePath('/private/tmp/id_rsa', cfg, 'mutate', DARWIN)).toBe(false)
  })

  it('tmpdir 在 /var/folders 下：不再因 sensitiveRoots 的 /var 前缀误报', () => {
    const p = `${MAC_TMP}/dsh-workspace-changes-K9/index-Q1/index`
    expect(isSensitivePath(p, cfg, 'mutate')).toBe(true) // 未配置该根时是一条 /var 根命中
    expect(isSensitivePath(p, cfgWithMacTmp, 'mutate')).toBe(false)
  })

  it('cfg.tempRoots 覆盖生效：自定义临时根写/删放行，其余照旧', () => {
    const custom: HookConfig = { ...DEFAULT_HOOK_CONFIG, tempRoots: ['/scratch/tmp'] }
    expect(isSensitivePath('/scratch/tmp/work/a.bin', custom, 'mutate')).toBe(false)
    expect(isSensitivePath('/scratch/work/a.bin', custom, 'mutate')).toBe(false)
    expect(isSensitivePath('/scratch/tmp/../../etc/hosts', custom, 'mutate')).toBe(true)
  })
})

describe('classifyOp：现场不再产出 red fs-destroy', () => {
  it('rmdir 私有 index（/var/folders/…/T 临时根）→ null（无报警）', () => {
    // classifyOp 走 process.platform（CI 上多为 linux，不折叠 /private）；用 tempRoots 覆盖把
    // 「归一化后落在临时根下」这一分支端到端覆盖——归一化本身由上组用例按 darwin 断言。
    const c: HookConfig = { ...DEFAULT_HOOK_CONFIG, tempRoots: ['/tmp', '/var/tmp', MAC_TMP] }
    expect(classifyOp({ module: 'fs', op: 'rmdirSync', args: [`${MAC_TMP}/dsh-workspace-changes-K9/index-Q1`] }, c))
      .toBeNull()
    expect(classifyOp({ module: 'fs', op: 'unlinkSync', args: [`${MAC_TMP}/dsh-workspace-changes-K9/index-Q1/index`] }, c))
      .toBeNull()
  })

  it('边界：/etc/hosts 删除仍 red fs-destroy（豁免不外溢）', () => {
    const a = classifyOp({ module: 'fs', op: 'unlinkSync', args: ['/etc/hosts'] }, DEFAULT_HOOK_CONFIG)
    expect(a?.kind).toBe('fs-destroy')
    expect(a?.severity).toBe('red')
  })
})

describe('端到端：真实 fs 包装器 + 模拟 darwin（复刻现场 op 序列）', () => {
  /**
   * 这是把三件事接起来的那一层验证：patchModule 的包装器 → classifyOp → isSensitivePath 的
   * 平台默认值（process.platform）。上面的用例都是显式传 'darwin' 直接调判定函数，若哪天默认
   * 参数没接到 process.platform，那些用例照绿而真机照报——所以这里把平台的读入口本身换成
   * darwin，跑一遍现场的真实 op 序列。Linux CI 上因此能复刻 macOS 的判定。
   */
  const withDarwin = <T>(fn: () => T): T => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform')
    Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })
    try {
      return fn()
    } finally {
      if (original !== undefined) Object.defineProperty(process, 'platform', original)
    }
  }

  const removeMod = (): Record<string, unknown> => ({
    // 真实调用会 ENOENT（这些路径在本机不存在），包装器在调用前分类，所以抛错不影响断言
    unlinkSync: () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) },
    rmdirSync: () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) },
    renameSync: () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) },
    writeFileSync: () => undefined,
  })
  const swallow = (fn: () => void): void => { try { fn() } catch { /* ENOENT */ } }

  it('现场 unlink/rmdir/rename 序列 → 零报警；/private/etc/hosts 删除仍 red', () => {
    const staging = '/private/tmp/.writer.applescript.9.4b1c5d6e-1111-2222-3333-444455556666.tmpdir'
    const macTmp = '/private/var/folders/95/k3x9q0r1/T/dsh-workspace-changes-K9'
    const alarms: HookAlarm[] = []
    const mod = removeMod()
    const c: HookConfig = { ...DEFAULT_HOOK_CONFIG, tempRoots: ['/tmp', '/var/tmp', MAC_TMP] }
    const dispose = patchModule(mod, 'fs', c, a => alarms.push(a), () => new Map())
    try {
      withDarwin(() => {
        swallow(() => (mod.unlinkSync as (p: string) => void)(`${staging}/writer.applescript.tmp`))
        swallow(() => (mod.renameSync as (a: string, b: string) => void)(
          `${staging}/writer.applescript.tmp`, '/private/var/folders/95/k3x9q0r1/T/out.applescript'))
        swallow(() => (mod.rmdirSync as (p: string) => void)(staging))
        swallow(() => (mod.unlinkSync as (p: string) => void)(`${macTmp}/index-Q1/index`))
        swallow(() => (mod.rmdirSync as (p: string) => void)(`${macTmp}/index-Q1`))
      })
      expect(alarms).toEqual([])
      // 对照：同一包装器下 /private/etc/hosts（规范化后命中 /etc 系统根）照旧 red fs-destroy
      withDarwin(() => swallow(() => (mod.unlinkSync as (p: string) => void)('/private/etc/hosts')))
      expect(alarms).toHaveLength(1)
      expect(alarms[0]).toMatchObject({ kind: 'fs-destroy', severity: 'red' })
    } finally {
      dispose()
    }
  })

  it('大小写变体不再绕过系统根：/ETC/hosts 写入 → persistence-write（darwin）', () => {
    // macOS 默认卷大小写不敏感：/ETC/hosts 与 /etc/hosts 是同一个文件。旧实现的前缀判定
    // 区分大小写，等于留一条「大写拼写静默改写 /etc/hosts」的口子。
    const alarms: HookAlarm[] = []
    const mod = removeMod()
    const dispose = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => alarms.push(a), () => new Map())
    try {
      withDarwin(() => (mod.writeFileSync as (p: string, d: string) => void)('/ETC/hosts', '1.2.3.4 evil'))
      expect(alarms).toHaveLength(1)
      expect(alarms[0]).toMatchObject({ kind: 'persistence-write' })
      // 非 darwin 平台不折叠大小写（ext4 区分大小写，/ETC/hosts 根本写不到 /etc/hosts）
      alarms.length = 0
      ;(mod.writeFileSync as (p: string, d: string) => void)('/ETC/hosts', 'x')
      expect(alarms).toEqual([])
    } finally {
      dispose()
    }
  })

  it('蜜罐/金丝雀在临时根下仍按 realpath 拼写命中（豁免不吞高置信信号）', () => {
    const alarms: HookAlarm[] = []
    const mod = removeMod()
    const c: HookConfig = {
      ...DEFAULT_HOOK_CONFIG,
      tempRoots: ['/tmp', '/var/tmp', MAC_TMP],
      honeypotRoots: ['/tmp/hp/'],
      integrityRoots: ['/tmp/canary.yaml'],
    }
    const dispose = patchModule(mod, 'fs', c, a => alarms.push(a), () => new Map())
    try {
      withDarwin(() => {
        swallow(() => (mod.unlinkSync as (p: string) => void)('/private/tmp/hp/lure.txt'))
        ;(mod.writeFileSync as (p: string, d: string) => void)('/private/tmp/canary.yaml', 'x')
      })
      expect(alarms.map(a => a.kind)).toEqual(['honeypot', 'integrity'])
    } finally {
      dispose()
    }
  })
})
