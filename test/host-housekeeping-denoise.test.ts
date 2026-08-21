import { describe, expect, it } from 'vitest'
import { patchModule, DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { isDshWebTempArtifact, isDshAtomicStagingPath } from '../lib/guard/runtime-denoise.js'
import type { HookAlarm, HookConfig } from '../lib/guard/runtime-hooks.js'

/**
 * 五轮用户反馈回归：DSH web 状态目录的原子写临时产物（`.shortcut-bar.json.<pid>.<uuid>.tmpdir`）
 * 由宿主自身高频创建/清理（lstat+rmdir 成对），栈里只有宿主帧 → 无归因 → 每次保存刷
 * red fs-destroy / yellow fs-probe。修复：无归因（且归因链未篡改）时按宿主自身豁免。
 * 边界：插件归因照报、真敏感路径照报、非临时产物照报、蜜罐/完整性金丝雀不受豁免。
 */
describe('DSH web 状态临时产物无归因豁免（五轮用户反馈）', () => {
  const TMP = `/home/u/.dsh/web/.shortcut-bar.json.${process.pid}.a1b2c3d4-e5f6-7890-abcd-ef0123456789.tmpdir`

  it('匹配器：web 目录 + 临时后缀命中；profiles/web 布局命中；凭据/会话/本体不命中', () => {
    expect(isDshWebTempArtifact(TMP)).toBe(true)
    expect(isDshWebTempArtifact('/home/u/.dsh/profiles/web/.x.json.1.a1b2c3d4-e5f6-7890-abcd-ef0123456789.tmp')).toBe(true)
    // 凭据面原子写临时件——刻意不在豁免范围
    expect(isDshWebTempArtifact(`/home/u/.dsh/.credentials.yaml.123.a1b2c3d4-e5f6-7890-abcd-ef0123456789.tmp`)).toBe(false)
    expect(isDshWebTempArtifact('/home/u/.dsh/sessions/s.jsonl.zstd.9a3')).toBe(false)
    // web 状态本体（非临时产物）不命中
    expect(isDshWebTempArtifact('/home/u/.dsh/web/shortcut-bar.json')).toBe(false)
    expect(isDshWebTempArtifact('/tmp/x.tmpdir')).toBe(false)
  })

  it('无归因 rmdir/lstat web 临时产物 → 不再报（用户反馈场景）', () => {
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK', lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.rmdirSync(TMP)
      mod.lstatSync(TMP)
      expect(sink).toEqual([])
    } finally { disp() }
  })

  it('边界：真敏感路径无归因照报（豁免不外溢）', () => {
    const mod: Record<string, unknown> = { unlinkSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.unlinkSync('/home/u/.ssh/id_rsa')
      expect(sink.some(a => a.kind === 'fs-destroy' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })

  it('边界：web 状态本体（非临时产物）无归因照报', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.lstatSync('/home/u/.dsh/web/shortcut-bar.json')
      expect(sink.some(a => a.kind === 'fs-probe')).toBe(true)
    } finally { disp() }
  })

  it('边界：插件归因碰 web 临时产物 → 照报（碰宿主状态=信号）', () => {
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK' }
    const sink: HookAlarm[] = []
    // rootIndex 命中本测试文件所在目录 → 栈归因到 @evil/plugin → 豁免条件（hint===undefined）不成立
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@evil/plugin']]))
    try {
      mod.rmdirSync(TMP)
      expect(sink.some(a => a.kind === 'fs-destroy' && a.pluginHint === '@evil/plugin')).toBe(true)
    } finally { disp() }
  })

  it('边界：完整性金丝雀优先级高于豁免（integrityRoots 命中 → red integrity 照报）', () => {
    const cfg = { ...DEFAULT_HOOK_CONFIG, integrityRoots: [TMP] } as HookConfig
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', cfg, a => sink.push(a), () => new Map())
    try {
      mod.rmdirSync(TMP)
      expect(sink.some(a => a.kind === 'integrity' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })
})

/**
 * 六轮用户反馈回归：DSH 宿主对任意文件（含 ~/.dsh/settings.yaml 本体）的原子写走 fs-local
 * writeFileAtomic——目标旁建 `.<basename>.<pid>.<uuid>.tmpdir` 暂存目录（0700），写入
 * `<basename>.tmp` 后 rename 提交、rm -rf 必删。用户手改配置触发宿主重存时，lstat+rmdir
 * 清理对落在 ~/.dsh 根（web/ 豁免之外）→ 无归因 red fs-destroy / yellow fs-probe。
 * 修复：段级严格形状匹配，无归因时按宿主自身豁免；凭据面协议形态（`<file>.<hex12>.tmp`）、
 * 配置本体、插件归因、蜜罐/完整性金丝雀照报。
 */
describe('DSH 原子写暂存目录无归因豁免（六轮用户反馈：settings.yaml 保存）', () => {
  const USER_STAGING = '/home/chenzheng/.dsh/.settings.yaml.277054.5fdbd427-01b0-44d2-a60f-acd62fba3302.tmpdir'
  const UUID = 'a1b2c3d4-e5f6-7890-abcd-ef0123456789'

  it('匹配器：~/.dsh 下 <name>.<pid>.<uuid>.tmpdir 段命中（目录本身与其内 .tmp）；形状外不命中', () => {
    expect(isDshAtomicStagingPath(USER_STAGING)).toBe(true)
    expect(isDshAtomicStagingPath(USER_STAGING + '/settings.yaml.tmp')).toBe(true)
    expect(isDshAtomicStagingPath('/home/u/.dsh/profiles/.x.json.1.' + UUID + '.tmpdir')).toBe(true)
    // 非 .dsh 目录不豁免
    expect(isDshAtomicStagingPath('/tmp/.x.1.' + UUID + '.tmpdir')).toBe(false)
    // 缺 pid 段的形态（storage-json 的 .<uuid>.tmp）不命中
    expect(isDshAtomicStagingPath('/home/u/.dsh/.' + UUID + '.tmp')).toBe(false)
    // 凭据面原子写临时件（hex12、无 pid/uuid 段）不命中——刻意保持报警
    expect(isDshAtomicStagingPath('/home/u/.dsh/.credentials.yaml.a1b2c3d4e5f6.tmp')).toBe(false)
    // 配置本体 / 会话日志不命中
    expect(isDshAtomicStagingPath('/home/u/.dsh/settings.yaml')).toBe(false)
    expect(isDshAtomicStagingPath('/home/u/.dsh/sessions/s.jsonl.zstd.9a3')).toBe(false)
  })

  it('无归因 rmdir/lstat/unlink settings 原子写暂存路径 → 不再报（用户机实测路径）', () => {
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK', lstatSync: () => 'OK', unlinkSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.rmdirSync(USER_STAGING)
      mod.lstatSync(USER_STAGING)
      mod.unlinkSync(USER_STAGING + '/settings.yaml.tmp')
      expect(sink).toEqual([])
    } finally { disp() }
  })

  it('边界：配置本体（非临时产物）无归因照报', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK', unlinkSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.lstatSync('/home/u/.dsh/settings.yaml')
      mod.unlinkSync('/home/u/.dsh/settings.yaml')
      expect(sink.some(a => a.kind === 'fs-probe')).toBe(true)
      expect(sink.some(a => a.kind === 'fs-destroy' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })

  it('边界：凭据面原子写临时件无归因照报（豁免不外溢到凭据协议形态）', () => {
    const mod: Record<string, unknown> = { unlinkSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.unlinkSync('/home/u/.dsh/.credentials.yaml.a1b2c3d4e5f6.tmp')
      expect(sink.some(a => a.kind === 'fs-destroy' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })

  it('边界：插件归因碰暂存目录 → 照报（碰宿主状态=信号）', () => {
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@evil/plugin']]))
    try {
      mod.rmdirSync(USER_STAGING)
      expect(sink.some(a => a.kind === 'fs-destroy' && a.pluginHint === '@evil/plugin')).toBe(true)
    } finally { disp() }
  })

  it('边界：完整性金丝雀优先级高于暂存目录豁免', () => {
    const cfg = { ...DEFAULT_HOOK_CONFIG, integrityRoots: [USER_STAGING] } as HookConfig
    const mod: Record<string, unknown> = { rmdirSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', cfg, a => sink.push(a), () => new Map())
    try {
      mod.rmdirSync(USER_STAGING)
      expect(sink.some(a => a.kind === 'integrity' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })
})
