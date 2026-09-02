import { describe, expect, it } from 'vitest'
import { patchModule, DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { isDshWebTempArtifact, isDshAtomicStagingPath, isDshRuntimeTempPath, isDshLockSiblingProbe } from '../lib/guard/runtime-denoise.js'
import type { HookAlarm, HookConfig } from '../lib/guard/runtime-hooks.js'
import { VetStatus } from '../lib/guard/status.js'
import { createT2Sink } from '../lib/guard/runtime-sink.js'

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

/**
 * 0.3.3（P7，用户警报疲劳反馈）：DSH 宿主会话存储写临时文件（~/.dsh/sessions 下的
 * *.tmp 等，随用随清）——lstat/stat 探针成对出现，栈里只有宿主帧 → 无归因 → 每次
 * 会话轮转刷 yellow fs-probe（实测：~/.dsh/sessions 下临时件被 lstat）。
 * 修复：仅对侦察类（fs-probe）+ 无归因 + 未篡改降噪；写/删同类路径不走此豁免
 * （会话日志轮换已有 isSessionLogFile 独立语义）；插件归因照报。
 */
describe('DSH sessions 运行时临时件无归因侦察豁免（P7）', () => {
  it('匹配器：sessions/ 下临时后缀命中；本体/凭据/其他目录不命中', () => {
    expect(isDshRuntimeTempPath('/home/u/.dsh/sessions/sess-abc.tmp')).toBe(true)
    expect(isDshRuntimeTempPath('/home/u/.dsh/profiles/web/node_modules/x/.dsh/sessions/y.tmp')).toBe(true)
    // 会话日志本体（轮换分片）不在豁免内——写/删语义不受影响
    expect(isDshRuntimeTempPath('/home/u/.dsh/sessions/s.jsonl.zstd.9a3')).toBe(false)
    // 凭据面/tmp 全局临时件不命中
    expect(isDshRuntimeTempPath('/home/u/.ssh/tmp/scan.tmp')).toBe(false)
    expect(isDshRuntimeTempPath('/tmp/x.tmp')).toBe(false)
    // 非 sessions 的 .dsh 临时件不命中（settings 原子写已有 isDshAtomicStagingPath 专属判定）
    expect(isDshRuntimeTempPath('/home/u/.dsh/settings.yaml.tmp')).toBe(false)
  })

  it('无归因 lstat/stat/access sessions 临时件 → 不再报 fs-probe（用户实测场景）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK', statSync: () => 'OK', accessSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.lstatSync('/home/u/.dsh/sessions/sess-abc.tmp')
      mod.statSync('/home/u/.dsh/sessions/sess-def.tmp')
      mod.accessSync('/home/u/.dsh/sessions/sess-ghi.tmp')
      expect(sink).toEqual([])
    } finally { disp() }
  })

  it('边界：sessions 非日志形状（非本体探针）无归因侦察照报（豁免不外溢）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      // 会话目录本体探针（非会话日志文件形状）——isSessionLogFile 不命中 → 照报；
      // 0.3.5 后会话日志文件形状（session.jsonl / 分片）的无归因 lstat 已是宿主家务静默
      mod.lstatSync('/home/u/.dsh/sessions')
      expect(sink.some(a => a.kind === 'fs-probe')).toBe(true)
    } finally { disp() }
  })

  it('边界：删除/写入 sessions 临时件不走侦察豁免（写删仍照报）', () => {
    const mod: Record<string, unknown> = { unlinkSync: () => 'OK', writeFileSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      // 该路径本身不在敏感判定面（临时后缀）→ 无报警是正常的；造一个敏感形态验证写删照报：
      mod.unlinkSync('/home/u/.dsh/sessions/x.secret.tmp')
      expect(sink.some(a => a.kind === 'fs-destroy' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })

  it('边界：插件归因碰 sessions 临时件 → 照报（碰宿主状态=信号）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@evil/plugin']]))
    try {
      mod.lstatSync('/home/u/.dsh/sessions/sess-abc.tmp')
      expect(sink.some(a => a.kind === 'fs-probe' && a.pluginHint === '@evil/plugin')).toBe(true)
    } finally { disp() }
  })

  it('边界：完整性金丝雀优先级高于豁免', () => {
    const canary = '/home/u/.dsh/sessions/vet-integrity-1.tmp'
    const cfg = { ...DEFAULT_HOOK_CONFIG, integrityRoots: [canary] } as HookConfig
    const mod: Record<string, unknown> = { rmSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', cfg, a => sink.push(a), () => new Map())
    try {
      mod.rmSync(canary)
      expect(sink.some(a => a.kind === 'integrity' && a.severity === 'red')).toBe(true)
    } finally { disp() }
  })
})

/**
 * 0.3.5（P8，用户机实测三条警报回归）：信任模型反转为官方全集判据后，官方真身的家务
 * 探针不再逐条黄警：
 * ① lstat(~/.dsh/.credentials.yaml.lock) 无归因（withFileLock 陈旧锁探测，宿主帧）→ 静默；
 * ② lstat(~/.dsh/sessions/…/session.jsonl.zstd.554ba1) 归因 @deepseek-ai/dsh-session-persistence-jsonl
 *   （会话存储本尊的轮换探针，无归因豁免结构上够不到）→ info 聚合观察（非黄警、非静默）；
 * ③ lstat(~/.dsh/settings.yaml.lock) 归因 @deepseek-ai/dsh-settings-file（atomic-write 在其帧内
 *   执行，首见/离线期未入内容信任锚）→ info 聚合观察。
 * 边界：第三方归因碰锁/碰会话分片照报；官方名碰凭据本体/配置本体照报（形状钉死）；
 * 官方名写删与蜜罐/金丝雀不受本豁免影响。
 */
describe('DSH 锁兄弟与官方会话家务探针（P8，0.3.5 用户警报疲劳⑥）', () => {
  it('匹配器：~/.dsh 下 <file>.lock 命中；.dsh 外/.lock 外不命中', () => {
    expect(isDshLockSiblingProbe('/home/u/.dsh/.credentials.yaml.lock')).toBe(true)
    expect(isDshLockSiblingProbe('/home/u/.dsh/settings.yaml.lock')).toBe(true)
    expect(isDshLockSiblingProbe('/home/u/.dsh/profiles/web/.x.lock')).toBe(true)
    // .dsh 外的锁兄弟无协议豁免依据 → 不命中（照报）
    expect(isDshLockSiblingProbe('/home/u/.ssh/id_rsa.lock')).toBe(false)
    expect(isDshLockSiblingProbe('/home/u/project/x.lock')).toBe(false)
    // 锁本体（非 .lock 后缀）不命中
    expect(isDshLockSiblingProbe('/home/u/.dsh/.credentials.yaml')).toBe(false)
  })

  it('①无归因 lstat 凭据锁兄弟 → 静默（用户机实测路径）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK', statSync: () => 'OK', accessSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.lstatSync('/home/chenzheng/.dsh/.credentials.yaml.lock')
      mod.statSync('/home/chenzheng/.dsh/.credentials.yaml.lock')
      mod.accessSync('/home/chenzheng/.dsh/.credentials.yaml.lock')
      expect(sink).toEqual([])
    } finally { disp() }
  })

  it('无归因 lstat 会话日志文件形状 → 静默（0.1.19 只修删除侧，侦察侧补齐）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
    try {
      mod.lstatSync('/home/chenzheng/.dsh/sessions/--mnt-data-1jiaru--/session-267e2cad/session.jsonl.zstd.554ba1')
      expect(sink).toEqual([])
    } finally { disp() }
  })

  it('③官方名归因 lstat settings 锁兄弟 → 打标 officialHousekeeping（sink 再降 info）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@deepseek-ai/dsh-settings-file']]))
    try {
      mod.lstatSync('/home/chenzheng/.dsh/settings.yaml.lock')
      const hit = sink.find(a => a.pluginHint === '@deepseek-ai/dsh-settings-file')
      expect(hit).toBeDefined()
      expect(hit?.kind).toBe('fs-probe')
      expect(hit?.officialHousekeeping).toBe(true)
    } finally { disp() }
  })

  it('②官方名归因 lstat 会话日志分片 → 打标 officialHousekeeping（用户机实测路径）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@deepseek-ai/dsh-session-persistence-jsonl']]))
    try {
      mod.lstatSync('/home/chenzheng/.dsh/sessions/--mnt-data-1jiaru--/session-267e2cad-6770-4496-96e4-caca6429b58a/session.jsonl.zstd.554ba1')
      const hit = sink.find(a => a.pluginHint === '@deepseek-ai/dsh-session-persistence-jsonl')
      expect(hit).toBeDefined()
      expect(hit?.kind).toBe('fs-probe')
      expect(hit?.officialHousekeeping).toBe(true)
    } finally { disp() }
  })

  it('边界：第三方归因 lstat .dsh 锁兄弟 → 照报（无 officialHousekeeping 标记，yellow）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@evil/plugin']]))
    try {
      mod.lstatSync('/home/u/.dsh/.credentials.yaml.lock')
      const hit = sink.find(a => a.kind === 'fs-probe')
      expect(hit?.pluginHint).toBe('@evil/plugin')
      expect(hit?.officialHousekeeping).not.toBe(true)
    } finally { disp() }
  })

  it('边界：第三方归因 lstat 会话日志分片 → 照报（无标记）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@evil/plugin']]))
    try {
      mod.lstatSync('/home/u/.dsh/sessions/x/session.jsonl.zstd.554ba1')
      const hit = sink.find(a => a.kind === 'fs-probe')
      expect(hit?.pluginHint).toBe('@evil/plugin')
      expect(hit?.officialHousekeeping).not.toBe(true)
    } finally { disp() }
  })

  it('边界：官方名 lstat 凭据本体/配置本体 → 照报（形状钉死，不吃 Tier B）', () => {
    const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
    const sink: HookAlarm[] = []
    const here = import.meta.dirname
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map([[here, '@deepseek-ai/dsh-settings-file']]))
    try {
      mod.lstatSync('/home/u/.dsh/.credentials.yaml')
      mod.lstatSync('/home/u/.dsh/settings.yaml')
      expect(sink.filter(a => a.kind === 'fs-probe').length).toBe(2)
      expect(sink.some(a => a.officialHousekeeping === true)).toBe(false)
    } finally { disp() }
  })
})

/** P8 sink 层：officialHousekeeping 标记 → info 聚合观察（可见、不计 alarmCount/level）。 */
describe('P8 sink：官方家务探针降 info 聚合（0.3.5）', () => {
  it('info 记录、跨包合并为一条、alarmCount 计 0、level 不抬', () => {
    const status = new VetStatus()
    const { sink } = createT2Sink(status)
    sink({ severity: 'yellow', kind: 'fs-probe', message: '探测 settings.yaml.lock', target: '/home/u/.dsh/settings.yaml.lock', pluginHint: '@deepseek-ai/dsh-settings-file', officialHousekeeping: true })
    sink({ severity: 'yellow', kind: 'fs-probe', message: '探测 session 分片', target: '/home/u/.dsh/sessions/x/s.jsonl.zstd.1', pluginHint: '@deepseek-ai/dsh-session-persistence-jsonl', officialHousekeeping: true })
    const snap = status.snapshot()
    const infos = snap.alarms.filter(a => a.kind === 'fs-probe')
    // 两条同 mergeKey → 聚合为一条 info
    expect(infos.length).toBe(1)
    expect(infos[0].severity).toBe('info')
    expect(snap.alarmCount).toBe(0)
    expect(snap.level).toBe('green')
  })

  it('未打标的官方名 fs-probe 照常 yellow（不是所有官方名都降级）', () => {
    const status = new VetStatus()
    const { sink } = createT2Sink(status)
    sink({ severity: 'yellow', kind: 'fs-probe', message: '探测 .credentials.yaml', target: '/home/u/.dsh/.credentials.yaml', pluginHint: '@deepseek-ai/dsh-settings-file' })
    const snap = status.snapshot()
    expect(snap.alarms.some(a => a.kind === 'fs-probe' && a.severity === 'yellow')).toBe(true)
    expect(snap.alarmCount).toBe(1)
  })
})
