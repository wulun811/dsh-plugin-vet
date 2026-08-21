import { describe, expect, it } from 'vitest'
import { patchModule, DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { isDshWebTempArtifact } from '../lib/guard/runtime-denoise.js'
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
