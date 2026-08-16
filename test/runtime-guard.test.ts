import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest'
import { VetStatus } from '../lib/guard/status.js'
import { analyzeSample, detectGrowth, type ProcSample, type RssSample, type WatchConfig } from '../lib/guard/runtime-watch.js'
import {
  classifyOp, isSensitivePath, isTransientTempPath, patchModule, pluginFromStack, setRootIndexing, DEFAULT_HOOK_CONFIG,
} from '../lib/guard/runtime-hooks.js'
import { readHostMetrics } from '../lib/guard/metrics.js'
import { ensureHoneypot, DEFAULT_HONEYPOT_DIR } from '../lib/guard/honeypot.js'
import { registerStatusRouteOnce, writeRuntimeGuardConfig, readPatchRuntimeGuard } from '../lib/guard/status-route.js'
import { decideRespawn, t2AlarmId, installRuntimeGuard, isAttributableEntry } from '../lib/guard/runtime-guard.js'
import { hasAuditRecord, setArchiveDirForTest } from '../lib/audit/archive.js'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import fsDefault from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const CFG: WatchConfig = { intervalMs: 2000, memLimitMb: 1024, forkBurstN: 5, fdLimit: 512, growthMb: 256, growthWindowMs: 600_000 }

function sample(partial: Partial<ProcSample>): ProcSample {
  return { rssKb: 512 * 1024, childCount: 0, fdCount: 10, at: Date.now(), ...partial }
}

describe('VetStatus（盾牌聚合器）', () => {
  it('green 初始态', () => {
    const s = new VetStatus()
    const snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarmCount).toBe(0)
  })

  it('yellow 报警 → yellow；同 id 窗口内去重', () => {
    const s = new VetStatus({ dedupeWindowMs: 60_000 })
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: Date.now() }
    expect(s.record(alarm)).toBe('new')
    expect(s.record({ ...alarm, at: Date.now() + 1000 })).toBe('deduped')
    expect(s.snapshot().level).toBe('yellow')
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('red 报警压过 yellow → red', () => {
    const s = new VetStatus()
    s.record({ id: 'a', severity: 'yellow', source: 't2', kind: 'fs-write', message: 'y', at: Date.now() })
    s.record({ id: 'b', severity: 'red', source: 't1', kind: 'mem', message: 'r', at: Date.now() })
    expect(s.snapshot().level).toBe('red')
  })

  it('窗口外的同 id 重新报警（P2-4 replace 语义：旧副本被顶替，不占双槽）', () => {
    const s = new VetStatus({ dedupeWindowMs: 10 })
    const oldAt = Date.now() - 1000
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: oldAt }
    expect(s.record(alarm)).toBe('new')
    // 窗口外同 id 重发：旧实现直接 push 新副本（持续报警 ~62s/次会占满 20 槽→alarmCount 虚高、
    // 其他报警被挤出）；修复后先移除旧副本再入列（replace 语义）
    expect(s.record({ ...alarm, at: Date.now() })).toBe('new')
    const snap = s.snapshot()
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms[0].at).not.toBe(oldAt) // 新记录顶替旧记录
  })

  it('alarmMax 环形截断', () => {
    const s = new VetStatus({ alarmMax: 3, dedupeWindowMs: 0 })
    for (let i = 0; i < 5; i++) {
      s.record({ id: `a${i}`, severity: 'yellow', source: 't2', kind: 'fs-write', message: `m${i}`, at: Date.now() + i })
    }
    expect(s.snapshot().alarmCount).toBe(3)
    expect(s.snapshot().alarms[0].id).toBe('a4')
  })

  it('noteScan suspicious → yellow 抬升', () => {
    const s = new VetStatus()
    expect(s.snapshot().level).toBe('green')
    s.noteScan({ pluginName: 'evil', verdict: 'suspicious', staticScore: 40, at: Date.now() })
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: 'good', verdict: 'clean', staticScore: 100, at: Date.now() })
    expect(s.snapshot().level).toBe('green')
  })

  it('P2-2：报警 TTL 过期后不再影响盾牌（误报不永久黄/红）', () => {
    // 500ms 前报警，TTL 100ms → 已过期：snapshot 里消失、level 回 green
    const s = new VetStatus({ alarmTtlMs: 100, dedupeWindowMs: 0 })
    s.record({ id: 'old-red', severity: 'red', source: 't1', kind: 'mem', message: 'x', at: Date.now() - 500 })
    expect(s.snapshot().level).toBe('green')
    expect(s.snapshot().alarmCount).toBe(0)
    // 新报警在 TTL 内 → 生效
    s.record({ id: 'fresh-red', severity: 'red', source: 't1', kind: 'mem', message: 'x', at: Date.now() })
    expect(s.snapshot().level).toBe('red')
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('忽略：dismissed 不计入 level 与 count；可恢复；记录保留', () => {
    const s = new VetStatus({ dedupeWindowMs: 0 })
    s.record({ id: 't1:fd:512', severity: 'yellow', source: 't1', kind: 'fd', message: 'x', at: Date.now() })
    s.record({ id: 't1:mem:2048', severity: 'red', source: 't1', kind: 'mem', message: 'y', at: Date.now() })
    expect(s.snapshot().level).toBe('red')
    // 忽略 red → 只剩 yellow
    s.dismiss('t1:mem:2048')
    let snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms.map(a => a.id)).toEqual(['t1:fd:512'])
    expect(snap.dismissed.map(a => a.id)).toEqual(['t1:mem:2048'])
    expect(s.isDismissed('t1:mem:2048')).toBe(true)
    // 全部忽略 → green（shield 不看被忽略的报警）
    s.dismiss('t1:fd:512')
    expect(s.snapshot().level).toBe('green')
    // 恢复 red → 它回来（fd 仍忽略）→ red，count 1
    s.restore('t1:mem:2048')
    snap = s.snapshot()
    expect(snap.level).toBe('red')
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms.map(a => a.id)).toEqual(['t1:mem:2048'])
    // 全部恢复 → count 2，dismissed 清空
    s.restore('t1:fd:512')
    snap = s.snapshot()
    expect(snap.alarmCount).toBe(2)
    expect(snap.dismissed).toHaveLength(0)
  })

  it('忽略状态随报警过期自动清除（将来复发重新可见，可再忽略）', () => {
    const s = new VetStatus({ alarmTtlMs: 100, dedupeWindowMs: 0 })
    s.record({ id: 'a', severity: 'red', source: 't1', kind: 'mem', message: 'x', at: Date.now() - 500 })
    s.dismiss('a')
    expect(s.snapshot().alarms).toHaveLength(0) // 记录已 TTL 过期
    expect(s.isDismissed('a')).toBe(false)       // 无存活记录 → 忽略自动清除
    // 同 id 再触发 → 重新可见
    s.record({ id: 'a', severity: 'red', source: 't1', kind: 'mem', message: 'x', at: Date.now() })
    expect(s.snapshot().alarmCount).toBe(1)
    expect(s.snapshot().level).toBe('red')
  })

  it('P3-2：lastScan 按 TTL 过期——一次 suspicious 不永久黄，过期回 green', () => {
    const s = new VetStatus({ alarmTtlMs: 100 })
    s.noteScan({ pluginName: 'evil', verdict: 'suspicious', staticScore: 40, at: Date.now() - 500 }) // 500ms 前（> TTL）
    expect(s.snapshot().level).toBe('green')
    expect(s.snapshot().lastScan).toBeUndefined()
    // 新鲜扫描 → yellow；clean 不抬升
    s.noteScan({ pluginName: 'e2', verdict: 'suspicious', staticScore: 40, at: Date.now() })
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: 'good', verdict: 'clean', staticScore: 100, at: Date.now() })
    expect(s.snapshot().level).toBe('green')
  })
})

describe('hasAuditRecord（档案门槛：M1 前缀 + P-1 版本精确）', () => {
  const d = mkdtempSync(join(process.cwd(), '.tmp-arch-'))
  const dir = join(d, 'audits')
  beforeAll(() => {
    mkdirSync(dir, { recursive: true })
    setArchiveDirForTest(dir)
  })
  afterAll(() => {
    setArchiveDirForTest(join(homedir(), '.dsh', 'vet', 'audits'))
    rmSync(d, { recursive: true, force: true })
  })
  it('M1：前缀伪造不命中——lodash-foo 档案 ≠ lodash 档案', () => {
    writeFileSync(join(dir, 'lodash-foo-1.0.0-20260815-120000.md'), '# x')
    expect(hasAuditRecord('lodash')).toBe(false)
    writeFileSync(join(dir, 'lodash-4.17.21-20260815-120000.md'), '# y')
    expect(hasAuditRecord('lodash')).toBe(true)
  })
  it('P-1：版本精确匹配——旧版本档案不放行新版本', () => {
    writeFileSync(join(dir, 'pkg-1.0.0-20260815-120000.md'), '# v1 档案')
    expect(hasAuditRecord('pkg', '1.0.0')).toBe(true)  // 同版本 → 通过
    expect(hasAuditRecord('pkg', '1.2.0')).toBe(false) // 升级 → 必须重新审计
  })
  it('P-1：不传版本（无法解析）→ 宽松匹配任意精确版本档案', () => {
    expect(hasAuditRecord('pkg')).toBe(true) // 存在 1.0.0 档案，宽松即过
    expect(hasAuditRecord('nope')).toBe(false)
  })
})

describe('decideRespawn / t2AlarmId（P0-2/P1-6 判定逻辑）', () => {
  it('P0-2：env 指向本哨兵 + 非 stopping + 未达上限 → respawn（旧实现恒 false 的死代码回归）', () => {
    expect(decideRespawn(42, 42, false, 0, 5)).toBe(true)
    expect(decideRespawn(42, 42, false, 4, 5)).toBe(true)
    // stopping → 不复活（off/卸载场景）
    expect(decideRespawn(42, 42, true, 0, 5)).toBe(false)
    // env 已清（undefined）或指向别的 pid → 不复活
    expect(decideRespawn(undefined, 42, false, 0, 5)).toBe(false)
    expect(decideRespawn(43, 42, false, 0, 5)).toBe(false)
    // 达上限 → 不复活
    expect(decideRespawn(42, 42, false, 5, 5)).toBe(false)
    // child pid 未定义（spawn 失败）→ 不复活
    expect(decideRespawn(undefined, undefined, false, 0, 5)).toBe(false)
  })

  it('P1-6：报警 id 拼 pluginHint——两插件同路径不同 id，不互吞', () => {
    const a = t2AlarmId('fs-read', '/home/u/.ssh/id_rsa', 'evil-a')
    const b = t2AlarmId('fs-read', '/home/u/.ssh/id_rsa', 'evil-b')
    expect(a).not.toBe(b)
    expect(t2AlarmId('fs-read', '/home/u/.ssh/id_rsa', 'evil-a'))
      .toBe(t2AlarmId('fs-read', '/home/u/.ssh/id_rsa', 'evil-a'))
    // 无归因时以 kind+target 为 id（与旧行为兼容）
    expect(t2AlarmId('fs-read', '/home/u/.ssh/id_rsa', undefined))
      .toBe('t2:fs-read:/home/u/.ssh/id_rsa:')
  })

  it('A9：归因映射排除 vet 自身（isAttributableEntry）——包装器帧不再把宿主报警栽给 vet', () => {
    expect(isAttributableEntry('@jieai/dsh-plugin-vet')).toBe(false)
    expect(isAttributableEntry('@deepseek-ai/dsh')).toBe(true)
    expect(isAttributableEntry('evil-plugin')).toBe(true)
    // 栈归因配合排除后的映射：首个非 vet 根命中 → 归因到真实调用方
    const roots = new Map([
      ['/app/node_modules/evil-plugin/lib', 'evil-plugin'],
    ])
    // 栈顶是 vet 包装器帧（不在映射里）→ 跳过 → 命中 evil-plugin
    const stack = 'Error\n    at wrapped (/app/node_modules/@jieai/dsh-plugin-vet/lib/guard/runtime-hooks.js:306:20)\n    at caller (/app/node_modules/evil-plugin/lib/index.js:10:5)'
    expect(pluginFromStack(stack, roots)).toBe('evil-plugin')
    // 全部帧都是 vet 自身 → 归因落空（无主），不栽赃
    const vetOnly = 'Error\n    at wrapped (/app/node_modules/@jieai/dsh-plugin-vet/lib/guard/runtime-hooks.js:306:20)'
    expect(pluginFromStack(vetOnly, roots)).toBeUndefined()
  })
})

describe('analyzeSample（T1 差分判定）', () => {
  it('内存超限 → red', () => {
    const alarms = analyzeSample(null, sample({ rssKb: 2048 * 1024 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'mem' })
  })

  it('fork 突增 → red（prev 为 null 不误报）', () => {
    expect(analyzeSample(null, sample({ childCount: 20 }), CFG)).toHaveLength(0)
    const alarms = analyzeSample(sample({ childCount: 1 }), sample({ childCount: 20 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'fork' })
  })

  it('fd 超限 → yellow', () => {
    const alarms = analyzeSample(null, sample({ fdCount: 600 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'yellow', kind: 'fd' })
  })

  it('稳态无报警', () => {
    expect(analyzeSample(sample({}), sample({}), CFG)).toHaveLength(0)
  })
})

describe('detectGrowth（持续膨胀/疑似泄漏检测）', () => {
  const gcfg = { growthMb: 256, growthWindowMs: 600_000 }
  const s = (rssMb: number, at: number): RssSample => ({ rssKb: rssMb * 1024, at })

  it('窗口内净增长 < 阈值 → 不报警', () => {
    const samples = [s(200, 0), s(300, 300_000), s(400, 600_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('净增长越过 1 倍 → yellow growth，倍数更新', () => {
    const samples = [s(200, 0), s(300, 300_000), s(500, 600_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(1)
    expect(r.alarms[0]).toMatchObject({ severity: 'yellow', kind: 'growth' })
    expect(r.alarms[0].message).toContain('持续膨胀')
    expect(r.multiples).toBe(1)
  })

  it('同倍数不重复报警（去重）', () => {
    const r = detectGrowth([s(200, 0), s(500, 600_000)], gcfg, 1)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(1)
  })

  it('回落归零重置倍数', () => {
    const r = detectGrowth([s(500, 0), s(200, 600_000)], gcfg, 2)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('窗口外的旧样本不参与（起点取窗口内）', () => {
    const samples = [s(900, 0), s(300, 200_000), s(600, 800_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.multiples).toBe(1)
  })

  it('测量跨度未覆盖完整窗口 → 不报警（起窗初期的瞬时尖峰不是"持续膨胀"）', () => {
    // 实测误报形态：窗口 10 分钟，但采样只覆盖 20 秒就涨了 274MB → 不构成窗口级持续膨胀
    const samples = [s(500, 0), s(774, 20_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('稳态抖动（最老样本晚于 cutoff 几 ms）仍能检出真实持续膨胀——跨度容差 90%', () => {
    // 真实采样时间戳带抖动：跨度 599999ms（略小于 600000ms 窗口），净增长 300MB → 必须报警
    // （此前严格 span >= window 的写法会让 growth 永远不触发）
    const samples = [s(500, 101_001), s(530, 300_000), s(800, 701_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(1)
    expect(r.multiples).toBe(1)
  })
})

describe('isSensitivePath / classifyOp（T2 分类）', () => {
  it('敏感路径判定', () => {
    expect(isSensitivePath('/etc/passwd', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etc', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etcetera/foo', DEFAULT_HOOK_CONFIG)).toBe(false)
    expect(isSensitivePath('/home/user/.ssh/id_rsa', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/.env.local', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/project/src/index.ts', DEFAULT_HOOK_CONFIG)).toBe(false)
  })

  it('敏感路径删除 → red fs-destroy', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rmSync', args: ['/etc/hosts'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red', kind: 'fs-destroy' })
  })

  it('atomic-write 协议锁（<file>.lock）的删/写豁免（盾牌实测误报）', () => {
    // DSH 写凭据用 dsh-atomic-write：wx 创建 <credentials>.lock（内容仅 PID），写完 finally rm 删锁——
    // 宿主每次保存凭据都触发 unlink(.lock) → fs-destroy red 无主误报（.dsh 敏感段命中）
    expect(classifyOp({ module: 'fs', op: 'unlink', args: ['/home/user/.dsh/.credentials.yaml.lock'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'fs', op: 'rmSync', args: ['/home/user/.dsh/.credentials.yaml.lock'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 锁文件的写入（wx 创建带 PID）也是协议操作 → 不再误报 fs-write
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/.dsh/.credentials.yaml.lock', '12345'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 精度不丢：凭据本体删除仍报 red fs-destroy，非 lock 敏感删除仍报
    expect(classifyOp({ module: 'fs', op: 'rmSync', args: ['/home/user/.dsh/.credentials.yaml'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'red', kind: 'fs-destroy' })
    expect(classifyOp({ module: 'fs', op: 'rmSync', args: ['/home/user/.ssh/id_rsa'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'red', kind: 'fs-destroy' })
  })

  it('敏感路径写入 → yellow fs-write', () => {
    const alarm = classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/.npmrc', 'x'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-write' })
  })

  it('敏感路径读取 → yellow fs-read', () => {
    const alarm = classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/user/.ssh/id_ed25519'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-read' })
  })

  it('普通路径写入不报警', () => {
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/a.txt', 'x'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('库名含 token 子串不误报（js-tokens 回归）', () => {
    // 旧规则：sensitiveSegments 子串匹配把合法库名 js-tokens 当敏感词
    expect(isSensitivePath('/opt/node_modules/@deepseek-ai/dsh/node_modules/js-tokens/index.js', DEFAULT_HOOK_CONFIG)).toBe(false)
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/opt/node_modules/@deepseek-ai/dsh/node_modules/js-tokens/index.js'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 沙箱清理临时文件（文件名带 js-tokens）也不该触发 fs-destroy
    expect(classifyOp({ module: 'fs', op: 'rmdir', args: ['/tmp/._probe-js-tokens.mjs.4152567.abc.tmpdir'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('凭据语义路径仍报警（精度不丢）', () => {
    expect(isSensitivePath('/app/secrets.prod.yaml', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/creds/credentials.json', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/server.key', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/prod.env', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.aws/credentials', DEFAULT_HOOK_CONFIG)).toBe(true)
  })

  it('含 shell/下载关键词的子进程 → yellow spawn', () => {
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['curl http://x'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'yellow', kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['/bin/sh', ['-c', 'rm -rf /tmp/x']] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['wget', ['https://x/y']] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
  })

  it('M7：readdir/stat 敏感路径侦察 → yellow fs-probe（凭据狩猎第一步可见）', () => {
    expect(classifyOp({ module: 'fs', op: 'readdirSync', args: ['/home/user/.ssh'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'yellow', kind: 'fs-probe' })
    expect(classifyOp({ module: 'fs', op: 'statSync', args: ['/home/user/.env'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-probe' })
    expect(classifyOp({ module: 'fs', op: 'accessSync', args: ['/etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-probe' })
    // 普通目录/文件侦察不报
    expect(classifyOp({ module: 'fs', op: 'readdirSync', args: ['/home/user/project'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('A9：node_modules 包目录豁免——敏感词包名（dsh-credentials-local 等）不再误报 fs-probe', () => {
    // 用户实测报警：宿主模块解析 require.resolve 内部 realpathSync 包内 package.json。
    // 注：P2-6 后 ~/.dsh 整段敏感（配置根），这些豁免用例的 fixture 一律放非 .dsh 工作路径，
    // 只测「node_modules 段之后不参与敏感判定」这一 A9 属性（.dsh 段之前的判定见下方 companion）。
    const pkg = '/home/chen/work/profiles/node_modules/@deepseek-ai/dsh-credentials-local/package.json'
    expect(isSensitivePath(pkg, DEFAULT_HOOK_CONFIG, 'read')).toBe(false)
    expect(classifyOp({ module: 'fs', op: 'realpathSync', args: [pkg] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'fs', op: 'realpath', args: [pkg] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'fs', op: 'statSync', args: [pkg] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // AWS SDK 凭据提供者全家桶（真实 12 个敏感词包名之一）
    expect(isSensitivePath('/home/chen/work/profiles/node_modules/@aws-sdk/credential-provider-env/package.json', DEFAULT_HOOK_CONFIG, 'read')).toBe(false)
    // 包内 .env 也不敏感（包文件是公开工件，凭据在用户/系统目录）
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/chen/work/node_modules/foo/.env'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // P2-6 companion：即使包名豁免，配置根 ~/.dsh 段之前的 .dsh 段照常敏感（readdirSync('~/.dsh') 侦察可见）
    expect(classifyOp({ module: 'fs', op: 'readdirSync', args: ['/home/chen/.dsh'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-probe' })
    expect(classifyOp({ module: 'fs', op: 'statSync', args: ['/home/chen/.dsh/profiles/foo/package.json'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-probe' })
    // mutate 下系统根前缀仍生效：删 /usr/lib/node_modules 下的文件照样报
    expect(isSensitivePath('/usr/lib/node_modules/foo/index.js', DEFAULT_HOOK_CONFIG, 'mutate')).toBe(true)
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/usr/lib/node_modules/foo/index.js', 'x'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // 豁免只作用于 node_modules 段之后：~/.ssh/node_modules/x 仍命中 .ssh
    expect(isSensitivePath('/home/u/.ssh/node_modules/x', DEFAULT_HOOK_CONFIG, 'read')).toBe(true)
    expect(classifyOp({ module: 'fs', op: 'readdirSync', args: ['/home/u/.ssh/node_modules'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-probe' })
  })

  it('A9 集成：包装器在线上报的 realpathSync 场景不再产生任何报警（端到端复刻）', () => {
    const tmp = mkdtempSync(join(process.cwd(), '.tmp-a9-'))
    const pkgDir = join(tmp, 'node_modules', '@deepseek-ai', 'dsh-credentials-local')
    mkdirSync(pkgDir, { recursive: true })
    mkdirSync(join(tmp, '.ssh'), { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), '{}')
    const alarms: HookAlarm[] = []
    // 生产 rootIndex：归因映射不含 vet 根（isAttributableEntry 已排除）
    const dispose = patchModule(fsDefault as unknown as Record<string, unknown>, 'fs', DEFAULT_HOOK_CONFIG, a => alarms.push(a), () => new Map([['/app/node_modules/evil/lib', 'evil-plugin']]))
    try {
      // 宿主模块解析链：realpathSync 包内 package.json（属性访问触发包装器，同线上）
      fsDefault.realpathSync(join(pkgDir, 'package.json'))
      fsDefault.statSync(join(pkgDir, 'package.json'))
      expect(alarms).toHaveLength(0)
      // 对照：真敏感路径（不在 node_modules 下）照常报警——豁免没有吞掉探测能力
      fsDefault.writeFileSync(join(tmp, '.ssh', 'probe'), 'x')
      expect(alarms).toHaveLength(1)
      expect(alarms[0].kind).toBe('fs-write')
    } finally {
      dispose()
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('常规子进程（git/node/pnpm）不报警', () => {
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['git', ['status']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'execFile', args: ['node', ['server.js']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['npm run build'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('读取系统根下普通文件不报警；写删仍报（read/mutate 分档）', () => {
    expect(isSensitivePath('/usr/lib/node_modules/foo/index.js', DEFAULT_HOOK_CONFIG, 'read')).toBe(false)
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/usr/lib/node_modules/foo/index.js'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(isSensitivePath('/usr/lib/node_modules/foo/index.js', DEFAULT_HOOK_CONFIG, 'mutate')).toBe(true)
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/usr/lib/node_modules/foo/index.js', 'x'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // /etc/passwd 由精确段名覆盖，读取仍报（枚举目标不漏）
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-read' })
    // 新增敏感名：.netrc / .pgpass / .gitconfig
    expect(isSensitivePath('/home/u/.netrc', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.pgpass', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.gitconfig', DEFAULT_HOOK_CONFIG)).toBe(true)
  })

  it('工具链临时产物豁免：tsc <源名>.<pid>.<uuid>.tmpdir 里的 secrets 是源文件名不是密钥文件', () => {
    const tmp = '/home/u/project/scanner-bin/rules/.secrets.ts.165387.14e663d0-bab4-4539-92de-22a80a17fd7d.tmpdir'
    expect(isTransientTempPath(tmp)).toBe(true)
    expect(isTransientTempPath('/home/u/x/report.tmp')).toBe(true)
    expect(isTransientTempPath('/home/u/x/file.ts')).toBe(false)
    expect(isSensitivePath(tmp, DEFAULT_HOOK_CONFIG)).toBe(false)
    // classifyOp 层面：rmdir 该临时目录 → 不报警（此前误报为 fs-destroy red）
    expect(classifyOp({ module: 'fs', op: 'rmdir', args: [tmp] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 父段仍敏感：~/.ssh/config.bak 命中 .ssh（临时后缀只豁免末段）
    expect(isSensitivePath('/home/u/.ssh/config.bak', DEFAULT_HOOK_CONFIG)).toBe(true)
    // .env 系临时文件仍敏感（.env. 前缀判定先于临时豁免）
    expect(isSensitivePath('/home/u/.env.tmp', DEFAULT_HOOK_CONFIG)).toBe(true)
    // 系统根内的临时文件仍算 mutate 敏感（写删 /usr 下的临时文件照样报）
    expect(isSensitivePath('/usr/lib/foo.tmp', DEFAULT_HOOK_CONFIG)).toBe(true)
    // 真实密钥名（不带临时后缀）不受影响
    expect(isSensitivePath('/home/u/.ssh/id_rsa', DEFAULT_HOOK_CONFIG)).toBe(true)
  })

  it('对象参数取 path', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rm', args: [{ path: '/etc/passwd', recursive: true }] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red' })
  })

  it('createWriteStream 写敏感路径 → yellow fs-write（D29 补漏：流式写入此前漏报）', () => {
    expect(classifyOp({ module: 'fs', op: 'createWriteStream', args: ['/home/user/.ssh/authorized_keys'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'yellow', kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'createWriteStream', args: ['/home/user/log.txt'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('open 带写 flags → fs-write；只读 flags → fs-read（D29 补漏）', () => {
    expect(classifyOp({ module: 'fs', op: 'open', args: ['/etc/hosts', 'w'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'openSync', args: ['/home/u/.env', 'a+'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'open', args: ['/etc/passwd', 'r'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-read' })
  })

  it('P1-7：open 首参路径以 r/w/a 开头不再误当 flags（open auth.txt 只读）', () => {
    // 旧实现 args.find(/^[rwa]/) 命中 'auth.txt'（a 开头）→ 误报 fs-write；现在 flags 只认短形态
    expect(classifyOp({ module: 'fs', op: 'open', args: ['auth.txt', 'r'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-read' })
    expect(classifyOp({ module: 'fs', op: 'open', args: ['auth.txt', 'r'] }, DEFAULT_HOOK_CONFIG)).not.toMatchObject({ kind: 'fs-write' })
    // 路径含 w 开头且只读 → 也不误报写
    expect(classifyOp({ module: 'fs', op: 'open', args: ['writable.txt', 'r'] }, DEFAULT_HOOK_CONFIG)).not.toMatchObject({ kind: 'fs-write' })
    // 真正的写 flags 仍报
    expect(classifyOp({ module: 'fs', op: 'open', args: ['auth.txt', 'w'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // 长字符串（如模式串）不算 flags
    expect(classifyOp({ module: 'fs', op: 'open', args: ['/home/u/.env', 'w'], }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
  })

  it('P1-8：exec 破坏性命令（rm -rf ~/.ssh）→ spawn 报警；常规清理不报', () => {
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['rm -rf ~/.ssh'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['rm -rf /tmp/x'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['echo x > /etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['rm', ['-rf', '/home/u/.ssh']] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['cp', ['-r', '/tmp/a', '/tmp/b']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 常规 git/node 仍不报
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['npm run build'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('cp/rename 双向：src 敏感（拷密钥出局）或 dest 敏感（覆盖系统文件）都报（D29 补漏）', () => {
    // src 敏感：把 .env 拷出去
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/home/u/.env', '/tmp/stolen'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // dest 敏感：把恶意文件覆盖成 /etc/hosts
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/evil', '/etc/hosts'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // rename 落位系统路径
    expect(classifyOp({ module: 'fs', op: 'rename', args: ['/tmp/evil', '/etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // 普通 cp 不报
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/a.txt', '/tmp/b.txt'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })
})

describe('R31：归因阶段 fs 直通（递归护栏）', () => {
  it('敏感包名（dsh-credentials-local）下归因不再无限递归：恰好一条报警、标志经 finally 清除', () => {
    const tmp = mkdtempSync(join(process.cwd(), '.tmp-r31-'))
    // 复刻真实崩溃场景：profile node_modules 里有含敏感词（credentials）的包名
    const pkgDir = join(tmp, 'node_modules', '@deepseek-ai', 'dsh-credentials-local')
    mkdirSync(pkgDir, { recursive: true })
    writeFileSync(join(pkgDir, 'package.json'), '{}')
    mkdirSync(join(tmp, '.ssh'), { recursive: true })
    const alarms: HookAlarm[] = []
    // 模拟生产 rootIndex：置标志 → 经被包装的 fs 探测敏感名包路径（会再进包装器）→ finally 清标志
    const rootIndex = (): Map<string, string> => {
      setRootIndexing(true)
      try {
        // realpathSync 在被包装的 fs 上属性访问调用（ESM 具名导入会绕过钩子）
        try { fsDefault.realpathSync(join(pkgDir, 'package.json')) } catch { /* 存在与否都要走包装器 */ }
        return new Map([[pkgDir, '@deepseek-ai/dsh-credentials-local']])
      } finally {
        setRootIndexing(false)
      }
    }
    const dispose = patchModule(fsDefault as unknown as Record<string, unknown>, 'fs', DEFAULT_HOOK_CONFIG, a => alarms.push(a), rootIndex)
    try {
      // 触发真实报警：写敏感路径 → 归因 → rootIndex 内 realpathSync 敏感名包 → 不应递归
      // （无护栏时此处 RangeError: Maximum call stack size exceeded）
      fsDefault.writeFileSync(join(tmp, '.ssh', 'probe'), 'x')
      expect(alarms).toHaveLength(1)
      expect(alarms[0].kind).toBe('fs-write')
      // 标志已清：第二次敏感写入照常报警（护栏不吞报警）
      fsDefault.writeFileSync(join(tmp, '.ssh', 'probe'), 'y')
      expect(alarms).toHaveLength(2)
    } finally {
      dispose()
      setRootIndexing(false)
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('置位期间敏感操作直通（不报警）；清除后恢复报警', () => {
    const alarms: HookAlarm[] = []
    const dispose = patchModule(fsDefault as unknown as Record<string, unknown>, 'fs', DEFAULT_HOOK_CONFIG, a => alarms.push(a), () => new Map())
    try {
      const p = join(mkdtempSync(join(process.cwd(), '.tmp-r31b-')), '.env')
      setRootIndexing(true)
      fsDefault.writeFileSync(p, 'x') // 直通：不报警
      expect(alarms).toHaveLength(0)
      setRootIndexing(false)
      fsDefault.writeFileSync(p, 'y') // 恢复：报警
      expect(alarms).toHaveLength(1)
    } finally {
      dispose()
      setRootIndexing(false)
    }
  })

  it('rootIndex 抛错：P1-3 归因失败不反噬原始调用——报警保留无主，写照常执行', () => {
    const alarms: HookAlarm[] = []
    let throwOnce = true
    const dispose = patchModule(fsDefault as unknown as Record<string, unknown>, 'fs', DEFAULT_HOOK_CONFIG, a => alarms.push(a), () => {
      setRootIndexing(true)
      try {
        if (throwOnce) {
          throwOnce = false
          throw new Error('rootIndex boom')
        }
        return new Map()
      } finally {
        setRootIndexing(false)
      }
    })
    try {
      const p = join(mkdtempSync(join(process.cwd(), '.tmp-r31c-')), '.env')
      // 旧实现把归因异常传给调用方（写被吞）；P1-3 改为 catch：报警保留（pluginHint 无主）、
      // fs 调用永不因归因失败而中断——归因只是 best-effort 增强
      fsDefault.writeFileSync(p, 'x')
      expect(alarms).toHaveLength(1)
      expect(alarms[0].kind).toBe('fs-write')
      expect(alarms[0].pluginHint).toBeUndefined() // 归因失败 → 报警无主而非丢失
      expect(readFileSync(p, 'utf8')).toBe('x')    // 原始写照常执行
      // 标志已清 + 归因恢复 → 正常报警且调用成功
      fsDefault.writeFileSync(p, 'y')
      expect(alarms).toHaveLength(2)
      expect(readFileSync(p, 'utf8')).toBe('y')
    } finally {
      dispose()
      setRootIndexing(false)
    }
  })
})

describe('pluginFromStack（栈归因）', () => {
  it('file:// 帧命中插件根 → 包名', () => {
    const roots = new Map([['/app/node_modules/evil-plugin/lib', 'evil-plugin']])
    const stack = 'Error\n    at wrapper (/app/node_modules/evil-plugin/lib/index.js:10:5)\n    at Object.<anonymous> (/app/main.js:1:1)'
    expect(pluginFromStack(stack, roots)).toBe('evil-plugin')
  })

  it('裸路径帧命中 → 包名；未命中 → undefined', () => {
    const roots = new Map([['/x/lib', '@scope/pkg']])
    expect(pluginFromStack('Error\n    at foo (/x/lib/a.js:1:1)', roots)).toBe('@scope/pkg')
    expect(pluginFromStack('Error\n    at foo (/other/b.js:1:1)', roots)).toBeUndefined()
  })

  it('空映射 / 空栈 → undefined', () => {
    expect(pluginFromStack(undefined, new Map())).toBeUndefined()
    expect(pluginFromStack('Error', new Map([['/x', 'x']]))).toBeUndefined()
  })
})

describe('patchModule（包装 + 恢复）', () => {
  it('危险操作报警、普通操作直通、disposer 恢复', () => {
    const calls: string[] = []
    const fake = {
      writeFile: (p: string) => { calls.push(`write:${p}`) },
      readFile: (p: string) => { calls.push(`read:${p}`) },
    }
    const alarms: string[] = []
    const dispose = patchModule(
      fake as unknown as Record<string, unknown>,
      'fs',
      DEFAULT_HOOK_CONFIG,
      a => { alarms.push(a.kind) },
      () => new Map(),
    )
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/home/user/.env')
    ;(fake as unknown as { readFile: (p: string) => void }).readFile('/home/user/a.txt')
    expect(alarms).toEqual(['fs-write'])
    expect(calls).toEqual(['write:/home/user/.env', 'read:/home/user/a.txt'])

    dispose()
    const restored = fake as unknown as Record<string, unknown>
    expect(restored.writeFile).toBeTypeOf('function')
    // 恢复后调用不再报警
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/etc/x')
    expect(alarms).toEqual(['fs-write'])
  })

  it('fs.promises 独立对象也被包装（Promise 调用同样报警）', async () => {
    const fakePromises = {
      readFile: async (p: string) => Buffer.from('x'),
      writeFile: async (p: string) => { },
    }
    const alarms: string[] = []
    const dispose = patchModule(
      fakePromises as unknown as Record<string, unknown>,
      'fs',
      DEFAULT_HOOK_CONFIG,
      a => { alarms.push(a.kind) },
      () => new Map(),
    )
    await (fakePromises as unknown as { readFile(p: string): Promise<Buffer> }).readFile('/home/user/.ssh/id_rsa')
    expect(alarms).toEqual(['fs-read'])
    await (fakePromises as unknown as { writeFile(p: string): Promise<void> }).writeFile('/home/user/.env')
    expect(alarms).toEqual(['fs-read', 'fs-write'])
    dispose()
  })
})

describe('readHostMetrics（宿主实时指标）', () => {
  it('Linux 下返回完整形状且字段在界内', () => {
    const m = readHostMetrics()
    expect(m.rssMb).toBeGreaterThanOrEqual(0)
    expect(m.cpuPct).toBeGreaterThanOrEqual(0)
    expect(m.ioReadMb).toBeGreaterThanOrEqual(0)
    expect(m.ioWriteMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpRssMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpCount).toBeGreaterThanOrEqual(0)
    expect(m.vetRssMb).toBeGreaterThanOrEqual(0)
    expect(m.vetCount).toBeGreaterThanOrEqual(0)
    expect(m.childCount).toBeGreaterThanOrEqual(-1)
    expect(m.fdCount).toBeGreaterThanOrEqual(-1)
    expect(m.at).toBeGreaterThan(0)
  })
})

describe('writeRuntimeGuardConfig（profile 配置写入）', () => {
  const mkCtx = (baseUrl: string): { baseUrl: string; logger?: undefined } => ({ baseUrl })

  it('enable 写入条目 + 重复 enable 幂等 + disable 移除', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n  config:\n    watch: false\n')

    const ctx = mkCtx(dir)
    const r1 = writeRuntimeGuardConfig(ctx, true)
    expect(r1.ok).toBe(true)
    const content1 = readFileSync(patch, 'utf8')
    expect(content1).toContain('- id: plugin-vet')
    expect(content1).toContain('runtimeGuard: watch')

    const r2 = writeRuntimeGuardConfig(ctx, true) // 重复开启：重写而不是叠加，仍只有一条
    expect(r2.ok).toBe(true)
    const content2 = readFileSync(patch, 'utf8')
    expect(content2.match(/- id: plugin-vet/g)?.length).toBe(1)

    const r3 = writeRuntimeGuardConfig(ctx, false)
    expect(r3.ok).toBe(true)
    const content3 = readFileSync(patch, 'utf8')
    expect(content3).not.toContain('plugin-vet')
    expect(content3).toContain('- id: settings')

    rmSync(dir, { recursive: true, force: true })
  })

  it('旧形态包名条目（含引号）会被重写/移除（自愈）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n- id: "@jieai/dsh-plugin-vet"\n  config:\n    runtimeGuard: watch\n')

    const r1 = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r1.ok).toBe(true)
    const content1 = readFileSync(patch, 'utf8')
    expect(content1).toContain('- id: plugin-vet')
    expect(content1).not.toContain('@jieai/dsh-plugin-vet')

    const r2 = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r2.ok).toBe(true)
    const content2 = readFileSync(patch, 'utf8')
    expect(content2).not.toContain('plugin-vet')
    expect(content2).not.toContain('@jieai/dsh-plugin-vet')
    expect(content2).toContain('- id: settings')

    rmSync(dir, { recursive: true, force: true })
  })

  it('vet 条目 config 含嵌套列表也能完整剥离（D29：缩进边界）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n  config:\n    watch: false\n- id: plugin-vet\n  config:\n    runtimeGuard: watch\n    allowlist:\n      - foo\n      - bar\n- id: other\n  config:\n    x: 1\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content).not.toContain('plugin-vet')
    expect(content).not.toContain('allowlist')
    expect(content).toContain('- id: settings')
    expect(content).toContain('- id: other')
    expect(content).toContain('x: 1')
    rmSync(dir, { recursive: true, force: true })
  })

  it('未配置时 disable 返回 ok', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })

  it('baseUrl 为 file: URL 时正常读写（DSH web profile 实际形态）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx('file:' + dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('runtimeGuard: watch')
    const r2 = writeRuntimeGuardConfig(mkCtx('file:' + dir), false)
    expect(r2.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).not.toContain('plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 enable 直接新建', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('- id: plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('H1：disable 后文件只剩 vet 条目 → 写 []（DSH boot 契约，空文件会抛错）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    runtimeGuard: watch\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content.trim()).toBe('[]')

    rmSync(dir, { recursive: true, force: true })
  })

  it('H2：开启守卫保留已有 config 的非 runtimeGuard 键（deny/allowlist 不被冲掉）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    mode: deny\n    allowlist:\n      - foo\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content).toContain('mode: deny')
    expect(content).toContain('allowlist')
    expect(content).toContain('runtimeGuard: watch')

    rmSync(dir, { recursive: true, force: true })
  })

  it('M5：readPatchRuntimeGuard 读文件级实际状态（watch/off）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    expect(readPatchRuntimeGuard(mkCtx(dir))).toBe('off')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    runtimeGuard: watch\n')
    expect(readPatchRuntimeGuard(mkCtx(dir))).toBe('watch')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 disable 视为未开启', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })
})

describe('registerStatusRouteOnce（webServer 就绪重试）', () => {
  it('webServer 未就绪 → false，不注册', () => {
    const routes: unknown[] = []
    const ctx = {
      baseUrl: '/tmp',
      get: () => undefined,
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'off' } as never, new VetStatus())
    expect(ok).toBe(false)
    expect(routes).toHaveLength(0)
  })

  it('webServer 就绪 → true，注册 /vet 前缀路由', () => {
    let handler: unknown
    const routes: unknown[] = []
    const ws = { register: (r: unknown) => { routes.push(r); return () => {} } }
    const ctx = {
      baseUrl: '/tmp',
      get: (name: string) => (name === 'webServer' ? ws : undefined),
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'watch' } as never, new VetStatus())
    expect(ok).toBe(true)
    expect(routes).toHaveLength(1)
    expect((routes[0] as { path: string }).path).toBe('/vet')
  })

  it('HTTP handler：GET status.json 返回快照；POST 无 Origin 拒绝；未知路径 404', () => {
    let handler: (req: unknown, res: unknown) => void
    const routes: unknown[] = []
    const ws = { register: (r: unknown) => { routes.push(r); return () => {} } }
    const status = new VetStatus()
    status.record({ id: 't1:fd:512', severity: 'yellow', source: 't1', kind: 'fd', message: 'x', at: Date.now() })
    const ctx = {
      baseUrl: '/tmp',
      get: (name: string) => (name === 'webServer' ? ws : undefined),
      effect: (fn: () => unknown) => { fn() },
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    } as never
    registerStatusRouteOnce(ctx as never, { runtimeGuard: 'watch' } as never, status)
    handler = (routes[0] as { handler: typeof handler }).handler

    // GET /vet/status.json → 200 快照
    const getRes: { code: number; body: unknown } = { code: 0, body: null }
    const gres = {
      writableEnded: false,
      writeHead: (code: number) => { getRes.code = code },
      end: (body: string) => { getRes.body = JSON.parse(body) },
    }
    handler({ method: 'GET', url: '/vet/status.json', headers: {} }, gres)
    expect(getRes.code).toBe(200)
    expect((getRes.body as { level: string }).level).toBe('yellow')
    expect((getRes.body as { runtimeGuard: string }).runtimeGuard).toBe('off')

    // POST /vet/runtime-guard 无 Origin → 403（跨站防护，M4）
    const postRes: { code: number; body: unknown } = { code: 0, body: null }
    const pres = {
      writableEnded: false,
      writeHead: (code: number) => { postRes.code = code },
      end: (body: string) => { postRes.body = JSON.parse(body) },
      on: () => {},
    }
    handler({ method: 'POST', url: '/vet/runtime-guard', headers: {} }, pres)
    expect(postRes.code).toBe(403)

    // 未知路径 → 404
    const nfRes: { code: number; body: unknown } = { code: 0, body: null }
    const nres = {
      writableEnded: false,
      writeHead: (code: number) => { nfRes.code = code },
      end: (body: string) => { nfRes.body = JSON.parse(body) },
    }
    handler({ method: 'GET', url: '/vet/other', headers: {} }, nres)
    expect(nfRes.code).toBe(404)

    // POST /vet/dismiss {id}（同源）→ 200；GET 再查 → 报警进 dismissed、count/level 降下来
    const mkRes = (): { code: number; body: unknown } & { writableEnded: boolean } => {
      const r = { code: 0, body: null as unknown, writableEnded: false }
      return Object.assign(r, {
        writeHead: (c: number) => { r.code = c },
        end: (b: string) => { r.body = JSON.parse(b) },
      })
    }
    const disRes = mkRes()
    handler(
      {
        method: 'POST',
        url: '/vet/dismiss',
        headers: { origin: 'http://x', host: 'x' },
        on: (ev: string, cb: (c?: Buffer) => void) => {
          if (ev === 'data') cb(Buffer.from(JSON.stringify({ id: 't1:fd:512' })))
          if (ev === 'end') cb()
        },
      },
      disRes,
    )
    expect(disRes.code).toBe(200)
    const get2 = mkRes()
    handler({ method: 'GET', url: '/vet/status.json', headers: {} }, get2)
    expect((get2.body as { alarmCount: number }).alarmCount).toBe(0)
    expect((get2.body as { level: string }).level).toBe('green')
    expect((get2.body as { dismissed: unknown[] }).dismissed).toHaveLength(1)

    // POST /vet/restore {id} → 报警回来
    const resRes = mkRes()
    handler(
      {
        method: 'POST',
        url: '/vet/restore',
        headers: { origin: 'http://x', host: 'x' },
        on: (ev: string, cb: (c?: Buffer) => void) => {
          if (ev === 'data') cb(Buffer.from(JSON.stringify({ id: 't1:fd:512' })))
          if (ev === 'end') cb()
        },
      },
      resRes,
    )
    expect(resRes.code).toBe(200)
    const get3 = mkRes()
    handler({ method: 'GET', url: '/vet/status.json', headers: {} }, get3)
    expect((get3.body as { alarmCount: number }).alarmCount).toBe(1)
    expect((get3.body as { level: string }).level).toBe('yellow')

    // dismiss 无 Origin → 403；缺 id / 非字符串 → 400
    const noOrigin = mkRes()
    handler({ method: 'POST', url: '/vet/dismiss', headers: {}, on: () => {} }, noOrigin)
    expect(noOrigin.code).toBe(403)
    const badId = mkRes()
    handler(
      {
        method: 'POST',
        url: '/vet/dismiss',
        headers: { origin: 'http://x', host: 'x' },
        on: (ev: string, cb: (c?: Buffer) => void) => {
          if (ev === 'data') cb(Buffer.from(JSON.stringify({})))
          if (ev === 'end') cb()
        },
      },
      badId,
    )
    expect(badId.code).toBe(400)
  })
})

describe('ensureHoneypot（蜜罐播种）', () => {
  it('创建诱饵文件集，内容/文件名无蜜罐关键词（反蜜罐）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-hp-data-'))
    const root = ensureHoneypot(dir)
    expect(root).toBe(dir)
    const names = ['id_rsa.pem', 'id_rsa.pub', '.env', 'credentials.json', '.npmrc', '.netrc', 'aws-credentials']
    for (const n of names) {
      expect(readFileSync(join(dir, n), 'utf8').length).toBeGreaterThan(10)
    }
    // 反蜜罐：文件名/内容都不该出现 honeypot/vet/decoy/fake 关键词
    for (const n of names) {
      expect(n).not.toMatch(/honeypot|vet|decoy|fake/i)
      expect(readFileSync(join(dir, n), 'utf8')).not.toMatch(/honeypot|vet[-_]|decoy|fake/i)
    }
    // RSA 诱饵是真实格式
    expect(readFileSync(join(dir, 'id_rsa.pem'), 'utf8')).toContain('BEGIN PRIVATE KEY')
    rmSync(dir, { recursive: true, force: true })
  })

  it('幂等：已存在诱饵不重写；被删诱饵自动重建', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-honeypot-'))
    ensureHoneypot(dir)
    const before = readFileSync(join(dir, '.env'), 'utf8')
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.env'), 'utf8')).toBe(before)
    // 用户预置文件不被覆盖
    writeFileSync(join(dir, '.env'), 'REAL=value')
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.env'), 'utf8')).toBe('REAL=value')
    // 被删诱饵重建（自愈）
    rmSync(join(dir, '.npmrc'))
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.npmrc'), 'utf8').length).toBeGreaterThan(10)
    rmSync(dir, { recursive: true, force: true })
  })

  it('默认目录位于 ~/.dsh 下且无蜜罐关键词', () => {
    expect(DEFAULT_HONEYPOT_DIR).toContain('.dsh')
    expect(DEFAULT_HONEYPOT_DIR).toContain('.local')
    expect(DEFAULT_HONEYPOT_DIR).not.toMatch(/honeypot|vet|decoy|fake/i)
  })
})

describe('installRuntimeGuard（T1 哨兵 + T2 钩子集成，覆盖率补盲）', () => {
  const mkCtx = (): { logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }; baseUrl?: string; loader?: unknown } => ({
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  })

  it('watch 模式：装 guard → 真实 fs 写敏感路径 → T2 报警进 status；dispose 恢复', () => {
    const ctx = mkCtx()
    const status = new VetStatus()
    const config = {
      runtimeGuard: 'watch' as const,
      runtimeIntervalMs: 2000, runtimeMemLimitMb: 1024, runtimeForkBurstN: 5,
      runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
      honeypot: { enabled: false, dir: '' },
    }
    const dispose = installRuntimeGuard(ctx as never, config as never, status)
    try {
      // 真实 fs 模块已被包装：写敏感路径应产生 fs-write 报警（T2 生效）
      const before = status.snapshot().alarmCount
      // 用真实 fs 触发（写一个临时敏感命名路径）
      const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-integ-'))
      try {
        // 用属性访问（fsDefault.writeFileSync）触发——ESM 具名导入是 patch 前固化的原始引用，
        // patchModule 包装的是模块对象属性（README 已知旁路），属性访问才能命中 T2 钩子
        fsDefault.writeFileSync(join(dir, 'id_rsa.pem'), 'x') // id_rsa 段名敏感
        const snap = status.snapshot()
        expect(snap.alarmCount).toBeGreaterThan(before)
        expect(snap.alarms[0].kind).toBe('fs-write')
        expect(snap.alarms[0].id).toContain('t2:fs-write:')
        // P1-6：id 含 pluginHint 段（无归因时为空段，格式完整）
        expect(snap.alarms[0].id).toMatch(/^t2:fs-write:.+:.*$/)
      } finally {
        fsDefault.rmSync(dir, { recursive: true, force: true })
      }
    } finally {
      dispose()
    }
    // dispose 后：环境变量清空、再写不再报警（钩子已恢复）
    expect(process.env.DSH_VET_SIDECAR_PID).toBeUndefined()
    const after = status.snapshot().alarmCount
    const dir2 = mkdtempSync(join(process.cwd(), '.tmp-guard-integ2-'))
    try {
      fsDefault.writeFileSync(join(dir2, 'id_rsa.pem'), 'y')
      expect(status.snapshot().alarmCount).toBe(after)
    } finally {
      fsDefault.rmSync(dir2, { recursive: true, force: true })
    }
  })

  it('off 模式：不 spawn 哨兵、不装钩子，蜜罐提示（覆盖率补盲）', () => {
    const ctx = mkCtx()
    const status = new VetStatus()
    const config = {
      runtimeGuard: 'off' as const,
      honeypot: { enabled: true, dir: '' },
    }
    const dispose = installRuntimeGuard(ctx as never, config as never, status)
    dispose()
    expect(ctx.logger.warn).toHaveBeenCalledWith(expect.stringContaining('蜜罐未生效'))
    expect(process.env.DSH_VET_SIDECAR_PID).toBeUndefined()
  })
})

describe('蜜罐报警（classifyOp）', () => {
  const mkCfg = (roots: string[]): typeof DEFAULT_HOOK_CONFIG => ({ ...DEFAULT_HOOK_CONFIG, honeypotRoots: roots })

  it('M7：readdir 蜜罐根目录 → honeypot 报警（翻找的第一个动作）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-hp-probe-'))
    ensureHoneypot(dir)
    const cfg = mkCfg([dir])
    expect(classifyOp({ module: 'fs', op: 'readdirSync', args: [dir] }, cfg)).toMatchObject({ kind: 'honeypot', severity: 'yellow' })
    expect(classifyOp({ module: 'fs', op: 'readdir', args: [dir] }, cfg)).toMatchObject({ kind: 'honeypot' })
    rmSync(dir, { recursive: true, force: true })
  })

  it('触碰诱饵路径 → 独立 honeypot 报警（读黄/删红）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-honeypot-'))
    ensureHoneypot(dir)
    const cfg = mkCfg([dir])
    const read = classifyOp({ module: 'fs', op: 'readFileSync', args: [join(dir, '.env')] }, cfg)
    expect(read).toMatchObject({ kind: 'honeypot', severity: 'yellow' })
    const del = classifyOp({ module: 'fs', op: 'rmSync', args: [join(dir, 'credentials.json')] }, cfg)
    expect(del).toMatchObject({ kind: 'honeypot', severity: 'red' })
    const write = classifyOp({ module: 'fs', op: 'writeFile', args: [join(dir, '.npmrc'), 'x'] }, cfg)
    expect(write).toMatchObject({ kind: 'honeypot', severity: 'yellow' })
    rmSync(dir, { recursive: true, force: true })
  })

  it('未启用蜜罐（空蜜罐根）不产生 honeypot 报警；普通敏感路径仍按原规则', () => {
    const cfg = mkCfg([])
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/user/.ssh/id_rsa'] }, cfg)).toMatchObject({ kind: 'fs-read' })
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/tmp/whatever/index.js'] }, cfg)).toBeNull()
  })
})
describe('sidecar 单例锁（D30 修漏：配置热重载重复 apply 不再叠加哨兵）', () => {
  // spawn 子进程需要真实可执行 JS：用编译产物（npm test = build + vitest；源码是 .ts 不能直接跑）
  const watchPath = fileURLToPath(new URL('../lib/guard/runtime-watch.js', import.meta.url))
  const args = [watchPath, '--vet-sidecar', '2000', '2048', '5', '512', '256', '600000']

  // T1 哨兵完全依赖 /proc（单例认亲 + 宿主存活看护都是 /proc 读取）；Windows 无 /proc，
  // 首个 tick 就会按「宿主不可读」优雅退出（exit 0），单例锁语义无从验证——Linux 专属用例。
  it.skipIf(process.platform === 'win32')('同宿主重复 spawn → 后者立即退出（exit 0），前者存活', async () => {
    const first = spawn(process.execPath, args, { stdio: 'ignore' })
    // 等第一个完成 exec（cmdline 可读）再 spawn 第二个，避免 /proc 竞态
    // 等 first 进入稳态（单例锁已通过、setInterval 已建立）再 spawn second——
    // 模拟生产时序：热重载时旧哨兵早已运行，新 spawn 的哨兵晚到 → 新自杀、旧存活。
    // 不能只等 exec：first 和 second 若几乎同时 exec 完，各自扫描都能看到对方 → 两个都自杀（测试竞态）。
    await new Promise((resolve) => setTimeout(resolve, 1000))
    const second = spawn(process.execPath, args, { stdio: 'ignore' })
    const code = await new Promise<number | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), 5000)
      second.on('exit', (c) => { clearTimeout(timer); resolve(c) })
    })
    expect(code).toBe(0) // 后者自杀退出
    // 前者还活着
    expect(first.exitCode).toBeNull()
    first.kill()
  })
})