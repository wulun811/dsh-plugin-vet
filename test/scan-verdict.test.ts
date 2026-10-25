/**
 * 扫描结论告警（0.4.1）：可读 + 可忽略 + 证据变化重新提醒。
 *
 * 起因是用户实测：DSH 0.2.1 的官方包钉了 zod@4.4.3，OSV 公告成立，盾牌因此永久黄，
 * 而旧实现没有任何可忽略的条目。这里锁住三件事：
 *   1. 文案把证据放在前 64 字符（面板折叠阈值）——依赖坐标必须第一屏可见；
 *   2. 忽略后 level 回 green，且同一证据重扫不会被重新拉黄；
 *   3. 证据变了（新公告 / 新规则 / verdict 变化）→ 新 id → 重新提醒，忽略不会永久失明。
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  parseOsvEvidence,
  scanVerdictAlarm,
  scanVerdictAlarmId,
  scanVerdictEvidenceKey,
  scanVerdictMessage,
  type ScanVerdictEcho,
} from '../lib/guard/scan-verdict.js'
import { VetStatus } from '../lib/guard/status.js'
import { setDismissedFileForTest } from '../lib/guard/dismissed-alerts.js'

// dismiss 会写持久化忽略表：每个用例用独立文件 + 清内存缓存，否则「忽略」用例会
// 把同证据的后续用例折叠进 dismissed 区（首轮就踩到了：alarms[0] 变 undefined）。
const TMP = mkdtempSync(join(tmpdir(), 'vet-scan-verdict-'))
let seq = 0
beforeEach(() => { setDismissedFileForTest(join(TMP, `dismissed-${seq++}.json`)) })
afterAll(() => { rmSync(TMP, { recursive: true, force: true }) })

const base = (over: Partial<ScanVerdictEcho> = {}): ScanVerdictEcho => ({
  pluginName: '@deepseek-ai/dsh-agent-loop',
  verdict: 'suspicious',
  staticScore: 80,
  at: Date.now(),
  rules: ['R2', 'R6', 'R9', 'R15', 'R10', 'OSV'],
  osv: '已知漏洞 GHSA-mrhx-c7xc-m3w5（CVE-2023-54404）：Zod can exhaust memory while validating oversized constrained collections',
  osvDependency: 'zod@4.4.3',
  osvId: 'GHSA-mrhx-c7xc-m3w5',
  osvAlias: 'CVE-2023-54404',
  official: true,
  ...over,
})

describe('scan-verdict：文案', () => {
  it('依赖坐标落在面板 64 字符折叠线之前（用户第一眼就能看到「是依赖的问题」）', () => {
    const msg = scanVerdictMessage(base())
    const at = msg.indexOf('zod@4.4.3')
    expect(at).toBeGreaterThanOrEqual(0)
    expect(at).toBeLessThan(64)
    expect(msg).toContain('GHSA-mrhx-c7xc-m3w5')
    expect(msg).toContain('CVE-2023-54404')
    expect(msg).toContain('官方包')
    expect(msg).toContain('忽略')
  })

  it('命中包自身（无依赖坐标）时不编造依赖', () => {
    const msg = scanVerdictMessage(base({ osvDependency: undefined }))
    expect(msg).not.toContain('依赖 undefined')
    expect(msg).not.toContain('依赖 ')
    expect(msg).toContain('GHSA-mrhx-c7xc-m3w5')
  })

  it('无 OSV 时退回结论 + 规则码', () => {
    const msg = scanVerdictMessage(base({ osv: undefined, osvId: undefined, osvAlias: undefined, osvDependency: undefined }))
    expect(msg).toContain('扫描结论 suspicious（80 分）')
    expect(msg).toContain('规则 R2/R6/R9/R15 等')
    expect(msg).not.toContain('已知漏洞')
  })

  it('工具代码用「工具 … 执行的代码」，不把工具名当插件名', () => {
    const msg = scanVerdictMessage(base({ subject: 'tool', pluginName: 'run_code', osv: undefined, osvId: undefined, osvAlias: undefined, osvDependency: undefined, official: undefined }))
    expect(msg).toContain('工具 run_code 执行的代码')
    expect(msg).not.toContain('官方包')
  })

  it('官方与非官方给不同的处置建议', () => {
    expect(scanVerdictMessage(base())).toContain('随 DSH 升级修复')
    expect(scanVerdictMessage(base({ official: false }))).not.toContain('随 DSH 升级修复')
    expect(scanVerdictMessage(base({ official: false }))).toContain('忽略')
  })
})

describe('scan-verdict：指纹', () => {
  it('同一组证据 → 同一 id；规则顺序不影响', () => {
    const a = scanVerdictAlarmId(base())
    const b = scanVerdictAlarmId(base({ rules: [...(base().rules ?? [])].reverse() }))
    expect(a).toBe(b)
    expect(scanVerdictEvidenceKey(base())).toBe(scanVerdictEvidenceKey(base({ at: 1, staticScore: 0 })))
  })

  it('证据变化 → 新 id（新公告 / 新依赖 / verdict 变化）', () => {
    const id = scanVerdictAlarmId(base())
    expect(scanVerdictAlarmId(base({ osvId: 'GHSA-new', osvAlias: 'CVE-2026-1' }))).not.toBe(id)
    expect(scanVerdictAlarmId(base({ osvDependency: 'zod@4.6.8' }))).not.toBe(id)
    expect(scanVerdictAlarmId(base({ verdict: 'critical' }))).not.toBe(id)
    expect(scanVerdictAlarmId(base({ rules: [...(base().rules ?? []), 'R16'] }))).not.toBe(id)
  })

  it('多条公告：文案写「等 N 条」，集合变化 → 新 id（忽略第一条不会封住第二条）', () => {
    const one = base({ osvIds: ['GHSA-a'], osvId: 'GHSA-a', osvAlias: undefined })
    const two = base({ osvIds: ['GHSA-a', 'GHSA-b'], osvId: 'GHSA-a', osvAlias: undefined })
    expect(scanVerdictMessage(two)).toContain('已知漏洞 GHSA-a 等 2 条')
    expect(scanVerdictAlarmId(two)).not.toBe(scanVerdictAlarmId(one))
    // finding 顺序不同不算新证据
    expect(scanVerdictEvidenceKey(base({ osvIds: ['GHSA-b', 'GHSA-a'], osvId: 'GHSA-a' })))
      .toBe(scanVerdictEvidenceKey(two))
  })

  it('聚合行不引用单个包的分数（「判定 suspicious」而非「80 分」）', () => {
    expect(scanVerdictMessage(base({ aggregate: true }))).not.toContain('80 分')
    expect(scanVerdictMessage(base({ aggregate: true }))).toContain('判定 suspicious')
    expect(scanVerdictMessage(base())).toContain('80 分')
  })

  it('clean → 无告警', () => {
    expect(scanVerdictAlarm(base({ verdict: 'clean' }))).toBeNull()
  })

  it('critical → red，suspicious → yellow', () => {
    expect(scanVerdictAlarm(base({ verdict: 'critical' }))?.severity).toBe('red')
    expect(scanVerdictAlarm(base())?.severity).toBe('yellow')
  })
})

describe('scan-verdict：忽略语义（端到端走 VetStatus）', () => {
  it('suspicious 扫描 → 黄色告警；忽略 → green，且重扫同一证据不拉回黄', () => {
    const s = new VetStatus()
    s.noteScan(base())
    let snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarmCount).toBe(1)
    const alarm = snap.alarms[0]
    expect(alarm.kind).toBe('scan-verdict')
    expect(alarm.message).toContain('zod@4.4.3')

    s.dismiss(alarm.id)
    snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarmCount).toBe(0)
    expect(snap.dismissed.map(a => a.id)).toContain(alarm.id)

    // 同一证据重扫：入列但折叠为 dismissed，不再黄
    s.noteScan(base({ at: Date.now() + 1 }))
    snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarmCount).toBe(0)
  })

  it('忽略后再出现新证据 → 新告警 → 重新黄（一次忽略不会永久失明）', () => {
    const s = new VetStatus()
    s.noteScan(base())
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')

    s.noteScan(base({ osvId: 'GHSA-next', osvAlias: 'CVE-2026-2', at: Date.now() + 1 }))
    const snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms[0].message).toContain('GHSA-next')
  })

  it('重扫转 clean → 撤销告警并回 green', () => {
    const s = new VetStatus()
    s.noteScan(base())
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: '@deepseek-ai/dsh-agent-loop', verdict: 'clean', staticScore: 100, at: Date.now() + 1 })
    const snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarms.filter(a => a.kind === 'scan-verdict')).toHaveLength(0)
    expect(snap.lastScan?.verdict).toBe('clean')
  })

  it('clean 只撤销本对象的结论，不动其他插件', () => {
    const s = new VetStatus()
    s.noteScan(base())
    s.noteScan(base({ pluginName: '@deepseek-ai/dsh-client-connection', at: Date.now() + 1 }))
    expect(s.snapshot().alarmCount).toBe(2)
    s.noteScan({ pluginName: '@deepseek-ai/dsh-agent-loop', verdict: 'clean', staticScore: 100, at: Date.now() + 2 })
    const snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarms.map(a => a.pluginHint)).toEqual(['@deepseek-ai/dsh-client-connection'])
  })

  it('lastScan 只作展示，不再单独抬 level（这是旧实现「黄得没有出路」的根因）', () => {
    const s = new VetStatus()
    // 直接写 lastScan 的旧路径已不存在：唯一入口 noteScan 必然落告警。
    s.noteScan(base())
    expect(s.snapshot().lastScan?.verdict).toBe('suspicious')
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')
    expect(s.snapshot().lastScan?.verdict).toBe('suspicious') // 回显仍在，只是不计黄
  })

  it('TTL 到期后结论告警与 lastScan 一起消失', () => {
    const s = new VetStatus({ alarmTtlMs: 100 })
    s.noteScan(base({ at: Date.now() - 500 }))
    const snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.lastScan).toBeUndefined()
    expect(snap.alarms).toHaveLength(0)
  })

  it('critical 结论 → red，忽略后回 green', () => {
    const s = new VetStatus()
    s.noteScan(base({ verdict: 'critical' }))
    expect(s.snapshot().level).toBe('red')
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')
  })
})

describe('scan-verdict：按公告聚合（54 个官方包不该刷出 54 行）', () => {
  const pkg = (name: string, over: Partial<ScanVerdictEcho> = {}) => base({ pluginName: name, aggregate: true, official: true, ...over })

  it('同一公告 + 同一依赖 → 一行；文案说「多个官方包」而不是逐个点名', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/dsh-agent-loop'))
    s.noteScan(pkg('@deepseek-ai/dsh-llm', { at: Date.now() + 1 }))
    s.noteScan(pkg('@deepseek-ai/dsh-commands', { at: Date.now() + 2 }))
    const snap = s.snapshot()
    expect(snap.alarms).toHaveLength(1)
    expect(snap.alarmCount).toBe(1)
    expect(snap.alarms[0].message).toContain('本机多个官方包')
    expect(snap.alarms[0].id.startsWith('scan-verdict:agg:')).toBe(true)
    expect(snap.alarms[0].count).toBe(3)
    expect(snap.level).toBe('yellow')
  })

  it('第三方包即使同一公告也不聚合——各自一行，各看各的', () => {
    const s = new VetStatus()
    s.noteScan(base({ pluginName: 'some-third-party' }))
    s.noteScan(base({ pluginName: 'another-third-party', at: Date.now() + 1 }))
    const snap = s.snapshot()
    expect(snap.alarms).toHaveLength(2)
    expect(snap.alarms.every(a => !a.id.startsWith('scan-verdict:agg:'))).toBe(true)
  })

  it('成员逐个转 clean：全清才撤行，中途仍有包受影响则保留', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/dsh-agent-loop'))
    s.noteScan(pkg('@deepseek-ai/dsh-llm', { at: Date.now() + 1 }))
    s.noteScan({ pluginName: '@deepseek-ai/dsh-agent-loop', verdict: 'clean', staticScore: 100, at: Date.now() + 2 })
    expect(s.snapshot().alarms).toHaveLength(1)
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: '@deepseek-ai/dsh-llm', verdict: 'clean', staticScore: 100, at: Date.now() + 3 })
    expect(s.snapshot().alarms).toHaveLength(0)
    expect(s.snapshot().level).toBe('green')
  })

  it('单成员聚合行：该包转 clean 后整行撤掉', () => {
    // 回归：成员登记曾在 record 之前 → record 开头的 expire() 把「还没有告警行」的成员集合
    // 清掉，于是这条行永远等不到「最后一个成员转 clean」，只能等 24h TTL（黄牌又没出路）。
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/dsh-agent-loop'))
    s.noteScan({ pluginName: '@deepseek-ai/dsh-agent-loop', verdict: 'clean', staticScore: 100, at: Date.now() + 1 })
    expect(s.snapshot().alarms).toHaveLength(0)
    expect(s.snapshot().level).toBe('green')
  })

  it('乱序 clean：先清「后扫描」的成员，不能把整行撤掉（其余包仍受影响）', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/p1'))
    s.noteScan(pkg('@deepseek-ai/p2', { at: Date.now() + 1 }))
    s.noteScan({ pluginName: '@deepseek-ai/p2', verdict: 'clean', staticScore: 100, at: Date.now() + 2 })
    const snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarms).toHaveLength(1)
    expect(snap.alarms[0].count).toBe(1)
    s.noteScan({ pluginName: '@deepseek-ai/p1', verdict: 'clean', staticScore: 100, at: Date.now() + 3 })
    expect(s.snapshot().level).toBe('green')
  })

  it('扫描跨过 60s 去重窗口（54 个包扫一分多钟）时 ×N 仍是受影响包数', () => {
    const s = new VetStatus({ dedupeWindowMs: 0 })
    for (let i = 0; i < 4; i++) s.noteScan(pkg(`@deepseek-ai/p${i}`, { at: Date.now() + i }))
    const snap = s.snapshot()
    expect(snap.alarms).toHaveLength(1)
    expect(snap.alarms[0].count).toBe(4)
  })

  it('同一包反复扫描不会把 ×N 累加（成员按包名去重）', () => {
    const s = new VetStatus()
    for (let i = 0; i < 5; i++) s.noteScan(pkg('@deepseek-ai/p0', { at: Date.now() + i * 1000 }))
    expect(s.snapshot().alarms).toHaveLength(1)
    expect(s.snapshot().alarms[0].count).toBe(1)
  })

  it('结论 id 切换（依赖命中 → 自身命中）时旧聚合行连同成员一起撤掉', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/pA'))
    expect(s.snapshot().alarms[0].id.startsWith('scan-verdict:agg:')).toBe(true)
    s.noteScan({
      pluginName: '@deepseek-ai/pA', verdict: 'suspicious', staticScore: 80, at: Date.now() + 1,
      rules: ['R6'], osv: '已知漏洞 GHSA-x', osvId: 'GHSA-x', official: true,
    })
    const snap = s.snapshot()
    expect(snap.alarms).toHaveLength(1)
    expect(snap.alarms[0].id.startsWith('scan-verdict:plugin:@deepseek-ai/pA:')).toBe(true)
  })

  it('证据变了但仍非 clean：旧行立刻撤掉，不留到 24h TTL', () => {
    const s = new VetStatus()
    s.noteScan(base({ pluginName: 'p', official: false }))
    s.noteScan(base({
      pluginName: 'p', official: false, at: Date.now() + 1,
      osvId: 'GHSA-new', osvIds: ['GHSA-new'], osvAlias: undefined,
    }))
    const rows = s.snapshot().alarms
    expect(rows).toHaveLength(1)
    expect(rows[0].message).toContain('GHSA-new')
  })

  it('第二条公告进来 → 另起一行重新黄（聚合键是公告集合，不是单条）', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/p1'))
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')
    s.noteScan(pkg('@deepseek-ai/p1', {
      at: Date.now() + 1, osvId: 'GHSA-mrhx-c7xc-m3w5',
      osvIds: ['GHSA-mrhx-c7xc-m3w5', 'GHSA-second'],
    }))
    const snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarms[0].id).toBe('scan-verdict:agg:osv:GHSA-mrhx-c7xc-m3w5+GHSA-second:zod@4.4.3:suspicious')
  })

  it('名为 osv 的对象不能撤销聚合行（命名空间隔离）', () => {
    // 回归：扁平命名空间下，`scan-verdict:osv:` 既是聚合前缀、也可能是某个包的撤销前缀，
    // 于是恰好叫 `osv` 的包一次 clean 扫描就能把 54 个官方包的 CVE 行整行抹掉。
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/p1'))
    s.noteScan(pkg('@deepseek-ai/p2', { at: Date.now() + 1 }))
    s.noteScan({ pluginName: 'osv', verdict: 'clean', staticScore: 100, at: Date.now() + 2 })
    s.noteScan({ pluginName: 'osv', verdict: 'suspicious', staticScore: 60, at: Date.now() + 3, rules: ['R6'] })
    const snap = s.snapshot()
    expect(snap.alarms.some(a => a.id.startsWith('scan-verdict:agg:'))).toBe(true)
    expect(snap.alarms.find(a => a.id.startsWith('scan-verdict:agg:'))?.count).toBe(2)
    expect(snap.level).toBe('yellow')
  })

  it('工具与插件同名时互不撤销（subject 进 id）', () => {
    // `workflow` / `run_code` 是真实工具名；第三方插件也可能叫这个名字。
    const s = new VetStatus()
    s.noteScan({ pluginName: 'workflow', verdict: 'suspicious', staticScore: 70, at: Date.now(), rules: ['R6'] })
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: 'workflow', verdict: 'clean', staticScore: 100, at: Date.now() + 1, subject: 'tool' })
    expect(s.snapshot().level).toBe('yellow')
    expect(s.snapshot().alarms).toHaveLength(1)
    // 同名工具自己的结论仍然生效、也仍然可撤
    s.noteScan({ pluginName: 'workflow', verdict: 'suspicious', staticScore: 40, at: Date.now() + 2, subject: 'tool', rules: ['R8'] })
    expect(s.snapshot().alarms).toHaveLength(2)
    s.noteScan({ pluginName: 'workflow', verdict: 'clean', staticScore: 100, at: Date.now() + 3, subject: 'tool' })
    expect(s.snapshot().alarms).toHaveLength(1)
  })

  it('已忽略的黄色观察升红时自动解除折叠（忽略不是对升级的预先批准）', () => {
    const s = new VetStatus()
    s.record({ id: 'u1', severity: 'info', source: 'scan', kind: 'upgrade-diff', message: 'old', mergeKey: 'scan:upgrade', at: Date.now() })
    s.dismiss('u1')
    expect(s.snapshot().level).toBe('green')
    s.record({ id: 'u2', severity: 'red', source: 'scan', kind: 'upgrade-diff', message: 'new exec', mergeKey: 'scan:upgrade', at: Date.now() + 1 })
    const snap = s.snapshot()
    expect(snap.level).toBe('red')
    expect(snap.alarmCount).toBe(1)
  })

  it('忽略官方聚合行不会顺带封住同公告的第三方包（聚合的安全边界）', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/p1'))
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')
    s.noteScan(base({ pluginName: 'some-third-party', official: false, aggregate: false, at: Date.now() + 1 }))
    const snap = s.snapshot()
    expect(snap.level).toBe('yellow')
    expect(snap.alarms).toHaveLength(1)
    expect(snap.alarms[0].pluginHint).toBe('some-third-party')
  })

  it('忽略聚合行 → 后续同公告的包也一并安静（这正是「一条通知」的含义）', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/dsh-agent-loop'))
    s.dismiss(s.snapshot().alarms[0].id)
    expect(s.snapshot().level).toBe('green')
    s.noteScan(pkg('@deepseek-ai/dsh-tools', { at: Date.now() + 1 }))
    expect(s.snapshot().level).toBe('green')
    expect(s.snapshot().alarmCount).toBe(0)
  })

  it('新公告不受旧忽略影响——升级后出现新 CVE 会重新黄', () => {
    const s = new VetStatus()
    s.noteScan(pkg('@deepseek-ai/dsh-agent-loop'))
    s.dismiss(s.snapshot().alarms[0].id)
    s.noteScan(pkg('@deepseek-ai/dsh-llm', { osvId: 'GHSA-next', osvAlias: 'CVE-2026-9', at: Date.now() + 1 }))
    expect(s.snapshot().level).toBe('yellow')
    expect(s.snapshot().alarms[0].message).toContain('GHSA-next')
  })
})

describe('parseOsvEvidence：跨进程载荷不信任形状', () => {
  it('解析结构化坐标', () => {
    expect(parseOsvEvidence('id=GHSA-1;alias=CVE-2024-1;dependency=zod@4.4.3')).toEqual({
      id: 'GHSA-1', alias: 'CVE-2024-1', dependency: 'zod@4.4.3',
    })
  })

  it('缺项/未知键/畸形输入 → 安全降级', () => {
    expect(parseOsvEvidence('id=GHSA-1')).toEqual({ id: 'GHSA-1' })
    expect(parseOsvEvidence('weird=1;;;id=')).toEqual({})
    expect(parseOsvEvidence('')).toEqual({})
    expect(parseOsvEvidence(undefined)).toEqual({})
    expect(parseOsvEvidence(42)).toEqual({})
    expect(parseOsvEvidence('=x;id')).toEqual({})
    // 超长值只可能是畸形载荷：别让它变成告警 Map 的键、再写进 dismissed-alerts.json
    expect(parseOsvEvidence('dependency=' + 'x'.repeat(500))).toEqual({})
    expect(parseOsvEvidence('dependency=' + 'x'.repeat(199))).toEqual({ dependency: 'x'.repeat(199) })
  })
})
