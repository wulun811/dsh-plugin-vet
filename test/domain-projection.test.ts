import { describe, expect, it } from 'vitest'
import fixture from './fixtures/domain/alarm-sites.json'
import { KIND_SPECS, knownCodes, specFor } from '../lib/domain/kinds.js'
import { mergeKeyOf, projectAlarm, projectAlarms, subjectIdOf } from '../lib/domain/project.js'
import { observationAlarmsFor } from '../lib/guards/internal-plugin.js'
import { HOST_SUBJECT, SELF_SUBJECT, type Evidence, type TrustOrigin } from '../lib/domain/types.js'

/**
 * 步骤 2 的验收：注册表与投影器。
 *
 * 这个文件的核心不是「函数算得对」，而是**旧行为能被新模型逐条表达出来**——
 * 施工图 §7 的原话：这条测试是收缩的验收单，它证明重建的模型能表达旧行为，
 * 而不是证明测试通过。
 *
 * `fixtures/domain/alarm-sites.json` 是 0.5.0 动工**之前**从源码里机械抽出的 76 个告警字面量
 * （记录点 + 规则表 + 哨兵），不是手写的。它记录的是 0.4.2 的真实形状；一旦有人把注册表
 * 或投影器改成表达不了旧形状，这里就会红，而且红得能定位到 file:line。
 *
 * 白名单只有时间戳（施工图 R10）：本文件不比较 `at`，其余字段一律精确比对。
 */

interface SiteLiteral {
  readonly expr: string
}
type Field = string | SiteLiteral | null

interface Site {
  readonly file: string
  readonly line: number
  readonly kind: Field
  readonly severity: Field
  readonly source: Field
  readonly mergeKey: Field
  readonly id: Field
  readonly hasTarget: boolean
  readonly hasPluginHint: boolean
  readonly hasSessionLog: boolean
  readonly message: string | null
}

const sites = fixture.sites as readonly Site[]

/** 报警通道 → 证据来源（`source` 是呈现层通道，`TrustOrigin` 是事实层来源）。 */
const ORIGIN_OF_CHANNEL: Record<string, TrustOrigin> = {
  scan: 'local_scan',
  t1: 'sentinel',
  t2: 'runtime_hook',
}

function at(file: string, line: number): string {
  return `${file}:${line}`
}

/** 按旧字面量造一条等价证据：主体取一个普通 npm 插件（不是 self/host）。 */
function evidenceOf(code: string, channel: string, over: Partial<Evidence> = {}): Evidence {
  const origin = ORIGIN_OF_CHANNEL[channel]
  if (origin === undefined) throw new Error(`未知通道：${channel}`)
  return {
    id: `fixture:${code}`,
    subject: { subjectId: subjectIdOf('@acme/plugin', '1.0.0'), kind: 'npm', name: '@acme/plugin', version: '1.0.0' },
    source: origin,
    producer: 'fixture',
    code,
    observedAt: 1_700_000_000_000,
    outcome: 'observed',
    attribution: 'exact',
    ...over,
  }
}

describe('注册表：覆盖源码里出现过的每一个告警码', () => {
  it('57 个字面量 kind 全部在表内', () => {
    const observed = new Set(sites.filter((s) => typeof s.kind === 'string').map((s) => s.kind as string))
    const missing = [...observed].filter((code) => !knownCodes().has(code))
    expect(missing, `未登记的告警码（新增检测器请先加 kinds.ts 一行）：${missing.join(', ')}`).toEqual([])
    expect(observed.size).toBe(57)
  })

  it('4 个动态 kind 的取值域也在表内', () => {
    // 三种展开：两个可在测试里**执行真实代码**验证，另两个的 kind 由上游模块拼装，
    // 这里按源码位置固化为取值域（改上游时这里会红，提示同步注册表）。
    const dynamics = sites.filter((s) => typeof s.kind !== 'string' && s.kind !== null)
    const exprs = new Set(dynamics.map((s) => (s.kind as SiteLiteral).expr))
    expect([...exprs].sort()).toEqual(['a.kind', 'alarm.kind', 'nav.alarm.kind', 'obs.kind'])

    // obs.kind ← observationAlarmsFor（internal-plugin.ts），执行真实函数取取值域
    const observedKinds = new Set(
      observationAlarmsFor([
        { rule: 'R17', severity: 'info', message: 'm' },
        { rule: 'R18', severity: 'info', message: 'm' },
        { rule: 'R19', severity: 'info', message: 'm' },
      ]).map((a) => a.kind),
    )
    expect(observedKinds).toEqual(new Set(['r17-observation', 'r18-observation', 'r19-observation']))

    // nav.alarm.kind ← version-diff（upgrade-diff / upgrade-cold）
    // a.kind ← runtime-watch 的 WatchAlarm（mem / fork / fd / growth）
    // alarm.kind ← runtime-sink 的官方家务探针（official-housekeeping-probe）
    const declared = new Set([
      ...observedKinds,
      'upgrade-diff',
      'upgrade-cold',
      'mem',
      'fork',
      'fd',
      'growth',
      'official-housekeeping-probe',
    ])
    for (const code of declared) expect(knownCodes().has(code), `${code} 未登记`).toBe(true)
  })

  it('同一个 (code, when) 不重复——顺序敏感的表，重复行会让后一行永远匹配不到', () => {
    const seen = new Set<string>()
    for (const spec of KIND_SPECS) {
      const key = `${spec.code}|${spec.when?.official === undefined ? 'any' : String(spec.when.official)}`
      expect(seen.has(key), `重复行：${key}`).toBe(false)
      seen.add(key)
    }
  })

  it('带 when 的行必须排在无条件行之前', () => {
    const firstAny = new Map<string, number>()
    KIND_SPECS.forEach((spec, index) => {
      if (spec.when === undefined && !firstAny.has(spec.code)) firstAny.set(spec.code, index)
    })
    KIND_SPECS.forEach((spec, index) => {
      if (spec.when === undefined) return
      const anyIndex = firstAny.get(spec.code)
      if (anyIndex !== undefined) {
        expect(index, `${spec.code} 的 when 行排在了兜底行之后，永远不会命中`).toBeLessThan(anyIndex)
      }
    })
  })
})

describe('投影器：能表达旧行为', () => {
  it('每一个旧字面量 mergeKey 都能被某个上下文复现（不多也不少）', () => {
    // 动态 kind 的行不参与（code 不是字面量，无法从 fixture 单独复原）；其中
    // official-housekeeping-probe 由下面的直接断言覆盖。
    const observed = sites
      .filter((s) => typeof s.mergeKey === 'string' && typeof s.kind === 'string')
      .map((s) => ({ site: s, key: s.mergeKey as string }))
    expect(observed.length).toBeGreaterThan(0)

    expect(projectAlarm(evidenceOf('official-housekeeping-probe', 't2')).mergeKey).toBe('t2:official-housekeeping-probe')

    for (const { site, key } of observed) {
      const code = site.kind as string
      const channel = site.source as string
      const contextGrid = [undefined, true, false].flatMap((official) =>
        [undefined, 'official'].map((mergeSubject) => ({ official, mergeSubject })),
      )
      const hits = contextGrid.filter((ctx) => {
        const alarm = projectAlarm(evidenceOf(code, channel), ctx)
        return alarm.mergeKey === key
      })
      expect(hits.length, `${at(site.file, site.line)} 的 mergeKey「${key}」无法复现`).toBeGreaterThan(0)
    }
  })

  it('旧字面量 severity 与注册表一致：常量行不许需要外部覆盖', () => {
    for (const site of sites) {
      if (typeof site.kind !== 'string' || typeof site.severity !== 'string') continue
      // 0.5.16（F16）：这里原先是 `if (typeof site.source !== 'string') continue`——76 个
      // 采集点里有 35 个 source 为 null（exfil-ledger 的 12 个 N3 落点全在内，它们走上游
      // sink 而不是 emitAlarm 的 facts.source），于是整类被静默跳过。注册表把六个 N3 单签名
      // 写成 red、代码一直发 yellow，两边全绿了很多版。现在按 code 直接比常量行：这条路
      // 不需要 source，也就没有理由跳过。
      const code = site.kind
      const rows = KIND_SPECS.filter((s) => s.code === code)
      const single = rows.length === 1 ? rows[0] : undefined
      if (single === undefined || single.severity === 'from-site') continue
      expect(single.severity, `${at(site.file, site.line)} ${code} 注册表=${single.severity}，采集点=${site.severity}`).toBe(
        site.severity,
      )
    }
  })

  it('每一个常量行都至少有一个采集点写得出它的严重度（注册表不许凭空发明）', () => {
    const observed = new Map<string, Set<string>>()
    for (const site of sites) {
      if (typeof site.kind !== 'string' || typeof site.severity !== 'string') continue
      const bucket = observed.get(site.kind) ?? new Set<string>()
      bucket.add(site.severity)
      observed.set(site.kind, bucket)
    }
    const orphan: string[] = []
    for (const spec of KIND_SPECS) {
      if (spec.severity === 'from-site') continue
      const seen = observed.get(spec.code)
      // fixture 是 0.4.2 的快照：这个 code 整体不在快照里 = 它是之后新加的检测器，
      // 快照无从评判，跳过（但要在下面计数里看得见，别让「跳过」变成新的静默）。
      if (seen === undefined) continue
      if (!seen.has(spec.severity)) orphan.push(`${spec.code}=${spec.severity}（源码只出现过 ${[...seen].join('/')}）`)
    }
    expect(orphan, `这些常量行的严重度在源码落点里不存在：${orphan.join(', ')}`).toEqual([])
  })

  it('多行码（官方/第三方两档）的每个观测值都是某一行给出的常量', () => {
    const byCode = new Map<string, string[]>()
    for (const site of sites) {
      if (typeof site.kind !== 'string' || typeof site.severity !== 'string') continue
      const bucket = byCode.get(site.kind) ?? []
      bucket.push(site.severity)
      byCode.set(site.kind, bucket)
    }
    for (const [code, severities] of byCode) {
      const rows = KIND_SPECS.filter((s) => s.code === code)
      if (rows.length < 2) continue
      const constants = rows.filter((r) => r.severity !== 'from-site').map((r) => r.severity as string)
      for (const severity of severities) {
        expect(constants, `${code} 观测到 ${severity}，但没有任何一行给出这个常量`).toContain(severity)
      }
    }
  })

  it('from-site 的行确实需要采集点给值：观测到的非默认值不能靠兜底撞上', () => {
    for (const site of sites) {
      if (typeof site.kind !== 'string' || typeof site.severity !== 'string') continue
      if (typeof site.source !== 'string') continue
      const code = site.kind
      const spec = specFor(code)
      if (spec?.severity !== 'from-site') continue
      // 采集点给了值 → 就用它
      expect(projectAlarm(evidenceOf(code, site.source), { severity: site.severity as never }).severity).toBe(site.severity)
      // 观测值不是默认的 yellow 时，兜底必须不等于它（否则「采集点给值」这条约束是空的）
      if (site.severity !== 'yellow') {
        expect(projectAlarm(evidenceOf(code, site.source)).severity, `${code} 的兜底撞上了真实值`).not.toBe(site.severity)
      }
    }
  })

  it('未登记 code 不吞报警：按不合并 + 采集点严重度照发', () => {
    const alarm = projectAlarm(evidenceOf('totally-new-code', 'scan', { message: '新东西' }), { severity: 'red' })
    expect(alarm.kind).toBe('totally-new-code')
    expect(alarm.severity).toBe('red')
    expect(alarm.mergeKey).toBeUndefined()
    expect(alarm.message).toBe('新东西')
  })
})

describe('投影器：字段推导', () => {
  it('self 主体不给 pluginHint（vet 自己坏了不是某个插件干了坏事）', () => {
    const alarm = projectAlarm(evidenceOf('vet-store-tamper', 'scan', { subject: SELF_SUBJECT }))
    expect(alarm.pluginHint).toBeUndefined()
    expect(alarm.source).toBe('scan')
  })

  it('宿主主体不给 pluginHint，且不因 kind=other 被当成 self', () => {
    const alarm = projectAlarm(evidenceOf('mem', 't1', { subject: HOST_SUBJECT }))
    expect(alarm.pluginHint).toBeUndefined()
    expect(alarm.source).toBe('t1')
    expect(specFor('mem')?.severity).toBe('from-site')
  })

  it('普通插件主体给 pluginHint，等于主体名', () => {
    expect(projectAlarm(evidenceOf('audit-required', 'scan')).pluginHint).toBe('@acme/plugin')
  })

  it('合并键前缀走证据来源：sentinel→t1 / runtime_hook→t2 / 观察→obs', () => {
    const n3 = projectAlarm(evidenceOf('n3-exfil', 't2'))
    expect(n3.mergeKey).toBe('t2:n3-exfil:@acme/plugin')
    const obs = projectAlarm(evidenceOf('r17-observation', 'scan'))
    expect(obs.mergeKey).toBe('obs:r17-observation:@acme/plugin')
  })

  it('literal 与 id 两种合并形状', () => {
    expect(projectAlarm(evidenceOf('upgrade-diff', 'scan'), { severity: 'info' }).mergeKey).toBe('scan:upgrade')
    expect(projectAlarm(evidenceOf('scan-verdict', 'scan'), { severity: 'red' }).mergeKey).toBe('fixture:scan-verdict')
  })

  it('空文案回落到 code，不产出一条无字报警', () => {
    expect(projectAlarm(evidenceOf('audit-required', 'scan', { message: '' })).message).toBe('audit-required')
    expect(projectAlarm(evidenceOf('audit-required', 'scan')).message).toBe('audit-required')
  })

  it('mergeKeyOf 对 none 与 literal 的边界', () => {
    const spec = specFor('audit-required')
    expect(spec).toBeDefined()
    expect(mergeKeyOf('none', spec!, evidenceOf('audit-required', 'scan'), {})).toBeUndefined()
    expect(mergeKeyOf('literal:t2:x', spec!, evidenceOf('audit-required', 'scan'), {})).toBe('t2:x')
  })

  it('subjectIdOf：版本与摘要缺席时不留占位符', () => {
    expect(subjectIdOf('a')).toBe('a')
    expect(subjectIdOf('a', '1.0.0')).toBe('a@1.0.0')
    expect(subjectIdOf('a', '1.0.0', '0123456789abcdef')).toBe('a@1.0.0#0123456789ab')
    expect(subjectIdOf('a', undefined, '0123456789abcdef')).toBe('a#0123456789ab')
  })
})

describe('projectAlarms：评估提供严重度', () => {
  const subject = evidenceOf('x', 'scan').subject

  it('评估的 critical 映射为 red，medium 映射为 yellow', () => {
    const evidence = [evidenceOf('fs-write', 't2')]
    const alarm = projectAlarms({
      subject,
      evidence,
      coverage: [],
      assessments: [
        {
          id: 'as-1',
          subject,
          claim: 'c',
          state: 'finding',
          severity: 'critical',
          evidenceIds: [evidence[0].id],
          ruleSetVersion: 'rules/1',
          evaluatedAt: 1,
          limitations: [],
        },
      ],
    })
    expect(alarm[0].severity).toBe('red')
  })

  it('多条评估取最严重的一条；unknown 不参与投票', () => {
    const evidence = [evidenceOf('fs-write', 't2')]
    const make = (id: string, severity: 'medium' | 'critical' | 'unknown') => ({
      id,
      subject,
      claim: 'c',
      state: 'finding' as const,
      severity,
      evidenceIds: [evidence[0].id],
      ruleSetVersion: 'rules/1',
      evaluatedAt: 1,
      limitations: [],
    })
    const out = projectAlarms({
      subject,
      evidence,
      coverage: [],
      assessments: [make('a', 'medium'), make('b', 'unknown'), make('c', 'critical')],
    })
    expect(out[0].severity).toBe('red')
  })

  it('没有评估时不丢行（评估缺席 ≠ 证据无效）', () => {
    const out = projectAlarms({ subject, evidence: [evidenceOf('audit-required', 'scan')], coverage: [], assessments: [] })
    expect(out).toHaveLength(1)
  })
})
