import { afterEach, describe, expect, it } from 'vitest'
import { domainProjectionStats, emitAlarm, resetDomainProjectionStats } from '../lib/guard/alarm-emit.js'
import { VetStatus } from '../lib/guard/status.js'
import { SELF_SUBJECT, type Evidence, type VetAlarm } from '../lib/domain/types.js'
import { npmSubject } from '../lib/domain/project.js'
import { VET_CONFIG_DEFAULTS, VetConfigSchema } from '../lib/config.js'

/**
 * 步骤 3 的验收：发射口本身。
 *
 * 三种模式各自的行为必须与文档一字不差——因为 `shadow` 是 0.5.0 的默认值，用户跑的就是它。
 * 特别注意第三条：影子期**输出仍走旧字面量**，投影只比对不生效；一旦有人图省事把 shadow
 * 写成「用投影 + 顺便比一下」，这一条会红。
 */

/** 固定「现在」：VetStatus 的 TTL 是 24h，用 2023 年的时间戳会让记录当场过期（第一次跑就是这么红的）。 */
const NOW = Date.now()

afterEach(() => {
  resetDomainProjectionStats()
  delete process.env.VET_DOMAIN_SHADOW_STRICT
})

/** 一条与投影器完全一致的旧字面量（id/severity/source/kind/message/target/pluginHint/mergeKey 都能被推出）。 */
function consistentLegacy(kind = 'audit-required'): VetAlarm {
  return {
    id: `audit-required:@acme/plugin`,
    severity: 'yellow',
    source: 'scan',
    kind,
    message: '插件 @acme/plugin 未审计',
    target: '@acme/plugin',
    pluginHint: '@acme/plugin',
    at: NOW,
  }
}

function record(status: VetStatus, alarm: VetAlarm, mode: 'shadow' | 'active' | 'legacy'): VetAlarm {
  emitAlarm(
    status,
    alarm,
    { subject: npmSubject('@acme/plugin', '1.0.0'), producer: 'fixture' },
    mode,
  )
  const snapshot = status.snapshot()
  expect(snapshot.alarms).toHaveLength(1)
  return snapshot.alarms[0]
}

describe('emitAlarm：三种模式', () => {
  it('legacy：只记旧字面量，不产生投影统计', () => {
    const status = new VetStatus()
    const alarm = record(status, consistentLegacy(), 'legacy')
    expect(alarm.kind).toBe('audit-required')
    expect(domainProjectionStats().mismatches).toBe(0)
  })

  it('active：记投影结果——合并键与 pluginHint 由注册表/主体推出，不来自字面量', () => {
    const status = new VetStatus()
    // 故意把字面量里的 pluginHint 写错：active 下不该被采信
    const alarm = record(status, { ...consistentLegacy(), pluginHint: '错误的名字', mergeKey: undefined }, 'active')
    expect(alarm.pluginHint).toBe('@acme/plugin')
    expect(alarm.severity).toBe('yellow')
  })

  it('shadow：输出仍是旧字面量（不是投影），但差异被计数', () => {
    const status = new VetStatus()
    const legacy = { ...consistentLegacy(), pluginHint: '错误的名字' }
    const alarm = record(status, legacy, 'shadow')
    // 输出走旧字面量 → 错误的 pluginHint 原样出现；这正是影子期「不改行为」的定义
    expect(alarm.pluginHint).toBe('错误的名字')
    expect(domainProjectionStats().mismatches).toBe(1)
    expect(domainProjectionStats().first).toContain('pluginHint')
  })

  it('shadow：一致时零差异', () => {
    const status = new VetStatus()
    record(status, consistentLegacy(), 'shadow')
    expect(domainProjectionStats().mismatches).toBe(0)
  })

  it('严格模式：第一条差异立即抛，且说明哪个字段不一致', () => {
    process.env.VET_DOMAIN_SHADOW_STRICT = '1'
    const status = new VetStatus()
    expect(() => record(status, { ...consistentLegacy(), source: 't2' }, 'shadow')).toThrow(/不等价/)
    try {
      emitAlarm(
        status,
        { ...consistentLegacy(), source: 't2' },
        { subject: npmSubject('@acme/plugin', '1.0.0') },
        'shadow',
      )
    } catch (error) {
      expect(String(error)).toContain('source')
      expect(String(error)).toContain('旧="t2"')
      expect(String(error)).toContain('投影="scan"')
    }
  })

  it('self 主体：投影不给 pluginHint，旧字面量也不该给（一致）', () => {
    const status = new VetStatus()
    const legacy: VetAlarm = {
      id: 'vet-store-tamper',
      severity: 'yellow',
      source: 'scan',
      kind: 'vet-store-tamper',
      message: '存储被改写',
      target: '~/.dsh/vet',
      at: NOW,
    }
    emitAlarm(status, legacy, { subject: SELF_SUBJECT }, 'shadow')
    expect(domainProjectionStats().mismatches).toBe(0)
  })

  it('status 缺席时静默返回（装配前的判定路径不该崩）', () => {
    expect(() => emitAlarm(undefined, consistentLegacy(), { subject: SELF_SUBJECT }, 'active')).not.toThrow()
  })

  /**
   * 0.5.18：**严格模式不能只在 shadow 下有效。**
   *
   * 旧实现在 `mode === 'active'` 时直接 `record(projected)` 就返回，比对那段根本走不到。
   * 这意味着等价性保险丝只在影子期通电——而影子期正是要结束的那一段。一旦默认切成
   * `active`，`VET_DOMAIN_SHADOW_STRICT=1` 就再也抛不出东西，CI 全绿却已经失去保护，
   * 且没有任何信号。
   *
   * 这条用例在旧实现下会红（active 分支不抛），是新逻辑的守卫。
   */
  it('严格模式在 active 下同样抛错（等价性保险丝不该只给 shadow 通电）', () => {
    process.env.VET_DOMAIN_SHADOW_STRICT = '1'
    const status = new VetStatus()
    expect(() =>
      emitAlarm(status, { ...consistentLegacy(), severity: 'red' }, { subject: npmSubject('@acme/plugin', '1.0.0') }, 'active'),
    ).toThrow(/不等价/)
    // 且差异确实被计数（不只是抛了就算）
    expect(domainProjectionStats().mismatches).toBe(1)
    expect(domainProjectionStats().first).toContain('severity')
  })

  it('非严格模式下 active 不抛，但差异照常计数、输出走投影', () => {
    const status = new VetStatus()
    emitAlarm(status, { ...consistentLegacy(), severity: 'red' }, { subject: npmSubject('@acme/plugin', '1.0.0') }, 'active')
    expect(domainProjectionStats().mismatches).toBe(1)
    // active 的语义：输出投影结果（常量行把它纠正成 yellow）
    expect(status.snapshot().alarms[0].severity).toBe('yellow')
  })

  it('from-site 的行才吃采集点严重度；常量行以注册表为准（影子能抓到不一致）', () => {
    const status = new VetStatus()
    // audit-required 是常量行：字面量写 red 会被投影纠正为 yellow → 影子必须报差异
    emitAlarm(
      status,
      { ...consistentLegacy(), severity: 'red' },
      { subject: npmSubject('@acme/plugin', '1.0.0') },
      'shadow',
    )
    expect(domainProjectionStats().mismatches).toBe(1)
    expect(domainProjectionStats().first).toContain('severity')
  })

  it('证据的 target/message/at 取自旧字面量，避免同一份事实写两遍', () => {
    const status = new VetStatus()
    emitAlarm(
      status,
      { ...consistentLegacy(), target: '/tmp/x', message: '自定义文案' },
      { subject: npmSubject('@acme/plugin', '1.0.0') },
      'active',
    )
    const alarm = status.snapshot().alarms[0]
    expect(alarm.target).toBe('/tmp/x')
    expect(alarm.message).toBe('自定义文案')
    expect(alarm.at).toBe(NOW)
  })
})

describe('emitAlarm：不变量', () => {
  it('任何模式都不丢行——注册表里没有的码也照发', () => {
    for (const mode of ['legacy', 'shadow', 'active'] as const) {
      resetDomainProjectionStats()
      const status = new VetStatus()
      const legacy: VetAlarm = {
        id: 'new-code:1',
        severity: 'info',
        source: 'scan',
        kind: 'not-registered-code',
        message: '新东西',
        at: NOW,
      }
      emitAlarm(status, legacy, { subject: npmSubject('@acme/plugin') }, mode)
      const recorded = status.snapshot().alarms
      expect(recorded, `${mode} 模式下丢了未登记码的报警`).toHaveLength(1)
      // active 模式下投影器没有主张 → 采集点的严重度必须原样保留（不许悄悄降成 yellow）
      expect(recorded[0].severity, `${mode} 模式下未登记码的严重度被改写了`).toBe('info')
    }
  })

  /**
   * 0.5.18：**出厂默认值本身要被验，不能只验手写的 mode 实参。**
   *
   * 发现方式：把 `config.ts` 的 `domainProjection` 默认值和 `emitAlarm` 的缺省形参
   * 都改成 `active` 跑全量——**一条都没红**。这不证明等价（虽然当时确实是等价的），
   * 它证明的是另一件事：没有任何测试在验「配置默认值 → 实际生效模式」这条链路。
   * 所有涉及投影的测试都显式传 mode，于是默认值写错、或者某处 `emitAlarm` 漏传第四参
   * 退回 shadow，测试都看不见。
   *
   * 这两条是切换 `active` 的前置条件：缺了它们，「默认值改了」与「默认值没改」在
   * CI 上是同一件事。
   */
  describe('出厂默认值 → 实际生效模式（0.5.18）', () => {
    it('配置 schema 的默认值就是文档写的那个', () => {
      // 默认值有三个出处（接口字面量 / VET_CONFIG_DEFAULTS / schemastery schema），这里钉
      // schema 与 VET_CONFIG_DEFAULTS 一致；它们漂移一次，就会让「用户没写这个键」的行为
      // 随升级改变，而两边都没人发现。
      const parsed = VetConfigSchema({}) as { domainProjection: string }
      expect(parsed.domainProjection).toBe(VET_CONFIG_DEFAULTS.domainProjection)
      // 0.5.18：切换点写在这里——改这一行之前，先确认 docs/FAILURES.md 的切换前置条件
      // （真实产物双模式对比 + 严格模式在 active 下仍能抛）仍然成立。
      expect(VET_CONFIG_DEFAULTS.domainProjection).toBe('active')
    })

    it('emitAlarm 的缺省形参与配置默认值一致（漏传第四参不该静默换模式）', () => {
      // 三模式必须同时被区分开，否则这条断言形同虚设——第一版只比了「输出行」，
      // 而 legacy 与 shadow 在等价输入上输出相同，把缺省改成 legacy 依然全绿。
      //
      // 用一条**不等价**的输入（常量行写了 red）：legacy 不比对 → 0 差异；
      // shadow 比对但不纠正 → 1 差异且输出仍是 red；active 直接纠正 → 1 差异且输出 yellow。
      // 于是「差异数」区分 legacy，「输出值」区分 shadow/active，两个维度合起来钉住三个模式。
      resetDomainProjectionStats()
      const implicit = new VetStatus()
      emitAlarm(implicit, { ...consistentLegacy(), severity: 'red' }, { subject: npmSubject('@acme/plugin', '1.0.0') })
      // 区分「有没有比对」：legacy 不比对
      expect(domainProjectionStats().mismatches, '缺省模式没有做投影比对（退回了 legacy？）').toBe(1)
      // 区分「输出走哪条」：shadow 保留 red，active 纠正为 yellow（注册表常量行）
      const expected = VET_CONFIG_DEFAULTS.domainProjection === 'active' ? 'yellow' : 'red'
      expect(implicit.snapshot().alarms[0].severity, '缺省模式的输出分支与配置默认值不一致').toBe(expected)

      // 再钉一层：显式传配置默认值时必须与之逐字段相同
      resetDomainProjectionStats()
      const explicit = new VetStatus()
      emitAlarm(
        explicit,
        { ...consistentLegacy(), severity: 'red' },
        { subject: npmSubject('@acme/plugin', '1.0.0') },
        VET_CONFIG_DEFAULTS.domainProjection,
      )
      expect(explicit.snapshot().alarms).toEqual(implicit.snapshot().alarms)
      expect(domainProjectionStats().mismatches).toBe(1)
    })

    it('三种模式对一条**等价**的告警产出同一条可见行（这是能切换的前提）', () => {
      // 等价性在别处逐字段证过；这里证的是用户可见的那一层：面板拿到的行一模一样。
      // 三种模式若在等价输入上产出不同行，切 active 就是一次行为变更而非内部重构。
      const rows = (['legacy', 'shadow', 'active'] as const).map((mode) => {
        const status = new VetStatus()
        emitAlarm(status, consistentLegacy(), { subject: npmSubject('@acme/plugin', '1.0.0') }, mode)
        return status.snapshot().alarms
      })
      expect(rows[1]).toEqual(rows[0])
      expect(rows[2]).toEqual(rows[0])
    })
  })

  it('Evidence 的形状在发射口是完整的（可交给校验器）', () => {
    // 这里不跑校验器（发射口是进程内可信路径，热路径不该付校验开销），
    // 只断言「投影需要的字段都被填上了」——缺 surface 就是 unknown，不是错。
    const status = new VetStatus()
    emitAlarm(status, consistentLegacy(), { subject: npmSubject('@acme/plugin', '1.0.0') }, 'active')
    const alarm = status.snapshot().alarms[0]
    expect(alarm.id).not.toBe('')
    expect(alarm.kind).toBe('audit-required')
    expect(alarm.at).toBeGreaterThan(0)
  })
})

// 类型层面的一次断言：Evidence 的必填字段与 emitAlarm 的构造保持一致
const _shapeCheck: Pick<Evidence, 'id' | 'subject' | 'source' | 'producer' | 'code' | 'observedAt' | 'outcome' | 'attribution'> = {
  id: 'x',
  subject: SELF_SUBJECT,
  source: 'local_scan',
  producer: 'p',
  code: 'c',
  observedAt: 1,
  outcome: 'observed',
  attribution: 'exact',
}
void _shapeCheck
