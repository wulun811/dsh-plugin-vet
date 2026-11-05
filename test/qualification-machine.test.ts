import { describe, expect, it } from 'vitest'
import {
  INITIAL_QUALIFICATION,
  QUALIFICATION_EVENTS,
  QUALIFICATION_STATUSES,
  canLoad,
  eventOfType,
  transition,
  transitionTable,
  type QualificationEvent,
  type QualificationState,
} from '../lib/domain/qualify.js'

/**
 * 0.5.1 步骤 6 的验收之一：45 格全枚举。
 *
 * 状态机最容易出的错不是「某一格写错」，而是**漏格**——漏格在运行期表现为一个说不清的状态，
 * 而且往往只在某个罕见组合下出现。所以这里不测「几个典型转移」，测**整张表**：
 * 5 个状态 × 9 个事件，一格不漏，并对每一格断言它属于允许的语义类别。
 */

const ALL = transitionTable()
const startOf = (status: (typeof QUALIFICATION_STATUSES)[number]): QualificationState =>
  status === 'qualified' ? { status, basis: 'digest', reasons: [] } : { status, reasons: [] }
const cell = (status: string, event: string): QualificationState => {
  const found = ALL.find((c) => c.status === status && c.event === event)
  if (found === undefined) throw new Error(`缺格：${status} × ${event}`)
  return found.result
}

describe('转移表：5 × 9 = 45 格，一格不漏', () => {
  it('格子数正好 45，且每个 (状态, 事件) 都有定义', () => {
    expect(ALL).toHaveLength(QUALIFICATION_STATUSES.length * QUALIFICATION_EVENTS.length)
    expect(ALL).toHaveLength(45)
    for (const status of QUALIFICATION_STATUSES) {
      for (const event of QUALIFICATION_EVENTS) {
        expect(() => cell(status, event), `缺格 ${status} × ${event}`).not.toThrow()
      }
    }
  })

  it('每一格的结果都属于五态之一，不会出现拼错的状态名', () => {
    for (const { result } of ALL) {
      expect(QUALIFICATION_STATUSES).toContain(result.status)
      expect(result.reasons.length).toBeGreaterThan(0)
    }
  })

  it('qualifed 之外的态不带 basis（basis 只描述「凭什么合格」）', () => {
    for (const { result } of ALL) {
      if (result.status === 'qualified') expect(result.basis).toBeDefined()
      else expect(result.basis).toBeUndefined()
    }
  })
})

describe('支配性不变式：只有新的审计事实能提升资格', () => {
  it('能到达 qualified 的事件只有两个：audit_passed 与 legacy_record_found', () => {
    const raisers = new Set<string>()
    for (const { status, event, result } of ALL) {
      if (result.status !== 'qualified') continue
      if (status === 'qualified') continue // 本来就在，不算「提升」
      raisers.add(event)
    }
    expect([...raisers].sort()).toEqual(['audit_passed', 'legacy_record_found'])
  })

  it('时间/配置/情报类事件从不合格态出发，永远不会变成合格', () => {
    for (const status of ['unassessed', 'recheck_required', 'insufficient_evidence', 'rejected'] as const) {
      for (const event of ['content_changed', 'standard_changed', 'runtime_config_changed', 'intel_changed'] as const) {
        expect(cell(status, event).status, `${status} × ${event}`).not.toBe('qualified')
      }
    }
  })

  it('改档位/改守卫（runtime_config_changed）不使已合格的资格失效——大规模拒载的成因就是这一格写错', () => {
    expect(cell('qualified', 'runtime_config_changed').status).toBe('qualified')
    expect(cell('qualified', 'runtime_config_changed').basis).toBe('digest')
  })

  it('OSV/registry 情报变化不使资格失效（情报不是资格前提）', () => {
    expect(cell('qualified', 'intel_changed').status).toBe('qualified')
  })
})

describe('三根失效轴互不牵连', () => {
  it('内容变 → 重审；标准变 → 看影响函数；配置变 → 不变', () => {
    expect(cell('qualified', 'content_changed').status).toBe('recheck_required')
    expect(cell('qualified', 'standard_changed').status).toBe('recheck_required')
    expect(cell('qualified', 'runtime_config_changed').status).toBe('qualified')
  })

  it('标准变但影响函数判定「不影响本主体」→ 保持合格（不搞「任何字段变了就全清」）', () => {
    const state = transition(startOf('qualified'), { type: 'standard_changed', impacts: false })
    expect(state.status).toBe('qualified')
    expect(state.reasons).toContain('standard-irrelevant')
  })

  it('recheck_required 下标准变但无影响 → 仍停在重审（没有新审计就不能抬起来）', () => {
    const state = transition(startOf('recheck_required'), { type: 'standard_changed', impacts: false })
    expect(state.status).toBe('recheck_required')
  })
})

describe('撤销与翻案', () => {
  it('撤销从任何状态都落到 unassessed（撤销是事件不是状态）', () => {
    for (const status of QUALIFICATION_STATUSES) {
      expect(cell(status, 'revoked').status, status).toBe('unassessed')
    }
  })

  it('例外过期等价于撤销：从合格落回未评估，必须重新审计（不是「过期了但还算数」）', () => {
    const state = transition(startOf('qualified'), { type: 'revoked' })
    expect(state.status).toBe('unassessed')
    expect(state.reasons).toContain('revoked')
    expect(canLoad(state)).toBe(false)
  })

  it('rejected 允许翻案，但只认「审计通过」——不通过的审计不能让驳回松动', () => {
    expect(cell('rejected', 'audit_passed').status).toBe('qualified')
    expect(cell('rejected', 'audit_insufficient').status).toBe('rejected')
    expect(cell('rejected', 'legacy_record_found').status).toBe('rejected')
    expect(cell('rejected', 'content_changed').status).toBe('rejected')
  })

  it('旧档案只在「还没有任何判定」时才认（迁移期兼容，不翻案）', () => {
    expect(cell('unassessed', 'legacy_record_found').status).toBe('qualified')
    expect(cell('unassessed', 'legacy_record_found').basis).toBe('legacy')
    for (const status of ['recheck_required', 'insufficient_evidence', 'rejected'] as const) {
      expect(cell(status, 'legacy_record_found').status, status).not.toBe('qualified')
    }
  })

  it('recheck_required / insufficient_evidence 被任一审计结论覆盖（重审必须给出结论）', () => {
    for (const status of ['recheck_required', 'insufficient_evidence'] as const) {
      expect(cell(status, 'audit_passed').status).toBe('qualified')
      expect(cell(status, 'audit_insufficient').status).toBe('insufficient_evidence')
      expect(cell(status, 'audit_failed').status).toBe('rejected')
    }
  })
})

describe('canLoad：requireAudit 只认这一个判断', () => {
  it('只有 qualified 可加载，其余四态都不可', () => {
    expect(canLoad({ status: 'qualified', basis: 'digest', reasons: [] })).toBe(true)
    expect(canLoad({ status: 'qualified', basis: 'legacy', reasons: [] })).toBe(true)
    for (const status of ['unassessed', 'recheck_required', 'insufficient_evidence', 'rejected'] as const) {
      expect(canLoad({ status, reasons: [] }), status).toBe(false)
    }
  })

  it('初始态是未评估，且不可加载', () => {
    expect(INITIAL_QUALIFICATION.status).toBe('unassessed')
    expect(canLoad(INITIAL_QUALIFICATION)).toBe(false)
  })
})

describe('全函数：任何输入都不抛', () => {
  it('用每个事件的真实样本跑一遍，不出现异常', () => {
    for (const status of QUALIFICATION_STATUSES) {
      for (const event of QUALIFICATION_EVENTS) {
        expect(() => transition(startOf(status), eventOfType(event))).not.toThrow()
      }
    }
  })

  it('重复施加同一事件收敛（幂等），不会越跑越乱', () => {
    for (const event of QUALIFICATION_EVENTS) {
      const once = transition(startOf('unassessed'), eventOfType(event))
      const twice = transition(once, eventOfType(event))
      expect(twice.status, `${event as QualificationEvent['type']}`).toBe(once.status)
    }
  })
})
