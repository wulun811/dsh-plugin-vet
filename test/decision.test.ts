/**
 * 策略解释器（`domain/decision.ts`）的单元测试。
 *
 * 三组，对应文件头那三条契约：
 * - A 组：**不知道就不能说可以**——`allow` 的每一种来路都被逐个堵死；
 * - B 组：动作阶梯（deny 的两个来路、require_review、report 的三种理由）；
 * - C 组：对象本身的纪律（确定性、可校验、range 声明、评估清单不做「问题清单」）。
 */
import { describe, it, expect } from 'vitest'
import { DECISION_REASON, UNKNOWN_INPUT, buildDecision, type DecisionPolicy } from '../lib/domain/decision.js'
import { validateDecision } from '../lib/domain/validate.js'
import type { Assessment, CoverageEntry, SubjectRef, Surface } from '../lib/domain/types.js'

const subject: SubjectRef = { subjectId: 'pkg@1.0.0', kind: 'npm', name: 'pkg', version: '1.0.0' }

function row(surface: Surface, result: CoverageEntry['result'], reasons: string[] = []): CoverageEntry {
  return { surface, result, reasons, observedAt: 1_000 }
}

function assessment(over: Partial<Assessment> = {}): Assessment {
  return {
    id: 'a-1',
    subject,
    claim: '静态扫描发现了可疑调用',
    state: 'finding',
    severity: 'critical',
    evidenceIds: [],
    ruleSetVersion: 'static-v27',
    evaluatedAt: 1_000,
    limitations: [],
    ...over,
  }
}

/** 两个面全 covered 的「干净」底稿：只有拿它才可能走到 allow。 */
const cleanCoverage: CoverageEntry[] = [row('file_tree', 'covered'), row('intel_osv', 'covered')]

const scope: DecisionPolicy['scope'] = ['file_tree', 'intel_osv']

function decide(over: Partial<Parameters<typeof buildDecision>[0]> & { policy?: Partial<DecisionPolicy> } = {}) {
  const { policy, ...rest } = over
  return buildDecision({
    id: 'dec-1',
    subject,
    boundary: 'pre_load',
    policyId: 'test-policy:1',
    decidedAt: 2_000,
    policy: { scope, ...policy },
    coverage: cleanCoverage,
    ...rest,
  })
}

describe('A 组：不知道就不能说可以', () => {
  it('九面齐全、零命中的干净底稿才给 allow，且 allow 不带未知输入', () => {
    const decision = decide()
    expect(decision.action).toBe('allow')
    expect(decision.unknownInputs).toEqual([])
    expect(decision.reasonCodes).toEqual([DECISION_REASON.noFinding])
    expect(validateDecision(decision)).toEqual([])
  })

  it('范围内有一个 unknown 面 → report，未知输入点名那个面', () => {
    const decision = decide({ coverage: [row('file_tree', 'covered'), row('intel_osv', 'unknown', ['offline'])] })
    expect(decision.action).toBe('report')
    expect(decision.unknownInputs).toEqual([UNKNOWN_INPUT.coverageGap('intel_osv')])
    expect(decision.reasonCodes).toContain(DECISION_REASON.unknownInputsPresent)
  })

  it('partial 与 failed 同样算「没看全」，不是「看了没事」', () => {
    for (const result of ['partial', 'failed'] as const) {
      const decision = decide({ coverage: [row('file_tree', 'covered'), row('intel_osv', result)] })
      expect(decision.action, result).toBe('report')
      expect(decision.unknownInputs, result).toContain(UNKNOWN_INPUT.coverageGap('intel_osv'))
    }
  })

  it('范围内压根没上报 → coverage:<面>:not-reported（漏报和没看是一回事）', () => {
    const decision = decide({ coverage: [row('file_tree', 'covered')] })
    expect(decision.action).toBe('report')
    expect(decision.unknownInputs).toEqual([UNKNOWN_INPUT.coverageMissing('intel_osv')])
  })

  it('excluded / unsupported 是「明确不看」，不算未知输入，但照样拦 allow', () => {
    const decision = decide({ coverage: [row('file_tree', 'covered'), row('intel_osv', 'excluded', ['osv-disabled'])] })
    expect(decision.action).toBe('report')
    // 关键区别：它进不了 unknownInputs——用户自己关掉的东西不该被说成「我们不知道」。
    expect(decision.unknownInputs).toEqual([])
    expect(decision.reasonCodes).toContain(DECISION_REASON.scopeNotFullyCovered)
    expect(decision.reasonCodes).not.toContain(DECISION_REASON.unknownInputsPresent)
  })

  it('调用方声明的未知输入同样让 allow 不可能出现', () => {
    const decision = decide({ unknownInputs: ['verdict:unrecognized'] })
    expect(decision.action).toBe('report')
    expect(decision.unknownInputs).toEqual(['verdict:unrecognized'])
  })

  it('评估自己说「证据不够」→ 这是未知输入，不是「没问题」', () => {
    const decision = decide({ assessments: [assessment({ state: 'insufficient_evidence', severity: 'unknown' })] })
    expect(decision.action).toBe('report')
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.assessmentInsufficient)
  })

  it('「有问题但定不了多严重」→ 未知输入，且不能靠排序挤过门槛', () => {
    const decision = decide({
      assessments: [assessment({ id: 'a-9', severity: 'unknown' })],
      policy: { denyFrom: 'critical' },
    })
    // denyFrom 已授权，但 ungraded 判读进不了门槛比较 → 不是 deny，但也绝不是 allow。
    expect(decision.action).toBe('report')
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.assessmentUngraded)
    expect(decision.reasonCodes).not.toContain(DECISION_REASON.findingAtOrAboveThreshold)
  })
})

describe('B 组：动作阶梯', () => {
  it('没有拦截授权的边界：critical 命中也只能 report，理由码明说「没授权」', () => {
    const decision = decide({ assessments: [assessment()] })
    expect(decision.action).toBe('report')
    expect(decision.reasonCodes).toContain(DECISION_REASON.findingNotAuthorized)
  })

  it('已授权且命中达到门槛 → deny', () => {
    const decision = decide({ assessments: [assessment()], policy: { denyFrom: 'high' } })
    expect(decision.action).toBe('deny')
    expect(decision.reasonCodes).toEqual([DECISION_REASON.denyAuthorized, DECISION_REASON.findingAtOrAboveThreshold])
    expect(validateDecision(decision)).toEqual([])
  })

  it('已授权但命中低于门槛 → report + finding-below-threshold', () => {
    const decision = decide({ assessments: [assessment({ severity: 'medium' })], policy: { denyFrom: 'critical' } })
    expect(decision.action).toBe('report')
    expect(decision.reasonCodes).toContain(DECISION_REASON.findingBelowThreshold)
  })

  it('失败关闭只认策略点名的那个未知输入，不做前缀/同类泛化', () => {
    const denyPolicy: Partial<DecisionPolicy> = { denyFrom: 'critical', failClosedOn: ['verdict:unrecognized'] }
    const named = decide({ policy: denyPolicy, unknownInputs: ['verdict:unrecognized'] })
    expect(named.action).toBe('deny')
    expect(named.reasonCodes).toContain(DECISION_REASON.failClosedOnUnknown)

    // 另一个未知输入不触发失败关闭：覆盖面缺口再多，也不该升级成拒载（误拦风暴的配方）。
    const other = decide({
      policy: denyPolicy,
      coverage: [row('file_tree', 'failed'), row('intel_osv', 'unknown')],
    })
    expect(other.action).toBe('report')
    expect(other.reasonCodes).not.toContain(DECISION_REASON.failClosedOnUnknown)
  })

  it('没有拦截授权时 failClosedOn 无处可关（不会凭空获得拒载权）', () => {
    const decision = decide({ policy: { failClosedOn: ['verdict:unrecognized'] }, unknownInputs: ['verdict:unrecognized'] })
    expect(decision.action).toBe('report')
  })

  it('判读互相矛盾 → require_review，不替人猜谁对', () => {
    const decision = decide({ assessments: [assessment({ state: 'disputed' })] })
    expect(decision.action).toBe('require_review')
    expect(decision.reasonCodes).toContain(DECISION_REASON.assessmentDisputed)
  })

  it('not_observed 是「看了，没有」，既不拦 allow 也不进未知输入', () => {
    const decision = decide({ assessments: [assessment({ state: 'not_observed', severity: 'info' })] })
    expect(decision.action).toBe('allow')
    expect(decision.unknownInputs).toEqual([])
  })
})

describe('C 组：对象纪律', () => {
  it('同样的输入给同样的决策（影子对照的前提）', () => {
    const a = decide({ assessments: [assessment()] })
    const b = decide({ assessments: [assessment()] })
    expect(a).toEqual(b)
  })

  it('同面两条结论取更差的那条，与数组顺序无关', () => {
    const forward = decide({ coverage: [row('file_tree', 'covered'), row('file_tree', 'failed'), row('intel_osv', 'covered')] })
    const backward = decide({ coverage: [row('intel_osv', 'covered'), row('file_tree', 'failed'), row('file_tree', 'covered')] })
    expect(forward.action).toBe('report')
    expect(forward.unknownInputs).toEqual([UNKNOWN_INPUT.coverageGap('file_tree')])
    expect(backward).toEqual(forward)
  })

  it('assessmentIds 是全部参与判读的判读，不是「命中清单」', () => {
    const decision = decide({
      assessments: [assessment({ id: 'hit' }), assessment({ id: 'quiet', state: 'not_observed', severity: 'info' })],
    })
    expect(decision.assessmentIds).toEqual(['hit', 'quiet'])
  })

  it('空 scope 直接炸：没有范围就无从回答「缺什么」', () => {
    expect(() => buildDecision({
      id: 'dec-x',
      subject,
      boundary: 'none',
      policyId: 'bad',
      decidedAt: 1,
      policy: { scope: [] },
    })).toThrow(/scope 为空/)
  })

  it('产出的每种动作都通过校验器（含 allow 的跨字段契约）', () => {
    const variants = [
      decide(),
      decide({ assessments: [assessment()] }),
      decide({ assessments: [assessment()], policy: { denyFrom: 'critical' } }),
      decide({ assessments: [assessment({ state: 'disputed' })] }),
      decide({ coverage: [row('file_tree', 'unknown'), row('intel_osv', 'unknown')] }),
    ]
    for (const decision of variants) expect(validateDecision(decision)).toEqual([])
  })
})
