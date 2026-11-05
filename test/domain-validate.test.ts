import { describe, expect, it } from 'vitest'
import {
  LIMITS,
  describeIssues,
  unstatedSurfaces,
  validateAssessment,
  validateCoverage,
  validateDecision,
  validateEvidence,
  validateQualification,
  validateReceipt,
  validateSubject,
} from '../lib/domain/validate.js'
import { SURFACES, SELF_SUBJECT, type Evidence } from '../lib/domain/types.js'

/**
 * 步骤 1 的验收：形状与校验。
 *
 * 这些测试不接任何现有逻辑（准出条件之一是 `lib/` 里没有 caller），所以它们的价值只有
 * 一个——把「什么样的输入算合法」钉死。此后注册表、投影器、快照三处都复用它，
 * 任一处放宽了这里就会红。
 */

function validEvidence(overrides: Partial<Evidence> = {}): Evidence {
  return {
    id: 'ev-1',
    subject: { subjectId: '@acme/plugin@1.2.3#abc123def456', kind: 'npm', name: '@acme/plugin', version: '1.2.3' },
    source: 'local_scan',
    producer: 'scanner/0.5.0',
    code: 'baseline-mismatch',
    observedAt: 1_700_000_000_000,
    surface: 'file_tree',
    outcome: 'observed',
    attribution: 'exact',
    message: '官方包 @acme/plugin@1.2.3 内容哈希与基线不一致',
    ...overrides,
  }
}

describe('domain/validate：主体', () => {
  it('合法主体无 issue', () => {
    expect(validateSubject(validEvidence().subject)).toEqual([])
  })

  it('self 主体的 subjectId 必须是 vet-self', () => {
    const issues = validateSubject({ subjectId: 'something-else', kind: 'self', name: 'vet' })
    expect(issues).toHaveLength(1)
    expect(issues[0].path).toBe('subject.subjectId')
    expect(() => validateSubject(SELF_SUBJECT)).not.toThrow()
    expect(validateSubject(SELF_SUBJECT)).toEqual([])
  })

  it('非法 kind 报出允许取值', () => {
    const issues = validateSubject({ subjectId: 'x', kind: 'binary', name: 'x' })
    expect(issues.some((i) => i.message.includes('不在允许取值内'))).toBe(true)
  })

  it('非对象输入不抛异常，只报一条', () => {
    for (const bad of [null, undefined, 42, 'str', [], true]) {
      const issues = validateSubject(bad)
      expect(issues).toHaveLength(1)
      expect(issues[0].message).toContain('期望对象')
    }
  })

  it('空字符串与超长字段都被拒', () => {
    expect(validateSubject({ subjectId: '', kind: 'npm', name: 'x' }).some((i) => i.message.includes('空字符串'))).toBe(true)
    const longName = 'a'.repeat(LIMITS.name + 1)
    expect(validateSubject({ subjectId: 'x', kind: 'npm', name: longName }).some((i) => i.message.includes('超过上限'))).toBe(
      true,
    )
  })
})

describe('domain/validate：证据', () => {
  it('合法证据无 issue', () => {
    expect(validateEvidence(validEvidence())).toEqual([])
  })

  it('缺必填字段逐条报出，路径可定位', () => {
    const issues = validateEvidence({ id: 'ev-1' })
    const paths = new Set(issues.map((i) => i.path))
    expect(paths.has('evidence.subject')).toBe(true)
    expect(paths.has('evidence.source')).toBe(true)
    expect(paths.has('evidence.producer')).toBe(true)
    expect(paths.has('evidence.code')).toBe(true)
    expect(paths.has('evidence.observedAt')).toBe(true)
    expect(paths.has('evidence.outcome')).toBe(true)
    expect(paths.has('evidence.attribution')).toBe(true)
  })

  it('code 不在注册表：给了注册表才报，没给不报（不在这里拒收）', () => {
    const evidence = validEvidence({ code: 'not-a-real-code' })
    expect(validateEvidence(evidence)).toEqual([])
    const issues = validateEvidence(evidence, { knownCodes: new Set(['baseline-mismatch']) })
    expect(issues).toHaveLength(1)
    expect(issues[0].path).toBe('evidence.code')
    expect(issues[0].message).toContain('不在注册表内')
  })

  it('NaN / Infinity 时间戳被拒（会毒化 TTL 与排序）', () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
      const issues = validateEvidence(validEvidence({ observedAt: bad }))
      expect(issues.some((i) => i.path === 'evidence.observedAt')).toBe(true)
    }
  })

  it('超长文案被拒；空文案允许（占位观测先于文案存在）', () => {
    expect(validateEvidence(validEvidence({ message: 'x'.repeat(LIMITS.message + 1) })).length).toBe(1)
    expect(validateEvidence(validEvidence({ message: '' }))).toEqual([])
    expect(validateEvidence(validEvidence({ message: undefined }))).toEqual([])
  })

  it('surface 缺席合法（不标就是不知道，不是错）', () => {
    expect(validateEvidence(validEvidence({ surface: undefined }))).toEqual([])
    expect(validateEvidence(validEvidence({ surface: 'disk' as never })).length).toBe(1)
  })
})

describe('domain/validate：覆盖面', () => {
  it('合法条目无 issue', () => {
    expect(
      validateCoverage({ surface: 'runtime_net', result: 'unsupported', reasons: ['no hook'], observedAt: 1 }),
    ).toEqual([])
  })

  it('reasons 必填且有条数上限', () => {
    expect(validateCoverage({ surface: 'runtime_net', result: 'failed', observedAt: 1 }).some((i) => i.path.endsWith('.reasons'))).toBe(
      true,
    )
    const many = Array.from({ length: LIMITS.listSmall + 1 }, (_, i) => `r${i}`)
    const issues = validateCoverage({ surface: 'runtime_net', result: 'failed', reasons: many, observedAt: 1 })
    expect(issues.some((i) => i.message.includes('超过上限'))).toBe(true)
  })

  it('unstatedSurfaces：没表过态的面一个都不许漏', () => {
    expect(unstatedSurfaces([])).toHaveLength(SURFACES.length)
    expect(unstatedSurfaces([{ surface: 'file_tree' }])).toEqual(SURFACES.filter((s) => s !== 'file_tree'))
    const all = SURFACES.map((surface) => ({ surface }))
    expect(unstatedSurfaces(all)).toEqual([])
  })
})

describe('domain/validate：评估 / 决策 / 回执 / 资格', () => {
  const subject = validEvidence().subject

  it('评估的 severity 允许多一档 unknown', () => {
    const base = {
      id: 'as-1',
      subject,
      claim: 'c',
      state: 'finding',
      evidenceIds: ['ev-1'],
      ruleSetVersion: 'rules/1',
      evaluatedAt: 1,
      limitations: [],
    }
    expect(validateAssessment({ ...base, severity: 'unknown' })).toEqual([])
    expect(validateAssessment({ ...base, severity: 'critical' })).toEqual([])
    expect(validateAssessment({ ...base, severity: 'red' }).length).toBe(1)
  })

  it('决策允许 action=unknown（策略算不出来也是一种结果）', () => {
    expect(
      validateDecision({
        id: 'd-1',
        subject,
        action: 'unknown',
        boundary: 'none',
        policyId: 'policy-1',
        assessmentIds: [],
        reasonCodes: [],
        // 0.5.11（B-9）：unknown 必须说清不知道什么，否则它和「懒得判」没有区别。
        unknownInputs: ['verdict:unrecognized'],
        decidedAt: 1,
      }),
    ).toEqual([])
  })

  it('决策：action=unknown 不带未知输入 → 报 issue（不说清就等于没说）', () => {
    const issues = validateDecision({
      id: 'd-1',
      subject,
      action: 'unknown',
      boundary: 'none',
      policyId: 'policy-1',
      assessmentIds: [],
      reasonCodes: [],
      unknownInputs: [],
      decidedAt: 1,
    })
    expect(issues).toHaveLength(1)
    expect(issues[0].path).toBe('decision.unknownInputs')
  })

  it('决策：action=allow 带未知输入 → 报 issue（不知道就不能说可以）', () => {
    const issues = validateDecision({
      id: 'd-1',
      subject,
      action: 'allow',
      boundary: 'none',
      policyId: 'policy-1',
      assessmentIds: [],
      reasonCodes: ['no-finding'],
      unknownInputs: ['coverage:intel_osv'],
      decidedAt: 1,
    })
    expect(issues).toHaveLength(1)
    expect(issues[0].path).toBe('decision.unknownInputs')
  })

  it('决策：unknownInputs 是必填字段（空数组可以，缺席不行）', () => {
    const issues = validateDecision({
      id: 'd-1',
      subject,
      action: 'report',
      boundary: 'none',
      policyId: 'policy-1',
      assessmentIds: [],
      reasonCodes: [],
      decidedAt: 1,
    })
    expect(issues.map((i) => i.path)).toContain('decision.unknownInputs')
  })

  it('回执：decisionId 可空（not_covered 先于决策存在）', () => {
    expect(
      validateReceipt({ id: 'r-1', boundary: 'fs_write', attemptedAt: 1, result: 'not_covered' }),
    ).toEqual([])
  })

  it('回执：applied 必须带 operationId，否则无法用 oracle 计数证伪', () => {
    const issues = validateReceipt({ id: 'r-1', boundary: 'fs_write', attemptedAt: 1, result: 'applied' })
    expect(issues).toHaveLength(1)
    expect(issues[0].path).toBe('receipt.operationId')
    expect(
      validateReceipt({ id: 'r-1', boundary: 'fs_write', attemptedAt: 1, result: 'applied', operationId: 'op-7' }),
    ).toEqual([])
  })

  it('资格：vet 不能给自己发资格', () => {
    const base = {
      subjectId: 'vet-self',
      status: 'qualified',
      basis: 'digest',
      reviewScope: 'all',
      evidenceDigest: 'abc',
      reviewer: 'agent',
      policyId: 'p',
      assessedAt: 1,
      invalidationReasons: [],
    }
    const issues = validateQualification(base)
    expect(issues).toHaveLength(1)
    expect(issues[0].message).toContain('权威矩阵')
  })

  it('资格：legacy 不再是状态，是 basis', () => {
    const issues = validateQualification({
      subjectId: '@acme/p@1',
      status: 'legacy_record_only',
      reviewScope: 'all',
      evidenceDigest: 'abc',
      reviewer: 'agent',
      policyId: 'p',
      assessedAt: 1,
      invalidationReasons: [],
    })
    expect(issues.some((i) => i.path === 'qualification.status')).toBe(true)
  })
})

describe('domain/validate：issue 渲染', () => {
  it('describeIssues 截断到 limit 条并带路径', () => {
    const issues = validateEvidence({})
    const line = describeIssues(issues, 2)
    expect(line.split('; ')).toHaveLength(2)
    expect(line).toContain('evidence.')
  })
})
