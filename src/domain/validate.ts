/**
 * 七类对象的运行时校验（施工图 §1 末段约束）。
 *
 * 为什么需要：这七类对象的输入有相当一部分来自**进程外**（运行时钩子的 IPC、审计档案文件、
 * OSV 响应）。TS 类型在运行时不存在，`as Evidence` 只是自我安慰。0.4.x 已经因为「信任了
 * 落盘数据」修过三次（store-stamp / attribution / baseline），这里的立场是同一个：
 * 结构不对就报出来，绝不悄悄补一个默认值——补默认值会把「数据坏了」变成「数据看着正常」。
 *
 * 校验器**只报告，不修复**。返回 issue 列表，空数组即合法；调用方决定拒收、降级还是照记。
 * 特别地：`code` 不在注册表时只记 issue `unknown-code`，**不在这里丢掉证据**——
 * 丢告警是安全上的 fail-open，比一条字段不合法危险得多。是否拒收由投影器按策略决定。
 */
import {
  SUBJECT_KINDS,
  SURFACES,
  type Attribution,
  type Boundary,
  type CoverageResult,
  type EvidenceOutcome,
  type PolicyAction,
  type ReceiptResult,
  type AssessmentState,
  type QualificationBasis,
  type QualificationStatus,
  type SubjectKind,
  type Surface,
  type TrustOrigin,
} from './types.js'

/** 一条校验问题。`path` 是点分路径（`evidence[0].subject.kind`），便于直接打进日志。 */
export interface ValidationIssue {
  readonly path: string
  readonly message: string
}

export type ValidationIssues = readonly ValidationIssue[]

/**
 * 长度上限。取值原则：比任何一条**当前真实数据**宽一个量级，但不给无限——
 * 上限的作用是让「有人往这里塞一兆」变成一条可读的 issue，而不是一次内存峰值。
 */
export const LIMITS = {
  id: 200,
  code: 120,
  name: 200,
  version: 128,
  producer: 200,
  message: 4096,
  reason: 512,
  path: 4096,
  digest: 128,
  claim: 2048,
  reviewer: 200,
  /** reasons / limitations / reasonCodes 这类小列表。 */
  listSmall: 64,
  /** evidenceIds / assessmentIds。 */
  listIds: 512,
  /** snapshot.excluded（文件级排除清单，可能很大）。 */
  listExcluded: 8192,
} as const

const TRUST_ORIGINS: readonly TrustOrigin[] = [
  'local_scan',
  'runtime_hook',
  'sentinel',
  'external_advisory',
  'plugin_claim',
  'agent_review',
  'human_attestation',
]
const COVERAGE_RESULTS: readonly CoverageResult[] = ['covered', 'partial', 'excluded', 'unsupported', 'failed', 'unknown']
const EVIDENCE_OUTCOMES: readonly EvidenceOutcome[] = ['observed', 'attempted', 'completed', 'failed', 'blocked', 'unknown']
const ATTRIBUTIONS: readonly Attribution[] = ['exact', 'correlated', 'host_only', 'unattributed']
const ASSESSMENT_STATES: readonly AssessmentState[] = [
  'finding',
  'corroborated',
  'disputed',
  'insufficient_evidence',
  'not_observed',
]
const ASSESSMENT_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const
const BOUNDARIES: readonly Boundary[] = ['pre_load', 'tool_call', 'fs_write', 'net', 'none']
const POLICY_ACTIONS: readonly PolicyAction[] = ['allow', 'report', 'require_review', 'deny', 'unknown']
const RECEIPT_RESULTS: readonly ReceiptResult[] = ['applied', 'failed', 'not_requested', 'not_covered', 'unknown']
const QUALIFICATION_STATUSES: readonly QualificationStatus[] = [
  'unassessed',
  'qualified',
  'recheck_required',
  'insufficient_evidence',
  'rejected',
]
const QUALIFICATION_BASES: readonly QualificationBasis[] = ['digest', 'legacy']

export interface ValidateOptions {
  /** 注册表里的已知 code 集合；提供时未知 code 记 issue（仍返回，不吞）。 */
  readonly knownCodes?: ReadonlySet<string>
}

function issue(path: string, message: string): ValidationIssue {
  return { path, message }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asRecord(value: unknown, path: string, out: ValidationIssue[]): Record<string, unknown> | null {
  if (!isRecord(value)) {
    out.push(issue(path, `期望对象，实际是 ${describe(value)}`))
    return null
  }
  return value
}

function describe(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

/** 可选字符串字段：缺席合法；存在则必须是非空（或允许空）且不超长。 */
function optString(
  rec: Record<string, unknown>,
  key: string,
  path: string,
  out: ValidationIssue[],
  max: number,
  opts: { readonly allowEmpty?: boolean } = {},
): void {
  const value = rec[key]
  if (value === undefined) return
  if (typeof value !== 'string') {
    out.push(issue(`${path}.${key}`, `期望字符串，实际是 ${describe(value)}`))
    return
  }
  if (opts.allowEmpty !== true && value === '') {
    out.push(issue(`${path}.${key}`, '不能为空字符串'))
    return
  }
  if (value.length > max) out.push(issue(`${path}.${key}`, `长度 ${value.length} 超过上限 ${max}`))
}

function reqString(rec: Record<string, unknown>, key: string, path: string, out: ValidationIssue[], max: number): void {
  if (rec[key] === undefined) {
    out.push(issue(`${path}.${key}`, '必填字段缺失'))
    return
  }
  optString(rec, key, path, out, max)
}

/** 必填的有限非负数（时间戳）。NaN/Infinity 一律拒——它们会毒化排序与 TTL 判定。 */
function reqTimestamp(rec: Record<string, unknown>, key: string, path: string, out: ValidationIssue[]): void {
  const value = rec[key]
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    out.push(issue(`${path}.${key}`, `期望有限非负数，实际是 ${describe(value)}`))
  }
}

function optTimestamp(rec: Record<string, unknown>, key: string, path: string, out: ValidationIssue[]): void {
  if (rec[key] === undefined) return
  reqTimestamp(rec, key, path, out)
}

function optBoolean(rec: Record<string, unknown>, key: string, path: string, out: ValidationIssue[]): void {
  const value = rec[key]
  if (value === undefined) return
  if (typeof value !== 'boolean') out.push(issue(`${path}.${key}`, `期望布尔，实际是 ${describe(value)}`))
}

/** 枚举字段：`required` 决定缺席是否算错。 */
function enumField<T extends string>(
  rec: Record<string, unknown>,
  key: string,
  path: string,
  out: ValidationIssue[],
  allowed: readonly T[],
  required = true,
): void {
  const value = rec[key]
  if (value === undefined) {
    if (required) out.push(issue(`${path}.${key}`, '必填字段缺失'))
    return
  }
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    out.push(issue(`${path}.${key}`, `不在允许取值内：${String(value)}（允许 ${allowed.join('/')}）`))
  }
}

/** 字符串数组：长度上限 + 每项非空 + 每项长度上限。 */
function stringArray(
  rec: Record<string, unknown>,
  key: string,
  path: string,
  out: ValidationIssue[],
  opts: { readonly required?: boolean; readonly maxItems: number; readonly maxItemLength: number },
): void {
  const value = rec[key]
  if (value === undefined) {
    if (opts.required === true) out.push(issue(`${path}.${key}`, '必填字段缺失'))
    return
  }
  if (!Array.isArray(value)) {
    out.push(issue(`${path}.${key}`, `期望数组，实际是 ${describe(value)}`))
    return
  }
  if (value.length > opts.maxItems) {
    out.push(issue(`${path}.${key}`, `条目数 ${value.length} 超过上限 ${opts.maxItems}`))
  }
  for (let i = 0; i < value.length; i++) {
    const item: unknown = value[i]
    if (typeof item !== 'string') {
      out.push(issue(`${path}.${key}[${i}]`, `期望字符串，实际是 ${describe(item)}`))
      continue
    }
    if (item === '') out.push(issue(`${path}.${key}[${i}]`, '不能为空字符串'))
    else if (item.length > opts.maxItemLength) {
      out.push(issue(`${path}.${key}[${i}]`, `长度 ${item.length} 超过上限 ${opts.maxItemLength}`))
    }
  }
}

/** 主体引用。`self` 是唯一允许 `version` 缺席的主流主体；其它 kind 也允许无版本（local 条目）。 */
export function validateSubject(value: unknown, path = 'subject'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  reqString(rec, 'subjectId', path, out, LIMITS.id)
  enumField<SubjectKind>(rec, 'kind', path, out, SUBJECT_KINDS)
  reqString(rec, 'name', path, out, LIMITS.name)
  optString(rec, 'version', path, out, LIMITS.version)
  optString(rec, 'snapshotId', path, out, LIMITS.id)
  optString(rec, 'instanceId', path, out, LIMITS.id)
  // self 的 subjectId 必须就是 vet-self：否则「vet 自己坏了」的告警会被算到别的去重桶里。
  if (rec.kind === 'self' && typeof rec.subjectId === 'string' && rec.subjectId !== 'vet-self') {
    out.push(issue(`${path}.subjectId`, `kind=self 时必须是 vet-self，实际 ${rec.subjectId}`))
  }
  return out
}

export function validateCoverage(value: unknown, path = 'coverage'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  enumField<Surface>(rec, 'surface', path, out, SURFACES)
  enumField<CoverageResult>(rec, 'result', path, out, COVERAGE_RESULTS)
  stringArray(rec, 'reasons', path, out, { required: true, maxItems: LIMITS.listSmall, maxItemLength: LIMITS.reason })
  reqTimestamp(rec, 'observedAt', path, out)
  optString(rec, 'observerVersion', path, out, LIMITS.version)
  optBoolean(rec, 'acknowledged', path, out)
  return out
}

export function validateEvidence(value: unknown, options: ValidateOptions = {}): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, 'evidence', out)
  if (rec === null) return out
  reqString(rec, 'id', 'evidence', out, LIMITS.id)
  out.push(...validateSubject(rec.subject, 'evidence.subject'))
  enumField<TrustOrigin>(rec, 'source', 'evidence', out, TRUST_ORIGINS)
  reqString(rec, 'producer', 'evidence', out, LIMITS.producer)
  reqString(rec, 'code', 'evidence', out, LIMITS.code)
  const code = rec.code
  if (typeof code === 'string' && code !== '' && options.knownCodes !== undefined && !options.knownCodes.has(code)) {
    out.push(issue('evidence.code', `不在注册表内：${code}`))
  }
  reqTimestamp(rec, 'observedAt', 'evidence', out)
  optTimestamp(rec, 'occurredAt', 'evidence', out)
  enumField<Surface>(rec, 'surface', 'evidence', out, SURFACES, false)
  enumField<EvidenceOutcome>(rec, 'outcome', 'evidence', out, EVIDENCE_OUTCOMES)
  enumField<Attribution>(rec, 'attribution', 'evidence', out, ATTRIBUTIONS)
  optString(rec, 'target', 'evidence', out, LIMITS.path)
  optString(rec, 'payloadDigest', 'evidence', out, LIMITS.digest)
  optString(rec, 'message', 'evidence', out, LIMITS.message, { allowEmpty: true })
  return out
}

export function validateAssessment(value: unknown, path = 'assessment'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  reqString(rec, 'id', path, out, LIMITS.id)
  out.push(...validateSubject(rec.subject, `${path}.subject`))
  reqString(rec, 'claim', path, out, LIMITS.claim)
  enumField<AssessmentState>(rec, 'state', path, out, ASSESSMENT_STATES)
  enumField(rec, 'severity', path, out, ASSESSMENT_SEVERITIES)
  stringArray(rec, 'evidenceIds', path, out, { required: true, maxItems: LIMITS.listIds, maxItemLength: LIMITS.id })
  reqString(rec, 'ruleSetVersion', path, out, LIMITS.version)
  reqTimestamp(rec, 'evaluatedAt', path, out)
  stringArray(rec, 'limitations', path, out, { required: true, maxItems: LIMITS.listSmall, maxItemLength: LIMITS.reason })
  return out
}

export function validateDecision(value: unknown, path = 'decision'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  reqString(rec, 'id', path, out, LIMITS.id)
  out.push(...validateSubject(rec.subject, `${path}.subject`))
  enumField<PolicyAction>(rec, 'action', path, out, POLICY_ACTIONS)
  enumField<Boundary>(rec, 'boundary', path, out, BOUNDARIES)
  reqString(rec, 'policyId', path, out, LIMITS.id)
  stringArray(rec, 'assessmentIds', path, out, { required: true, maxItems: LIMITS.listIds, maxItemLength: LIMITS.id })
  stringArray(rec, 'reasonCodes', path, out, { required: true, maxItems: LIMITS.listSmall, maxItemLength: LIMITS.code })
  stringArray(rec, 'unknownInputs', path, out, { required: true, maxItems: LIMITS.listSmall, maxItemLength: LIMITS.code })
  // 两条跨字段契约（B-9）：不是形状问题，是「这个对象自相矛盾」——和 Receipt 里
  // 「applied 必须带 operationId」同一条纪律：说不清凭什么的结论一律报出来。
  const unknownInputs = rec.unknownInputs
  if (Array.isArray(unknownInputs)) {
    if (rec.action === 'allow' && unknownInputs.length > 0) {
      out.push(issue(`${path}.unknownInputs`, 'action=allow 时不能有未知输入：不知道就不能说可以'))
    }
    if (rec.action === 'unknown' && unknownInputs.length === 0) {
      out.push(issue(`${path}.unknownInputs`, 'action=unknown 时必须说明不知道什么（否则它和「懒得判」没有区别）'))
    }
  }
  reqTimestamp(rec, 'decidedAt', path, out)
  return out
}

export function validateReceipt(value: unknown, path = 'receipt'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  reqString(rec, 'id', path, out, LIMITS.id)
  // decisionId 可空——这是 T4 的直接后果，不是疏漏（见 types.ts Receipt 注释）。
  optString(rec, 'decisionId', path, out, LIMITS.id)
  enumField<Boundary>(rec, 'boundary', path, out, BOUNDARIES)
  reqTimestamp(rec, 'attemptedAt', path, out)
  enumField<ReceiptResult>(rec, 'result', path, out, RECEIPT_RESULTS)
  optString(rec, 'operationId', path, out, LIMITS.id)
  // applied 必须能自证：没有 operationId 的 applied 无法被「原调用计数未增加」证伪。
  if (rec.result === 'applied' && rec.operationId === undefined) {
    out.push(issue(`${path}.operationId`, 'result=applied 时必须带 operationId（否则无法用 oracle 计数证伪）'))
  }
  return out
}

export function validateQualification(value: unknown, path = 'qualification'): ValidationIssues {
  const out: ValidationIssue[] = []
  const rec = asRecord(value, path, out)
  if (rec === null) return out
  reqString(rec, 'subjectId', path, out, LIMITS.id)
  enumField<QualificationStatus>(rec, 'status', path, out, QUALIFICATION_STATUSES)
  enumField<QualificationBasis>(rec, 'basis', path, out, QUALIFICATION_BASES, false)
  optString(rec, 'subjectDigest', path, out, LIMITS.digest)
  reqString(rec, 'reviewScope', path, out, LIMITS.reason)
  reqString(rec, 'evidenceDigest', path, out, LIMITS.digest)
  reqString(rec, 'reviewer', path, out, LIMITS.reviewer)
  reqString(rec, 'policyId', path, out, LIMITS.id)
  reqTimestamp(rec, 'assessedAt', path, out)
  stringArray(rec, 'invalidationReasons', path, out, {
    required: true,
    maxItems: LIMITS.listSmall,
    maxItemLength: LIMITS.reason,
  })
  if (rec.subjectId === 'vet-self') out.push(issue(`${path}.subjectId`, 'vet 不能给自己发资格（权威矩阵 §11.3）'))
  return out
}

/**
 * 覆盖面完整性：返回**从未表过态**的面。
 *
 * 这是不变式 2 的可执行形式——「没采集到」不等于「没问题」。九个面里没有条目的那些，
 * 面板必须显示成 unknown；`projectAlarms` 会据此产出 coverage 行，而不是留白。
 */
export function unstatedSurfaces(entries: readonly { readonly surface: Surface }[]): Surface[] {
  const seen = new Set<Surface>()
  for (const entry of entries) seen.add(entry.surface)
  return SURFACES.filter((surface) => !seen.has(surface))
}

/** 把 issue 列表压成一行，便于直接塞进日志（最多展开前 `limit` 条）。 */
export function describeIssues(issues: ValidationIssues, limit = 3): string {
  return issues
    .slice(0, limit)
    .map((i) => `${i.path}: ${i.message}`)
    .join('; ')
}
