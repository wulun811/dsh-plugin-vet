/**
 * 资格状态机（施工图 §5.1）：五态、九事件、45 格。
 *
 * 为什么资格是状态机而另外两样不是——判据是「有持久状态 + 多个写入方 + 现在允许做什么随状态变化」。
 * 资格三条全中：档案落盘（持久）、审核人/内容变化/撤销都能写（多写入方）、`qualified` 与否
 * 直接决定 requireAudit 拦不拦（改变允许的动作）。运行时干预是单步、无跨调用状态；posture 是
 * 算出来的。所以只有这一处值得写转移表。
 *
 * 两处对评审稿的削减（施工图已裁定，这里落实）：
 * - `LEGACY_RECORD_ONLY` **不是状态**，是 `qualified.basis` 的取值。它和 QUALIFIED 的允许动作
 *   完全相同（都能加载），差的是凭据来源；做成状态会让每个转移都要同时处理两个「允许态」。
 * - `REVOKED` **不是状态**，是事件，落到 UNASSESSED。状态回答「现在允许什么」，不回答「曾经
 *   发生过什么」——撤销的痕迹在事件与告警里，不在状态位里。
 *
 * **支配性不变式**：资格只能被**新的审计事实**提升。时间流逝、进程重启、清缓存、改配置，
 * 都不能让状态上升。这条在下面的表里是结构性的：只有 `audit_passed` 与 `legacy_record_found`
 * 两个事件能到达 qualified，其余事件最多持平或下降。
 */
import type { QualificationBasis, QualificationStatus } from './types.js'

/** 状态机的状态 = 状态 + 凭据来源 + 造成它的理由（理由进档案/告警，不进判断）。 */
export interface QualificationState {
  readonly status: QualificationStatus
  readonly basis?: QualificationBasis
  readonly reasons: readonly string[]
}

/** 事件。九个，不多不少——每个都对应一个真实会发生的写入。 */
export type QualificationEvent =
  /** 完成了一次审计，且证据充分（`basis` 说明这次审计是绑摘要的还是旧式的）。 */
  | { readonly type: 'audit_passed'; readonly basis: QualificationBasis }
  /** 迁移期发现历史档案（没有摘要可比）。只对 UNASSESSED 生效，见下方注释。 */
  | { readonly type: 'legacy_record_found' }
  /** 完成了一次审计，但证据不足。 */
  | { readonly type: 'audit_insufficient' }
  /** 完成了一次审计，结论是不通过。 */
  | { readonly type: 'audit_failed' }
  /** 内容摘要变了（同版本不同字节，或版本变了）。 */
  | { readonly type: 'content_changed' }
  /** 审计标准变了；`impacts` 由影响函数判定是否会在本主体上产生不同结论。 */
  | { readonly type: 'standard_changed'; readonly impacts: boolean }
  /** 运行时档位/守卫配置变了。 */
  | { readonly type: 'runtime_config_changed' }
  /** OSV / registry 情报变了。 */
  | { readonly type: 'intel_changed' }
  /** 部署者撤销了这条资格。 */
  | { readonly type: 'revoked' }

/** 九个事件的类型名（测试用它枚举整张表，避免手写漏格）。 */
export const QUALIFICATION_EVENTS = [
  'audit_passed',
  'legacy_record_found',
  'audit_insufficient',
  'audit_failed',
  'content_changed',
  'standard_changed',
  'runtime_config_changed',
  'intel_changed',
  'revoked',
] as const

export type QualificationEventType = (typeof QUALIFICATION_EVENTS)[number]

/** 五个状态（顺序固定，测试按它枚举）。 */
export const QUALIFICATION_STATUSES: readonly QualificationStatus[] = [
  'unassessed',
  'qualified',
  'recheck_required',
  'insufficient_evidence',
  'rejected',
]

export const INITIAL_QUALIFICATION: QualificationState = { status: 'unassessed', reasons: [] }

/** 现在允许做什么。requireAudit 只认这一个判断，不认具体状态名。 */
export function canLoad(state: QualificationState): boolean {
  return state.status === 'qualified'
}

/** 给出一个事件的最小样本（测试枚举 45 格时用；`standard_changed` 取「有影响」那支）。 */
export function eventOfType(type: QualificationEventType): QualificationEvent {
  switch (type) {
    case 'audit_passed':
      return { type, basis: 'digest' }
    case 'standard_changed':
      return { type, impacts: true }
    default:
      return { type }
  }
}

function state(status: QualificationStatus, basis: QualificationBasis | undefined, reason: string): QualificationState {
  return basis === undefined ? { status, reasons: [reason] } : { status, basis, reasons: [reason] }
}

const UNASSESSED = (reason: string): QualificationState => state('unassessed', undefined, reason)
const QUALIFIED = (basis: QualificationBasis, reason: string): QualificationState => state('qualified', basis, reason)
const RECHECK = (reason: string): QualificationState => state('recheck_required', undefined, reason)
const INSUFFICIENT = (reason: string): QualificationState => state('insufficient_evidence', undefined, reason)
const REJECTED = (reason: string): QualificationState => state('rejected', undefined, reason)

/**
 * 转移。**全函数**：任何 (状态, 事件) 都有定义，绝不抛错——状态机在加载路径上，
 * 一个「未定义转移」异常会让插件加载失败，那比任何判定错误都糟。
 */
export function transition(current: QualificationState, event: QualificationEvent): QualificationState {
  switch (event.type) {
    // ── 新审计事实：唯一能把状态抬上去的一类 ────────────────────────────────
    case 'audit_passed':
      return QUALIFIED(event.basis, 'audit-passed')
    case 'legacy_record_found':
      // 迁移期兼容：只有**还没有任何判定**时才认旧档案。已经判定过的（recheck / rejected /
      // insufficient）不能被一份更旧的档案翻案——那不是新事实，是旧事实。
      return current.status === 'unassessed'
        ? QUALIFIED('legacy', 'legacy-record')
        : preserve(current, 'legacy-record-ignored')
    case 'audit_insufficient':
      // 审计跑了但证据不够：对 rejected 不生效（一次不通过的判定不能被「更弱的审」冲掉）。
      return current.status === 'rejected' ? REJECTED('rejected-still') : INSUFFICIENT('audit-insufficient')
    case 'audit_failed':
      return REJECTED('audit-failed')

    // ── 失效：只在「已经合格」时有意义（其余状态本来就不合格）─────────────────
    case 'content_changed':
      return current.status === 'qualified' ? RECHECK('content-changed') : preserve(current, 'content-changed')
    case 'standard_changed':
      if (current.status !== 'qualified') return preserve(current, 'standard-changed')
      // 影响函数：只有「会改变本主体结论」的标准变化才触发重审。不搞「任何字段变了就全清」，
      // 那是大规模拒载的成因，不是严谨。
      return event.impacts ? RECHECK('standard-changed') : preserve(current, 'standard-irrelevant')

    // ── 不改变资格的配置/情报变化（这三个是「失效轴互不牵连」的落点）──────────
    case 'runtime_config_changed':
      return preserve(current, 'runtime-config')
    case 'intel_changed':
      return preserve(current, 'intel')

    // ── 撤销：不是状态，是事件 ──────────────────────────────────────────────
    case 'revoked':
      return UNASSESSED('revoked')
  }
}

/** 保持不变，但把这次事件记进 reasons（便于面板解释「它为什么没变」）。 */
function preserve(current: QualificationState, reason: string): QualificationState {
  const reasons = current.reasons.includes(reason) ? current.reasons : [...current.reasons, reason]
  return current.basis === undefined
    ? { status: current.status, reasons }
    : { status: current.status, basis: current.basis, reasons }
}

/**
 * 整张表（5 × 9 = 45 格）。测试直接枚举它，人也可以一眼看全。
 *
 * 这里刻意把「格子」写成数据而不是只留 switch：switch 只能证明「我写了的转移是对的」，
 * 数据表能证明「没有漏格」——漏格在运行期表现为一个说不清的状态，比写错更难查。
 */
export function transitionTable(): Array<{ status: QualificationStatus; event: QualificationEventType; result: QualificationState }> {
  const out: Array<{ status: QualificationStatus; event: QualificationEventType; result: QualificationState }> = []
  for (const status of QUALIFICATION_STATUSES) {
    for (const eventType of QUALIFICATION_EVENTS) {
      const start: QualificationState = status === 'qualified'
        ? { status, basis: 'digest', reasons: [] }
        : { status, reasons: [] }
      out.push({ status, event: eventType, result: transition(start, eventOfType(eventType)) })
    }
  }
  return out
}
