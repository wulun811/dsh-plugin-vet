/**
 * 策略解释器（施工图 §5.4 / 对照清单 B-9）：从「看到了什么」算出「该做什么」。
 *
 * 这个文件只做一件事，却是最容易被做错的一件：**把「不知道」翻译成一个动作**。
 *
 * 0.5.x 之前，拦不拦是 `if (score > threshold)` 的形状。阈值一旦写死，就再也分不清
 * 「这次放行是因为查干净了」还是「因为压根没查」。九个面的覆盖面（`domain/coverage.ts`）
 * 已经让「没查」可见了，但**可见不等于参与判定**——面板上写着 partial，判定里照样 allow。
 * 那正是「虚假安全感」的生成方式：不是撒谎，是两个子系统各说各的。
 *
 * 所以这里的输入里必须有覆盖面，输出里必须有 `unknownInputs`，并且有三条硬契约
 * （前两条校验器也各有一条）：
 *
 * 1. **不知道就不能说可以**：`allow` 只在「范围内的面全部 covered、且没有任何未知输入」时出现；
 * 2. **定不了就必须说清定不了什么**：`unknown` 必须带非空 `unknownInputs`；
 * 3. **未知输入被提到时，理由码里一定有它**（`unknown-inputs-present`）——理由与字段不能各说各的。
 *
 * 它同时是「不同拦截点可以有不同策略」的落点：`scope`（这次判定回答哪几个面）、
 * `denyFrom`（有没有获授权拦截、门槛多高）、`failClosedOn`（哪几个未知输入按失败关闭）
 * 全是入参而非常量。同一份证据，装载门禁与 N7 的危险行为拦截本来就该给出不同结论；
 * 把它们塞进同一个常量等于让最严的那个边界定义所有边界。
 */
import { worseCoverageResult } from './coverage.js'
import type {
  Assessment,
  AssessmentSeverity,
  Boundary,
  CoverageEntry,
  Decision,
  PolicyAction,
  SubjectRef,
  Surface,
} from './types.js'

/**
 * 未知输入码。形状 `<class>:<detail>`。
 *
 * 面上带 detail（哪个面不知道），评估类的**不带对象 id**：`assessmentIds` 已经回答了
 * 「看过哪几条判读」，这里回答的是「缺哪一类输入」。把 id 编进码里会让策略不得不按
 * 实例匹配（`failClosedOn` 就退化成一张名单），而绝大多数策略要表达的是「这类输入
 * 缺了就别放行」。
 */
export const UNKNOWN_INPUT = {
  /** 声明范围内的面压根没上报结论（调用方漏了，不是「看了没问题」）。 */
  coverageMissing: (surface: Surface): string => `coverage:${surface}:not-reported`,
  /** 面报了 unknown / partial / failed——看了，但没看全。 */
  coverageGap: (surface: Surface): string => `coverage:${surface}`,
  /** 有判读自己说「证据不够」。 */
  assessmentInsufficient: 'assessment:insufficient',
  /** 有判读说「有问题」，但严重度也定不了（`severity: 'unknown'`）。 */
  assessmentUngraded: 'assessment:ungraded',
} as const

/**
 * 理由码：这条决策**为什么**是这个动作。
 *
 * 与 `unknownInputs` 的分工：那个说「缺什么」，这个说「据此做了什么」。面板与审计读的是
 * 这一份，所以码要短、稳定、可以出现在一次 grep 里——不要往里塞动态内容。
 */
export const DECISION_REASON = {
  /** 这个边界拿到了拦截授权。 */
  denyAuthorized: 'deny-authorized',
  /** 有判读达到（或超过）授权门槛。 */
  findingAtOrAboveThreshold: 'finding-at-or-above-threshold',
  /** 有判读，但没到授权门槛。 */
  findingBelowThreshold: 'finding-below-threshold',
  /** 有判读，但这个边界没有拦截授权（只能报）。 */
  findingNotAuthorized: 'deny-not-authorized',
  /** 没有任何「有问题」的判读。 */
  noFinding: 'no-finding',
  /** 判读互相矛盾（有人说是、有人说不是）→ 交给人。 */
  assessmentDisputed: 'assessment-disputed',
  /** 存在未知输入；动作不能是 allow。 */
  unknownInputsPresent: 'unknown-inputs-present',
  /** 策略对这个未知输入显式授权失败关闭。 */
  failClosedOnUnknown: 'fail-closed-on-unknown',
  /** 范围内的面没有全部 covered（含明确不看的 excluded/unsupported）。 */
  scopeNotFullyCovered: 'scope-not-fully-covered',
} as const

export type DecisionReason = (typeof DECISION_REASON)[keyof typeof DECISION_REASON]

/**
 * 本边界的策略快照（`Decision.policyId` 指向它）。
 *
 * 三样都是必答的：回答哪些面、有没有拦截授权、哪些未知按失败关闭。缺一样就会有人
 * 「用默认值」把它补上——而这里的默认值无论怎么取，都会在某个边界上是错的。
 */
export interface DecisionPolicy {
  /**
   * 这次判定回答的是哪几个观测面。
   *
   * 必填且非空：不声明范围，`unknownInputs` 就没有分母——「九面里有三个不知道」与
   * 「两面里有一个不知道」是完全不同的两句话。范围之外的面不是「不知道」，是**不问**；
   * 那是策略的选择，由 `policyId` 记录，不冒充成未知。
   */
  readonly scope: readonly Surface[]
  /**
   * 已获授权的拦截门槛。`undefined` = 这个边界**没有**拦截授权，最多只能 `report`。
   *
   * 「发现了问题」与「获准拦截」是两件事（I07）：扫描器说 critical，不等于 vet 有权
   * 在装载路径上拒绝一个包。默认没有授权，是唯一不会自己给自己扩权的默认值。
   */
  readonly denyFrom?: AssessmentSeverity
  /**
   * 出现这些未知输入时按失败关闭处置（要求 `denyFrom` 已授权，否则无处可关）。
   *
   * 按**精确码**匹配，不做前缀匹配：`coverage:` 前缀匹配会让「某一次没看某个面」静默
   * 升级成「所有面缺了都拦」，那是一次误拦风暴的配方。
   */
  readonly failClosedOn?: readonly string[]
}

export interface DecisionInput {
  readonly id: string
  readonly subject: SubjectRef
  readonly boundary: Boundary
  readonly policyId: string
  readonly decidedAt: number
  readonly policy: DecisionPolicy
  /** 参与本次判定的评估。缺席 = 没有判读（不是「没有发现」——那要一条 `not_observed`）。 */
  readonly assessments?: readonly Assessment[]
  /**
   * 本边界上这些面的结论。缺席的面在 `scope` 内一律记 `coverage:<面>:not-reported`
   * ——漏报和没看是同一件事：都不知道。
   */
  readonly coverage?: readonly CoverageEntry[]
  /**
   * 调用方自己知道、但覆盖面表达不了的未知输入（如 `verdict:unrecognized` 这种协议漂移）。
   * 它们同样会让 `allow` 不可能出现，也正是 `failClosedOn` 能匹配到的东西。
   */
  readonly unknownInputs?: readonly string[]
}

/** `critical` 最高。`unknown` 排在最低且是负数：定不了严重度的判读不能靠排序挤过门槛。 */
const SEVERITY_RANK: Record<AssessmentSeverity, number> = {
  unknown: -1,
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** 只有这两种状态是在说「有问题」。`not_observed` 是「看了，没有」，不是未知。 */
function isAffirmative(assessment: Assessment): boolean {
  return assessment.state === 'finding' || assessment.state === 'corroborated'
}

/**
 * 读完所有输入，只做两件事：记下**缺什么**，把判读分成「有问题」与「自相矛盾」。
 *
 * 与动作阶梯分开，是因为这两件事的错法完全不同：这里错会把「不知道」记成「知道」，
 * 那里错会把「不知道」翻成「不行」。混在一个函数里，两种错都只能在一条长 if 里找。
 */
interface ReadInputs {
  readonly unknownInputs: string[]
  /** 范围内没有被 covered 的面数（含 excluded/unsupported：明确不看也是没看全）。 */
  readonly notCovered: number
  /** 可比较严重度的「有问题」判读。 */
  readonly findings: Assessment[]
  readonly disputed: number
}

function readInputs(input: DecisionInput): ReadInputs {
  const unknownInputs: string[] = []
  const addUnknown = (code: string): void => {
    if (!unknownInputs.includes(code)) unknownInputs.push(code)
  }
  // 调用方声明的排在最前：它们比覆盖面推出来的更具体（覆盖面只知道「这个面不满」）。
  for (const code of input.unknownInputs ?? []) addUnknown(code)

  // 同面多条取最差（与 `withUnknownDefaults` 同一条纪律）。用 Map 保序：同一份输入
  // 换个数组顺序不该改变结论。
  const rows = new Map<Surface, CoverageEntry>()
  for (const row of input.coverage ?? []) {
    const prev = rows.get(row.surface)
    rows.set(row.surface, prev === undefined ? row : { ...prev, result: worseCoverageResult(prev.result, row.result) })
  }

  let notCovered = 0
  for (const surface of input.policy.scope) {
    const row = rows.get(surface)
    if (row === undefined) {
      addUnknown(UNKNOWN_INPUT.coverageMissing(surface))
      notCovered += 1
      continue
    }
    if (row.result === 'unknown' || row.result === 'partial' || row.result === 'failed') {
      addUnknown(UNKNOWN_INPUT.coverageGap(surface))
    }
    if (row.result !== 'covered') notCovered += 1
  }

  const findings: Assessment[] = []
  let disputed = 0
  for (const assessment of input.assessments ?? []) {
    if (assessment.state === 'disputed') disputed += 1
    if (assessment.state === 'insufficient_evidence') addUnknown(UNKNOWN_INPUT.assessmentInsufficient)
    if (!isAffirmative(assessment)) continue
    if (assessment.severity === 'unknown') {
      // 「有问题，但定不了多严重」——它既进不了门槛比较，也不该被当成没问题。
      addUnknown(UNKNOWN_INPUT.assessmentUngraded)
      continue
    }
    findings.push(assessment)
  }

  return { unknownInputs, notCovered, findings, disputed }
}

/**
 * 动作阶梯：从上往下第一个成立的格子就是答案。
 *
 * 顺序不是随手排的——**授权先于矛盾，矛盾先于命中，命中先于未知**：
 * 已获授权且达标的问题不需要再问谁；矛盾时宁可多问一句；而「什么都没发现但有未知输入」
 * 必须落在 report 而不是 allow，这正是这个文件的主题。
 */
function pickAction(
  read: ReadInputs,
  policy: DecisionPolicy,
): { readonly action: PolicyAction; readonly reasons: string[] } {
  const denyFrom = policy.denyFrom
  const atOrAbove =
    denyFrom === undefined ? [] : read.findings.filter((a) => SEVERITY_RANK[a.severity] >= SEVERITY_RANK[denyFrom])
  const failClosedOn = (policy.failClosedOn ?? []).find((code) => read.unknownInputs.includes(code))
  const reasons: string[] = []
  // 所有出口都走它：理由数组是同一个可变对象，出口只决定动作。
  const done = (action: PolicyAction): { readonly action: PolicyAction; readonly reasons: string[] } => ({ action, reasons })

  if (denyFrom !== undefined && atOrAbove.length > 0) {
    reasons.push(DECISION_REASON.denyAuthorized, DECISION_REASON.findingAtOrAboveThreshold)
    return done('deny')
  }
  if (denyFrom !== undefined && failClosedOn !== undefined) {
    reasons.push(DECISION_REASON.denyAuthorized, DECISION_REASON.failClosedOnUnknown)
    return done('deny')
  }
  if (read.disputed > 0) {
    // 判读互相矛盾时不猜谁对：降级的代价是「多问一句」，猜错的代价是「按错的那条执行」。
    reasons.push(DECISION_REASON.assessmentDisputed)
    return done('require_review')
  }
  if (read.findings.length > 0) {
    reasons.push(denyFrom === undefined ? DECISION_REASON.findingNotAuthorized : DECISION_REASON.findingBelowThreshold)
    return done('report')
  }
  if (read.unknownInputs.length > 0) {
    // 什么也没发现，但确实有不知道的输入：这正是「report 按现状报告未知」。
    reasons.push(DECISION_REASON.noFinding)
    return done('report')
  }
  if (read.notCovered > 0) {
    // 没有未知，但有**明确不看**的面：同样是「不能说你没问题」，只是不知道的东西已经
    // 被承认过了（excluded/unsupported）。它拦 allow，但不冒充未知输入。
    reasons.push(DECISION_REASON.noFinding, DECISION_REASON.scopeNotFullyCovered)
    return done('report')
  }
  reasons.push(DECISION_REASON.noFinding)
  return done('allow')
}

/**
 * 按策略算出一条决策。
 *
 * 纯函数：同样的输入永远给同样的输出（`id`/`decidedAt` 由调用方给）。这是影子对照能成立
 * 的前提——两个实现如果需要读同一份可变状态，比较出来的差异就分不清是逻辑不同还是时序不同。
 */
export function buildDecision(input: DecisionInput): Decision {
  if (input.policy.scope.length === 0) {
    // 编程错误，不是运行时输入：没有范围就无从回答「缺什么」。宁可在这里炸，
    // 也不要产出一条 `unknownInputs: []` 的决策——那等于宣称「我什么都没缺」。
    throw new Error('vet: 决策策略没有声明观测面（policy.scope 为空）')
  }
  const read = readInputs(input)
  const { action, reasons } = pickAction(read, input.policy)
  // 契约 3：字段里有未知输入，理由里就一定有它（反过来没有危害——没有未知输入时不会推这条码）。
  // 放在这里统一推一次，避免阶梯上每个分支各记一遍、漏一个。
  const reasonCodes = read.unknownInputs.length > 0 ? [...reasons, DECISION_REASON.unknownInputsPresent] : reasons

  return {
    id: input.id,
    subject: input.subject,
    action,
    boundary: input.boundary,
    policyId: input.policyId,
    // 全部参与判读的评估，不只是「命中」的那几条：一条 `not_observed` 同样参与了
    // 「没有发现」这个结论，漏掉它会让 `assessmentIds` 变成一份「问题清单」。
    assessmentIds: [...new Set((input.assessments ?? []).map((a) => a.id))],
    reasonCodes: [...new Set(reasonCodes)],
    unknownInputs: read.unknownInputs,
    decidedAt: input.decidedAt,
  }
}
