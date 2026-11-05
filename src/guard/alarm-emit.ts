/**
 * 报警发射口：采集点 → 投影器 → `VetStatus`（施工图步骤 3）。
 *
 * 采集点今天直接写 8 个字段的告警字面量。这个口子把它们分成两半：
 * - **事实**由采集点给：看到了什么码、哪个主体、什么文案、什么目标；
 * - **形状**由注册表 + 投影器推：严重度（常量行）、来源通道、合并键、pluginHint。
 *
 * 过渡期设计（0.5.0 起）：`legacy` 字面量原样保留在此处，三种模式共用它——
 * - `legacy`：只记旧字面量（行为与 0.4.2 完全一致）
 * - `shadow`：记旧字面量，同时投影一遍并**逐字段比对**（差异只计数，不影响输出）
 * - `active`：记投影结果（**0.5.18 起的缺省**），同样做比对
 *
 * 为什么保留旧字面量而不是一次性删掉：R9 的答案是「投影出错怎么退」。留着它，回滚是一次
 * 配置改动而不是一次回滚代码。0.5.1 原计划删掉字面量，但那件事到今天还没做——理由变了：
 * 现在它是**等价的参照物**，删掉参照物就再也无法证明投影没走样。比对在三种模式下都跑，
 * 所以严格模式（CI）的保护不随缺省值变化而失效（F18）。
 */
import type { VetConfig } from '../config.js'
import type { VetAlarm, VetStatus } from './status.js'
import {
  type Attribution,
  type Evidence,
  type EvidenceOutcome,
  type SubjectRef,
  type Surface,
  type TrustOrigin,
} from '../domain/types.js'
import { projectAlarm } from '../domain/project.js'
import { specFor } from '../domain/kinds.js'
import type { AlarmSeverity } from '../domain/types.js'

export type DomainProjectionMode = VetConfig['domainProjection']

/** 采集点补充的事实。缺省按「本地扫描观察到的一次事实」处理。 */
export interface EmitFacts {
  readonly subject: SubjectRef
  readonly official?: boolean
  /** 合并键里不是主体名的分量（`esm-guard-coverage` 的 `official`）。 */
  readonly mergeSubject?: string
  /** 合并键第四段（`m1-contract-violation` 的字段名）。 */
  readonly mergeExtra?: string
  readonly source?: TrustOrigin
  readonly surface?: Surface
  readonly outcome?: EvidenceOutcome
  readonly attribution?: Attribution
  readonly producer?: string
  readonly sessionLog?: boolean
}

/** 投影比对忽略的字段：`count` 由 `VetStatus.record` 维护，不属于投影范围。 */
const COMPARED_FIELDS = ['id', 'severity', 'source', 'kind', 'message', 'target', 'pluginHint', 'sessionLog', 'mergeKey'] as const

let mismatchCount = 0
let firstMismatch: string | undefined

/** 影子期诊断：投影与旧字面量不等价的次数（严格模式下第一条即抛，这里用于测试断言）。 */
export function domainProjectionStats(): { readonly mismatches: number; readonly first?: string } {
  return firstMismatch === undefined ? { mismatches: mismatchCount } : { mismatches: mismatchCount, first: firstMismatch }
}

export function resetDomainProjectionStats(): void {
  mismatchCount = 0
  firstMismatch = undefined
}

/**
 * 严格模式：**任何**投影差异立即抛错。
 *
 * 存在的唯一理由是 CI——`VET_DOMAIN_SHADOW_STRICT=1` 跑全量测试，任何一条真实调用路径上
 * 的投影不等价都会让对应测试红。这比手写 22 组 fixture 强：fixture 只能证明「我想到的输入」，
 * 严格模式证明「测试覆盖到的全部输入」。
 */
function strictMode(): boolean {
  return process.env.VET_DOMAIN_SHADOW_STRICT === '1'
}

/**
 * 投影不等价（严格模式专用）。单独一个类，是为了让「观测失败必须静默」的 catch 能把它
 * 排除在外——`sink` 的顶层 catch 会吞掉一切（观测不许成为对插件的 DoS 面），
 * 但 CI 里的等价性断言被吞掉就成了**假绿**：面板行为照旧、测试全过、等价性已破。
 */
export class DomainProjectionMismatch extends Error {
  constructor(readonly detail: string) {
    super(`domain 投影与旧字面量不等价 —— ${detail}`)
    this.name = 'DomainProjectionMismatch'
  }
}

function diffAlarm(expected: VetAlarm, actual: VetAlarm): string[] {
  const out: string[] = []
  for (const field of COMPARED_FIELDS) {
    const e = expected[field]
    const a = actual[field]
    if (e !== a) out.push(`${field}: 旧=${JSON.stringify(e)} 投影=${JSON.stringify(a)}`)
  }
  return out
}

/**
 * 发射一条报警。
 *
 * @param status 调用方可能没有 status（部分判定路径在装配前跑），为 `undefined` 时静默返回。
 * @param legacy 旧字面量：它是**事实来源**（id / 文案 / 目标 / 采集点严重度都从它读，避免同一份
 *               事实写两遍），同时也是 `shadow` / `legacy` 两种模式的输出。
 * @param mode 缺省与 `config.domainProjection` 的缺省一致（0.5.18 起为 `active`）：调用方漏传时
 *             仍然比对，而不是悄悄退回 legacy——漏传应当表现为「CI 里红」，不是「等价性静默失效」。
 *             三种模式都比对，只有输出不同（见下方 `diff` 处的注释）。
 */
export function emitAlarm(status: VetStatus | undefined, legacy: VetAlarm, facts: EmitFacts, mode: DomainProjectionMode = 'active'): void {
  if (status === undefined) return
  if (mode === 'legacy') {
    status.record(legacy)
    return
  }
  const evidence: Evidence = {
    id: legacy.id,
    subject: facts.subject,
    source: facts.source ?? 'local_scan',
    producer: facts.producer ?? 'vet',
    code: legacy.kind,
    observedAt: legacy.at,
    outcome: facts.outcome ?? 'observed',
    attribution: facts.attribution ?? 'exact',
    ...(legacy.target !== undefined ? { target: legacy.target } : {}),
    ...(legacy.message !== undefined ? { message: legacy.message } : {}),
  }
  if (facts.surface !== undefined) (evidence as { surface?: Surface }).surface = facts.surface
  // 只有 `from-site` 的行才把采集点算好的严重度喂进去——否则常量行的比对就成了自证
  // （投影直接用旧值，影子里永远相等，这张表也就白写了）。
  const spec = specFor(legacy.kind, { official: facts.official })
  const projected = projectAlarm(evidence, {
    official: facts.official,
    // 未登记的 code 也算 from-site：投影器没有主张，就不该覆盖采集点的判断。
    severity: spec === undefined || spec.severity === 'from-site' ? (legacy.severity as AlarmSeverity) : undefined,
    mergeSubject: facts.mergeSubject,
    mergeExtra: facts.mergeExtra,
    sessionLog: facts.sessionLog ?? legacy.sessionLog,
  })
  /**
   * 比对在**两种模式**下都做，只有输出不同。
   *
   * 0.5.18：原先 `active` 在这里直接 `record(projected)` 就返回，比对整段跳过——于是
   * 一旦默认切到 `active`，`VET_DOMAIN_SHADOW_STRICT=1` 就再也抛不出东西，CI 的等价性
   * 保护静默失效，而且失效得无声无息（测试全绿，因为测试自己传 shadow）。
   * 严格模式的意义是"任何真实调用路径上的不等价都会红"，那它就不该取决于输出走哪条分支。
   *
   * 代价是 active 下多做一次 `diffAlarm`（9 个字段的 `!==`，不分配、不 IO）。等价性是这个
   * 过渡期存在的全部理由，为省这一次比对把它关掉，等于把保险丝换成指示灯。
   */
  const diff = diffAlarm(legacy, projected)
  if (diff.length > 0) {
    mismatchCount += 1
    const line = `${legacy.kind}（${legacy.id}）：${diff.join('；')}`
    if (firstMismatch === undefined) firstMismatch = line
    if (strictMode()) throw new DomainProjectionMismatch(line)
  }
  // active：输出投影结果；shadow：输出旧字面量（只比对不生效）。两者的差别仅在输出。
  status.record(mode === 'active' ? projected : legacy)
}
