/**
 * 回执（施工图 §5.2）：拦截到底有没有发生。
 *
 * 干预**不是状态机**——决策→执行→结果是一次性的，没有「回到某态」。硬写成状态机会暗示
 * 「决策会累积」，接下来就会有人给它建表、做持久化。这里真正要定的是：
 * **什么时候允许写 `applied`**。三个必要条件，缺一只能写别的。
 *
 * 为什么值得单独一个对象：0.4.x 说「已拦截」的全部依据是**我们自己写的日志**。
 * 一条报警只要发出去了，就没有任何东西能证伪「它其实没拦住」。`applied` 必须是可证伪的，
 * 否则「已阻止」只是一句自述（这是施工图 §11.2 的停止规则之一）。
 */
import type { Boundary, PolicyAction, Receipt, ReceiptResult } from './types.js'

export interface ReceiptInput {
  readonly id: string
  readonly boundary: Boundary
  readonly attemptedAt: number
  /** 决策动作。没有决策对象时为 `undefined`（N7 某些路径先抛后判，T4 的直接后果）。 */
  readonly action?: PolicyAction
  /**
   * 拦截点是否在**真实边界之前**。false = 我们是在副作用发生之后才拦的，
   * 那种情况无论计数如何都不能写 applied。
   */
  readonly beforeBoundary: boolean
  /** 原调用计数器：判定时刻与写回执时刻的两次读数。相等才说明原调用没进来。 */
  readonly forwardedBefore: number
  readonly forwardedAfter: number
  readonly operationId?: string
  /**
   * 关联的**决策对象** id。0.5.2 没有决策存储（N7 的 `BlockDecision` 是判定结果，不是
   * 落库的 Decision 对象），所以这里通常缺席——缺席是诚实的，编一个 id 才是伪造。
   * 字段留着是为了 0.6 真的建决策对象时能接上。
   */
  readonly decisionId?: string
}

/**
 * 三条守卫，按顺序判：
 *
 * 1. 没有决策对象 → `not_covered`（回执先于决策存在）
 * 2. 决策不是 `deny` → `not_requested`（allow / report 没有「施加」可言）
 * 3. 拦截点不在真实边界之前 → `not_covered`（我们没资格声称挡住）
 * 4. 原调用计数变了 → `failed`（这就是 C09：说了拦，实际放过去了）
 * 5. 其余才 `applied`，且必须带 `operationId`
 */
export function buildReceipt(input: ReceiptInput): Receipt {
  const base = {
    id: input.id,
    boundary: input.boundary,
    attemptedAt: input.attemptedAt,
  }
  // 只带调用方真的有的 decisionId，不拿回执自己的 id 顶上（那是两回事）。
  const withDecision = input.decisionId === undefined ? base : { ...base, decisionId: input.decisionId }
  if (input.action === undefined) return { ...base, result: 'not_covered' }
  if (input.action !== 'deny') return { ...withDecision, result: 'not_requested' }
  if (!input.beforeBoundary) return { ...withDecision, result: 'not_covered' }
  if (input.forwardedAfter !== input.forwardedBefore) return { ...withDecision, result: 'failed' }
  if (input.operationId === undefined) return { ...withDecision, result: 'unknown' }
  return { ...withDecision, result: 'applied', operationId: input.operationId }
}

/** 只有 `applied` 支持「已拦截」这句话。其余结果都必须换个说法。 */
export function supportsBlockedClaim(receipt: Receipt): boolean {
  return receipt.result === 'applied'
}

/** 结果的中文短语（报警文案与面板共用，避免两处各写一套）。 */
export function describeReceiptResult(result: ReceiptResult): string {
  switch (result) {
    case 'applied':
      return '已拦截且原调用未进入'
    case 'failed':
      return '判定为拦截但原调用已进入'
    case 'not_requested':
      return '策略未要求拦截'
    case 'not_covered':
      return '该边界未被覆盖'
    default:
      return '结果未知'
  }
}
