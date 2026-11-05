/**
 * 回执的读法（0.5.7）：把「最近一次拦截判定」变成可核对的一行。
 *
 * 回执本身是事实（`buildReceipt` 产出、oracle 记住），这里不复制事实，只回答两个面板需要、
 * 但事实对象里没有的问题：
 *
 * 1. **哪些边界有回执**——今天只有 fs 写入（N7）和工具调用两条路径会拦，其余边界要么不可拦
 *    （net/spawn 只有观测），要么观察不到（`pre_load`）。把这张清单写死在这里，比面板里
 *    散着三个 if 强：加一条拦截路径时，漏改这里只会少一行，不会画错一行。
 * 2. **这句话能不能说**——`claimsBlocked` 直接由 `supportsBlockedClaim` 算，不让前端自己
 *    再推一遍（两处推导就有两处可能在某个深夜不一致）。
 *
 * 为什么要有 TTL：回执说的是「上一次判定」，不是「现在的状态」。一周前的 `applied` 仍然是
 * 真话，但把它摆在面板上说「已拦下」，用户会以为刚刚拦下一次攻击。超过 TTL 就不显示——
 * **不显示是诚实的，标一个过期时间也行，但假装它是当前状态不行**。
 */
import type { Boundary, ReceiptResult } from '../domain/types.js'
import { supportsBlockedClaim } from '../domain/receipt.js'
import { lastReceiptOf } from './receipt-oracle.js'

/** 今天会产生回执的边界。顺序即面板顺序（先文件、后工具），不随时间跳动。 */
export const RECEIPT_BOUNDARIES: readonly Boundary[] = ['fs_write', 'tool_call']

/** 与报警同一天有效期：一天前的拦截记录还能说明「它会拦」，再久就只是历史。 */
export const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000

export interface ReceiptView {
  readonly boundary: Boundary
  readonly result: ReceiptResult
  /** `result === 'applied'`：只有它为真时，「已拦截」这句话才可以下。 */
  readonly claimsBlocked: boolean
  readonly operationId?: string
  readonly attemptedAt: number
}

/**
 * 当前可展示的回执（每个边界最近一条，按 `RECEIPT_BOUNDARIES` 排序）。
 *
 * 返回空数组表示「没有可展示的拦截判定」——**不是**「一切正常」。面板据此不渲染整块，
 * 而不是渲染一条绿色的「未拦截任何操作」。
 */
export function currentReceipts(now: number = Date.now(), ttlMs: number = RECEIPT_TTL_MS): ReceiptView[] {
  const out: ReceiptView[] = []
  for (const boundary of RECEIPT_BOUNDARIES) {
    const receipt = lastReceiptOf(boundary)
    if (receipt === undefined) continue
    if (now - receipt.attemptedAt > ttlMs) continue
    out.push({
      boundary: receipt.boundary,
      result: receipt.result,
      claimsBlocked: supportsBlockedClaim(receipt),
      ...(receipt.operationId !== undefined ? { operationId: receipt.operationId } : {}),
      attemptedAt: receipt.attemptedAt,
    })
  }
  return out
}
