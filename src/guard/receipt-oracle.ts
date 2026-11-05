/**
 * 回执的副作用 oracle（施工图 §5.2 第三条守卫）。
 *
 * 「原调用计数未增加」听起来是同义反复，除非计数器真的在别的地方递增：
 * - `noteAttempt(boundary)` 在**判定点**调用（一次可能被拦的调用）；
 * - `noteForwarded(token)` 在**真正调用原函数之前**调用。
 *
 * 两者分离才是 oracle。如果将来有人把 sink 挪到原调用之后，attempts 会涨而 forwarded 也涨，
 * `applied` 立刻变成 `failed`——这正是这套计数存在的意义：让「已阻止」可证伪。
 *
 * 0.5.5：计数从「全局两个整数」改成**每次判定一份 token**。原因是第二个边界（`tool_call`）
 * 的判定窗口里有 await（要先把工具代码送扫描器），两个并发调用共用全局计数会互相污染读数：
 * A 的回执会读到 B 的放行，把一次真的拦截判成 `failed`。token 让读数只属于这次判定，
 * 而置位点仍然在**调用原函数的那一行旁边**——这就够证伪了。
 */
import type { Boundary, Receipt } from '../domain/types.js'

/**
 * 一次走到判定点的调用。
 *
 * `forwarded` 由 `noteForwarded` 在调用原函数之前置位；回执读的就是它。它可以被伪造——
 * 但伪造点必须落在**调用原函数的那一行**，而不是判定点。这就是这套 oracle 的强度边界，
 * 写在这里免得下次有人以为它是密码学意义上的证明。
 */
export interface AttemptToken {
  readonly boundary: Boundary
  /** 该边界上的第几次判定（1 起）；回执的 operationId 由它构成。 */
  readonly id: number
  forwarded: boolean
}

const attemptSeq = new Map<Boundary, number>()
const lastReceipt = new Map<Boundary, Receipt>()

/** 一次可能被拦的调用到达判定点。 */
export function noteAttempt(boundary: Boundary): AttemptToken {
  const id = (attemptSeq.get(boundary) ?? 0) + 1
  attemptSeq.set(boundary, id)
  return { boundary, id, forwarded: false }
}

/** 原函数即将被调用（放行路径）。必须在调用点旁边调用，不能挪到判定点。 */
export function noteForwarded(token: AttemptToken): void {
  token.forwarded = true
}

/** 某边界上到目前的判定次数（诊断/测试用）。 */
export function attemptCount(boundary: Boundary): number {
  return attemptSeq.get(boundary) ?? 0
}

export function nextOperationId(token: AttemptToken): string {
  return `${token.boundary}#${token.id}`
}

export function rememberReceipt(receipt: Receipt): void {
  lastReceipt.set(receipt.boundary, receipt)
}

/** 某边界最近一次回执（测试与面板诊断用）。 */
export function lastReceiptOf(boundary: Boundary): Receipt | undefined {
  return lastReceipt.get(boundary)
}

export function resetReceiptOracle(): void {
  attemptSeq.clear()
  lastReceipt.clear()
}
