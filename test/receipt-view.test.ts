import { beforeEach, describe, expect, it } from 'vitest'
import { buildReceipt } from '../lib/domain/receipt.js'
import type { Boundary, Receipt } from '../lib/domain/types.js'
import { rememberReceipt, resetReceiptOracle } from '../lib/guard/receipt-oracle.js'
import { RECEIPT_TTL_MS, currentReceipts } from '../lib/guard/receipt-view.js'

/**
 * 回执视图（0.5.7）：面板那一栏「它到底拦住过没有」。
 *
 * 这里钉的是**读法**，不是回执本身的判据（判据在 domain/receipt 与 receipt-oracle 的测试里）。
 * 三条容易写错的地方：
 * - `claimsBlocked` 只能来自 `supportsBlockedClaim`，不能前端或这里再推一遍；
 * - 过期的回执不出现（它说的是历史，不是现在）；
 * - 没有回执是空数组，不是「正常」——面板据此整块不渲染。
 */

const NOW = 1_700_000_000_000

function receiptAt(boundary: Boundary, at: number, over: Partial<Parameters<typeof buildReceipt>[0]> = {}): Receipt {
  return buildReceipt({
    id: `r:${boundary}`,
    boundary,
    attemptedAt: at,
    action: 'deny',
    beforeBoundary: true,
    forwardedBefore: 0,
    forwardedAfter: 0,
    operationId: `${boundary}#1`,
    ...over,
  })
}

/** 记住一条回执并读回它的视图（三条「不可宣称」用例共用）。 */
function viewOf(over: Partial<Parameters<typeof buildReceipt>[0]>): ReturnType<typeof currentReceipts>[number] {
  rememberReceipt(receiptAt('tool_call', NOW, over))
  const [row] = currentReceipts(NOW)
  return row
}

describe('0.5.7：回执视图', () => {
  beforeEach(() => resetReceiptOracle())

  it('没有回执 → 空数组（不是「一切正常」）', () => {
    expect(currentReceipts(NOW)).toEqual([])
  })

  it('applied 才说「可下已拦截」，并带 operationId', () => {
    rememberReceipt(receiptAt('fs_write', NOW - 1000))
    expect(currentReceipts(NOW)).toEqual([
      { boundary: 'fs_write', result: 'applied', claimsBlocked: true, operationId: 'fs_write#1', attemptedAt: NOW - 1000 },
    ])
  })

  it('failed（判定拦截但原调用进来了）不可宣称已拦截', () => {
    const row = viewOf({ forwardedAfter: 1 })
    expect(row.result).toBe('failed')
    expect(row.claimsBlocked).toBe(false)
  })

  it('not_covered（拦截点在副作用之后）同样不可宣称', () => {
    const row = viewOf({ beforeBoundary: false })
    expect(row.result).toBe('not_covered')
    expect(row.claimsBlocked).toBe(false)
  })

  it('没有 operationId 时字段缺席（落 unknown，不编一个 id）', () => {
    const row = viewOf({ operationId: undefined })
    expect(row.result).toBe('unknown')
    expect('operationId' in row).toBe(false)
  })

  it('过期回执不出现；其余照旧', () => {
    rememberReceipt(receiptAt('fs_write', NOW - RECEIPT_TTL_MS - 1))
    rememberReceipt(receiptAt('tool_call', NOW - RECEIPT_TTL_MS + 1))
    const rows = currentReceipts(NOW)
    expect(rows.map((r) => r.boundary)).toEqual(['tool_call'])
  })

  it('顺序固定（先文件、后工具），不随时间跳动', () => {
    rememberReceipt(receiptAt('tool_call', NOW))
    rememberReceipt(receiptAt('fs_write', NOW - 5000))
    expect(currentReceipts(NOW).map((r) => r.boundary)).toEqual(['fs_write', 'tool_call'])
  })

  it('每个边界只留最近一条', () => {
    rememberReceipt(receiptAt('fs_write', NOW - 5000, { operationId: 'fs_write#1' }))
    rememberReceipt(receiptAt('fs_write', NOW - 100, { operationId: 'fs_write#2' }))
    const rows = currentReceipts(NOW)
    expect(rows).toHaveLength(1)
    expect(rows[0].operationId).toBe('fs_write#2')
  })
})
