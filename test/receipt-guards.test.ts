import { afterEach, describe, expect, it } from 'vitest'
import { buildReceipt, describeReceiptResult, supportsBlockedClaim } from '../lib/domain/receipt.js'
import {
  attemptCount,
  lastReceiptOf,
  nextOperationId,
  noteAttempt,
  noteForwarded,
  rememberReceipt,
  resetReceiptOracle,
} from '../lib/guard/receipt-oracle.js'

/**
 * 0.5.2 步骤 7 之二：回执的三条守卫。
 *
 * 要证的东西只有一句：**「已拦截」必须可证伪**。0.4.x 说「已阻止」的依据全是我们自己写的
 * 日志——发出去就没人能拆穿。这里把 applied 绑在三条同时成立的条件上，并且用真实的
 * attempt token 演示：一旦原调用进来了，applied 立刻塌成 failed。
 *
 * 0.5.5：oracle 从「全局 attempts/forwarded 两个整数」改成每次判定一份 token——
 * 第二个边界（tool_call）的判定窗口里有 await，全局计数会让并发调用互相污染读数。
 */

afterEach(() => resetReceiptOracle())

const base = {
  id: 'r-1',
  boundary: 'fs_write' as const,
  attemptedAt: 1_700_000_000_000,
  forwardedBefore: 0,
  forwardedAfter: 0,
  operationId: 'fs_write#1',
}

describe('三条守卫：什么时候才允许写 applied', () => {
  it('决策 deny + 拦截点在边界前 + 原调用计数未增 → applied', () => {
    const receipt = buildReceipt({ ...base, action: 'deny', beforeBoundary: true })
    expect(receipt.result).toBe('applied')
    expect(receipt.operationId).toBe('fs_write#1')
    expect(supportsBlockedClaim(receipt)).toBe(true)
  })

  it('C09 反例：计数变了 → failed（说了拦，实际放过去了）', () => {
    const receipt = buildReceipt({ ...base, action: 'deny', beforeBoundary: true, forwardedAfter: 1 })
    expect(receipt.result).toBe('failed')
    expect(supportsBlockedClaim(receipt)).toBe(false)
    expect(describeReceiptResult(receipt.result)).toContain('原调用已进入')
  })

  it('C10 反例：决策不是 deny → not_requested（allow/report 没有「施加」可言）', () => {
    for (const action of ['allow', 'report', 'require_review'] as const) {
      expect(buildReceipt({ ...base, action, beforeBoundary: true }).result).toBe('not_requested')
    }
  })

  it('拦截点不在真实边界之前 → not_covered（无论计数如何都不能声称挡住）', () => {
    expect(buildReceipt({ ...base, action: 'deny', beforeBoundary: false }).result).toBe('not_covered')
  })

  it('没有决策对象 → not_covered 且不带 decisionId（回执先于决策存在）', () => {
    const receipt = buildReceipt({ ...base, beforeBoundary: true })
    expect(receipt.result).toBe('not_covered')
    expect(receipt.decisionId).toBeUndefined()
  })

  it('不伪造 decisionId：没有决策对象时就不带这个字段（带上等于声称引用了一个不存在的对象）', () => {
    const withoutDecision = buildReceipt({ ...base, action: 'deny', beforeBoundary: true })
    expect(withoutDecision.result).toBe('applied')
    expect(withoutDecision.decisionId).toBeUndefined()
    const withDecision = buildReceipt({ ...base, action: 'deny', beforeBoundary: true, decisionId: 'dec-7' })
    expect(withDecision.decisionId).toBe('dec-7')
  })

  it('条件都够但没有 operationId → unknown（没有序号就无法核对）', () => {
    const { operationId: _drop, ...withoutOp } = base
    void _drop
    expect(buildReceipt({ ...withoutOp, action: 'deny', beforeBoundary: true }).result).toBe('unknown')
  })
})

describe('oracle：每次判定一份 token，让 applied 可证伪', () => {
  it('放行路径会置位 token，回执据此判 failed', () => {
    const attempt = noteAttempt('fs_write') // 走到判定点
    noteForwarded(attempt) // 原函数被调用（放行）
    const receipt = buildReceipt({
      ...base,
      action: 'deny',
      beforeBoundary: true,
      forwardedBefore: 0,
      forwardedAfter: attempt.forwarded ? 1 : 0,
      operationId: nextOperationId(attempt),
    })
    expect(receipt.result).toBe('failed')
  })

  it('拦截路径不置位 → applied', () => {
    const attempt = noteAttempt('fs_write')
    const receipt = buildReceipt({
      ...base,
      action: 'deny',
      beforeBoundary: true,
      forwardedBefore: 0,
      forwardedAfter: attempt.forwarded ? 1 : 0,
      operationId: nextOperationId(attempt),
    })
    expect(receipt.result).toBe('applied')
  })

  it('并发窗口：A 的放行不会把 B 的拦截判成 failed（0.5.5 把全局计数改成 token 的理由）', () => {
    // tool_call 的判定窗口里有 await（代码要先送扫描器）——两个调用会交错。
    // 旧实现读数来自全局 forwarded：B 写回执时会读到 A 的放行，把一次真的拦截判成 failed
    // （一个反向的诚实错误：明明拦住了却说没拦住）。token 让读数只属于这次判定。
    const a = noteAttempt('tool_call')
    const b = noteAttempt('tool_call')
    noteForwarded(a) // A 在自己窗口里放行，恰好落在 B 的判定窗口中间
    const bReceipt = buildReceipt({
      ...base,
      boundary: 'tool_call',
      action: 'deny',
      beforeBoundary: true,
      forwardedBefore: 0,
      forwardedAfter: b.forwarded ? 1 : 0,
      operationId: nextOperationId(b),
    })
    expect(bReceipt.result).toBe('applied')
  })

  it('操作序号按边界各自编号（面板/日志里「哪一次」不串台）', () => {
    const fs1 = noteAttempt('fs_write')
    const tool1 = noteAttempt('tool_call')
    const fs2 = noteAttempt('fs_write')
    expect(nextOperationId(fs1)).toBe('fs_write#1')
    expect(nextOperationId(tool1)).toBe('tool_call#1')
    expect(nextOperationId(fs2)).toBe('fs_write#2')
    expect(attemptCount('fs_write')).toBe(2)
    expect(attemptCount('pre_load')).toBe(0)
  })

  it('最近一次回执按边界留存，供面板/测试核验', () => {
    rememberReceipt(buildReceipt({ ...base, action: 'deny', beforeBoundary: true }))
    expect(lastReceiptOf('fs_write')!.result).toBe('applied')
    expect(lastReceiptOf('net')).toBeUndefined()
  })
})

describe('话术门禁', () => {
  it('只有 applied 支持「已拦截」', () => {
    const applied = buildReceipt({ ...base, action: 'deny', beforeBoundary: true })
    const failed = buildReceipt({ ...base, action: 'deny', beforeBoundary: true, forwardedAfter: 1 })
    expect(supportsBlockedClaim(applied)).toBe(true)
    expect(supportsBlockedClaim(failed)).toBe(false)
  })

  it('每种结果都有可读短语，没有一种落到「未定义」', () => {
    for (const result of ['applied', 'failed', 'not_requested', 'not_covered', 'unknown'] as const) {
      expect(describeReceiptResult(result)).not.toBe('')
      expect(describeReceiptResult(result)).not.toContain('未定义')
    }
  })
})
