import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, numberyValue, lineOf } from '../ast.js'

/**
 * R9 resource safety (PLAN.md §14.2 R9-1). Three A-tier signals:
 *
 * 1. unbounded allocation literal: `new Array(2**31)` / `Array(n)` /
 *    `Array.from({ length: n })` / `Buffer.alloc(huge)` — a statically known
 *    huge allocation (≥ ALLOC_LIMIT units).
 * 2. synchronous exit-less loop: `while(true)` / `for(;;)` whose body has no
 *    break/return/throw and no await — a busy-wait that wedges the event loop
 *    (module-top-level in npm packages stalls the whole harness process).
 *    A body with await is a likely resident service loop → advisory info only.
 * 3. unbounded child-process spawn inside an exit-less synchronous loop
 *    (`spawn`/`exec`/`execFile`/`fork`/`new Worker`) — fork-bomb pattern.
 *
 * Severity is capped at high by design (§14.1): critical would short-circuit
 * the LLM audit, and resource-class signals need LLM context review (a
 * `while(true){ await ... }` may be a legitimate service loop).
 */
const ALLOC_LIMIT = 100_000_000
const SPAWN_CALLS = new Set(['spawn', 'exec', 'execFile', 'fork'])
const SPAWN_NEWS = new Set(['Worker'])

/** Per-node exit signals of a loop body, skipping nested functions. */
interface ExitSignals {
  hasBreak: boolean
  hasReturn: boolean
  hasThrow: boolean
  hasAwait: boolean
}

function exitSignals(body: ts.Node): ExitSignals {
  const sig: ExitSignals = { hasBreak: false, hasReturn: false, hasThrow: false, hasAwait: false }
  const visit = (n: ts.Node, inInnerLoop: boolean): void => {
    if (ts.isFunctionLike(n)) return // nested functions don't affect this loop
    if (ts.isBreakStatement(n) && !inInnerLoop) sig.hasBreak = true
    if (ts.isReturnStatement(n)) sig.hasReturn = true
    if (ts.isThrowStatement(n)) sig.hasThrow = true
    if (ts.isAwaitExpression(n)) sig.hasAwait = true
    const nested = inInnerLoop || (ts.isIterationStatement(n, false) && n !== body)
    ts.forEachChild(n, child => visit(child, nested))
  }
  visit(body, false)
  return sig
}

/** Collect spawn-ish call/new nodes in a body tree (skipping nested functions). */
function collectSpawns(body: ts.Node, out: ts.Node[]): void {
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionLike(n)) return
    if (ts.isCallExpression(n)) {
      const callee = n.expression
      if (ts.isIdentifier(callee) && SPAWN_CALLS.has(callee.text)) out.push(n)
      else if (ts.isPropertyAccessExpression(callee) && SPAWN_CALLS.has(callee.name.text)) out.push(n)
    } else if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && SPAWN_NEWS.has(n.expression.text)) {
      out.push(n)
    }
    ts.forEachChild(n, visit)
  }
  visit(body)
}

/** `while(true)` or `for(;;)` — statically provable unbounded loops. */
function unboundedLoop(n: ts.Node): ts.WhileStatement | ts.ForStatement | undefined {
  if (ts.isWhileStatement(n) && n.expression.kind === ts.SyntaxKind.TrueKeyword) return n
  if (ts.isForStatement(n) && n.initializer === undefined && n.condition === undefined && n.incrementor === undefined) return n
  return undefined
}

/** R9-1 allocation checks: new Array / Array() / Array.from({length}) / Buffer.alloc*. */
function allocFinding(ruleText: string, n: ts.Node, sf: ts.SourceFile, amount: number): Finding | undefined {
  if (amount < ALLOC_LIMIT) return undefined
  return {
    rule: 'R9',
    severity: 'high',
    confidence: 'certain',
    message: `无界分配：${ruleText}（静态值 ${amount} ≥ ${ALLOC_LIMIT}，可致 OOM）`,
    evidence: n.getText(sf).slice(0, 200),
    line: lineOf(sf, n),
  }
}

function checkArrayAlloc(n: ts.CallExpression | ts.NewExpression, sf: ts.SourceFile, found: Finding[]): void {
  const callee = n.expression
  // Array(n) / new Array(n)
  if (ts.isIdentifier(callee)) {
    if (callee.text === 'Array') {
      const arg = n.arguments?.[0]
      if (arg !== undefined) {
        const v = numberyValue(arg, sf)
        if (v !== undefined) {
          const f = allocFinding('Array(n) 巨大数组', n, sf, v)
          if (f !== undefined) found.push(f)
        }
      }
    }
    return
  }
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.expression)) return
  const base = callee.expression.text
  const method = callee.name.text
  // Buffer.alloc(n) / Buffer.allocUnsafe(n)
  if (base === 'Buffer' && (method === 'alloc' || method === 'allocUnsafe')) {
    const arg = n.arguments?.[0]
    if (arg !== undefined) {
      const v = numberyValue(arg, sf)
      if (v !== undefined) {
        const f = allocFinding(`Buffer.${method}(n) 巨大缓冲`, n, sf, v)
        if (f !== undefined) found.push(f)
      }
    }
    return
  }
  // Array.from({ length: n })
  if (base === 'Array' && method === 'from') {
    const arg = n.arguments?.[0]
    if (arg !== undefined && ts.isObjectLiteralExpression(arg)) {
      for (const prop of arg.properties) {
        if (ts.isPropertyAssignment(prop) && prop.name.getText(sf) === 'length') {
          const v = numberyValue(prop.initializer, sf)
          if (v !== undefined) {
            const f = allocFinding('Array.from({ length: n }) 巨大数组', n, sf, v)
            if (f !== undefined) found.push(f)
          }
        }
      }
    }
  }
}

export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (ts.isCallExpression(n)) checkArrayAlloc(n, sf, found)
    if (ts.isNewExpression(n)) checkArrayAlloc(n, sf, found)
    const loop = unboundedLoop(n)
    if (loop === undefined) return
    const body = loop.statement
    const sig = exitSignals(body)
    if (sig.hasAwait) {
      found.push({
        rule: 'R9',
        severity: 'info',
        confidence: 'heuristic',
        message: '无出口常驻循环（含 await，可能是合法服务循环；交由 LLM 审计复核上下文）',
        evidence: loop.getText(sf).slice(0, 200),
        line: lineOf(sf, loop),
      })
      return
    }
    if (!sig.hasBreak && !sig.hasReturn && !sig.hasThrow) {
      found.push({
        rule: 'R9',
        severity: 'high',
        confidence: 'certain',
        message: '无出口同步循环（死循环/忙等：无 break/return/throw/await，可卡死宿主事件循环）',
        evidence: loop.getText(sf).slice(0, 200),
        line: lineOf(sf, loop),
      })
      const spawns: ts.Node[] = []
      collectSpawns(body, spawns)
      for (const s of spawns) {
        found.push({
          rule: 'R9',
          severity: 'high',
          confidence: 'likely',
          message: '无出口循环内启动子进程/worker（fork 炸弹模式）',
          evidence: s.getText(sf).slice(0, 200),
          line: lineOf(sf, s),
        })
      }
    }
  })
  return found
}
