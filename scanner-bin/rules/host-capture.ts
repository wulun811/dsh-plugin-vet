import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, isShadowed, lineOf } from '../ast.js'

/** Host closures exposed to sandbox code: workflow globals + dynamic-package primitives. */
const ESCAPE_SOURCES = new Set([
  'agent', 'parallel', 'pipeline', 'phase', 'log',
  'TextEncoder', 'TextDecoder', 'btoa', 'atob',
])

/**
 * R4 host-closure capture: an escape source whose `.constructor` is read
 * (or that feeds Object.getPrototypeOf) reaches the host Function/chain.
 * Plain calls (log('x'), agent(fn)) are legitimate and never flagged.
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isIdentifier(n) || !ESCAPE_SOURCES.has(n.text)) return
    if (isShadowed(n.text, n)) return
    const parent = n.parent
    if (parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.expression === n && parent.name.text === 'constructor') {
      found.push({
        rule: 'R4',
        severity: 'critical',
        confidence: 'certain',
        message: `宿主闭包捕获：${n.text}.constructor 可达宿主 Function（构造器链逃逸源）`,
        evidence: parent.getText(sf).slice(0, 300),
        line: lineOf(sf, n),
      })
      return
    }
    if (parent !== undefined && ts.isCallExpression(parent) && parent.arguments[0] === n) {
      const callee = parent.expression
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'getPrototypeOf') {
        found.push({
          rule: 'R4',
          severity: 'critical',
          confidence: 'certain',
          message: `宿主闭包捕获：Object.getPrototypeOf(${n.text}) 原型链可达宿主`,
          evidence: parent.getText(sf).slice(0, 300),
          line: lineOf(sf, n),
        })
      }
    }
  })
  return found
}
