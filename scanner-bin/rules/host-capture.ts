import ts from 'typescript'
import type { Finding, RuleContext, Severity } from '../protocol.js'
import { walk, isShadowed, lineOf } from '../ast.js'

/** Host closures exposed to sandbox code: workflow globals + dynamic-package primitives. */
const ESCAPE_SOURCES = new Set([
  'agent', 'parallel', 'pipeline', 'phase', 'log',
  'TextEncoder', 'TextDecoder', 'btoa', 'atob',
])

/**
 * 宿主全局内置对象（有 prototype 的构造器/对象，round-7 P1）。对它们 prototype 成员
 * 的覆盖赋值 = 污染宿主运行时全局——沙箱里可达宿主，插件包加载进宿主时同样污染宿主。
 */
const HOST_PROTOTYPES = new Set([
  'Object', 'Array', 'String', 'Number', 'Boolean', 'Function', 'Symbol', 'BigInt',
  'RegExp', 'Date', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet',
  'Error', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'AggregateError',
  'ArrayBuffer', 'SharedArrayBuffer', 'DataView',
  'Uint8Array', 'Uint8ClampedArray', 'Int8Array', 'Uint16Array', 'Int16Array',
  'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
  'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams',
  'AbortController', 'AbortSignal', 'Event', 'EventTarget', 'CustomEvent',
  'MessageChannel', 'MessagePort', 'Buffer',
])

/** 剥掉外层括号。 */
function unwrapParens(e: ts.Expression): ts.Expression {
  let cur = e
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression
  return cur
}

/** X.prototype（或 globalThis.X.prototype / (X).prototype）中的宿主内置名；非内置或被遮蔽 → undefined。 */
function hostProtoOwner(expr: ts.Expression): string | undefined {
  let cur = unwrapParens(expr)
  if (ts.isPropertyAccessExpression(cur) && ts.isIdentifier(cur.expression) && cur.expression.text === 'globalThis') {
    cur = cur.name
  }
  if (!ts.isIdentifier(cur) || !HOST_PROTOTYPES.has(cur.text)) return undefined
  if (isShadowed(cur.text, cur)) return undefined
  return cur.text
}

/** 是否 `X.prototype` 形态（含括号包裹）。 */
function isProtoAccess(n: ts.Expression): boolean {
  const cur = unwrapParens(n)
  return ts.isPropertyAccessExpression(cur) && cur.name.text === 'prototype'
}

/** round-7（P1）：宿主全局原型污染——赋值/defineProperty 覆盖 <内置>.prototype 成员。 */
function checkProtoMutation(sf: ts.SourceFile, ctx: RuleContext, found: Finding[]): void {
  const severity: Severity = ctx.request.kind === 'code' ? 'critical'
    : ctx.request.targetKind === 'generic' ? 'info' // 通用包里的 polyfill（core-js 类）是常见合法代码
    : 'high'
  const note = ctx.request.kind === 'code' ? '（沙箱内可达宿主运行时）' : '（包加载进宿主时污染宿主全局）'

  const push = (owner: string, member: string, evidence: ts.Node): void => {
    found.push({
      rule: 'R4',
      severity,
      confidence: 'likely',
      message: '宿主全局原型污染：' + owner + '.prototype' + member + ' 覆盖赋值' + note,
      evidence: evidence.getText(sf).slice(0, 300),
      line: lineOf(sf, evidence),
    })
  }

  walk(sf, n => {
    // 赋值形态：X.prototype = ...（整体替换） / X.prototype.member = ... / X.prototype['member'] = ...
    // （TS AST 中赋值是 operatorToken 为 = 的 BinaryExpression）
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = unwrapParens(n.left)
      if (ts.isPropertyAccessExpression(left) && left.name.text === 'prototype') {
        const owner = hostProtoOwner(left.expression)
        if (owner !== undefined) push(owner, '', n)
        return
      }
      if (ts.isPropertyAccessExpression(left) || ts.isElementAccessExpression(left)) {
        const base = unwrapParens(left.expression)
        if (isProtoAccess(base)) {
          const owner = hostProtoOwner((unwrapParens(base) as ts.PropertyAccessExpression).expression)
          if (owner !== undefined) {
            const member = ts.isPropertyAccessExpression(left) ? '.' + left.name.text
              : '[' + left.argumentExpression.getText(sf).slice(0, 60) + ']'
            push(owner, member, n)
          }
        }
      }
      return
    }
    // defineProperty/defineProperties 形态：Object.defineProperty(X.prototype, 'name', {...})
    if (ts.isCallExpression(n)) {
      const callee = unwrapParens(n.expression)
      if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'defineProperty' && callee.name.text !== 'defineProperties') return
      const base = unwrapParens(callee.expression)
      if (!ts.isIdentifier(base) || base.text !== 'Object') return
      const arg0 = n.arguments[0]
      if (arg0 === undefined || !isProtoAccess(arg0)) return
      const owner = hostProtoOwner((unwrapParens(arg0) as ts.PropertyAccessExpression).expression)
      if (owner === undefined) return
      const arg1 = n.arguments[1]
      const member = arg1 !== undefined && (ts.isStringLiteral(arg1) || ts.isNoSubstitutionTemplateLiteral(arg1))
        ? '.' + arg1.text
        : (arg1 !== undefined ? '[' + arg1.getText(sf).slice(0, 60) + ']' : '')
      push(owner, member, n)
    }
  })
}

/**
 * R4 host-closure capture: an escape source whose `.constructor` is read
 * (or that feeds Object.getPrototypeOf) reaches the host Function/chain.
 * Plain calls (log('x'), agent(fn)) are legitimate and never flagged.
 * round-7（P1）：新增宿主全局原型污染检测（两种形态均覆盖：闭包捕获仅沙箱 code 模式；
 * 原型污染在 files 模式也判——插件包加载进宿主即污染宿主全局）。
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  // F12：R4 闭包捕获只针对沙箱（code 模式）——workflow globals（agent/log/phase 等）只存在于
  // 沙箱运行时；files 模式（npm 包/插件源码）里它们是未定义自由变量，
  // log.constructor === Object 这类探测是常见合法代码，报 critical 是误报。
  if (ctx.request.kind === 'code') {
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
  }
  checkProtoMutation(sf, ctx, found)
  return found
}
