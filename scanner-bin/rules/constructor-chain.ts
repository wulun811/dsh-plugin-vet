import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'

/**
 * R1 constructor-chain escape: `x.constructor("return process")` — the receiver's
 * constructor is the host Function, so the string body returns process.
 * Certain when the argument is a plain literal; likely when assembled.
 *
 * round-5/6（外部实测）：覆盖三种调用形态——
 *   1) CallExpression 点访问：x.constructor('return process')
 *   2) CallExpression 元素访问：x['constructor']('return ' + 'process')
 *   3) NewExpression：new (globalThis.constructor.constructor)('return process')()
 *      ——constructor 本来就是拿来 new 的，此形态比普通调用更常见；
 *      新表达式 callee 支持属性访问链（globalThis.constructor.constructor）、
 *      元素访问、以及 const 绑定别名（const c = x.constructor; new c(...)）。
 */
export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  const ESCAPE_RE = /return\s+\w*(?:globalThis|global|window)?\.?\s*process\b|this\.constructor|process(?:\[|\()/

  const check = (n: ts.CallExpression | ts.NewExpression, callee: ts.Expression, args: readonly ts.Expression[] | undefined): void => {
    if (!isConstructorCallee(callee, sf)) return
    const arg = args?.[0]
    if (arg === undefined) return
    const sv = stringyValue(arg, sf)
    if (sv === undefined) return
    if (!ESCAPE_RE.test(sv.text)) return
    found.push({
      rule: 'R1',
      severity: 'critical',
      confidence: sv.exact ? 'certain' : 'likely',
      message: ts.isNewExpression(n)
        ? '构造器链逃逸（new 形态）：new (...constructor...) 指向宿主 Function，可借此返回 process'
        : '构造器链逃逸：宿主函数的 constructor 指向宿主 Function，可借此返回 process',
      evidence: n.getText(sf).slice(0, 300),
      line: lineOf(sf, n),
    })
  }

  walk(sf, n => {
    if (ts.isCallExpression(n)) {
      check(n, n.expression, n.arguments)
      return
    }
    if (ts.isNewExpression(n)) {
      check(n, n.expression, n.arguments)
    }
  })
  return found
}

/**
 * callee 是否最终指向 .constructor（含元素访问与 const 别名绑定）：
 * - x.constructor / x['constructor'] / globalThis.constructor.constructor（链尾是 constructor）
 * - const c = x.constructor; new c(...)——标识符经 initializerMap 追踪到构造器来源
 */
function isConstructorCallee(callee: ts.Expression, sf: ts.SourceFile): boolean {
  const nameOf = (e: ts.Expression): string | undefined => {
    if (ts.isPropertyAccessExpression(e)) return e.name.text
    if (ts.isElementAccessExpression(e)) {
      const key = e.argumentExpression
      if (key !== undefined && (ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key))) return key.text
    }
    return undefined
  }
  // 递归解析：属性/元素访问链取链尾名；标识符追踪 const 初始化
  const resolve = (e: ts.Expression, depth: number): { tailName: string; seenCtor: boolean } | undefined => {
    if (depth > 8) return undefined
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const name = nameOf(e)
      if (name === undefined) return undefined
      const base = resolve(e.expression, depth + 1)
      // globalThis.constructor.constructor：链上有 constructor 即视为构造器链
      return { tailName: name, seenCtor: name === 'constructor' || (base?.seenCtor ?? false) }
    }
    if (ts.isIdentifier(e)) {
      // const c = x.constructor; new c(...) —— 追踪到构造器来源
      const init = constInitializerOf(sf, e.text)
      if (init !== undefined && init !== e) {
        const r = resolve(init, depth + 1)
        if (r !== undefined) return r
      }
      return { tailName: e.text, seenCtor: false }
    }
    if (ts.isParenthesizedExpression(e)) return resolve(e.expression, depth + 1)
    return undefined
  }
  const r = resolve(callee, 0)
  return r?.seenCtor ?? false
}

/** 从源文件收集 const/let 初始化映射（首个声明优先，与 stringyValue 同口径）。 */
const initMaps = new WeakMap<ts.SourceFile, Map<string, ts.Expression>>()
function constInitializerOf(sf: ts.SourceFile, name: string): ts.Expression | undefined {
  let map = initMaps.get(sf)
  if (map === undefined) {
    map = new Map()
    const m = map // 闭包内 narrowing 丢失，捕获局部引用
    walk(sf, n => {
      if (!ts.isVariableDeclaration(n) || n.initializer === undefined) return
      if (ts.isIdentifier(n.name) && !m.has(n.name.text)) m.set(n.name.text, n.initializer)
    })
    initMaps.set(sf, map)
  }
  return map.get(name)
}