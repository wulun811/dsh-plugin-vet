import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf, isShadowedForStringy } from '../ast.js'
import { tryDecodeLiteral } from '../decode.js'

/**
 * 逃逸字符串特征（R1 与 R2 的 new Function 升级共用同一判定——单源定义，两侧禁止各自
 * 漂移；round-22 起在 constructor-chain 定义、dynamic-exec 导入复用）。
 * 覆盖形态：
 * - return process / return globalThis.process / process['exit'] / process('x')（旧三态）
 * - return (process)（括号包裹）
 * - globalThis['process'] / global['process'] / window['process']（前缀元素访问：
 *   字符串体经 Function 构造后即取到 process 全局）
 */
export const ESCAPE_RE = /return\s+\w*(?:globalThis|global|window)?\.?\s*process\b|this\.constructor|process(?:\[|\()|return\s*\(\s*process\b|(?:globalThis|global|window)\s*\[\s*['"]process['"]\s*\]/

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
  const check = (n: ts.CallExpression | ts.NewExpression, callee: ts.Expression, args: readonly ts.Expression[] | undefined): void => {
    if (!isConstructorCallee(callee, sf)) return
    const arg = args?.[0]
    if (arg === undefined) return
    // round-15 review（R1/R2 N2 语料盲区）：stringyValue 只认静态字符串；base64/hex/
    // charCode 混淆的参数（atob('cmV0dXJuIHByb2Nlc3M=')、Buffer.from(...,'base64')）此前
    // 完全漏报——引擎已采集 decodedLiterals 且 R13/R7/R11 消费，这里对参数表达式直接
    // 走 tryDecodeLiteral 兜底（与 collectDecodedLiterals 同源判定）。
    const sv = stringyValue(arg, sf)
    const decoded = sv === undefined ? tryDecodeLiteral(arg, sf) : undefined
    const text = sv?.text ?? decoded?.text
    if (text === undefined) return
    if (!ESCAPE_RE.test(text)) return
    found.push({
      rule: 'R1',
      severity: 'critical',
      confidence: sv?.exact === true ? 'certain' : 'likely',
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
      // round-22（遮蔽修复）：别名解析必须认遮蔽——function f(c){ new c('return process') }
      // 里 c 是形参，遮蔽模块级 const c = x.constructor；此前无遮蔽检查 → 追踪到构造器
      // 来源误报 critical。isShadowedForStringy 语义：只认形参/块声明/catch 遮蔽，
      // 不把模块顶层同名声明当遮蔽（顶层别名解析是 R1 的正常主路径）。
      if (!isShadowedForStringy(e.text, e)) {
        const init = constInitializerOf(sf, e.text)
        if (init !== undefined && init !== e) {
          const r = resolve(init, depth + 1)
          if (r !== undefined) return r
        }
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