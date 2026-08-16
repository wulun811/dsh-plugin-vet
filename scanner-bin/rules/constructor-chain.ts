import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'

/**
 * R1 constructor-chain escape: `x.constructor("return process")` — the receiver's
 * constructor is the host Function, so the string body returns process.
 * Certain when the argument is a plain literal; likely when assembled.
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isCallExpression(n)) return
    const callee = n.expression
    // round-4/5（实测对抗）：元素访问形态 x['constructor'](...) 是恶意代码最常用写法，
    // 旧实现只认点访问 x.constructor(...)，x['constructor']('return ' + 'process') 完全漏检（verdict=clean）。
    // 两种形态都查：属性名取点访问的 name 或元素访问的字符串字面量。
    let ctorName: string | undefined
    if (ts.isPropertyAccessExpression(callee)) {
      ctorName = callee.name.text
    } else if (ts.isElementAccessExpression(callee)) {
      const key = callee.argumentExpression
      if (key !== undefined && (ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key))) {
        ctorName = key.text
      }
    }
    if (ctorName !== 'constructor') return
    const arg = n.arguments[0]
    if (arg === undefined) return
    const sv = stringyValue(arg, sf)
    if (sv === undefined) return
    if (!/return\s+\w*(?:globalThis|global|window)?\.?\s*process\b|this\.constructor|process(?:\[|\()/.test(sv.text)) return
    found.push({
      rule: 'R1',
      severity: 'critical',
      confidence: sv.exact ? 'certain' : 'likely',
      message: '构造器链逃逸：宿主函数的 constructor 指向宿主 Function，可借此返回 process',
      evidence: n.getText(sf).slice(0, 300),
      line: lineOf(sf, n),
    })
  })
  return found
}