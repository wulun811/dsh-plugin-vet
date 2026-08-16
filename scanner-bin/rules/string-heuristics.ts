import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'

const PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /return\s*[+ ]*\s*['"]?process/, desc: '拼接逃逸特征："return " + "process"' },
  { re: /getBuiltinModule/, desc: 'getBuiltinModule 引用' },
  { re: /child_process/, desc: 'child_process 引用' },
  { re: /require\(\s*['"](child_process|fs|net|vm)/, desc: 'require 危险内置模块' },
  { re: /process\.(env|exit|mainModule)/, desc: 'process 敏感成员引用' },
]

/**
 * R6 coarse string sweep. info/heuristic only — NEVER participates in verdict.
 */
/** Concatenation-aware surface: `"return " + "process"` spans two literals, so the
 * full expression text is tested too (source-adjacent heuristic). */
const CONCAT_RE = /\breturn\b[\s\S]*?\+[\s\S]*?\bprocess\b/

/**
 * 混淆特征（round-7，P4b）：需要「组合证据」才报——独立出现的 charCodeAt/fromCharCode/
 * atob 是终端协议解析（ANSI 转义序列、字节处理）的常规代码，42 条系统误报（dsh-tui
 * parse-keypress/csi/osc/stringWidth 实测）。仅当同文件内同时存在动态执行信号
 * （eval/Function/new Function/vm 系列/构造器捕获）才作为混淆提示输出。
 */
const OBFS_CALL_PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /String\.fromCharCode/, desc: '混淆特征 String.fromCharCode' },
  { re: /Buffer\.from\(.+base64\)/, desc: '混淆特征 Buffer.from(base64)' },
  { re: /atob\(/, desc: '混淆特征 atob(' },
  { re: /charCodeAt/, desc: '混淆特征 charCodeAt 循环' },
]

const OBFS_LITERAL_PATTERNS: { re: RegExp; desc: string }[] = OBFS_CALL_PATTERNS

/** 剥掉外层括号。 */
function unwrapParens(e: ts.Expression): ts.Expression {
  let cur = e
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression
  return cur
}

/** 同文件内是否存在动态执行信号（与 R2 同口径的节点形态，粗检即可）。 */
function hasDynamicExecSignal(sf: ts.SourceFile): boolean {
  let found = false
  walk(sf, n => {
    if (found) return
    if (ts.isCallExpression(n)) {
      const callee = unwrapParens(n.expression)
      if (ts.isIdentifier(callee) && (callee.text === 'eval' || callee.text === 'Function')) { found = true; return }
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'constructor') {
        const base = unwrapParens(callee.expression)
        if (ts.isArrowFunction(base) || ts.isFunctionExpression(base)) { found = true; return }
      }
      if (ts.isPropertyAccessExpression(callee)) {
        const base = unwrapParens(callee.expression)
        if (ts.isIdentifier(base) && base.text === 'vm'
          && (callee.name.text === 'runInContext' || callee.name.text === 'runInNewContext')) { found = true; return }
      }
      return
    }
    if (ts.isNewExpression(n)) {
      const expr = unwrapParens(n.expression)
      if (ts.isIdentifier(expr) && (expr.text === 'Function' || expr.text === 'AsyncFunction')) { found = true }
    }
  })
  return found
}

export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  const obfHits: { desc: string; text: string; n: ts.Node }[] = []
  const push = (desc: string, text: string, n: ts.Node): void => {
    found.push({
      rule: 'R6',
      severity: 'info',
      confidence: 'heuristic',
      message: `字符串特征：${desc}`,
      evidence: text.slice(0, 200),
      line: lineOf(sf, n),
    })
  }
  const pushObf = (desc: string, text: string, n: ts.Node): void => {
    obfHits.push({ desc, text, n })
  }
  walk(sf, n => {
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const text = n.getText(sf)
      if (CONCAT_RE.test(text)) push('拼接逃逸特征：return + process', text, n)
      return
    }
    if (ts.isCallExpression(n)) {
      // 调用表达式文本命中混淆特征（矩阵发现的漏检面）
      const text = n.getText(sf)
      for (const p of OBFS_CALL_PATTERNS) {
        if (p.re.test(text)) pushObf(p.desc, text, n)
      }
      return
    }
    if (!ts.isStringLiteral(n) && !ts.isNoSubstitutionTemplateLiteral(n) && !ts.isTemplateExpression(n)) return
    const text = ts.isTemplateExpression(n)
      ? n.head.text + n.templateSpans.map(s => s.literal.text).join('')
      : n.text
    for (const p of PATTERNS) {
      if (p.re.test(text)) push(p.desc, text, n)
    }
    for (const p of OBFS_LITERAL_PATTERNS) {
      if (p.re.test(text)) pushObf(p.desc, text, n)
    }
  })
  // round-7（P4b）：混淆特征仅在有动态执行组合证据时输出（见模块注释）
  if (obfHits.length > 0 && hasDynamicExecSignal(sf)) {
    for (const h of obfHits) push(h.desc, h.text, h.n)
  }
  return found
}
