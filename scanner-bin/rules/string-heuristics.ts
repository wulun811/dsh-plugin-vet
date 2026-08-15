import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'

const PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /return\s*[+ ]*\s*['"]?process/, desc: '拼接逃逸特征："return " + "process"' },
  { re: /getBuiltinModule/, desc: 'getBuiltinModule 引用' },
  { re: /child_process/, desc: 'child_process 引用' },
  { re: /require\(\s*['"](child_process|fs|net|vm)/, desc: 'require 危险内置模块' },
  { re: /process\.(env|exit|mainModule)/, desc: 'process 敏感成员引用' },
  { re: /String\.fromCharCode/, desc: '混淆特征 String.fromCharCode' },
  { re: /Buffer\.from\(.+base64\)/, desc: '混淆特征 Buffer.from(base64)' },
  { re: /atob\(/, desc: '混淆特征 atob(' },
  { re: /charCodeAt/, desc: '混淆特征 charCodeAt 循环' },
]

/**
 * R6 coarse string sweep. info/heuristic only — NEVER participates in verdict.
 */
/** Concatenation-aware surface: `"return " + "process"` spans two literals, so the
 * full expression text is tested too (source-adjacent heuristic). */
const CONCAT_RE = /\breturn\b[\s\S]*?\+[\s\S]*?\bprocess\b/

/** 混淆特征：出现在调用表达式文本（String.fromCharCode / atob / charCodeAt / Buffer.from base64），
 * 而非字符串字面量内容——矩阵测试发现的 R6 漏检面。 */
const OBFS_CALL_PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /String\.fromCharCode/, desc: '混淆特征 String.fromCharCode' },
  { re: /Buffer\.from\(.+base64\)/, desc: '混淆特征 Buffer.from(base64)' },
  { re: /atob\(/, desc: '混淆特征 atob(' },
  { re: /charCodeAt/, desc: '混淆特征 charCodeAt 循环' },
]

export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
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
        if (p.re.test(text)) push(p.desc, text, n)
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
  })
  return found
}
