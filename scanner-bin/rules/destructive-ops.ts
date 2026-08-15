import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'

/**
 * R11 destructive file operations (PLAN.md 14.2 R11). Cap at high (fail-open
 * caution; critical is reserved for escape classes). Signals:
 *  - fs delete ops (unlink/rm/rmdir + Sync) -> medium (cleanup is common; LLM
 *    audit reviews context); high when the path literal is sensitive.
 *  - fs write/rename ops onto a sensitive path literal -> high.
 *  - fs readdir over a sensitive directory literal -> medium.
 * Honest gaps: destructured/aliased fs calls (const { unlinkSync } = require('fs'))
 * and non-literal paths are not attributed; verified in the capability list.
 */
const SENSITIVE_PATH = /(\/etc\/|\/root\/|\/usr\/|\/boot\/|\/proc\/|\/sys\/|\/var\/(spool|run|cache|log)\/|\.ssh|\/.aws|\/.gnupg|crontab)/
const DELETE_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync'])
const READDIR_OPS = new Set(['readdir', 'readdirSync'])

/** fs.* or fs.promises.* call base name, else undefined. */
function fsBase(callee: ts.PropertyAccessExpression): string | undefined {
  const base = callee.expression
  if (ts.isIdentifier(base)) return base.text
  if (ts.isPropertyAccessExpression(base) && ts.isIdentifier(base.expression)) return base.expression.text + '.' + base.name.text
  return undefined
}

export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isCallExpression(n)) return
    const callee = n.expression
    if (!ts.isPropertyAccessExpression(callee)) return
    const op = callee.name.text
    const base = fsBase(callee)
    if (base === undefined || !base.startsWith('fs')) return
    const arg = n.arguments?.[0]
    let pathText: string | undefined
    if (arg !== undefined) {
      const sv = stringyValue(arg, sf)
      if (sv !== undefined) pathText = sv.text
    }
    const sensitive = pathText !== undefined && SENSITIVE_PATH.test(pathText)
    const push = (severity: 'high' | 'medium', message: string): void => {
      found.push({ rule: 'R11', severity, confidence: 'likely', message, evidence: n.getText(sf).slice(0, 200), line: lineOf(sf, n) })
    }
    if (DELETE_OPS.has(op)) {
      push(sensitive ? 'high' : 'medium', sensitive
        ? '删除敏感路径：fs.' + op + '(' + (pathText ?? '?') + ')'
        : '删除文件操作：fs.' + op + '（清理操作常见，交由 LLM 审计复核上下文）')
      return
    }
    if (WRITE_OPS.has(op) && sensitive) {
      push('high', '写入敏感路径：fs.' + op + '(' + (pathText ?? '?') + ')')
      return
    }
    if (READDIR_OPS.has(op) && sensitive) {
      push('medium', '遍历敏感目录：fs.' + op + '(' + (pathText ?? '?') + ')')
    }
  })
  return found
}
