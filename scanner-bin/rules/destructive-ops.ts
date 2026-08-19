import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'

/**
 * R11 destructive file operations . Cap at high (fail-open
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
// P2-6：写集与 T2 对齐——copyFile/cp/createWriteStream/truncate 此前静态层漏检
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream', 'truncate', 'truncateSync'])
const READDIR_OPS = new Set(['readdir', 'readdirSync'])

/** fs.* or fs.promises.* call base name, else undefined.
 * P2-6：旧实现用 base.startsWith('fs')——自定义对象 fsmap.rm() / fsUtil.writeFile() 会被误判成 fs 调用。
 * 只认字面量 'fs' 与 'fs.promises'（编译器可确认的模块绑定，不猜变量名）。 */
function fsBase(callee: ts.PropertyAccessExpression): string | undefined {
  const base = callee.expression
  if (ts.isIdentifier(base) && base.text === 'fs') return 'fs'
  if (ts.isPropertyAccessExpression(base)
    && ts.isIdentifier(base.expression) && base.expression.text === 'fs'
    && base.name.text === 'promises') return 'fs.promises'
  return undefined
}

export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
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
  // N2：解码语料中的敏感路径（base64/hex/charCode 还原的路径——代码刻意隐藏 fs 目标）
  for (const d of ctx.decodedLiterals ?? []) {
    if (SENSITIVE_PATH.test(d.text)) {
      found.push({
        rule: 'R11',
        severity: 'high',
        confidence: 'likely',
        decodedFrom: d.method,
        message: '解码还原的敏感路径（' + d.method + '）：' + d.text.slice(0, 120),
        evidence: d.text.slice(0, 200),
        file: d.file,
        line: d.line,
      })
    }
  }
  return found
}
