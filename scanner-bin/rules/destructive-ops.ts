import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'
import { moduleBindings } from '../capability.js'

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

/** fs.* / fs.promises.* / require('fs').op / 解构绑定标识符调用 的 fs 面判定。
 * P2-6：旧实现用 base.startsWith('fs')——自定义对象 fsmap.rm() / fsUtil.writeFile() 会被误判成 fs 调用。
 * 只认字面量 'fs' 与 'fs.promises'（编译器可确认的模块绑定，不猜变量名）。
 * round-16：补 require('fs')/require('fs/promises') 直调形态与 moduleBindings 解构/别名绑定
 * （`const { unlinkSync } = require('fs')` 的裸标识符调用；capability 层早已认，规则层对齐）。 */
function fsBase(callee: ts.PropertyAccessExpression, fsRefs: Set<string>): string | undefined {
  const base = callee.expression
  if (ts.isIdentifier(base) && (base.text === 'fs' || fsRefs.has(base.text))) return 'fs'
  if (ts.isPropertyAccessExpression(base)
    && ts.isIdentifier(base.expression) && base.expression.text === 'fs'
    && base.name.text === 'promises') return 'fs.promises'
  if (ts.isCallExpression(base)) {
    const c = base.expression
    if (ts.isIdentifier(c) && c.text === 'require' && base.arguments.length > 0) {
      const spec = stringyValue(base.arguments[0], base.getSourceFile())
      const bare = spec?.text.replace(/^node:/, '')
      if (bare === 'fs' || bare === 'fs/promises') return bare === 'fs' ? 'fs' : 'fs.promises'
    }
  }
  return undefined
}

export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  const { fsRefs } = moduleBindings(sf)
  // round-16：文件是否真的绑定 fs（解构/别名/绑定/require 直调都算）——N2 语料门控用，
  // 与 R20 的 hasCpUsage 同款"文件级双信号"：纯解码串（如 base64 配置数据）+ 无任何 fs
  // 足迹的文件不再凭语料判红（实证 FP：解码含 '/etc/passwd' 的数据串 → high → suspicious）。
  let directRequireFs = false
  walk(sf, n => {
    if (!ts.isCallExpression(n)) return
    if (ts.isIdentifier(n.expression) && n.expression.text === 'require' && n.arguments.length > 0) {
      const spec = stringyValue(n.arguments[0], sf)
      const bare = spec?.text.replace(/^node:/, '')
      if (bare === 'fs' || bare === 'fs/promises') {
        directRequireFs = true
        return
      }
    }
    // 裸标识符调用（解构/别名绑定后的 unlinkSync('/etc/...')）
    if (ts.isIdentifier(n.expression) && fsRefs.has(n.expression.text)) {
      const op = n.expression.text
      const arg = n.arguments?.[0]
      let pathText: string | undefined
      if (arg !== undefined) {
        const sv = stringyValue(arg, sf)
        if (sv !== undefined) pathText = sv.text
      }
      const sensitive = pathText !== undefined && SENSITIVE_PATH.test(pathText)
      if (DELETE_OPS.has(op)) {
        found.push({ rule: 'R11', severity: sensitive ? 'high' : 'medium', confidence: 'likely',
          message: (sensitive ? '删除敏感路径：' : '删除文件操作：') + op + '(' + (pathText ?? '?') + ')',
          evidence: n.getText(sf).slice(0, 200), line: lineOf(sf, n) })
        return
      }
      if (WRITE_OPS.has(op) && sensitive) {
        found.push({ rule: 'R11', severity: 'high', confidence: 'likely',
          message: '写入敏感路径：' + op + '(' + (pathText ?? '?') + ')',
          evidence: n.getText(sf).slice(0, 200), line: lineOf(sf, n) })
      }
    }
  })
  walk(sf, n => {
    if (!ts.isCallExpression(n)) return
    const callee = n.expression
    if (!ts.isPropertyAccessExpression(callee)) return
    const op = callee.name.text
    const base = fsBase(callee, fsRefs)
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
  // round-16 门控：文件必须实际绑定 fs（直接语义相关），否则跳过、不判红
  const hasFsUsage = fsRefs.size > 0 || directRequireFs
  if (hasFsUsage) {
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
  }
  return found
}
