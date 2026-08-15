import ts from 'typescript'
import type { Finding, RuleContext, Severity, Confidence } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'

const ESCAPE_RE = /return\s+\w*process|this\.constructor|process\./
const VM_EXEC = new Set(['runInContext', 'runInNewContext'])

/**
 * R2 dynamic execution: eval / Function / new Function / new AsyncFunction /
 * (async()=>{}).constructor capture / vm.runInContext|runInNewContext /
 * dynamic import() / require. Severity splits by scenario: require is a real
 * capability reach in npm packages (files), a trapped dead end in the sandbox (code).
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []

  const add = (n: ts.Node, severity: Severity, confidence: Confidence, message: string): void => {
    found.push({ rule: 'R2', severity, confidence, message, evidence: n.getText(sf).slice(0, 300), line: lineOf(sf, n) })
  }

  walk(sf, n => {
    if (ts.isCallExpression(n)) {
      checkCall(n, sf, ctx, add)
      return
    }
    if (ts.isNewExpression(n)) {
      checkNew(n, sf, add)
      return
    }
    if (isConstructorCapture(n)) {
      add(n, 'high', 'certain', '(async()=>{}).constructor 捕获（可达宿主 Function）')
    }
  })
  return found
}

function checkCall(n: ts.CallExpression, sf: ts.SourceFile, ctx: RuleContext, add: (n: ts.Node, sev: Severity, conf: Confidence, msg: string) => void): void {
  const callee = n.expression
  const name = ts.isIdentifier(callee) ? callee.text : undefined
  if (name === 'eval') {
    add(n, 'high', 'certain', 'eval 动态执行（任意代码执行）')
    return
  }
  if (name === 'Function') {
    add(n, 'high', 'certain', 'Function() 动态构造函数')
    return
  }
  if (name === 'import') {
    add(n, 'medium', 'likely', '动态 import()')
    return
  }
  if (name === 'require') {
    // files: npm 包内 require 是真实 Node 能力触达 → high；code(沙箱): 被 trap 的通道 → medium
    if (ctx.request.kind === 'files') {
      add(n, 'high', 'likely', 'require() 动态模块加载（npm 包内真实能力触达）')
    } else if (!isTopLevelConstRequire(n)) {
      add(n, 'medium', 'likely', 'require()（沙箱内被 trap，但属逃逸尝试）')
    }
    return
  }
  // vm.runInContext / vm.runInNewContext（PLAN.md R2 命中清单；审核补漏）
  if (ts.isPropertyAccessExpression(callee)
    && ts.isIdentifier(callee.expression) && callee.expression.text === 'vm'
    && VM_EXEC.has(callee.name.text)) {
    add(n, 'high', 'certain', `vm.${callee.name.text}() 沙箱内执行代码`)
  }
}

function checkNew(n: ts.NewExpression, sf: ts.SourceFile, add: (n: ts.Node, sev: Severity, conf: Confidence, msg: string) => void): void {
  const expr = n.expression
  const name = ts.isIdentifier(expr) ? expr.text : undefined
  if (name === 'Function' || name === 'AsyncFunction') {
    const arg = n.arguments?.[0]
    if (arg !== undefined) {
      const sv = stringyValue(arg, sf)
      if (sv !== undefined && ESCAPE_RE.test(sv.text)) {
        // 参数含逃逸字符串 → 升级 critical（复用 R1 特征）
        add(n, 'critical', sv.exact ? 'certain' : 'likely', '动态构造（new Function）参数含逃逸字符串')
        return
      }
    }
    add(n, 'high', 'certain', 'new Function / new AsyncFunction 动态执行')
    return
  }
  if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'constructor') {
    add(n, 'high', 'certain', 'new (async()=>{}).constructor 捕获构造器')
  }
}

function isConstructorCapture(n: ts.Node): boolean {
  if (!ts.isPropertyAccessExpression(n) || n.name.text !== 'constructor') return false
  const base = n.expression
  return ts.isArrowFunction(base) || ts.isFunctionExpression(base)
}

/** 顶级 `const x = require('y')`（声明初始化即该调用）——仅 code 场景用于降噪。 */
function isTopLevelConstRequire(call: ts.CallExpression): boolean {
  const parent = call.parent
  if (parent === undefined || !ts.isVariableDeclaration(parent) || parent.initializer !== call) return false
  const decl = parent.parent
  return decl !== undefined && ts.isVariableDeclarationList(decl) && decl.parent !== undefined && ts.isVariableStatement(decl.parent)
}
