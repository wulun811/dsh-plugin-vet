import ts from 'typescript'
import type { Finding, RuleContext, Severity, Confidence } from '../protocol.js'
import { walk, stringyValue, lineOf, isShadowed } from '../ast.js'

// F2：globalThis/global/window 前缀 + 括号访问都算逃逸特征（return globalThis.process /
// process['exit'] 此前漏报）
const ESCAPE_RE = /return\s+\w*(?:globalThis|global|window)?\.?\s*process\b|this\.constructor|process(?:\[|\()/
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
    // targetKind='generic'（非 DSH 插件包/官方运行时）：动态执行是功能（loader/bundle/worker 的
    // require、new Function 模块包装），降级为能力触达面 medium，不进 verdict
    if (ctx.request.targetKind === 'generic' && (severity === 'critical' || severity === 'high')) {
      severity = 'medium'
      message = '能力触达面（非 DSH 插件包）：' + message
    }
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
  // P2-1：eval/Function 被局部遮蔽（const Function = safe; Function(x)）时不是动态执行——
  // 与 R3/R4 一致做 shadowing 检查，避免误报 high。
  if (name === 'eval') {
    if (!isShadowed('eval', callee as ts.Identifier)) {
      add(n, 'high', 'certain', 'eval 动态执行（任意代码执行）')
    }
    return
  }
  if (name === 'Function') {
    if (!isShadowed('Function', callee as ts.Identifier)) {
      add(n, 'high', 'certain', 'Function() 动态构造函数')
    }
    return
  }
  if (name === 'import') {
    add(n, 'medium', 'likely', '动态 import()')
    return
  }
  if (name === 'require') {
    // D30：factory 形参 require（window.__ModuleLoader__.load({ factory: (require) => ... })）
    // 是 DSH 客户端插件加载器注入的同步 require（客户端 bundle 标准写法），非模块级动态加载 → info 不进 verdict
    if (isFactoryParamRequire(n)) {
      add(n, 'info', 'likely', 'require()（客户端加载器 factory 形参注入，DSH bundle 标准写法）')
      return
    }
    // F14：require 分级——危险内置模块（child_process/vm/net/worker 等，可执行/逃逸面）→ high；
    // 普通模块（path/fs/自定义包）→ medium（正常 CJS 插件 require 标准库是常规操作，
    // 整体判 suspicious 是误报——R6 已对危险模块单独提示）
    const arg = n.arguments?.[0]
    const mod = arg !== undefined && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) ? arg.text : undefined
    if (ctx.request.kind === 'files') {
      if (mod !== undefined && /^(node:)?(child_process|vm|worker_threads|cluster|net|dgram|tls|https?|http2)/.test(mod)) {
        add(n, 'high', 'likely', `require('${mod}') 危险内置模块（执行/网络能力触达）`)
      } else if (mod !== undefined && /^(node:)?(fs|path|os|util|crypto|events)/.test(mod)) {
        add(n, 'medium', 'likely', `require('${mod}') 标准内置模块`)
      } else {
        add(n, 'medium', 'likely', 'require() 动态模块加载（npm 包内能力触达）')
      }
    } else if (!isTopLevelConstRequire(n)) {
      add(n, 'medium', 'likely', 'require()（沙箱内被 trap，但属逃逸尝试）')
    }
    return
  }
  // vm.runInContext / vm.runInNewContext（R2 命中清单；审核补漏）
  if (ts.isPropertyAccessExpression(callee)
    && ts.isIdentifier(callee.expression) && callee.expression.text === 'vm'
    && VM_EXEC.has(callee.name.text)) {
    add(n, 'high', 'certain', `vm.${callee.name.text}() 沙箱内执行代码`)
  }
}

function checkNew(n: ts.NewExpression, sf: ts.SourceFile, add: (n: ts.Node, sev: Severity, conf: Confidence, msg: string) => void): void {
  const expr = n.expression
  const name = ts.isIdentifier(expr) ? expr.text : undefined
  // P2-1：new Function/AsyncFunction 同样受局部遮蔽影响（const Function = safe; new Function(x)）
  if (name === 'Function' || name === 'AsyncFunction') {
    if (ts.isIdentifier(expr) && isShadowed(name, expr)) return
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

/**
 * D30：require 是箭头函数/函数的形参（DSH 客户端加载器 `factory: (require) =>` 注入）→
 * 调用点在形参绑定作用域内，非模块级 require，是客户端 bundle 标准写法，不报 high。
 * P1-9：旧实现遇到「最近的函数没有 require 形参」就 return false——factory 内嵌套的
 * 内层函数调用 require 时（闭包捕获外层形参）被误报 high。改为继续向外找绑定函数；
 * 只有从调用点向上所有函数都没有 require 形参（即模块级 require）才返回 false。
 */
function isFactoryParamRequire(call: ts.CallExpression): boolean {
  const name = 'require'
  let node: ts.Node | undefined = call
  while (node !== undefined) {
    if (ts.isFunctionLike(node)) {
      for (const p of node.parameters) {
        if (ts.isIdentifier(p.name) && p.name.text === name) return true
      }
      // 本层函数无 require 形参 → 继续向外（外层 factory 可能注入）
    }
    node = node.parent
  }
  return false
}

/** 顶级 `const x = require('y')`（声明初始化即该调用）——仅 code 场景用于降噪。 */
function isTopLevelConstRequire(call: ts.CallExpression): boolean {
  const parent = call.parent
  if (parent === undefined || !ts.isVariableDeclaration(parent) || parent.initializer !== call) return false
  const decl = parent.parent
  return decl !== undefined && ts.isVariableDeclarationList(decl) && decl.parent !== undefined && ts.isVariableStatement(decl.parent)
}