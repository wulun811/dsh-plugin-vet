import ts from 'typescript'
import type { Finding, RuleContext, Severity, Confidence } from '../protocol.js'
import { walk, stringyValue, lineOf, isShadowed } from '../ast.js'

// F2：globalThis/global/window 前缀 + 括号访问都算逃逸特征（return globalThis.process /
// process['exit'] 此前漏报）
const ESCAPE_RE = /return\s+\w*(?:globalThis|global|window)?\.?\s*process\b|this\.constructor|process(?:\[|\()/
const VM_EXEC = new Set(['runInContext', 'runInNewContext'])

/** 剥掉外层括号（round-7，P1）：new (Function)('...') / (eval)('x') 此前被当普通表达式漏检。 */
function unwrapParens(e: ts.Expression): ts.Expression {
  let cur = e
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression
  return cur
}

/**
 * R2 dynamic execution: eval / Function / new Function / new AsyncFunction /
 * (async()=>{}).constructor capture / vm.runInContext|runInNewContext /
 * dynamic import() / require. Severity splits by scenario: require is a real
 * capability reach in npm packages (files), a trapped dead end in the sandbox (code).
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []

  const add = (n: ts.Node, severity: Severity, confidence: Confidence, message: string): void => {
    // targetKind='generic'（非 DSH 插件包/官方运行时）或 bin 入口文件（round-7，P4c：
    // bin 脚本永远独立运行，spawnSync/require(child_process) 是标准 CLI 写法）：
    // 动态执行是功能面，降级为能力触达面 medium，不进 verdict
    const cliEntry = ctx.cliFiles !== undefined && ctx.cliFiles.has(sf.fileName)
    if ((ctx.request.targetKind === 'generic' || cliEntry) && (severity === 'critical' || severity === 'high')) {
      severity = 'medium'
      message = (ctx.request.targetKind === 'generic' ? '能力触达面（非 DSH 插件包）：' : 'CLI/bin 入口（按通用代码判定）：') + message
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
  // round-7：剥括号——(eval)('x') / (Function)('x') 是同一形态
  const callee = unwrapParens(n.expression)
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
  // round-9（0.1.16 加固）：间接/前缀形态——globalThis.eval / window.eval /
  // globalThis['eval'] / (0, eval) 是经典反静态分析惯用法，此前全漏检
  const indirect = indirectEvalName(callee)
  if (indirect !== null) {
    add(n, 'high', 'certain',
      indirect.name === 'eval'
        ? '间接 eval 动态执行（' + indirect.what + '，任意代码执行）'
        : '间接 Function 动态构造（' + indirect.what + '）')
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
    // round-9（0.1.16 加固）：require('child' + '_process') 拼接形态此前漏检（只认字面量）——
    // stringyValue 常量折叠后按同一口径分级
    const mod = arg !== undefined
      ? (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg) ? arg.text : stringyValue(arg, sf)?.text)
      : undefined
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

/**
 * 间接/前缀 eval·Function 形态识别（round-9，0.1.16 加固）：
 * - 属性访问：globalThis.eval / global.eval / window.eval（前缀标识符限定，不含任意对象方法）
 * - 元素访问：globalThis['eval'] / globalThis['Function']
 * - 逗号运算符：(0, eval) / (safe, Function)——经典 indirect eval
 * 返回 { name, what }；非这些形态返回 null。
 */
function indirectEvalName(callee: ts.Expression): { name: string; what: string } | null {
  const isGlobalBase = (id: ts.Identifier): boolean =>
    id.text === 'globalThis' || id.text === 'global' || id.text === 'window'
  if (ts.isPropertyAccessExpression(callee)
    && ts.isIdentifier(callee.expression) && isGlobalBase(callee.expression)
    && (callee.name.text === 'eval' || callee.name.text === 'Function')) {
    return { name: callee.name.text, what: callee.expression.text + '.' + callee.name.text }
  }
  if (ts.isElementAccessExpression(callee)
    && ts.isIdentifier(callee.expression) && isGlobalBase(callee.expression)
    && callee.argumentExpression !== undefined
    && (ts.isStringLiteral(callee.argumentExpression) || ts.isNoSubstitutionTemplateLiteral(callee.argumentExpression))
    && (callee.argumentExpression.text === 'eval' || callee.argumentExpression.text === 'Function')) {
    const nm = callee.argumentExpression.text
    return { name: nm, what: callee.expression.text + "['" + nm + "']" }
  }
  if (ts.isBinaryExpression(callee) && callee.operatorToken.kind === ts.SyntaxKind.CommaToken) {
    const last = unwrapParens(callee.right)
    if (ts.isIdentifier(last) && (last.text === 'eval' || last.text === 'Function')) {
      return { name: last.text, what: '(0, ' + last.text + ')' }
    }
  }
  return null
}

function checkNew(n: ts.NewExpression, sf: ts.SourceFile, add: (n: ts.Node, sev: Severity, conf: Confidence, msg: string) => void): void {
  // round-7（P1）：new (Function)('return process')——括号包裹的 callee 此前漏检（外部实测对抗样本）
  const expr = unwrapParens(n.expression)
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
  // round-7.2：复用 isConstructorCapture 的 base 校验——只有箭头/函数字面量才是真捕获；
  // new n.constructor(n.type, n)（React 事件对象克隆等 minified bundle 形态）的 base 是变量，不报。
  if (isConstructorCapture(expr)) add(n, 'high', 'certain', 'new (async()=>{}).constructor 捕获构造器')
}

function isConstructorCapture(n: ts.Node): boolean {
  if (!ts.isPropertyAccessExpression(n) || n.name.text !== 'constructor') return false
  const base = unwrapParens(n.expression)
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