import ts from 'typescript'
import type { Finding, RuleContext, Severity } from '../protocol.js'
import { walk, isShadowed, lineOf } from '../ast.js'

const CRITICAL_MEMBERS = new Set(['getBuiltinModule', 'mainModule', 'module', 'exit'])
/** round-5（实测评估）：信号处理器内的 process.exit 是优雅退出（MCP server 等常驻插件
 * 在 SIGTERM/SIGINT 回调里关闭资源后退出是正常操作面），降级 info 不进 verdict；
 * 非信号上下文的裸 process.exit（条件分支、错误路径、任意位置）保持 critical。 */
const SIGNAL_HANDLERS = new Set(['SIGTERM', 'SIGINT', 'SIGUSR1', 'SIGUSR2', 'SIGHUP', 'SIGQUIT', 'SIGABRT', 'SIGBREAK'])
const SIGNAL_EVENTS = new Set(['on', 'once'])

/**
 * exit 调用是否位于 process.on/once('SIG*', handler) 的处理器回调内（含嵌套箭头/函数）。
 * 向上找最近的函数边界：若存在一个祖先调用是 process.on/once 且第一个参数是信号字符串，
 * 且该调用位于本函数边界之外（即本函数是被注册的 handler 本体）→ 是信号处理上下文。
 */
function inSignalHandler(exitNode: ts.Node): boolean {
  // exitNode 是 process 标识符：parent = process.exit（属性访问），再上一级 = 调用表达式
  let exitCall = exitNode.parent
  if (exitCall !== undefined && ts.isPropertyAccessExpression(exitCall)) exitCall = exitCall.parent
  if (exitCall === undefined || !ts.isCallExpression(exitCall)) return false
  // 找到最近的函数体（exit 所在的函数）
  let fn: ts.Node | undefined = exitNode
  while (fn !== undefined && !ts.isFunctionLike(fn)) fn = fn.parent
  if (fn === undefined) return false
  // 从 fn 的父级向上找 process.on('SIG*', ...) 注册调用
  let cur: ts.Node | undefined = fn.parent
  while (cur !== undefined) {
    if (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
      const pa = cur.expression
      const evt = pa.name.text
      if (SIGNAL_EVENTS.has(evt) && ts.isIdentifier(pa.expression) && pa.expression.text === 'process') {
        const arg0 = cur.arguments[0]
        if (arg0 !== undefined && (ts.isStringLiteral(arg0) || ts.isNoSubstitutionTemplateLiteral(arg0)) && SIGNAL_HANDLERS.has(arg0.text)) {
          return true
        }
      }
    }
    cur = cur.parent
  }
  return false
}

/**
 * R3 direct process access. `process` is a data global: absent from
 * NODE_API_REDIRECTS (sandbox.ts:96-108), it stays undefined inside vm
 * contexts (sandbox.ts:90-94). So runtime='sandbox' caps hits at high —
 * a bare reference there is an attempted/failed escape or a typeof probe;
 * the real escape is the constructor chain (R1/R4). runtime='host'
 * (run_code AsyncFunction realm, bootstrap.ts:405) and files mode keep
 * critical severity: process is genuinely reachable.
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isIdentifier(n) || n.text !== 'process') return
    if (isShadowed('process', n)) return

    const parent = n.parent
    let severity: Severity = 'info'
    let message = '裸 process 引用（可能为 typeof 探测）'
    let evidence = n.getText(sf)

    if (parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.expression === n) {
      const member = parent.name.text
      evidence = parent.getText(sf)
      // round-5：process.on/once('SIG*', handler) 注册信号处理器是常驻插件正常操作面 → info
      if (SIGNAL_EVENTS.has(member) && ts.isCallExpression(parent.parent)) {
        const arg0 = parent.parent.arguments[0]
        if (arg0 !== undefined && (ts.isStringLiteral(arg0) || ts.isNoSubstitutionTemplateLiteral(arg0)) && SIGNAL_HANDLERS.has(arg0.text)) {
          severity = 'info'
          message = 'process.' + member + ' 信号处理器注册（常驻插件正常操作面）'
        }
      } else if (CRITICAL_MEMBERS.has(member)) {
        // round-5：信号处理器回调内的 process.exit = 优雅退出 → info；其余上下文 critical
        if (member === 'exit' && inSignalHandler(n)) {
          severity = 'info'
          message = '信号处理回调内的 process.exit（优雅退出，常驻插件正常操作面）'
        } else {
          severity = 'critical'
          message = '直接访问 process.' + member + '（Node 能力逃逸通道）'
        }
      } else {
        severity = 'high'
        message = '直接访问 process.' + member
      }
    } else if (parent !== undefined && ts.isElementAccessExpression(parent) && parent.expression === n) {
      // F4：process['exit'] 括号访问此前只报 info——同样致命，按属性访问口径判定
      const arg = parent.argumentExpression
      const member = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg) ? arg.text : undefined
      evidence = parent.getText(sf)
      if (member !== undefined && CRITICAL_MEMBERS.has(member)) {
        severity = 'critical'
        message = '直接访问 process[\'' + member + '\']（Node 能力逃逸通道）'
      } else if (member !== undefined) {
        severity = 'high'
        message = '直接访问 process[\'' + member + '\']'
      } else {
        severity = 'high'
        message = '直接访问 process[...]（动态成员）'
      }
    }

    if (severity === 'critical' && ctx.runtime === 'sandbox') severity = 'high'

    // 形态降级（round-7，P4a/P4c）：process 访问是能力触达面或产品功能，不是沙箱逃逸 →
    // info 不进 verdict。三类形态：generic 包（PLAN §14.3 边界落地）、bin 入口文件
    // （CLI 脚本永远独立运行）、应用型包（bin 声明：TUI/CLI/server 的 process 即产品功能，
    // 外部实测 dsh-tui 4065 分扣减全部误报）
    const cliEntry = ctx.cliFiles !== undefined && ctx.cliFiles.has(sf.fileName)
    if (severity !== 'info' && (ctx.request.targetKind === 'generic' || cliEntry || ctx.appShape === true)) {
      const why = ctx.request.targetKind === 'generic' ? '非 DSH 插件包'
        : cliEntry ? 'CLI/bin 入口'
        : '应用型包（bin 入口，process 即产品功能）'
      severity = 'info'
      message = '能力触达面（' + why + '）：' + message
    }

    found.push({
      rule: 'R3',
      severity,
      confidence: 'certain',
      message,
      evidence: evidence.slice(0, 300),
      line: lineOf(sf, n),
    })
  })
  return found
}