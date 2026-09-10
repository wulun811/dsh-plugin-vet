import ts from 'typescript'
import type { Finding, RuleContext, Severity } from '../protocol.js'
import { walk, isShadowed, isShadowedForStringy, lineOf } from '../ast.js'

const CRITICAL_MEMBERS = new Set(['getBuiltinModule', 'mainModule', 'module', 'exit', 'reallyExit'])
/** round-5（实测评估）：信号处理器内的 process.exit 是优雅退出（MCP server 等常驻插件
 * 在 SIGTERM/SIGINT 回调里关闭资源后退出是正常操作面），降级 info 不进 verdict；
 * 非信号上下文的裸 process.exit（条件分支、错误路径、任意位置）保持 critical。 */
const SIGNAL_HANDLERS = new Set(['SIGTERM', 'SIGINT', 'SIGUSR1', 'SIGUSR2', 'SIGHUP', 'SIGQUIT', 'SIGABRT', 'SIGBREAK'])
const SIGNAL_EVENTS = new Set(['on', 'once'])
/**
 * round-7.1（P-1/P-2）：纯只读/无副作用成员——能力触达面而非逃逸通道（读 cwd/env/pid
 * 从来不是逃逸，运行时插件代码本就跑在宿主进程里，这些数据天然可读）。plugin 模式也降
 * info 不进 verdict：MCP/工具插件（dsh-bridges 类：无 bin 声明但有 @deepseek-ai 依赖，
 * 134 条 cwd/env/platform 误报全部清零）与 wechat-mp 的 cacheFile + pid + .tmp 原子写
 * 临时名（write-then-rename，与 vet 自身 atomic-write 同款）不再误伤。
 */
const READONLY_MEMBERS = new Set([
  'env', 'cwd', 'platform', 'pid', 'ppid', 'arch', 'version', 'versions', 'release',
  'argv', 'argv0', 'execArgv', 'execPath', 'title', 'uptime', 'memoryUsage', 'hrtime',
  'cpuUsage', 'resourceUsage', 'getActiveResourcesInfo', 'features', 'config', 'debugPort',
  'stdin', 'stdout', 'stderr', 'exitCode', 'connected', 'domain', 'allowedNodeEnvironmentFlags',
  'sourceMapsEnabled', 'report', 'emitWarning',
  'nextTick', 'on', 'once', 'off', 'removeListener', 'removeAllListeners', 'emit',
  'listeners', 'listenerCount', 'eventNames', 'setUncaughtExceptionCaptureCallback',
  'getuid', 'getgid', 'geteuid', 'getegid', 'getgroups',
])
/** 有副作用/能力型成员（plugin 模式保持 high，round-7.1 显式化）：kill/abort/chdir/权限/原生加载等。 */
const SIDE_EFFECT_MEMBERS = new Set([
  'kill', 'abort', 'chdir', 'umask', 'setuid', 'setgid', 'setgroups', 'initgroups',
  'dlopen', 'binding', 'send', 'disconnect',
])

/**
 * exit 调用是否位于 process.on/once('SIG*', handler) 的处理器回调内（含嵌套箭头/函数）。
 * 向上找最近的函数边界：若存在一个祖先调用是 process.on/once 且第一个参数是信号字符串，
 * 且该调用位于本函数边界之外（即本函数是被注册的 handler 本体）→ 是信号处理上下文。
 */
function inSignalHandler(exitNode: ts.Node): boolean {
  // exitNode 是 process 标识符：parent = process.exit（属性访问）或 global.process（属性访问），
  // 逐级上溯直到找到最近的调用表达式（round-9：global.process.exit 需跨两级属性访问）
  let exitCall = exitNode.parent
  while (exitCall !== undefined && ts.isPropertyAccessExpression(exitCall)) exitCall = exitCall.parent
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
/**
 * round-10.x（接入 dsh.so 静态注册站）：测试/CI 文件内的 process 访问是开发期行为，
 * 不是发布物逃逸通道。按能力触达面降 info——与 bin/appShape/generic 同构降级，但比 pilot 的
 * "全部降级"更精准：只放过测试/CI 文件（目录 test/tests/spec/specs/__tests__/.github
 * 或文件名 *.test.*  *.spec.*  *.e2e.*  coverage.*  vitest.*  jest.*），真实源码里的 process.exit 仍 critical。
 * 注：scripts/ 不是测试/CI 目录——包里的 scripts/ 常是产品代码（CLI 工具、构建脚本），其内
 * 的 process.exit 是真实逃逸意图，不能降级（曾把 scripts/ 与测试目录等同 → 潜在漏报）。
 */
export function isTestOrCiFile(fileName: string): boolean {
  const segs = fileName.replace(/\\/g, '/').split('/').filter(Boolean)
  if (segs.some(s => s === 'test' || s === 'tests' || s === 'spec' || s === 'specs' || s === '__tests__' || s === '.github')) return true
  const base = segs[segs.length - 1] ?? fileName
  return /\.(test|spec|e2e)\./i.test(base) || /(^|[^a-z0-9])coverage\./i.test(base) || /^(vitest|jest)\./i.test(base)
}

/**
 * round-22：`const { exit, pid } = process` 解构绑定 → { 使用名: process 成员名 }。
 * 解构成员调用（exit(1) / getBuiltinModule('fs')）与 process.exit 同一条逃逸通道，
 * 旧遍历在调用点只见匿名标识符 → 全部落「裸 process 引用」info。
 */
function destructuredProcessMembers(sf: ts.SourceFile): Map<string, string> {
  const out = new Map<string, string>()
  walk(sf, n => {
    if (!ts.isVariableDeclaration(n)) return
    if (!ts.isObjectBindingPattern(n.name)) return
    const init = n.initializer
    if (init === undefined) return
    const isProcessInit = (ts.isIdentifier(init) && init.text === 'process')
      || (ts.isPropertyAccessExpression(init) && init.name.text === 'process'
        && ts.isIdentifier(init.expression)
        && (init.expression.text === 'globalThis' || init.expression.text === 'global' || init.expression.text === 'window'))
    if (!isProcessInit) return
    for (const el of n.name.elements) {
      if (!ts.isIdentifier(el.name)) continue
      if (el.propertyName !== undefined && ts.isIdentifier(el.propertyName)) out.set(el.name.text, el.propertyName.text)
      else out.set(el.name.text, el.name.text)
    }
  })
  return out
}

export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  const cliEntryOf = (): boolean => ctx.cliFiles !== undefined && ctx.cliFiles.has(sf.fileName)
  /** 形态降级（与主遍历同口径；抽取共用避免新形态漏降级）。
   * 0.3.9（审查修复）：appShape（仅声明 bin）不再对**全包所有文件**降级——元数据自证即可
   * 系统性压 verdict（恶意包声明任一 bin、把载荷命名成任意 js，R3 对全部逃逸链失明）；收窄
   * 为「声明 bin 且当前文件是 bin/scripts 命中的入口文件」才按应用型降级（真实 CLI 的
   * cwd/进程访问确实是产品功能）。 */
  const degrade = (severity: Severity, message: string): { severity: Severity; message: string } => {
    if (severity === 'info') return { severity, message }
    const testOrCi = isTestOrCiFile(ctx.filePath ?? sf.fileName)
    if (ctx.request.targetKind === 'generic' || cliEntryOf() || testOrCi) {
      const why = testOrCi ? '测试/CI 文件'
        : ctx.request.targetKind === 'generic' ? '非 DSH 插件包'
        : 'CLI/bin 入口'
      return { severity: 'info', message: '能力触达面（' + why + '）：' + message }
    }
    if (ctx.appShape === true && cliEntryOf()) {
      return { severity: 'info', message: '能力触达面（应用型 CLI 入口）：' + message }
    }
    return { severity, message }
  }
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
      } else if (READONLY_MEMBERS.has(member)) {
        // round-7.1：只读成员是能力触达面（读 cwd/env/pid 不是逃逸通道）→ info 不进 verdict
        severity = 'info'
        message = '只读 process 成员（能力触达面）：process.' + member
      } else {
        // SIDE_EFFECT_MEMBERS 与未知成员：保持 high（kill/abort/权限/原生加载有真实副作用；
        // 未知成员保守判定）
        severity = 'high'
        message = '直接访问 process.' + member
      }
    } else if (parent !== undefined && ts.isPropertyAccessExpression(parent) && parent.name === n
      && ts.isIdentifier(parent.expression)
      && (parent.expression.text === 'globalThis' || parent.expression.text === 'global' || parent.expression.text === 'window')) {
      // round-9（0.1.16 加固）：global.process.exit() / globalThis.process.mainModule 等前缀形态——
      // process 是属性名而非表达式，旧检查（parent.expression === n）不成立 → 落默认 info 漏检。
      // 与标准形态同一成员口径：exit/mainModule/binding 等 critical，只读成员 info，副作用 high。
      const gp = parent.parent
      const member = gp !== undefined && ts.isPropertyAccessExpression(gp) && gp.expression === parent ? gp.name.text : undefined
      evidence = member !== undefined && gp !== undefined ? gp.getText(sf) : parent.getText(sf)
      if (member === undefined) {
        severity = 'info'
        message = '裸 process 引用（' + parent.expression.text + '.process，无成员访问）'
      } else if (CRITICAL_MEMBERS.has(member)) {
        if (member === 'exit' && inSignalHandler(n)) {
          severity = 'info'
          message = '信号处理回调内的 process.exit（优雅退出，常驻插件正常操作面）'
        } else {
          severity = 'critical'
          message = '直接访问 ' + parent.expression.text + '.process.' + member + '（Node 能力逃逸通道）'
        }
      } else if (READONLY_MEMBERS.has(member)) {
        severity = 'info'
        message = '只读 process 成员（能力触达面）：' + parent.expression.text + '.process.' + member
      } else {
        severity = 'high'
        message = '直接访问 ' + parent.expression.text + '.process.' + member
      }
    } else if (parent !== undefined && ts.isElementAccessExpression(parent) && parent.expression === n) {
      // F4：process['exit'] 括号访问此前只报 info——同样致命，按属性访问口径判定
      const arg = parent.argumentExpression
      const member = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg) ? arg.text : undefined
      evidence = parent.getText(sf)
      if (member !== undefined && CRITICAL_MEMBERS.has(member)) {
        severity = 'critical'
        message = '直接访问 process[\'' + member + '\']（Node 能力逃逸通道）'
      } else if (member !== undefined && READONLY_MEMBERS.has(member)) {
        severity = 'info'
        message = '只读 process 成员（能力触达面）：process[\'' + member + '\']'
      } else {
        severity = 'high'
        message = '直接访问 process[...]（动态成员）'
      }
    }

    if (severity === 'critical' && ctx.runtime === 'sandbox') severity = 'high'

    // 形态降级（round-7，P4a/P4c）：process 访问是能力触达面或产品功能，不是沙箱逃逸 →
    // info 不进 verdict。三类形态：generic 包（PLAN §14.3 边界落地）、bin 入口文件
    // （CLI 脚本永远独立运行）、应用型 CLI 入口（0.3.9 收窄——见 degrade 注释：appShape
    // 不再对全包所有文件降级，元数据自证不可系统性压低 verdict）。
    const cliEntry = ctx.cliFiles !== undefined && ctx.cliFiles.has(sf.fileName)
    const testOrCi = isTestOrCiFile(ctx.filePath ?? sf.fileName)
    if (severity !== 'info' && (ctx.request.targetKind === 'generic' || cliEntry || testOrCi
      || (ctx.appShape === true && cliEntry))) {
      const why = testOrCi ? '测试/CI 文件'
        : ctx.request.targetKind === 'generic' ? '非 DSH 插件包'
        : 'CLI/bin 入口'
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

  // round-22：globalThis['process'] 元素访问形态——'process' 是字符串字面量不是
  // 标识符，主遍历对它零命中（连 info 都没有，与 globalThis.process 的检测面不对称）。
  // 成员分级与属性访问同口径（exit 等 critical / 只读 info / 其余 high）。
  walk(sf, n => {
    if (!ts.isElementAccessExpression(n)) return
    const base = n.expression
    if (!(ts.isIdentifier(base) && (base.text === 'globalThis' || base.text === 'global' || base.text === 'window'))) return
    const key = n.argumentExpression
    if (key === undefined || !(ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key)) || key.text !== 'process') return
    const gp = n.parent
    let member: string | undefined
    let evidence = n.getText(sf)
    if (gp !== undefined && ts.isPropertyAccessExpression(gp) && gp.expression === n) {
      member = gp.name.text
      evidence = gp.getText(sf)
    } else if (gp !== undefined && ts.isElementAccessExpression(gp) && gp.expression === n) {
      const k2 = gp.argumentExpression
      if (k2 !== undefined && (ts.isStringLiteral(k2) || ts.isNoSubstitutionTemplateLiteral(k2))) member = k2.text
      evidence = gp.getText(sf)
    }
    let severity: Severity = 'info'
    let message = '裸 process 引用（' + base.text + "['process']，无成员访问）"
    if (member !== undefined) {
      if (CRITICAL_MEMBERS.has(member)) {
        severity = 'critical'
        message = '直接访问 ' + base.text + "['process']." + member + '（Node 能力逃逸通道）'
      } else if (READONLY_MEMBERS.has(member)) {
        severity = 'info'
        message = '只读 process 成员（能力触达面）：' + base.text + "['process']." + member
      } else {
        severity = 'high'
        message = '直接访问 ' + base.text + "['process']." + member
      }
    }
    if (severity === 'critical' && ctx.runtime === 'sandbox') severity = 'high'
    const d = degrade(severity, message)
    found.push({
      rule: 'R3',
      severity: d.severity,
      confidence: 'certain',
      message: d.message,
      evidence: evidence.slice(0, 300),
      line: lineOf(sf, n),
    })
  })

  // round-22：`const { exit } = process; exit(1)` 解构成员形态——调用点是匿名标识符，
  // 与 process.exit 同一条逃逸通道，按解构成员分级（与属性访问同口径）。
  const destructured = destructuredProcessMembers(sf)
  for (const [name, member] of destructured) {
    walk(sf, n => {
      if (!ts.isIdentifier(n) || n.text !== name) return
      if (n.parent !== undefined && ts.isBindingElement(n.parent)) return // 声明位本身（解构名）
      if (isShadowedForStringy(name, n)) return
      // 成员使用即访问（exit() 调用 / 裸引用都算）；与属性形态同分级：
      // 只读成员 info（能力触达面），critical 成员 critical，其余 high（含副作用成员）。
      let severity: Severity = 'high'
      let message = 'process 解构成员访问：' + member
      if (CRITICAL_MEMBERS.has(member)) {
        severity = 'critical'
        message = 'process 解构成员调用/访问：' + member + '（Node 能力逃逸通道）'
      } else if (READONLY_MEMBERS.has(member)) {
        severity = 'info'
        message = '只读 process 成员（能力触达面，解构）：' + member
      }
      if (severity === 'critical' && ctx.runtime === 'sandbox') severity = 'high'
      const d = degrade(severity, message)
      found.push({
        rule: 'R3',
        severity: d.severity,
        confidence: 'certain',
        message: d.message,
        evidence: n.getText(sf),
        line: lineOf(sf, n),
      })
    })
  }
  return found
}