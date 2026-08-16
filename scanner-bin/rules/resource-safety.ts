import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, numberyValue, stringyValue, lineOf } from '../ast.js'

/**
 * R9 resource safety . Signals, capped at high (14.1:
 * critical would short-circuit the LLM audit, which resource-class issues need):
 *
 * R9-1 (high): unbounded allocation literal (new Array(2**31) / Array(n) /
 *   Array.from({length}) / Buffer.alloc(huge)); synchronous exit-less loop
 *   while(true)/for(;;) (busy-wait wedges the event loop; module-top-level in
 *   npm packages stalls the whole harness); child-process spawn inside such a
 *   loop (fork-bomb pattern). A loop body with await is a likely resident
 *   service loop, advisory info only.
 * R9-2 (medium): nested-quantifier regex (ReDoS, (a+)+ style exponential
 *   backtracking); recursion without any conditional branch (rough check).
 * R9-3 (info/medium): in-loop += accumulation (possible O(n2) string),
 *   in-loop map.set growth signal, in-loop Promise.all concurrency signal.
 */
const ALLOC_LIMIT = 100_000_000
const SPAWN_CALLS = new Set(['spawn', 'exec', 'execFile', 'fork'])
const SPAWN_NEWS = new Set(['Worker'])
/**
 * (a+)+ style ReDoS detection. round-5/6 重写（外部实测驱动）：
 * - 旧正则把 (?:x)? 组首 '?' 修饰符误当量词 → 所有单可选组误报（线性复杂度）
 * - 真指数回溯 = 组内顶层带量词（组可匹配变长）+ 组后紧跟量词：(a+)+、(?:\\d+)+
 * - round-6：alternation 分支互斥（((?:[^']|'')*)）→ 线性，不报；
 *   分支重叠（(a|aa)+：aa 以 a 开头）→ 指数回溯，报
 */
function isRedosPattern(pattern: string): boolean {
  const findClose = (open: number): number => {
    let depth = 0
    for (let j = open; j < pattern.length; j++) {
      if (pattern[j] === '(') depth++
      else if (pattern[j] === ')') {
        depth--
        if (depth === 0) return j
      }
    }
    return -1
  }
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] !== '(') continue
    const close = findClose(i)
    if (close === -1) return false
    const inner = pattern.slice(i + 1, close)
    let body = inner
    if (body.startsWith('?:') || body.startsWith('?=') || body.startsWith('?!')) body = body.slice(2)
    let hasInnerQuant = false
    let depth = 0
    for (let j = 0; j < body.length; j++) {
      const ch = body[j]
      if (ch === '(') { depth++; continue }
      if (ch === ')') { depth--; continue }
      if (depth === 0 && (ch === '*' || ch === '+' || ch === '?')) {
        if (j === 0 || body[j - 1] !== '\\') { hasInnerQuant = true; break }
      }
    }
    const after = pattern[close + 1]
    // round-7（P3）：组后 '?'（(https?:)? 类）至多一次额外分支——回溯有界、最坏线性，
    // 不是 (a+)+ 类指数回溯（指数要求组后 */+ 可重复叠加）。外部实测 dsh-wechat-mp
    // markdown.js 的 /^(https?:)?\/\//i 常规 URL 探测误报 medium。
    if (after !== '*' && after !== '+') continue
    // 组内带量词 + 组后 */+：典型指数回溯
    if (hasInnerQuant) return true
    // 组内 alternation：分支互斥 → 线性不报；分支重叠 → 指数回溯报
    if (hasAlternation(body) && !branchesDisjoint(body)) return true
  }
  return false
}
/** 组内顶层是否存在 alternation 分支（跳过嵌套括号区）。 */
function hasAlternation(body: string): boolean {
  let depth = 0
  for (let j = 0; j < body.length; j++) {
    const ch = body[j]
    if (ch === '(') depth++
    else if (ch === ')') depth--
    else if (ch === '|' && depth === 0) return true
  }
  return false
}
/**
 * alternation 顶层分支两两互斥判定：每个分支取首字符集合（近似），
 * 集合不相交 → 互斥（线性）。首字符支持：字面量、. \\d \\w \\s、
 * 字符类 [...]（^ 否定类无法近似 → 保守视为不互斥）。无法分析 → 不互斥（保守报）。
 */
function branchesDisjoint(body: string): boolean {
  const branches: string[] = []
  let depth = 0
  let cur = ''
  for (let j = 0; j < body.length; j++) {
    const ch = body[j]
    if (ch === '(') depth++
    else if (ch === ')') depth--
    if (ch === '|' && depth === 0) { branches.push(cur); cur = ''; continue }
    cur += ch
  }
  branches.push(cur)
  if (branches.length < 2) return false
  const charSets = branches.map(firstCharSet)
  for (let i = 0; i < charSets.length; i++) {
    for (let j = i + 1; j < charSets.length; j++) {
      if (charSets[i] === null || charSets[j] === null) return false
      if (setsIntersect(charSets[i]!, charSets[j]!)) return false
    }
  }
  return true
}
/** 分支首 token 的字符集合近似：null = 无法分析（保守不互斥）。 */
function firstCharSet(branch: string): Set<string> | null {
  const b = branch.trimStart()
  if (b === '') return new Set()
  const c = b[0]
  if (c === '\\') {
    const esc = b[1]
    if (esc === 'd') return new Set(['0-9'])
    if (esc === 'w') return new Set(['0-9', 'A-Z', 'a-z', '_'])
    if (esc === 's') return new Set([' ', 't', 'n', 'r', 'f'])
    if (esc === 'D' || esc === 'W' || esc === 'S') return null
    return new Set([esc])
  }
  if (c === '.') return null
  if (c === '[') {
    const close = b.indexOf(']')
    if (close === -1) return null
    const cls = b.slice(1, close)
    if (cls.startsWith('^')) {
      const neg = cls.slice(1)
      // 单字符否定类 [^x]：与字面量 y 相交当且仅当 y === x（round-6：((?:[^']|'')*) 分支互斥）
      if (neg.length === 1) return { negated: true, char: neg } as unknown as Set<string>
      return null // 多字符否定类无法近似，保守
    }
    return new Set(cls.split(''))
  }
  if (c === '(' || c === '?') return null
  return new Set([c])
}
function setsIntersect(a: Set<string>, b: Set<string>): boolean {
  const an = (a as unknown as { negated?: boolean; char?: string }).negated
  const bn = (b as unknown as { negated?: boolean; char?: string }).negated
  if (an === true) {
    const ch = (a as unknown as { char: string }).char
    // [^x] 与集合 S 相交：否定类覆盖几乎所有字符，仅当 S 恰为 {x} 时才不相交
    return !(b.size === 1 && b.has(ch))
  }
  if (bn === true) return setsIntersect(b, a)
  for (const x of a) if (b.has(x)) return true
  return false
}

/** Per-node exit signals of a loop body, skipping nested functions. */
interface ExitSignals {
  hasBreak: boolean
  hasReturn: boolean
  hasThrow: boolean
  hasAwait: boolean
}

function exitSignals(body: ts.Node): ExitSignals {
  const sig: ExitSignals = { hasBreak: false, hasReturn: false, hasThrow: false, hasAwait: false }
  const visit = (n: ts.Node, inInnerLoop: boolean): void => {
    if (ts.isFunctionLike(n)) return // nested functions don't affect this loop
    if (ts.isBreakStatement(n) && !inInnerLoop) sig.hasBreak = true
    if (ts.isReturnStatement(n)) sig.hasReturn = true
    if (ts.isThrowStatement(n)) sig.hasThrow = true
    if (ts.isAwaitExpression(n)) sig.hasAwait = true
    const nested = inInnerLoop || (ts.isIterationStatement(n, false) && n !== body)
    ts.forEachChild(n, child => visit(child, nested))
  }
  visit(body, false)
  return sig
}

/** Collect spawn-ish call/new nodes in a body tree (skipping nested functions). */
function collectSpawns(body: ts.Node, out: ts.Node[]): void {
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionLike(n)) return
    if (ts.isCallExpression(n)) {
      const callee = n.expression
      if (ts.isIdentifier(callee) && SPAWN_CALLS.has(callee.text)) out.push(n)
      else if (ts.isPropertyAccessExpression(callee) && SPAWN_CALLS.has(callee.name.text)) out.push(n)
    } else if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && SPAWN_NEWS.has(n.expression.text)) {
      out.push(n)
    }
    ts.forEachChild(n, visit)
  }
  visit(body)
}

/** while(true) or for(;;) - statically provable unbounded loops. */
function unboundedLoop(n: ts.Node): ts.WhileStatement | ts.ForStatement | undefined {
  if (ts.isWhileStatement(n) && n.expression.kind === ts.SyntaxKind.TrueKeyword) return n
  if (ts.isForStatement(n) && n.initializer === undefined && n.condition === undefined && n.incrementor === undefined) return n
  return undefined
}

/** R9-1 allocation checks: new Array / Array() / Array.from({length}) / Buffer.alloc*. */
function allocFinding(ruleText: string, n: ts.Node, sf: ts.SourceFile, amount: number): Finding | undefined {
  if (amount < ALLOC_LIMIT) return undefined
  return {
    rule: 'R9',
    severity: 'high',
    confidence: 'certain',
    message: '无界分配：' + ruleText + '（静态值 ' + amount + ' ≥ ' + ALLOC_LIMIT + '，可致 OOM）',
    evidence: n.getText(sf).slice(0, 200),
    line: lineOf(sf, n),
  }
}

function checkArrayAlloc(n: ts.CallExpression | ts.NewExpression, sf: ts.SourceFile, found: Finding[]): void {
  const callee = n.expression
  // Array(n) / new Array(n)
  if (ts.isIdentifier(callee)) {
    if (callee.text === 'Array') {
      const arg = n.arguments?.[0]
      if (arg !== undefined) {
        const v = numberyValue(arg, sf)
        if (v !== undefined) {
          const f = allocFinding('Array(n) 巨大数组', n, sf, v)
          if (f !== undefined) found.push(f)
        }
      }
    }
    return
  }
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.expression)) return
  const base = callee.expression.text
  const method = callee.name.text
  // Buffer.alloc(n) / Buffer.allocUnsafe(n)
  if (base === 'Buffer' && (method === 'alloc' || method === 'allocUnsafe')) {
    const arg = n.arguments?.[0]
    if (arg !== undefined) {
      const v = numberyValue(arg, sf)
      if (v !== undefined) {
        const f = allocFinding('Buffer.' + method + '(n) 巨大缓冲', n, sf, v)
        if (f !== undefined) found.push(f)
      }
    }
    return
  }
  // Array.from({ length: n })
  if (base === 'Array' && method === 'from') {
    const arg = n.arguments?.[0]
    if (arg !== undefined && ts.isObjectLiteralExpression(arg)) {
      for (const prop of arg.properties) {
        if (ts.isPropertyAssignment(prop) && prop.name.getText(sf) === 'length') {
          const v = numberyValue(prop.initializer, sf)
          if (v !== undefined) {
            const f = allocFinding('Array.from({ length: n }) 巨大数组', n, sf, v)
            if (f !== undefined) found.push(f)
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// R9-2: ReDoS nested quantifiers + recursion without a conditional branch
// ---------------------------------------------------------------------------

function checkRedosPattern(pattern: string, n: ts.Node, sf: ts.SourceFile, found: Finding[]): void {
  if (isRedosPattern(pattern)) {
    found.push({
      rule: 'R9',
      severity: 'medium',
      confidence: 'likely',
      message: '正则嵌套量词（ReDoS 风险：(a+)+ 类指数回溯）',
      evidence: n.getText(sf).slice(0, 200),
      line: lineOf(sf, n),
    })
  }
}

/** Regex literal /pattern/flags and new RegExp('pattern'). */
function checkReDoS(sf: ts.SourceFile, found: Finding[]): void {
  walk(sf, n => {
    if (ts.isRegularExpressionLiteral(n)) {
      const text = n.text
      const lastSlash = text.lastIndexOf('/')
      if (text.startsWith('/') && lastSlash > 0) {
        checkRedosPattern(text.slice(1, lastSlash), n, sf, found)
      }
      return
    }
    if ((ts.isCallExpression(n) || ts.isNewExpression(n)) && ts.isIdentifier(n.expression) && n.expression.text === 'RegExp') {
      const arg = n.arguments?.[0]
      if (arg !== undefined) {
        const sv = stringyValue(arg, sf)
        if (sv !== undefined) checkRedosPattern(sv.text, n, sf, found)
      }
    }
  })
}

/** Function name: declared name, or the const binding of an arrow/expression. */
function functionName(fn: ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction, sf: ts.SourceFile): string | undefined {
  if (fn.name !== undefined) return fn.name.text
  const parent = fn.parent
  if (parent !== undefined && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text
  return undefined
}

/**
 * Rough recursion check: direct self-call with no if/switch/ternary/&&/|| in the body tree.
 * round-7（P4d）：集合遍历形态（for-of/for-in）与带条件循环（while(cond)/do/for(;cond;)）
 * 是常见终止机制——自调用在其内不做「无终止」粗判（外部实测 dsh-tui 的 zeroLayoutRecursive
 * yoga-layout 树遍历误报；while(true)/for(;;) 保持判定）。
 */
function checkRecursion(sf: ts.SourceFile, found: Finding[]): void {
  walk(sf, n => {
    if (!ts.isFunctionDeclaration(n) && !ts.isFunctionExpression(n) && !ts.isArrowFunction(n)) return
    const name = functionName(n, sf)
    if (name === undefined || name === '') return
    const body = n.body
    if (body === undefined) return
    let selfCall = false
    let selfCallBounded = false
    let hasCondition = false
    const visit = (node: ts.Node, bounded: boolean): void => {
      if (node !== n && ts.isFunctionLike(node)) return
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) {
        selfCall = true
        if (bounded) selfCallBounded = true
      }
      if (ts.isIfStatement(node) || ts.isSwitchStatement(node) || ts.isConditionalExpression(node)
        || (ts.isBinaryExpression(node)
          && (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken || node.operatorToken.kind === ts.SyntaxKind.BarBarToken))) {
        hasCondition = true
      }
      let next = bounded
      if (!next) {
        if (ts.isForOfStatement(node) || ts.isForInStatement(node)) next = true
        else if (ts.isWhileStatement(node) && node.expression.kind !== ts.SyntaxKind.TrueKeyword) next = true
        else if (ts.isDoStatement(node)) next = true
        else if (ts.isForStatement(node) && node.condition !== undefined) next = true
      }
      ts.forEachChild(node, child => visit(child, next))
    }
    visit(body, false)
    if (selfCall && !selfCallBounded && !hasCondition) {
      found.push({
        rule: 'R9',
        severity: 'medium',
        confidence: 'likely',
        message: '递归无终止条件粗检：' + name + ' 直接自调用且函数体内无条件分支',
        evidence: n.getText(sf).slice(0, 200),
        line: lineOf(sf, n),
      })
    }
  })
}

// ---------------------------------------------------------------------------
// R9-3: in-loop accumulation / growth / concurrency signals (advisory)
// ---------------------------------------------------------------------------

/** 右侧表达式是否算术（数值累加而非字符串拼接）：数字字面量或算术/位运算表达式。 */
function isArithmeticRhs(expr: ts.Expression): boolean {
  if (ts.isNumericLiteral(expr)) return true
  if (!ts.isBinaryExpression(expr)) return false
  switch (expr.operatorToken.kind) {
    case ts.SyntaxKind.AsteriskToken:
    case ts.SyntaxKind.SlashToken:
    case ts.SyntaxKind.PercentToken:
    case ts.SyntaxKind.AsteriskAsteriskToken:
    case ts.SyntaxKind.LessThanLessThanToken:
    case ts.SyntaxKind.GreaterThanGreaterThanToken:
    case ts.SyntaxKind.AmpersandToken:
    case ts.SyntaxKind.BarToken:
    case ts.SyntaxKind.CaretToken:
      return true
    default:
      return false
  }
}

function isAnyLoop(n: ts.Node): boolean {
  return ts.isForStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n)
    || ts.isForInStatement(n) || ts.isForOfStatement(n)
}
/**
 * R9-3 有界性判定（D30：真实插件误报修复）：for-of/for-in 遍历的是显式集合/对象
 * （`for (const p of registry.plugins)`），循环次数受集合大小约束，map.set/+=/Promise.all
 * 的增长上界 = 集合大小，不是「无界增长信号」，不报。只有 while/do/for(;;) 这类潜在
 * 无界循环（次数不由既有集合决定）才保留信号。
 */
function isBoundedIteration(n: ts.Node): boolean {
  return ts.isForInStatement(n) || ts.isForOfStatement(n)
}


function checkLoopBodyPatterns(sf: ts.SourceFile, found: Finding[]): void {
  walk(sf, n => {
    if (!isAnyLoop(n)) return
    // D30：for-of/for-in 有界遍历 → 增长受集合大小约束，跳过 R9-3 全部信号
    if (isBoundedIteration(n)) return
    const body = (n as ts.ForStatement | ts.WhileStatement | ts.DoStatement | ts.ForInStatement | ts.ForOfStatement).statement
    const visit = (node: ts.Node): void => {
      if (ts.isFunctionLike(node)) return
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) {
        // 右侧是算术表达式（total += w * coef 类）→ 数值累加，非字符串拼接，不报（自扫降噪）
        if (isArithmeticRhs(node.right)) return
        found.push({
          rule: 'R9',
          severity: 'info',
          confidence: 'heuristic',
          message: '循环内 += 累加（字符串拼接可能 O(n²)）',
          evidence: node.getText(sf).slice(0, 200),
          line: lineOf(sf, node),
        })
        return
      }
      if (ts.isCallExpression(node)) {
        const callee = node.expression
        if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'set' && ts.isIdentifier(callee.expression)) {
          found.push({
            rule: 'R9',
            severity: 'medium',
            confidence: 'likely',
            message: '循环内集合写入 map.set（无界增长信号）',
            evidence: node.getText(sf).slice(0, 200),
            line: lineOf(sf, node),
          })
          return
        }
        if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'all'
          && ts.isIdentifier(callee.expression) && callee.expression.text === 'Promise') {
          found.push({
            rule: 'R9',
            severity: 'info',
            confidence: 'heuristic',
            message: '循环内 Promise.all（无界并发信号）',
            evidence: node.getText(sf).slice(0, 200),
            line: lineOf(sf, node),
          })
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(body)
  })
}

export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (ts.isCallExpression(n)) checkArrayAlloc(n, sf, found)
    if (ts.isNewExpression(n)) checkArrayAlloc(n, sf, found)
    const loop = unboundedLoop(n)
    if (loop === undefined) return
    const body = loop.statement
    const sig = exitSignals(body)
    if (sig.hasAwait) {
      found.push({
        rule: 'R9',
        severity: 'info',
        confidence: 'heuristic',
        message: '无出口常驻循环（含 await，可能是合法服务循环；交由 LLM 审计复核上下文）',
        evidence: loop.getText(sf).slice(0, 200),
        line: lineOf(sf, loop),
      })
      return
    }
    if (!sig.hasBreak && !sig.hasReturn && !sig.hasThrow) {
      // generic（通用/官方代码，含 minified bundle）：死循环是风险提示 → medium；
      // bin 入口文件（round-7：CLI 脚本独立运行，忙等是应用自身问题）同样 medium；
      // DSH 插件包（plugin）保持 high（插件死循环是 DoS 逃逸面）
      const generic = _ctx.request.targetKind === 'generic' || _ctx.cliFiles?.has(sf.fileName) === true
      found.push({
        rule: 'R9',
        severity: generic ? 'medium' : 'high',
        confidence: 'certain',
        message: generic
          ? '无出口同步循环（死循环/忙等：无 break/return/throw/await；minified bundle 可能误判）'
          : '无出口同步循环（死循环/忙等：无 break/return/throw/await，可卡死宿主事件循环）',
        evidence: loop.getText(sf).slice(0, 200),
        line: lineOf(sf, loop),
      })
      const spawns: ts.Node[] = []
      collectSpawns(body, spawns)
      for (const s of spawns) {
        found.push({
          rule: 'R9',
          severity: 'high',
          confidence: 'likely',
          message: '无出口循环内启动子进程/worker（fork 炸弹模式）',
          evidence: s.getText(sf).slice(0, 200),
          line: lineOf(sf, s),
        })
      }
    }
  })
  checkReDoS(sf, found)
  checkRecursion(sf, found)
  checkLoopBodyPatterns(sf, found)
  return found
}
