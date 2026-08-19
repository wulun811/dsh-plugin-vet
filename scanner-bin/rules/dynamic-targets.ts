import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'
import { tryDecodeLiteral } from '../decode.js'

/**
 * R15 dynamic-string provenance (N5): "the network target is deliberately
 * constructed so the static layer cannot audit it" is itself a signal.
 *
 * Detects network sinks (fetch / WebSocket / http(s).request|get /
 * net.connect|createConnection) whose target argument cannot be statically
 * resolved to a string (N2's tryDecodeLiteral and stringyValue both fail) →
 * info, heuristic: the runtime target is unknowable from source, so the
 * declared capability side (N1 manifest) cannot name it — runtime observation
 * (N1 hidden-capability red) becomes the only evidence for what host it
 * actually talks to.
 *
 * v2 severity policy: default info (observation) — many legitimate plugins
 * build URLs dynamically. Escalation happens only when other signals stack
 * (N1 hidden-capability firing at runtime is the red signal; this finding
 * stays as its static-side context note).
 *
 * Noise controls (deterministic):
 *  - Resolvable targets (literal / constant concat / template with static
 *    substitutions / N2-decodable atob·Buffer.from·charCode) are declared →
 *    not flagged (N2 already re-feeds their text into R13/R7/R11).
 *  - http(s).request/get with an object-literal first arg = the options form
 *    (http.request({ hostname, path })) → skipped; a plain unresolved
 *    identifier there is ambiguous (could be an options object) → skipped too.
 *  - fetch/WebSocket first arg and net.connect host arg are URL/string by
 *    contract → unresolved identifiers are flagged as dynamic.
 *  - One finding per call site; no argument → skipped.
 * @module dsh-plugin-vet/scanner-r15
 */

type SinkKind = 'fetch' | 'ws' | 'http' | 'net'

interface Sink {
  kind: SinkKind
  argIndex: number
}

function sinkOf(n: ts.CallExpression | ts.NewExpression): Sink | null {
  // new WebSocket(url)：NewExpression 形态（fetch/http/net 都是普通调用）
  if (ts.isNewExpression(n) && n.expression !== undefined && ts.isIdentifier(n.expression) && n.expression.text === 'WebSocket') {
    return { kind: 'ws', argIndex: 0 }
  }
  const callee = n.expression
  if (ts.isIdentifier(callee)) {
    if (callee.text === 'fetch') return { kind: 'fetch', argIndex: 0 }
    if (callee.text === 'WebSocket') return { kind: 'ws', argIndex: 0 }
    return null
  }
  if (!ts.isPropertyAccessExpression(callee)) return null
  const name = callee.name.text
  const base = callee.expression
  const baseName = ts.isIdentifier(base) ? base.text : ''
  if ((name === 'request' || name === 'get') && (baseName === 'http' || baseName === 'https')) {
    return { kind: 'http', argIndex: 0 }
  }
  // round-9（0.1.16 加固）：undici.request/stream/pipeline/upgrade——undici 已在 N1 网络模块面，
  // R15 sink 补齐；首参按契约是 URL/字符串 → 未解析标识符照报（与 fetch 同口径）
  if ((name === 'request' || name === 'stream' || name === 'pipeline' || name === 'upgrade') && baseName === 'undici') {
    return { kind: 'fetch', argIndex: 0 }
  }
  if ((name === 'connect' || name === 'createConnection') && baseName === 'net') {
    return { kind: 'net', argIndex: 1 }
  }
  // require('http')/require('net') 直接属性访问形态：require('http').request(x)
  if (ts.isCallExpression(base)) {
    const rcallee = base.expression
    if (!(ts.isIdentifier(rcallee) && rcallee.text === 'require')) return null
    const spec = base.arguments.length > 0 && ts.isStringLiteral(base.arguments[0]) ? base.arguments[0].text : ''
    if ((name === 'request' || name === 'get') && (spec === 'http' || spec === 'https')) return { kind: 'http', argIndex: 0 }
    if ((name === 'connect' || name === 'createConnection') && spec === 'net') return { kind: 'net', argIndex: 1 }
  }
  return null
}

type Resolution = 'resolved' | 'dynamic' | 'ambiguous' | 'skip'

/** 目标参数的静态可解性：resolved=可声明；dynamic=不可解；ambiguous=标识符未解析（http 表单歧义）；skip=无参数/对象表单。 */
function resolveTarget(node: ts.Expression | undefined, sf: ts.SourceFile): Resolution {
  if (node === undefined) return 'skip'
  if (ts.isObjectLiteralExpression(node)) return 'skip' // http.request({...}) options 表单，目标在字段里
  if (stringyValue(node, sf) !== undefined) return 'resolved'
  if (tryDecodeLiteral(node, sf) !== undefined) return 'resolved'
  if (ts.isIdentifier(node)) return 'ambiguous'
  return 'dynamic'
}

function shouldFlag(kind: SinkKind, res: Resolution): boolean {
  if (res === 'dynamic') return true
  // fetch/WebSocket 首参与 net host 参数按契约是 URL/字符串：未解析标识符也报（源码无法声明目标）。
  if (res === 'ambiguous') return kind === 'fetch' || kind === 'ws' || kind === 'net'
  return false
}

/** R15 dynamic network target (N5): info/heuristic, observation only. */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isCallExpression(n) && !ts.isNewExpression(n)) return
    const sink = sinkOf(n as ts.CallExpression | ts.NewExpression)
    if (sink === null) return
    // NewExpression.arguments 可选（`new WebSocket()` 无参数）；CallExpression.arguments 恒为数组
    const args = (n as ts.CallExpression | ts.NewExpression).arguments ?? []
    const target = args[sink.argIndex]
    const res = resolveTarget(target, sf)
    if (!shouldFlag(sink.kind, res)) return
    const sinkLabel = sink.kind === 'fetch' ? 'fetch' : sink.kind === 'ws' ? 'WebSocket' : sink.kind === 'http' ? 'http(s) 请求' : 'net 连接'
    const targetText = target === undefined ? '' : target.getText(sf).slice(0, 120).replace(/\s+/g, ' ')
    found.push({
      rule: 'R15',
      severity: 'info',
      confidence: 'heuristic',
      message: '网络目标动态构造，静态不可审计（N5）——' + sinkLabel + ' 的目标参数由运行时数据/表达式构成，源码无法声明目标主机；请结合运行时观测（N1 隐能力）确认其实际目标',
      evidence: targetText,
      line: lineOf(sf, n),
    })
  })
  return found
}
