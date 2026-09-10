import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'
import { isTestOrCiFile } from './process-direct.js'

/**
 * R13 network-exfil: hardcoded exfiltration sinks in string literals.
 *
 * Messaging webhooks (Discord/Telegram/Slack), cloud-metadata endpoints
 * (IAM credential exfiltration surface) and Tor hidden services are
 * damning static evidence wherever they appear in a plugin's source, in the
 * same spirit as R7 hardcoded secrets. Regex over string-literal text only
 * (never evaluated), one finding per pattern per literal.
 *
 * round-23（0.3.10 误报治理，OSS 注册表 64 例反馈）：判定从「字面量内出现端点子串即
 * high」收紧为三层，消除三类系统性误报——拒绝名单/守卫、散文/标签/文档串、形状不合法的
 * .onion 命中：
 *   ① 端点形状：整字面量必须整体形如 host/IP/URL（模板字面量任一静态段亦算）。散文/标签/
 *      说明串不再命中（直接丢弃，零噪音）；
 *   ② Tor 只认合法 label（v2 16 / v3 56 base32）——action.onion、句子里的 .onion 不再命中；
 *   ③ 守卫/拒绝名单语境降 info（能力触达面观测，不再推高 verdict）：相等性比较操作数
 *      （host === "metadata.google.internal"）、new Set(...) 且绑定被 .has()/.includes()/
 *      .indexOf() 消费、Object.freeze(...) 表、容器绑定名含 DENY/BLOCK/REFUSE 等守卫语义；
 *      测试/CI 文件同 R3 口径降 info（开发期行为，非发布物逃逸通道）。
 * 脱敏占位（[REDACTED]、***、xxxx 类占位串）同样降 info。真阳性通道（webhook URL /
 * 合法 onion 地址，且非守卫/测试语境）保持 high/likely。
 */
const EXFIL_PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /discord(app)?\.com\/api\/webhooks/i, desc: 'Discord webhook（数据外泄端点）' },
  { re: /api\.telegram\.org\/bot[0-9]+:/i, desc: 'Telegram bot webhook（数据外泄端点）' },
  { re: /hooks\.slack\.com\/services/i, desc: 'Slack webhook（数据外泄端点）' },
  { re: /169\.254\.169\.254/, desc: 'AWS 云元数据端点（IAM 凭据外泄面）' },
  { re: /metadata\.(google|compute)\.internal/i, desc: '云元数据端点（IAM 凭据外泄面）' },
  { re: /100\.100\.100\.200/, desc: '阿里云元数据端点（凭据外泄面）' },
  // round-23：只认合法 Tor label（v2 16 / v3 56 位 base32，[a-z2-7]）；"action.onion"、
  // 句子里的裸 .onion 不再命中（此前 /.onion\b/ 命中一切包含 .onion 的串）。
  { re: /(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b/i, desc: 'Tor 隐藏服务目标（匿名外泄）' },
]

/**
 * ① 端点形状：整字面量必须是 host/IP/URL（host/IP 部分必选，scheme/端口/路径可选）。
 * 散文（"cloud metadata (169.254.169.254) is not allowed"）、标签、说明串天然不满足。
 */
const ENDPOINT_SHAPE =
  /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:\.?[a-z0-9-]+)+(?:\.[a-z]{2,})?(?::\d+)?(?:\/[^\s]*)?$/i
function isEndpointShaped(text: string): boolean {
  return ENDPOINT_SHAPE.test(text)
}

/** ④ 脱敏占位：evidence 含 [REDACTED]、***、xxxx 占位串（示例模板，非真实端点）。 */
const REDACTED_MARK = /\[REDACTED\]|\*{3,}|(?:^|[^a-z0-9])x{4,}(?:[^a-z0-9]|$)/i
function isRedacted(text: string): boolean {
  return REDACTED_MARK.test(text)
}

/** ③ 守卫/拒绝名单容器命名提示（辅助置信，不作主判）。 */
const GUARD_NAME =
  /(?:DENY|BLOCK|REFUSE|FORBID|GUARD|PRIVATE|RESERVED|INTERNAL|METADATA|SSRF)/i

/** 成员判定方法：Set.has / Array.includes / Array.indexOf（守卫消费特征）。 */
const MEMBERSHIP_METHODS = new Set(['has', 'includes', 'indexOf'])

/** 收集每个标识符绑定名的属性访问成员名（.has/.includes/.indexOf 等消费判定）。 */
function collectMemberUses(sf: ts.SourceFile): Map<string, Set<string>> {
  const uses = new Map<string, Set<string>>()
  walk(sf, n => {
    if (!ts.isPropertyAccessExpression(n)) return
    const e = n.expression
    if (!ts.isIdentifier(e)) return
    let set = uses.get(e.text)
    if (set === undefined) {
      set = new Set()
      uses.set(e.text, set)
    }
    set.add(n.name.text)
  })
  return uses
}

/** 收集被下标访问的标识符绑定名（BLOCKED_HOSTS[host] 查表形态）。 */
function collectElementUses(sf: ts.SourceFile): Set<string> {
  const uses = new Set<string>()
  walk(sf, n => {
    if (!ts.isElementAccessExpression(n)) return
    const e = n.expression
    if (ts.isIdentifier(e)) uses.add(e.text)
  })
  return uses
}

/** 绑定名分析：从表达式向上找最近的变量声明（≤3 跳，跨语句/函数即停）。 */
function bindingNameOf(init: ts.Node): string | undefined {
  let cur: ts.Node | undefined = init
  for (let i = 0; i < 3 && cur !== undefined; i++) {
    const p: ts.Node | undefined = cur.parent
    if (p !== undefined && ts.isVariableDeclaration(p) && p.initializer === cur && ts.isIdentifier(p.name)) {
      return p.name.text
    }
    if (p !== undefined && (ts.isStatement(p) || ts.isFunctionLike(p))) return undefined
    cur = p
  }
  return undefined
}

/** 从字面量向上找最近的数组字面量容器（允许少量调用包装如 rule("1.2.3.4", …)；跨语句/函数即停）。 */
function arrayContainerOf(n: ts.Node): ts.ArrayLiteralExpression | undefined {
  let cur: ts.Node | undefined = n.parent
  for (let hops = 0; cur !== undefined && hops < 6; hops++) {
    if (ts.isArrayLiteralExpression(cur)) return cur
    if (ts.isStatement(cur) || ts.isFunctionLike(cur)) return undefined
    cur = cur.parent
  }
  return undefined
}

/** Object.freeze(...) 调用判定（含 Object['freeze'] 形态）。 */
function isObjectFreezeCallee(expr: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(expr)
    && ts.isIdentifier(expr.expression) && expr.expression.text === 'Object'
    && expr.name.text === 'freeze') return true
  if (ts.isElementAccessExpression(expr)
    && ts.isIdentifier(expr.expression) && expr.expression.text === 'Object'
    && ts.isStringLiteralLike(expr.argumentExpression) && expr.argumentExpression.text === 'freeze') return true
  return false
}

function consumedByMembership(name: string, uses: Map<string, Set<string>>): boolean {
  const set = uses.get(name)
  if (set === undefined) return false
  for (const m of set) if (MEMBERSHIP_METHODS.has(m)) return true
  return false
}

/**
 * 数组容器是否具守卫语义（G2）：
 *  - new Set(arr) 且绑定被成员判定消费或绑定名含守卫语义；
 *  - Object.freeze(arr) / 直接绑定数组：绑定名含守卫语义或被成员判定消费。
 */
function isGuardArray(arr: ts.ArrayLiteralExpression, uses: Map<string, Set<string>>): boolean {
  const parent = arr.parent
  if (parent !== undefined && ts.isCallExpression(parent) && parent.arguments[0] === arr) {
    const callee = parent.expression
    if (ts.isNewExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === 'Set') {
      const b = bindingNameOf(parent)
      return b !== undefined && (GUARD_NAME.test(b) || consumedByMembership(b, uses))
    }
    if (isObjectFreezeCallee(callee)) {
      const b = bindingNameOf(parent)
      return b !== undefined && (GUARD_NAME.test(b) || consumedByMembership(b, uses))
    }
    return false
  }
  const b = bindingNameOf(arr)
  return b !== undefined && (GUARD_NAME.test(b) || consumedByMembership(b, uses))
}

function isFrozenObject(obj: ts.ObjectLiteralExpression): boolean {
  const p = obj.parent
  return p !== undefined && ts.isCallExpression(p) && p.arguments[0] === obj && isObjectFreezeCallee(p.expression)
}

/**
 * ③ 守卫/拒绝名单语境判定：
 *  G1 相等性比较操作数（===/!==/==/!=）——inner === "metadata.google.internal" 判黑名单；
 *  G2 数组守卫容器（Set+.has / 冻结表 / 绑定名守卫语义 + 成员判定消费）；
 *  G3 对象守卫容器（绑定名守卫语义 + freeze 包装或下标查表消费）。
 * 全部为「有正向守卫证据才降级」——目标列表（Set + for..of + fetch）无成员判定消费，保持原判。
 */
function guardContextOf(
  n: ts.Node,
  uses: Map<string, Set<string>>,
  elemUses: Set<string>,
): boolean {
  const p = n.parent
  if (p !== undefined && ts.isBinaryExpression(p) && (n === p.left || n === p.right)) {
    const op = p.operatorToken.kind
    if (op === ts.SyntaxKind.EqualsEqualsEqualsToken
      || op === ts.SyntaxKind.ExclamationEqualsEqualsToken
      || op === ts.SyntaxKind.EqualsEqualsToken
      || op === ts.SyntaxKind.ExclamationEqualsToken) return true
  }
  const arr = arrayContainerOf(n)
  if (arr !== undefined && isGuardArray(arr, uses)) return true
  let cur: ts.Node | undefined = n.parent
  for (let hops = 0; cur !== undefined && hops < 3; hops++) {
    if (ts.isObjectLiteralExpression(cur)) {
      const b = bindingNameOf(cur)
      if (b !== undefined && GUARD_NAME.test(b) && (isFrozenObject(cur) || elemUses.has(b))) return true
      return false
    }
    if (ts.isStatement(cur) || ts.isFunctionLike(cur)) return false
    cur = cur.parent
  }
  return false
}

interface EmitOpts {
  sf: ts.SourceFile
  n?: ts.Node
  text: string
  pattern: { desc: string }
  decoded?: { method: string; file?: string; line?: number }
}

function emit(
  found: Finding[],
  opts: EmitOpts,
  ctx: RuleContext,
  uses: Map<string, Set<string>>,
  elemUses: Set<string>,
): void {
  const { sf, n, text, pattern, decoded } = opts
  const reasons: string[] = []
  if (isRedacted(text)) {
    reasons.push('脱敏占位（非真实端点）')
  } else {
    const guard = n !== undefined && guardContextOf(n, uses, elemUses)
    if (guard) reasons.push('拒绝名单/守卫语义（非外联目标）')
    else if (isTestOrCiFile(ctx.filePath ?? sf.fileName)) reasons.push('能力触达面（测试/CI 文件）')
  }
  const severity = reasons.length > 0 ? 'info' : 'high'
  const prefix = reasons.length > 0 ? reasons[0] + '：' : ''
  const base = decoded !== undefined ? '硬编码外联端点（经解码还原）：' : '硬编码外联端点：'
  found.push({
    rule: 'R13',
    severity,
    confidence: 'likely',
    ...(decoded !== undefined
      ? { decodedFrom: decoded.method as Finding['decodedFrom'], file: decoded.file, line: decoded.line }
      : n !== undefined ? { line: lineOf(sf, n) } : {}),
    message: prefix + base + pattern.desc,
    evidence: text.slice(0, 200),
  })
}

/**
 * R13 hardcoded external exfiltration sinks. high/likely（守卫/测试/脱敏语境降 info）;
 * literals only.
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  const uses = collectMemberUses(sf)
  const elemUses = collectElementUses(sf)
  walk(sf, n => {
    if (!ts.isStringLiteral(n) && !ts.isNoSubstitutionTemplateLiteral(n) && !ts.isTemplateExpression(n)) return
    const text = ts.isTemplateExpression(n)
      ? n.head.text + n.templateSpans.map(s => s.literal.text).join('')
      : n.text
    for (const p of EXFIL_PATTERNS) {
      // 保留原字面量 flags（/i 等）——只传 'g' 会丢弃大小写不敏感标志
      const re = new RegExp(p.re.source, p.re.flags)
      const m = re.exec(text)
      if (m === null) continue
      // ① 端点形状：整字面量（或模板字面量的任一静态段）不形如端点 → 散文/标签/说明串，
      // 直接丢弃本字面量（不再看其余 pattern）
      const shaped = isEndpointShaped(text)
        || (ts.isTemplateExpression(n)
          && [n.head, ...n.templateSpans.map(s => s.literal)].some(seg => isEndpointShaped(seg.text)))
      if (!shaped) break
      emit(found, { sf, n, text, pattern: p }, ctx, uses, elemUses)
      break // 每个 pattern 每段只报一条
    }
  })
  // N2：解码语料并入同一模式匹配（base64/hex/charCode/拼接还原的端点）
  for (const d of ctx.decodedLiterals ?? []) {
    for (const p of EXFIL_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags)
      const m = re.exec(d.text)
      if (m === null) continue
      if (!isEndpointShaped(d.text)) break
      emit(found, { sf, text: d.text, pattern: p, decoded: { method: d.method, file: d.file, line: d.line } }, ctx, uses, elemUses)
      break
    }
  }
  return found
}