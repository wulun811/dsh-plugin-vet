import ts from 'typescript'
import type { Finding, RuleContext, Severity } from '../protocol.js'
import { walk, stringyValue, lineOf } from '../ast.js'
import { tryDecodeLiteral } from '../decode.js'
import { moduleBindings } from '../capability.js'
import { isTestOrCiFile } from './process-direct.js'

type DecodeMethod = 'base64' | 'hex' | 'charCode' | 'concat' | 'template'

/**
 * R20 shell download-and-exec in JS exec/spawn-family arguments (round-15, 0.3.2).
 *
 * 背景（外部实测对抗样本/演练）：`exec('curl ... | sh')` 这类 JS 内嵌下载即执行串此前
 * 无静态规则命中——R6 只做 info 级粗扫（且无 curl 模式），R14 只覆盖随包分发的非 JS
 * 脚本文件（.sh/.ps1/...）。本规则把 R14 同款模式收口到 **exec/spawn 族调用实参位**：
 * 「child_process 绑定 + 危险命令实参」双信号 = 组合证据（N6 纪律：单串永不直接判红；
 * R14 的 curl -o 落盘形态降 medium——下载不等于执行）。
 *
 * 覆盖形态：exec/spawn/execSync/spawnSync/execFile/execFileSync/fork 的首实参与多实参
 * （spawn('sh', ['-c', 'curl|sh']) 数组形态同样命中）；实参支持 N2 窄解码
 * （exec(Buffer.from('...', 'base64')) 还原后同样命中，带 decodedFrom 标注）；
 * 文件级解码语料（atob/常量拼接还原的字符串）在有 child_process 绑定的文件里同样
 * 并入匹配（与 R13 同语料纪律）。
 *
 * round-16（0.3.3）：绑定口径升级（capability.moduleBindings 二次绑定）——
 * `const { exec } = cp` 解构别名、`const e2 = exec` 别名转发、`util.promisify(cp.exec)`
 * 包装、`const a = { b: { cp: require('child_process') } }` 对象内嵌（属性链根判定）
 * 均可命中；N2 新增 Array.join 组装解码与 Buffer.from 拼接递归；curl/wget/|sh 三式
 * 大小写不敏感（CURL|SH 不再绕过）；动态中段实参按"静态片段占位"匹配（partial 标注），
 * 实参位与文件级语料同文本去重（不再双报）。
 *
 * 降级：generic（官方/信任包）→ info；测试/CI 文件 → info（fixture 与测试代码天然含
 * 对抗字符串）。与 R14 同口径：普通 `exec('curl -s <url>')`（无管道、无落盘）不报——
 * 桥接类插件合法调用 curl 是正常集成面，零误报优先。
 */
const EXEC_OPS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'])

/** 与 R14 DOWNLOAD_EXEC 同款模式（优先级顺序即判定顺序：管道/编码形态在前，落盘 medium 在后）。 */
const SUSPECT_PATTERNS: { re: RegExp; desc: string; sev?: 'high' | 'medium' }[] = [
  { re: /curl[^\n|]*\|\s*(ba|z)?sh\b/i, desc: 'curl|sh 远程代码执行' },
  { re: /wget[^\n|]*\|\s*(ba|z)?sh\b/i, desc: 'wget|sh 远程代码执行' },
  { re: /(iwr|Invoke-WebRequest|DownloadString)[^\n]*\|/i, desc: 'PowerShell 下载管道' },
  { re: /powershell[^\r\n]{0,120}-enc(odedcommand)?\b/i, desc: '编码 PowerShell（隐藏载荷）' },
  { re: /\b(IEX|Invoke-Expression)\b/i, desc: 'PowerShell Invoke-Expression' },
  { re: /\b(certutil|bitsadmin|mshta|scrobj|regsvr32|rundll32)\b/i, desc: '系统下载/执行原语' },
  { re: /curl[^\n]*-o\s+\S+/i, desc: 'curl 下载落盘', sev: 'medium' },
  { re: /\bpython[0-9]?\s+-[cC]\b[^\n]{0,220}\b(urllib|requests|urlopen|urlretrieve|exec)\b/i, desc: 'Python -c 网络/执行脚本' },
  { re: /\bruby\s+-[eE]\b[^\n]{0,160}\b(Net::HTTP|open-uri|system|exec)\b/i, desc: 'Ruby -e 网络/执行脚本' },
  { re: /\bperl\s+-[eE]\b[^\n]{0,160}\b(LWP|HTTP::(Tiny|Request)|system|exec)\b/i, desc: 'Perl -e 网络/执行脚本' },
]

const MAX_FINDINGS_PER_FILE = 12

/** 实参文本收集：静态字面量/模板 + N2 解码兜底 + 动态段占位片段
 * （round-16：`exec('curl -s ' + url + ' | sh')` 可静态匹配的字面量头尾此前被整体丢弃；
 * 片段文本用 \u0000 占位动态段后仍可命中完整危险形态，见 fragmentText）。 */
interface ArgText { text: string; decodedFrom?: DecodeMethod; partial?: boolean }
function argTexts(arg: ts.Expression, sf: ts.SourceFile): ArgText[] {
  const out: ArgText[] = []
  const sv = stringyValue(arg, sf)
  if (sv !== undefined) out.push({ text: sv.text })
  const dec = tryDecodeLiteral(arg, sf)
  if (dec !== undefined && dec.text !== sv?.text) out.push({ text: dec.text, decodedFrom: dec.method })
  const frag = fragmentText(arg, sf)
  if (frag !== undefined && frag !== sv?.text && !out.some(o => o.text === frag)) out.push({ text: frag, partial: true })
  return out
}

/** 动态段占位片段求值：模板/二进制加号中"能静态求值的字面量部分"拼接，
 * 动态子表达式以 \u0000 占位（绝不猜测动态值；全部是动态 → undefined）。 */
function fragmentText(node: ts.Expression, sf: ts.SourceFile): string | undefined {
  if (ts.isTemplateExpression(node)) {
    const parts: string[] = []
    let hasStatic = false
    const pushPart = (text: string, exact: boolean): void => {
      if (text !== '') hasStatic = hasStatic || /\S/.test(text)
      parts.push(text)
    }
    pushPart(node.head.text, true)
    for (const span of node.templateSpans) {
      const sub = stringyValue(span.expression, sf)
      if (sub !== undefined) pushPart(sub.text, sub.exact)
      else {
        const inner = fragmentText(span.expression, sf)
        if (inner !== undefined) pushPart(inner, false)
        else pushPart('\u0000', false)
      }
      pushPart(span.literal.text, true)
    }
    if (!hasStatic) return undefined
    return parts.join('')
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const lv = stringyValue(node.left, sf)
    const rv = stringyValue(node.right, sf)
    const lf = lv !== undefined ? { text: lv.text, exact: true } : fragmentOf(node.left, sf)
    const rf = rv !== undefined ? { text: rv.text, exact: true } : fragmentOf(node.right, sf)
    const f = (p: { text: string; exact: boolean } | undefined, fallback: string): string => p !== undefined && p.text !== '' ? p.text : fallback
    const left = f(lf, '\u0000')
    const right = f(rf, '\u0000')
    if (left === '\u0000' && right === '\u0000') return undefined
    return left + right
  }
  return undefined
}

/** fragmentText 的辅助：等价于 stringyValue 但允许占位。 */
function fragmentOf(node: ts.Expression, sf: ts.SourceFile): { text: string; exact: boolean } | undefined {
  const sub = stringyValue(node, sf)
  if (sub !== undefined) return { text: sub.text, exact: sub.exact }
  const frag = fragmentText(node, sf)
  return frag !== undefined ? { text: frag, exact: false } : undefined
}

function firstPattern(text: string): { re: RegExp; desc: string; sev?: 'high' | 'medium' } | undefined {
  for (const p of SUSPECT_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags)
    if (re.test(text)) return p
  }
  return undefined
}

function isCpBase(base: ts.Expression, cpRefs: Set<string>): boolean {
  if (ts.isIdentifier(base)) return base.text === 'child_process' || cpRefs.has(base.text)
  if (ts.isCallExpression(base)) {
    const callee = base.expression
    if (ts.isIdentifier(callee) && callee.text === 'require' && base.arguments.length > 0) {
      const spec = stringyValue(base.arguments[0], base.getSourceFile())
      if (spec !== undefined && spec.text.replace(/^node:/, '') === 'child_process') return true
    }
  }
  // round-16：属性链递归到根（a.b.cp.spawn → a 被 object-literal 绑定为 cp 时命中）
  if (ts.isPropertyAccessExpression(base)) return isCpBase(base.expression, cpRefs)
  return false
}

function isExecCall(n: ts.CallExpression, cpRefs: Set<string>, execAliasRefs: Set<string>): boolean {
  const callee = n.expression
  if (ts.isIdentifier(callee)) {
    // round-16：执行位 = EXEC_OPS 字面名 ∪ promisify/别名转发出的调用名（execAsync 等），
    // 二者都要求 cp 绑定（moduleBindings 二次绑定集）。
    return (EXEC_OPS.has(callee.text) || execAliasRefs.has(callee.text)) && cpRefs.has(callee.text)
  }
  if (ts.isPropertyAccessExpression(callee)) {
    return EXEC_OPS.has(callee.name.text) && isCpBase(callee.expression, cpRefs)
  }
  return false
}

/**
 * R20: shell download-and-exec in exec/spawn-family arguments.
 * high/likely（管道/编码/系统原语形态，→ suspicious）；medium/likely（curl -o 落盘）；
 * generic 与测试/CI 文件 → info（能力触达面，不进 verdict）。
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const { cpRefs, execAliasRefs } = moduleBindings(sf)
  const generic = ctx.request.targetKind === 'generic'
  const testOrCi = isTestOrCiFile(ctx.filePath ?? sf.fileName)
  const found: Finding[] = []
  // require('child_process').exec(...) 直调形态无解构绑定（cpRefs 为空）——walk 中识别为
  // 「文件确实引用 child_process」，供 isExecCall 的 require-base 分支与文件级语料闸门使用。
  let directRequireCp = false
  const push = (p: NonNullable<ReturnType<typeof firstPattern>>, text: string, node: ts.Node, opts: { decodedFrom?: DecodeMethod; partial?: boolean } = {}): void => {
    if (found.length >= MAX_FINDINGS_PER_FILE) return
    let severity: Severity = p.sev ?? 'high'
    if (generic || testOrCi) severity = 'info'
    const suffix = generic ? '（能力触达面：官方/信任包）' : testOrCi ? '（测试/CI 文件）' : '（exec/spawn 实参，进程内命令执行面）'
    found.push({
      rule: 'R20',
      severity,
      confidence: 'likely',
      message: 'exec 实参下载即执行'
        + (opts.decodedFrom !== undefined ? '（经解码还原）' : '')
        + (opts.partial === true ? '（实参含动态段，静态片段命中）' : '')
        + '：' + p.desc + suffix,
      evidence: text.slice(0, 200),
      line: lineOf(sf, node),
      ...(opts.decodedFrom !== undefined ? { decodedFrom: opts.decodedFrom } : {}),
    })
  }

  // 1) 实参位：exec/spawn 族调用的字面量/模板/解码实参（数组实参逐元素展开：
  //    spawn('sh', ['-c', 'curl … | sh']) 形态；ArrayLiteral 元素可能含展开/动态项，跳过即可）
  const reported = new Set<string>() // round-16：实参位已报文本 → 文件级语料去重（同一解码串此前双报）
  walk(sf, n => {
    if (found.length >= MAX_FINDINGS_PER_FILE) return
    if (!ts.isCallExpression(n)) return
    if (ts.isIdentifier(n.expression) && n.expression.text === 'require' && n.arguments.length > 0) {
      const sv = stringyValue(n.arguments[0], sf)
      if (sv !== undefined && sv.text.replace(/^node:/, '') === 'child_process') directRequireCp = true
    }
    if (!isExecCall(n, cpRefs, execAliasRefs)) return
    const argsToScan: ts.Expression[] = []
    for (const arg of n.arguments) {
      if (ts.isArrayLiteralExpression(arg)) argsToScan.push(...arg.elements)
      else argsToScan.push(arg)
    }
    for (const arg of argsToScan) {
      for (const at of argTexts(arg, sf)) {
        const p = firstPattern(at.text)
        if (p === undefined) continue
        push(p, at.text, n, { decodedFrom: at.decodedFrom, partial: at.partial })
        reported.add(at.text)
        return // 每个调用位一条（按 SUSPECT_PATTERNS 优先级取首个命中）
      }
    }
  })

  // 2) 文件级解码语料：文件引用 child_process（绑定或直调 require）时，N2 还原的字符串并入
  //    同一匹配（const s = atob('...'); exec(s) 这类文件内变量中转形态）
  const hasCpUsage = cpRefs.size > 0 || directRequireCp
  for (const d of ctx.decodedLiterals ?? []) {
    if (!hasCpUsage) break
    if (found.length >= MAX_FINDINGS_PER_FILE) break
    if (reported.has(d.text)) continue // 实参位已报同文本 → 不双报
    const p = firstPattern(d.text)
    if (p === undefined) continue
    found.push({
      rule: 'R20',
      severity: generic || testOrCi ? 'info' : (p.sev ?? 'high'),
      confidence: 'likely',
      message: 'exec 实参下载即执行（经解码还原，文件级语料）：' + p.desc,
      evidence: d.text.slice(0, 200),
      decodedFrom: d.method,
      file: d.file,
      line: d.line,
    })
  }
  return found
}