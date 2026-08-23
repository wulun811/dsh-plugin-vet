/**
 * R17 !!js 配置面检测（round-12，0.2.6；覆盖 dsh 40 路径报告 P2/G-3 静态面）。
 *
 * 目标：cordis.yml / cordis.patch.yml / plugin.yml 等根级配置文件里的 `!!js` 表达式。
 * 背景（第三方审计报告）：Loader 在插件 apply 前对 !!js 做配置即代码求值（宿主级 RCE，
 * host 进程可触达 process）；报告实测官方发布物 PWNED-BY-LIVE-JS。此前 cordis.yml/patch
 * 完全不在静态扫描面（SOURCE_EXT 无 yaml、R12 只看 package.json）。
 *
 * 设计纪律（N1/N2/N5/N6，见 PLAN-supplement-vet-capabilities.md）：
 *   - 只提取文本，绝不 eval/执行/require —— 这是处理不可信配置的红线；
 *   - 自研窄解析（行级 tag 识别 + 括号续行），不做完整 YAML 语义（anchor/merge/tag 处理
 *     才是 YAML 解析器的攻击面，这里完全不碰）；
 *   - 输入硬上限：表达式数 ≤64/文件、单条 ≤8KB、续行 ≤6 行 —— 超限即截断，防 DoS；
 *   - severity：单动词恒 info/heuristic（官方 bundle 自己就用 !!js 做合法配置，
 *     单条命中把官方包扫红是灾难）；「危险动词 + 外联主机/凭据路径」双组合才 high/likely；
 *   - 测试/CI 文件内一律降 info（复用 R3 的 isTestOrCiFile 语义）；
 *   - 词表遵循「组合命中」纪律：单串永不直接 high（N6，规则数据不自伤）。
 */
import { decodeB64, decodeHex } from '../decode.js'
import { isTestOrCiFile } from './process-direct.js'
import type { Finding } from '../protocol.js'

/** 配置文件扩展名（walker 侧 SOURCE_EXT 已过滤；engine 侧再按本规则收口）。 */
export const CONFIG_EXT = new Set(['yml', 'yaml'])

/** 根级配置文件名：cordis.yml / cordis.patch.yml / plugin.yml / *.patch.yml。 */
export function isRootConfigName(name: string): boolean {
  return /^(cordis|plugin)\.ya?ml$/i.test(name) || /\.patch\.ya?ml$/i.test(name)
}

/** 单文件表达式上限（防 DoS，N2 同款纪律）。 */
const MAX_EXPR = 64
const MAX_EXPR_BYTES = 8 * 1024
const MAX_CONT_LINES = 6
const MAX_FINDINGS_PER_FILE = 16

// ── 危险动词（配置加载期执行面；单条命中 → info）──────────────────────────
const DANGER_VERBS: { re: RegExp; label: string }[] = [
  { re: /\bchild_process\b/, label: 'child_process' },
  { re: /\bprocess\s*\.\s*exit\b/, label: 'process.exit' },
  { re: /\brequire\s*\(\s*['"](?:child_process|vm|worker_threads|cluster|fs|net|tls|dgram|http|https)/, label: 'require(危险模块)' },
  { re: /\beval\s*\(/, label: 'eval(' },
  { re: /\bnew\s+Function\b/, label: 'new Function' },
  { re: /\bfetch\s*\(/, label: 'fetch(' },
  { re: /\b(?:http|https)\.request\b/, label: 'http.request' },
  { re: /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(/, label: '子进程调用' },
  { re: /\bvm\./, label: 'vm.' },
  { re: /\b(?:curl|wget|nc|ncat|telnet)\b/, label: 'shell 外联工具' },
  { re: /\b(?:powershell|pwsh|Invoke-WebRequest|DownloadString|-enc\b)/i, label: 'PowerShell 下载即执行' },
  { re: /\b(?:globalThis|global)\s*\.\s*process\b/, label: 'global.process' },
]

// ── 外联主机（与 src/guard/runtime-net.ts SENSITIVE_HOSTS 同构；回环/白名单不算）──
const EXFIL_HOSTS: { re: RegExp; label: string }[] = [
  { re: /webhook\.site/i, label: 'webhook.site' },
  { re: /requestbin\.com/i, label: 'requestbin.com' },
  { re: /ngrok\.io/i, label: 'ngrok.io' },
  { re: /localtunnel\.me/i, label: 'localtunnel.me' },
  { re: /pastebin\.com/i, label: 'pastebin.com' },
  { re: /oast\.(?:me|live)/i, label: 'OOB 外联(oast)' },
  { re: /burpcollaborator\.net/i, label: 'Burp Collaborator' },
  { re: /dnslog\.cn/i, label: 'dnslog.cn' },
  { re: /interact\.sh/i, label: 'interact.sh' },
  { re: /\b(?:api\.binance\.com|api\.coinbase\.com)\b/i, label: 'crypto API' },
  // 裸外网 IP：候选正则 + 非公开段复检（见 scanText 的 __ip__ 分支）
  { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, label: '__ip__' },
]

// ── 凭据/密钥路径段（与 confirm-block credentialFiles 同构；收窄到"路径/文件名"形态，
//    裸词 credentials/secrets 不判——配置对象字段名是合法常见形态，会误伤）──────────
const CRED_SEGMENTS: { re: RegExp; label: string }[] = [
  { re: /~?\/\.ssh|id_rsa|id_ed25519|id_ecdsa|id_dsa/, label: 'SSH 私钥' },
  { re: /~?\/\.aws|aws_access_key/, label: 'AWS 凭据' },
  { re: /credentials\.ya?ml\b/, label: '凭据文件(credentials.yaml)' },
  { re: /~?\/\.npmrc/, label: '.npmrc token' },
  { re: /~?\/\.env\b|\.env\./, label: '.env' },
  { re: /~?\/\.kube|kubeconfig/, label: 'kubeconfig' },
  { re: /~?\/\.pgpass|~?\/\.netrc|\.git-credentials/, label: '认证文件' },
  { re: /-----BEGIN(?: [A-Z ]+)? PRIVATE KEY-----/, label: '硬编码私钥' },
]

/** 私有/保留/回环地址段（集成测试网 172.16-31、CGNAT 100.64-127 等）——不算"外联目标"。 */
const NON_PUBLIC_IP_RE = /^0\.|^10\.|^127\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\.|^100\.(6[4-9]|[7-9]\d|1\d\d)\.|^192\.0\.|^198\.(18|19)\.|^203\.0\.113\.|^22[4-9]\.|^23\d\.|^24\d\./

interface JsExpr { text: string; line: number }

/** 剥离行注释（# 在引号/中括号外才剥；配置里 # 极少用引号包，保守处理）。 */
function stripComment(line: string): string {
  let inS = false
  let inD = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === "'" && !inD) inS = !inS
    else if (c === '"' && !inS) inD = !inD
    else if (c === '#' && !inS && !inD) return line.slice(0, i)
  }
  return line
}

/** 在行内找 !!js / !js / !!js/function tag 的位置（跳过引号内出现）。
 * 返回表达式起点（tag 之后）或 -1。 */
function findJsTagIndex(line: string): number {
  const m = /(?:^|[^A-Za-z0-9_-])(!!js(?:\/function)?|!js)\b/.exec(line)
  if (m === null) return -1
  const tagStart = m.index + (m[0].length - m[1].length)
  // 校验 tag 不在引号内（配置模板示例里的 !!js 文本不提取）
  let inS = false
  let inD = false
  for (let i = 0; i < tagStart; i++) {
    const c = line[i]
    if (c === "'" && !inD) inS = !inS
    else if (c === '"' && !inS) inD = !inD
  }
  if (inS || inD) return -1
  return m.index + m[0].length
}

/** 剥掉表达式外层引号（!!js "..." 形态）。 */
function unquote(expr: string): string {
  const t = expr.trim()
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    // 去首尾引号，内部转义保持原样（文本判定不关心转义结果）
    return t.slice(1, -1)
  }
  // !!js |js| 形态（yaml-js 约定）：去管道分隔
  const pipe = /^\|(\w+)\|\s*(.*)$/.exec(t)
  if (pipe !== null) return pipe[2]
  return t
}

/** 括号配平度（>0 = 有未闭合，需要续行）。 */
function bracketDelta(line: string): number {
  let d = 0
  let inS = false
  let inD = false
  for (const c of line) {
    if (c === "'" && !inD) inS = !inS
    else if (c === '"' && !inS) inD = !inD
    else if (!inS && !inD) {
      if (c === '(' || c === '{' || c === '[') d++
      else if (c === ')' || c === '}' || c === ']') d--
    }
  }
  return d
}

/** 提取全部 !!js 表达式文本（只取文本，绝不求值）。 */
function extractJsExpressions(content: string): JsExpr[] {
  const out: JsExpr[] = []
  const lines = content.split(/\r?\n/)
  for (let i = 0; i < lines.length && out.length < MAX_EXPR; i++) {
    const stripped = stripComment(lines[i])
    const tag = findJsTagIndex(stripped)
    if (tag === -1) continue
    let expr = unquote(stripped.slice(tag))
    let depth = bracketDelta(expr)
    let j = i + 1
    while (depth > 0 && j < lines.length && j - i <= MAX_CONT_LINES) {
      const more = stripComment(lines[j])
      expr += '\n' + more
      depth += bracketDelta(more)
      j++
    }
    expr = expr.trim()
    if (expr === '') continue
    if (expr.length > MAX_EXPR_BYTES) expr = expr.slice(0, MAX_EXPR_BYTES)
    out.push({ text: expr, line: i + 1 })
  }
  return out
}

/** base64/hex 窄解码（N2 同款上限：单串 ≤4KB）。返回还原的文本。 */
function decodeTexts(expr: string): string[] {
  const out: string[] = []
  // base64：≥40 字符的字母数字+/= 长串（短串噪声多，不尝试）
  for (const m of expr.matchAll(/[A-Za-z0-9+/=]{40,}/g)) {
    const t = m[0].replace(/[^A-Za-z0-9+/=]/g, '')
    const d = decodeB64(t)
    if (d !== undefined && d.length <= 4096) out.push(d)
  }
  // hex：≥64 字符纯 hex
  for (const m of expr.matchAll(/\b[0-9a-fA-F]{64,}\b/g)) {
    const d = decodeHex(m[0])
    if (d !== undefined && d.length <= 4096) out.push(d)
  }
  return out
}

/** 对一段文本跑动词/外联/凭据特征（去重）。凭据面先剥 process.env/import.meta.env 语境
 * （'.env.' 会误匹配 'process.env.' 结构——合法配置读 env 变量路径是常态，必须排除）。 */
function scanText(text: string, decoded: boolean): { verbs: string[]; hosts: string[]; creds: string[] } {
  const verbs: string[] = []
  const hosts: string[] = []
  const creds: string[] = []
  for (const v of DANGER_VERBS) if (v.re.test(text)) verbs.push(v.label)
  for (const h of EXFIL_HOSTS) {
    if (h.label === '__ip__') {
      // 裸 IP 复检：仅非公开段才算外联目标（8.8.8.8 算；172.16/10./192.168 等不算）
      let m: RegExpExecArray | null
      const re = new RegExp(h.re.source, 'g')
      let foundPublic = false
      while ((m = re.exec(text)) !== null) {
        if (!NON_PUBLIC_IP_RE.test(m[0])) { foundPublic = true; break }
      }
      if (foundPublic) hosts.push('裸 IP 目标')
    } else if (h.re.test(text)) {
      hosts.push(h.label)
    }
  }
  const credHay = text
    .replace(/process\s*\.\s*env\b/gi, '')
    .replace(/import\s*\.\s*meta\s*\.\s*env\b/gi, '')
  for (const c of CRED_SEGMENTS) if (c.re.test(credHay)) creds.push(c.label)
  return { verbs: [...new Set(verbs)], hosts: [...new Set(hosts)], creds: [...new Set(creds)] }
}

/**
 * 对一个配置文件跑 R17。text = 文件全文；name = basename；file = 全路径（用于测试/CI 降级）。
 * 返回 findings：!!js 存在性 info 观测 + 单动词 info + 双组合 high。
 */
export function runConfigScan(text: string, name: string, file?: string, targetKind?: 'plugin' | 'generic'): Finding[] {
  const findings: Finding[] = []
  const testOrCi = file !== undefined && isTestOrCiFile(file)
  // 产出一律按测试/CI 降 info 处理（双组合也不例外——测试配置里的载荷是夹具）
  const push = (f: Omit<Finding, 'rule'>, forceInfo = false): void => {
    if (findings.length >= MAX_FINDINGS_PER_FILE) return
    findings.push({
      ...f,
      rule: 'R17',
      file: name,
      severity: forceInfo || testOrCi ? 'info' : f.severity,
    })
  }

  const exprs = extractJsExpressions(text)
  if (exprs.length === 0) return findings
  // 存在性观测（确定性：tag 存在 = 该配置含代码）
  push({
    severity: 'info',
    confidence: 'certain',
    message: '配置含 !!js 表达式（配置即代码，加载期在宿主进程执行）',
    evidence: '!!js ×' + exprs.length,
    line: exprs[0].line,
  })

  const genericDowngrade = targetKind === 'generic'
  for (const expr of exprs) {
    let { verbs, hosts, creds } = scanText(expr.text, false)
    // N2 联动：解码还原的文本同样参与判定（base64/hex 藏 payload）
    for (const d of decodeTexts(expr.text)) {
      const r = scanText(d, true)
      verbs.push(...r.verbs)
      hosts.push(...r.hosts)
      creds.push(...r.creds)
    }
    verbs = [...new Set(verbs)]
    hosts = [...new Set(hosts)]
    creds = [...new Set(creds)]
    if (verbs.length === 0) continue
    const combo = (hosts.length > 0 || creds.length > 0)
    // 双组合 → 每条表达式只产一条 high（多动词并列，避免同一条载荷重复扣分）；
    // 无组合 → 每个动词一条 info 观测（权重 0，只作审计取证）
    if (combo) {
      push({
        severity: genericDowngrade ? 'info' : 'high',
        confidence: 'likely',
        message: '!!js 配置含危险动词 ' + verbs.slice(0, 3).join('/') + ' 且引用外联目标/凭据路径（' +
          [...hosts, ...creds].slice(0, 3).join('、') + '）——配置即代码 + 数据面（P2/G-3 形态）',
        evidence: expr.text.slice(0, 200),
        line: expr.line,
      })
      continue
    }
    for (const v of verbs) {
      // 单动词：info 观测（官方 bundle 自用 !!js 合法配置不误伤；N0 默认不进 verdict）
      push({
        severity: 'info',
        confidence: 'heuristic',
        message: '!!js 配置含危险动词：' + v + '（加载期执行面；单条不判级，组合命中才升级）',
        evidence: expr.text.slice(0, 160),
        line: expr.line,
      })
    }
  }
  return findings
}