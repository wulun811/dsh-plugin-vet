/**
 * R18 指令/技能注入观测（round-12，0.2.6；覆盖 dsh 40 路径报告 G-1/P20/P30 静态面）。
 *
 * 目标：AGENTS.md / CLAUDE.md / CODEGOV.md 与 skills 目录、*.skill 目录下的 SKILL.md 里的
 * 指令注入文本。背景（第三方审计报告）：G-1 恶意仓库指令注入（L0 前提：无需代码执行/安装/审批，
 * 打开目录或 agent 读文件即触发）——恶意仓储里放 AGENTS.md/技能包，诱导模型
 * 读取密钥/外联/覆盖指令；报告实测 baseline + skill 注入均成立。
 *
 * 设计纪律（N0/N6，见 PLAN-supplement-vet-capabilities.md）：
 *   - **组合式命中**：指令动词(V) × 动作目标(A1 凭据/A2 外联/A3 持久化隐藏) 至少两组独立
 *     信号命中才产出 finding；单串永不报（安全工具的防御文案天然含有注入字符串——dsh.so
 *     报告 116 Critical 的教训就是规则数据自引用）；
 *   - **首版全 info/heuristic**：文本面误报方差大，v1 只观测不进 verdict；v2 依据真实
 *     语料误报率再决定哪些组合升 high（N0：默认不判级起步）；
 *   - 只扫指令/技能文件（isInstructionFile 收口），README/docs/任意 .md 不进面；
 *   - 测试/CI 文件恒 info；
 *   - 输入硬上限：单文件 512KB 截断、每文件 ≤12 条 finding；
 *   - 不可见字符剥离（对抗 ZWSP/零宽字符打断模式串）；
 *   - 纯文本正则，无嵌套量词（ReDoS 纪律与既有规则一致）。
 */
import type { Finding } from '../protocol.js'

const MAX_FILE_BYTES = 512 * 1024
const MAX_FINDINGS_PER_FILE = 12

/** 不可见字符（渲染隐形、可被攻击者用来打断模式串，如 "ignore\u200B previous"）：
 * 零宽空格/连接符/不换行空格 U+200B–U+200D、BOM U+FEFF、词连接符 U+2060。
 * 匹配前剥离（只影响自然语言文本面，无副作用；不删换行，行号不变）。 */
const INVISIBLE_RE = /[\u200B-\u200D\uFEFF\u2060]/g
function stripInvisibles(s: string): string {
  return s.replace(INVISIBLE_RE, '')
}

/** 指令/技能文件收口（引擎侧兜底；收集侧 listInstructionFiles 同款白名单）。
 * 只认：AGENTS.md/CLAUDE.md/CODEGOV.md（任意深度，但收集侧限包根/skills），
 * 或路径含 /skills/ 或 .skill 段的 .md。 */
export function isInstructionFile(file: string): boolean {
  const norm = file.replace(/\\/g, '/')
  const base = norm.slice(norm.lastIndexOf('/') + 1)
  if (/^(AGENTS|CLAUDE|CODEGOV)\.md$/i.test(base)) return true
  if (!/\.md$/i.test(base)) return false
  const segs = norm.split('/')
  return segs.includes('skills') || segs.some(s => /\.skill$/i.test(s))
}

// ── 组词表（组合式；单组命中 = 不报）────────────────────────────────────

/** V 指令动词：改写/覆盖既有指令的意图表达。 */
const V_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|prompts?|directives?)/i, label: 'ignore previous instructions' },
  { re: /do\s+not\s+(follow|obey|listen\s+to)\s+(the\s+)?(previous|instructions?|system)/i, label: 'do not follow instructions' },
  { re: /override\s+(the\s+)?(previous|system\s+)?(instructions?|rules?)/i, label: 'override instructions' },
  { re: /disregard\s+(previous|all\s+(other\s+)?instructions?)/i, label: 'disregard instructions' },
  { re: /you\s+are\s+(now|no\s+longer)/i, label: 'you are now…' },
  { re: /new\s+(set\s+of\s+)?instructions?/i, label: 'new instructions' },
  { re: /忽略(之前|先前|上面|以上)(的)?(指令|规则|提示)/, label: '忽略之前指令' },
  { re: /不再(遵守|遵循)(之前|先前)?(的)?(指令|规则)/, label: '不再遵守指令' },
  { re: /从现在开始(听从|照做|执行)/, label: '从现在开始执行' },
]

/** A1 凭据/密钥碰触。 */
const A1_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /~?\/\.ssh|id_rsa|id_ed25519|id_ecdsa/, label: 'SSH 私钥' },
  { re: /~?\/\.aws|aws_access_key/, label: 'AWS 凭据' },
  { re: /(credentials|secrets?|tokens?)/i, label: '凭据/密钥文件' },
  { re: /~?\/\.npmrc/, label: '.npmrc' },
  { re: /~?\/\.env\b|\.env\./, label: '.env' },
  { re: /~?\/\.kube|kubeconfig/, label: 'kubeconfig' },
  { re: /~?\/\.git-credentials|~?\/\.pgpass|~?\/\.netrc/, label: '认证文件' },
]

/** A2 外联/数据外泄。 */
const A2_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /curl\s+[^\n|]{0,40}\|\s*(ba|z)?sh|wget\s+[^\n|]{0,40}\|\s*(ba|z)?sh/i, label: 'curl|sh 下载即执行' },
  { re: /webhook\.site|requestbin\.com|ngrok\.io|localtunnel\.me|pastebin\.com/i, label: '外联采集站' },
  { re: /oast\.(me|live)|burpcollaborator\.net|dnslog\.cn|interact\.sh/i, label: 'OOB 外联' },
  { re: /\bnc\s+-[a-zA-Z]*[el]/i, label: 'netcat 连接/监听' },
  { re: /(upload|发送|贴到|post\s+to)\b.{0,30}(https?:\/\/|webhook|pastebin)/i, label: '上传到外部' },
]

/** A3 持久化/隐藏痕迹。 */
const A3_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /crontab|chmod\s+\+s|authorized_keys/i, label: '持久化后门面' },
  { re: /(>>|append|写入|追加).{0,20}(\.bashrc|\.zshrc|\.profile|\.bash_profile)/i, label: 'shell 启动文件写入' },
  { re: /rm\s+-rf/i, label: 'rm -rf' },
  { re: /(清|删)(除|空|掉).{0,6}(日志|痕迹|历史)|unset\s+HIST/i, label: '清除痕迹' },
]

interface GroupHit { group: 'V' | 'A1' | 'A2' | 'A3'; label: string; line: number }

function matchGroup(text: string, lineBase: number, group: GroupHit['group'], patterns: { re: RegExp; label: string }[]): GroupHit[] {
  const hits: GroupHit[] = []
  for (const p of patterns) {
    const re = new RegExp(p.re.source, 'gi')
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      if (hits.length >= 24) break
      hits.push({ group, label: p.label, line: lineBase + countLinesBefore(text, m.index) })
    }
  }
  return hits
}

function countLinesBefore(text: string, index: number): number {
  let n = 0
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') n++
  return n
}

/**
 * 对一份指令/技能文件跑 R18。text = 全文；name = basename；file = 全路径。
 * 组合判定：V ∧ (A1 ∨ A2 ∨ A3) 同文件命中 → 一条 info 观测（附各组证据）。
 */
export function runInstructionScan(text: string, name: string, file?: string): Finding[] {
  const findings: Finding[] = []
  if (text.length === 0) return findings
  const body = text.length > MAX_FILE_BYTES ? text.slice(0, MAX_FILE_BYTES) : text
  const clean = stripInvisibles(body)
  // 注：v1 全部 info，测试/CI 文件无需额外降级路径（severity 已恒 info）；结构保留便于 v2 升级
  void file
  const vHits = matchGroup(clean, 1, 'V', V_PATTERNS)
  if (vHits.length === 0) return findings
  const aHits = [
    ...matchGroup(clean, 1, 'A1', A1_PATTERNS),
    ...matchGroup(clean, 1, 'A2', A2_PATTERNS),
    ...matchGroup(clean, 1, 'A3', A3_PATTERNS),
  ]
  if (aHits.length === 0) return findings
  const groups = new Set(aHits.map(h => h.group))
  if (![...groups].some(g => g === 'A1' || g === 'A2' || g === 'A3')) return findings
  const evidence = [
    ...vHits.slice(0, 2).map(h => `[V]${h.label}@L${h.line}`),
    ...aHits.slice(0, 3).map(h => `[${h.group}]${h.label}@L${h.line}`),
  ].join(' ')
  findings.push({
    rule: 'R18',
    severity: 'info',
    confidence: 'heuristic',
    file: name,
    line: vHits[0].line,
    message: '指令文件含疑似注入组合（指令改写×' + [...new Set(vHits.map(h => h.label))].slice(0, 2).join('/') +
      '；动作：' + [...new Set(aHits.map(h => h.group))].join(',') + '）——首版仅观测（G-1 形态，v2 据误报语料升级）',
    evidence: evidence.slice(0, 240),
  })
  return findings
}