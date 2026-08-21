/**
 * Self-scan trust annotation（dsh.so "vet 扫 vet" 展示语义的权威来源）。
 *
 * 问题：把 vet 当作一个待审计插件来扫（SECURITY SCAN 面板 / scan_plugin target=package），
 * 其源码天然命中扫描器的全部危险能力词表——T1/T2 的实现就是监视 fs/child_process/net，
 * 检测规则文件里写着 curl|sh 正则、honeypot 里造着假私钥。原始报告全是 Critical，普通用户
 * 看了劝退。
 *
 * 这条途径（① 能力声明降级）在 *vet 自己的 scan 途径* 里实现：不是"扫到自己就跳过/变绿"
 * （那等于给攻击者伪造同名包一条绿色通道，也不让被攻破的 vet 再被自己的扫描器发现），而是
 * 换一套对本体可验证的评判标准——
 *
 *   - 危险 token（模块 / 出站目标 / 环境变量 / 敏感路径 / 子进程命令）逐个和 vet 自带的能力
 *     声明比对；**token 全部在声明内 → 降为 info（已声明 · 审计档案）**；
 *     **任一个不在声明内 → 保留原 severity（有界豁免，新增能力照旧 Critical）**。
 *   - 检测规则数据 / 诱饵 / 文案文件（rules/*、honeypot、i18n、黑名单）按文件豁免——这是
 *     数据集自引用，不是代码行为；安全由产物钉扎兜底：非 pinned-match 时本模块不产出
 *     Trusted（见②引脚），文件形同陌生人，豁免不生效。
 *
 * 本模块只做纯函数注解（不触 IO、不改 scan 报告原文——原始 findings 原样保留、可展开），
 * 输出 selfScan 数据块 + 供评分卡使用的"零化已声明项"后的计分。verdict 只由 retained 的
 * decisive 决定：已声明能力度量为声明侧事实（N1 差分同语义），不构成未知威胁。
 *
 * ⚠ 信任边界（不得放宽）：出站 host（非回环非 osv.dev）、未声明 env、凭据/密钥路径、
 * worker_threads/vm/cluster 等 IPC 原语——这四个方向出现的任一 token 都令该 finding retained，
 * 不加待定豁免。钉扎（pinned-match）是本机制生效的前提（②引脚）。
 */
import type { Finding, Severity, Verdict } from '../scanner/protocol.js'

// ── ① 能力声明（vet 安全层自身声明的合法能力面）──────────────────────────────
// 精确到具体 token；新增能力若不在清单内 → 不豁免。改这份声明 = 改字节 = 钉扎失效。

/** 合法引用的内建模块（T1/T2 监视对象 + 宿主实现）。worker_threads/vm/cluster/inspector 不声明。 */
export const DECLARED_MODULES = [
  'child_process', 'fs', 'fs/promises', 'path', 'os', 'crypto',
  'http', 'https', 'url', 'module', 'net', 'tls', 'dgram',
] as const

/** 出现即视为危险 IPC/动态执行原语（vet 不合法使用）——这些不是"未声明"，是明确禁区。 */
export const UNDECLARED_TRIGGER_MODULES = [
  'worker_threads', 'vm', 'cluster', 'inspector',
] as const

/** 合法读取的配置环境变量（宿主注入点；其余 process.env.* 一律视为未声明）。 */
export const DECLARED_ENV = [
  'DSH_PLUGIN_VET_CACHE_DIR', 'DSH_PLUGIN_VET_ARCHIVE_DIR', 'DSH_PLUGIN_VET_STATS_DIR',
  'DSH_PLUGIN_VET_BASELINE_DIR', 'DSH_PLUGIN_VET_CONTRACTS_DIR', 'DSH_PLUGIN_VET_FORENSICS_DIR',
  'DSH_VET_SIDECAR_PID', 'HOME',
] as const

/** 合法网络目标：仅回环 + 相对路径（向宿主要状态）+ osv.dev（OSV opt-in，仅发送依赖名/版本）。
 *  其它任何 host（外传端点/内网段/真实域名）出现 → 未声明，retain。 */
export const DECLARED_HOSTS = ['localhost', '127.0.0.1', '::1', 'unix-socket', 'osv.dev'] as const

/** 合法敏感路径段：vet 自身存储区域（homedir()/.dsh/vet）。凭据/密钥相关不声明。 */
export const DECLARED_FS_SEGMENTS = ['.dsh', 'vet', 'cache', 'archive', 'stats', 'baseline'] as const

/** 凭据/密钥敏感段：命中任一 → 未声明（honeypot 之外的真实凭据面）。 */
export const UNDECLARED_FS_SEGMENTS = [
  '.ssh', '.aws', '.azure', '.gcloud', 'credentials', 'id_rsa', '.pem', '.key',
  '.npmrc', '.git-credentials', '.dockercfg', '.env',
] as const

/** 合法子进程命令：scanner 子进程 + 传递依赖扫描器（仅本地已装时执行，无 npx 自动安装）。
 *  shell 管道（curl|sh / sh -c / 编码 PowerShell）不声明。 */
export const DECLARED_SPAWN = ['process.execPath', 'upstream-radar'] as const

/** 检测数据集文件（按 basename 匹配）：命中即数据集自引用（规则数据/黑名单/诱饵/文案）。
 *  仅在 pinned-match 下豁免——否则按实名代码逐 token 判。 */
export const DETECTION_DATA_FILES = [
  'non-js-scripts', 'string-heuristics', 'dynamic-exec', 'capability',
  'runtime-net', 'honeypot', 'i18n',
] as const

/** 开发夹具（test/spec 文件）：R13/R14 探测器实测样本（Discord/Telegram webhook、AWS 元数据、
 *  Tor 目标等——故意放的真实外传样本以验证规则命中）、回归用例等测试输入，不随包发布。
 *  与检测规则数据同性质（数据集自引用）；仅 pinned-match 下豁免（② 钉扎兜底：改字节即失效，
 *  被替换 vet 的 test/spec 不在被审计字节里，豁免不成立）。 */
/** basenameOf 已剥扩展名 → 按剥离后的 basename 判 .test/.spec/.e2e/.fixture/.sample 结尾。 */
export const DEV_FIXTURE_RE = /\.(test|spec|e2e|fixture|sample)$/

export function isDevFixtureFile(file: string | undefined): boolean {
  const base = basenameOf(file)
  return base !== undefined && DEV_FIXTURE_RE.test(base)
}

export type SelfPinState = 'pinned-match' | 'dev-tree' | 'unpinned'

export interface SelfScanInfo {
  isTrustLayer: boolean
  version?: string
  pin: SelfPinState
  declared: { modules: string; envVars: string; hosts: string; fsStore: string }
  annotation: {
    /** 命中且全部 token 在声明内 → 视为已声明能力面。 */
    declared: number
    /** 数据集自引用（文件级豁免）。 */
    datasetSelfRef: number
    /** 开发夹具（test/spec 实测样本，仅 pinned 生效）。 */
    devFixtures: number
    /** 含未声明 token → 保留原严重级（必须复查的面）。 */
    retained: Array<{ rule: string; severity: Severity; message: string; file?: string; line?: number }>
  }
  verdict: Verdict
  staticScore: number
}

interface ParsedTokens {
  modules: string[]
  hosts: string[]
  env: string[]
  fs: string[]
  spawn: string[]
}

// ── token 提取（确定性，纯正则）─────────────────────────────────────────────

function basenameOf(file: string | undefined): string | undefined {
  if (file === undefined) return undefined
  const slash = file.lastIndexOf('/')
  const dot = file.lastIndexOf('.')
  return file.slice(slash + 1, dot > slash ? dot : undefined)
}

/** 是否数据集自引用文件（规则数据/黑名单/诱饵/文案）。 */
export function isDetectionDataFile(file: string | undefined): boolean {
  const base = basenameOf(file)
  return base !== undefined && (DETECTION_DATA_FILES as readonly string[]).includes(base)
}

const UNDECLARED_HOST_MARKERS = [
  'webhook.site', 'requestbin.com', 'ngrok.io', 'localtunnel.me',
  'oast.me', 'oast.live', 'burpcollaborator.net', 'dnslog.cn', 'interact.sh',
] as const

/** 从 evidence+message+file 提取危险 token。 */
export function parseTokens(finding: Finding): ParsedTokens {
  const hay = [finding.evidence, finding.message, finding.file ?? ''].join(' | ')
  const out: ParsedTokens = { modules: [], hosts: [], env: [], fs: [], spawn: [] }
  const lower = hay.toLowerCase()
  // 模块：声明集 + 禁区集内出现的名字（仅禁区集缺水会导致 false-negative，故两集都列入）
  for (const m of [...(DECLARED_MODULES as readonly string[]), ...(UNDECLARED_TRIGGER_MODULES as readonly string[])]) {
    if (lower.includes(m) && !out.modules.includes(m)) out.modules.push(m)
  }
  // env：process.env.NAME 中未在声明集的
  {
    const re = /process.env.([A-Za-z_][A-Za-z0-9_]*)/g
    let mm: RegExpExecArray | null
    for (mm = re.exec(hay); mm !== null; mm = re.exec(hay)) {
      if (!(DECLARED_ENV as readonly string[]).includes(mm[1])) out.env.push(mm[1])
    }
  }
  // hosts：URL 主机 / 裸 IP（非回环）/ 外传域名标记
  {
    const re = /https?:[/][/]([^/\s"']+)/g
    let mm: RegExpExecArray | null
    for (mm = re.exec(hay); mm !== null; mm = re.exec(hay)) {
      const host = mm[1].split(':')[0]
      if (host !== '' && !(DECLARED_HOSTS as readonly string[]).includes(host)) out.hosts.push(host)
    }
    const ipRe = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g
    for (mm = ipRe.exec(hay); mm !== null; mm = ipRe.exec(hay)) {
      if (mm[1] !== '127.0.0.1') out.hosts.push(mm[1])
    }
    for (const h of UNDECLARED_HOST_MARKERS) {
      if (lower.includes(h) && !out.hosts.includes(h)) out.hosts.push(h)
    }
  }
  // fs：凭据/密钥敏感段。先剥离 process.env/import.meta.env 的引用语境——其子串 '.env' 会误伤
  // 裸 process 成员引用（能力触达面 info），真实的 env 变量由上方 env 正则单独判定。
  const fsHay = lower.replace(/process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env/g, '')
  for (const seg of UNDECLARED_FS_SEGMENTS) {
    if (fsHay.includes(seg)) out.fs.push(seg)
  }
  // spawn：shell 管道 / 编码命令
  if (/sh\s+-c|curl[^\n|]*\|\s*(ba|z)?sh\b|wget[^\n|]*\|\s*(ba|z)?sh\b|Invoke-WebRequest|DownloadString|-enc\b/i.test(lower)) {
    out.spawn.push('shell-pipe')
  }
  return out
}

/** 一条 finding 是否全部危险 token 都在声明内（→ 可降级）。任一个不在 → false（保留）。 */
export function isDeclared(finding: Finding, tokens: ParsedTokens = parseTokens(finding)): boolean {
  if (tokens.modules.some(m => (UNDECLARED_TRIGGER_MODULES as readonly string[]).includes(m as never))) return false
  if (tokens.env.length > 0) return false
  if (tokens.hosts.length > 0) return false
  if (tokens.fs.length > 0) return false
  if (tokens.spawn.length > 0) return false
  return true
}

// ── 计分镜像（KEEP IN SYNC：与 scanner-bin/score.ts 保持一致；跨 rootDir 无法单源共享）──

const WEIGHTS: Record<Severity, number> = { critical: 45, high: 20, medium: 8, info: 0 }
const CONFIDENCE_COEF: Record<string, number> = { certain: 1.0, likely: 0.8 }

export function computeSelfScore(findings: readonly Finding[]): number {
  let total = 0
  for (const f of findings) {
    const coef = f.confidence === 'heuristic' ? 0.5 : CONFIDENCE_COEF[f.confidence] ?? 1
    total += WEIGHTS[f.severity] * coef
  }
  return Math.max(0, Math.min(100, Math.round(100 - total)))
}

export function computeSelfVerdict(findings: readonly Finding[]): Verdict {
  const decisive = findings.filter(f => f.confidence !== 'heuristic')
  if (decisive.some(f => f.severity === 'critical')) return 'critical'
  if (decisive.some(f => f.severity === 'high')) return 'suspicious'
  return 'clean'
}

/**
 * 纯注解：把 vet 本体扫描报告的 findings 拆成「已声明能力面」（数据集自引用文件级豁免 + token
 * 全声明）与「必须保留」（含未声明 token）。不修改入参；raw findings 由调用方原样展示。
 */
export function annotateSelfScan(
  findings: readonly Finding[],
  ctx: { pin: SelfPinState; version?: string; isTrustLayer?: boolean },
): SelfScanInfo {
  // pinned-match 才启用文件级数据集豁免；dev-tree/unpinned 下数据集文件也逐 token 判。
  const filesExempt: boolean = ctx.pin === 'pinned-match'
  const declared: Finding[] = []
  const retained: Finding[] = []
  let datasetSelfRef = 0
  let devFixtures = 0
  for (const f of findings) {
    if (filesExempt && isDetectionDataFile(f.file)) {
      datasetSelfRef++
      continue
    }
    if (filesExempt && isDevFixtureFile(f.file)) {
      devFixtures++
      continue
    }
    const tokens = parseTokens(f)
    if (isDeclared(f, tokens)) declared.push(f)
    else retained.push(f)
  }
  const verdict = computeSelfVerdict(retained)
  const staticScore = computeSelfScore(retained)
  return {
    isTrustLayer: ctx.isTrustLayer ?? true,
    ...(ctx.version !== undefined ? { version: ctx.version } : {}),
    pin: ctx.pin,
    declared: {
      modules: (DECLARED_MODULES as readonly string[]).join(', '),
      envVars: (DECLARED_ENV as readonly string[]).join(', '),
      hosts: (DECLARED_HOSTS as readonly string[]).join(', '),
      fsStore: (DECLARED_FS_SEGMENTS as readonly string[]).join(', '),
    },
    annotation: {
      declared: declared.length,
      datasetSelfRef,
      devFixtures,
      retained: retained.map(f => ({ rule: f.rule, severity: f.severity, message: f.message, ...(f.file !== undefined ? { file: f.file } : {}), ...(f.line !== undefined ? { line: f.line } : {}) })),
    },
    verdict,
    staticScore,
  }
}
