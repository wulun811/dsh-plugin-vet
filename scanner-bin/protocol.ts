/**
 * Scanner wire protocol (shared by client and scanner-bin).
 * @module dsh-plugin-vet/scanner-protocol
 */

export type Language = 'js' | 'ts'
export type Runtime = 'host' | 'sandbox'
export type Severity = 'critical' | 'high' | 'medium' | 'info'
export type Confidence = 'certain' | 'likely' | 'heuristic'
export type Verdict = 'critical' | 'suspicious' | 'clean'

export interface ScanRequest {
  kind: 'code' | 'files'
  language?: Language
  runtime?: Runtime
  code?: string
  files?: string[]
  rules?: Record<string, boolean>
  /** 扫描目标身份：'plugin'（DSH 插件包，严格逃逸判定，默认）| 'generic'（通用代码审计，R3 降级为能力触达面 info）。 */
  targetKind?: 'plugin' | 'generic'
  /** OSV 已知漏洞核对（npm 生态）：仅 files 模式且存在 package.json 时生效；严格 opt-in（=== true）。 */
  osv?: boolean
  /** 宿主侧计划超时（P2-1 对齐）：engine 以此收敛扫描预算（budget=min(files×2s, timeout-余量)），
   * 保证 R8-skip 先于宿主 kill 触发（否则 15+/31+ 文件包被 kill 报 scan-fail，优雅降级不可达）。 */
  timeoutMs?: number
  /** P1：传递依赖 OSV 核对（opt-in，默认 false）：调用 upstream-radar CLI 扫描传递依赖树。 */
  transitiveDeps?: boolean
}

export interface Finding {
  rule: string
  severity: Severity
  message: string
  evidence: string
  file?: string
  line?: number
  confidence: Confidence
}

export interface ScanReport {
  engine: 'static-v9'
  sourceCount: number
  findings: Finding[]
  staticScore: number
  verdict: Verdict
}

export interface ScanResponse {
  ok: boolean
  error?: string
  report?: ScanReport
}

/** 规则/引擎实现变更必须递增此版本——cache key 与缓存有效性校验都依赖它（round-6：R1 new 形态、R9 ReDoS 判定变更后未递增导致旧缓存中毒；round-7：R2 括号形态/R4 原型污染/R6 组合证据/R9 判定/R3 形态降级；round-7.1：R3 只读成员分类/R4 generic 不再降 info；round-7.2：R2 new X.constructor 复用 isConstructorCapture base 校验/R9 带标签 break 出口语义；round-8：新增 R13 网络外泄端点/R14 非 JS 脚本下载即执行；round-8.1：R14 大小写不敏感（PowerShell/cmd 命令不分大小写）、curl -o 落盘降 medium、flags 传播修复）。 */
export const ENGINE_VERSION = 'static-v9' as const

/** The rules of static-v9. R8 is a meta finding emitted by the engine (scan timeout skip). */
export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14'] as const

/** Shared context handed to every rule. */
export interface RuleContext {
  request: ScanRequest
  runtime: Runtime
  /** 包内 bin 入口文件的 basename 集合（engine 从 package.json bin 字段解析，round-7）——
   * bin 脚本永远独立运行（CLI），按通用代码判定：R2/R3 降级能力触达面、R9 死循环降 medium。 */
  cliFiles?: Set<string>
  /** 应用型包（package.json 声明非空 bin，round-7）：process 访问是产品功能（CLI/TUI/server），
   * R3 降级能力触达面 info——与 generic 降级同构的「应用型」降级（外部实测：dsh-tui/dsh-bridges）。 */
  appShape?: boolean
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'info']
export const CONFIDENCES: readonly Confidence[] = ['certain', 'likely', 'heuristic']
