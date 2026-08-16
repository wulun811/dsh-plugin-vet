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
  engine: 'static-v4'
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

/** 规则/引擎实现变更必须递增此版本——cache key 与缓存有效性校验都依赖它（round-6：R1 new 形态、R9 ReDoS 判定变更后未递增导致旧缓存中毒）。 */
export const ENGINE_VERSION = 'static-v4' as const

/** The 9 rules of v1. R8 is a meta finding emitted by the engine (scan timeout skip). */
export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R9', 'R10', 'R11', 'R12'] as const

/** Shared context handed to every rule. */
export interface RuleContext {
  request: ScanRequest
  runtime: Runtime
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'info']
export const CONFIDENCES: readonly Confidence[] = ['certain', 'likely', 'heuristic']
