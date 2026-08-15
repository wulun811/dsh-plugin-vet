/**
 * 客户端侧协议类型。⚠ 与 scanner-bin/protocol.ts 保持同步（实现决策：跨构建根目录无法单源共享，
 * 协议测试以 scanner-bin 为准做往返校验）。
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
  engine: 'static-v1'
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
