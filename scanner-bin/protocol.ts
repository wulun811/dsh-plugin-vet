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

export const ENGINE_VERSION = 'static-v1' as const

/** The 9 rules of v1. R8 is a meta finding emitted by the engine (scan timeout skip). */
export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R9', 'R10', 'R11'] as const

/** Shared context handed to every rule. */
export interface RuleContext {
  request: ScanRequest
  runtime: Runtime
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'info']
export const CONFIDENCES: readonly Confidence[] = ['certain', 'likely', 'heuristic']
