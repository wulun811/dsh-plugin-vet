import type { Finding, Verdict } from '../scanner/protocol.js'

export interface LlmFinding {
  category: 'secret' | 'exfiltration' | 'telemetry' | 'obfuscation' | 'dangerous-api' | 'other'
  evidence: string
  risk: 'low' | 'medium' | 'high' | 'critical'
  suggestion: string
}

/** 两分制评分卡：static（确定性）+ llm（可选，主观维度），禁止合成单一总分（PLAN.md §2.2-4）。 */
export interface PluginScorecard {
  pluginName: string
  pluginVersion?: string
  scannedAt: string
  static: {
    verdict: Verdict
    staticScore: number
    findings: Finding[]
  }
  llm?: LlmSection
}

export type LlmSection =
  | {
      /** deep:false 或部分轮次失败时缺省（渲染为 n/a）——不合成不存在的主观分（D9）。 */
      qualityScore?: number
      findings: LlmFinding[]
      summary: string
      recommendation: 'approve' | 'review' | 'reject'
      confidence: 'high' | 'medium' | 'low'
      partial: boolean
    }
  | { error: 'audit-failed' | 'audit-skipped'; reason: string }
