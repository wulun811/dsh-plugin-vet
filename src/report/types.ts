import type { Finding, Verdict } from '../scanner/protocol.js'
import type { SelfScanInfo } from './self-scan.js'

/** 评分卡：静态判定（确定性）。审计调查由 agent 按 AUDIT_PROTOCOL 执行，vet 不内置 LLM 审计。 */
export interface PluginScorecard {
  pluginName: string
  pluginVersion?: string
  scannedAt: string
  static: {
    verdict: Verdict
    staticScore: number
    findings: Finding[]
  }
  /** vet 本体自扫注解（仅被扫目标 realpath 确认为 vet 自身时输出）。 */
  selfScan?: SelfScanInfo
}
