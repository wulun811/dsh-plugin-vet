/**
 * 市场扫描闸门类型定义（P0 特性）。
 */
import type { Verdict, Finding } from './scanner/protocol.js'

export interface GateRequest {
  /** 插件包路径（绝对路径）。 */
  packagePath: string
  /** 扫描模式：report（只输出）| deny（阻塞安装）。默认 report。 */
  mode?: 'report' | 'deny'
  /** deny 模式下触发拦截的阈值：critical | suspicious。默认 critical。 */
  denyOn?: 'critical' | 'suspicious'
  /** 扫描超时（毫秒）。默认按文件数动态计算。 */
  timeoutMs?: number
  /** 是否启用 OSV 已知漏洞核对。默认 false（安装流程期望秒级反馈）。 */
  osvCheck?: boolean
}

export interface GateResult {
  /** 扫描结论。 */
  verdict: Verdict
  /** 静态评分。 */
  staticScore: number
  /** 插件名称。 */
  pluginName: string
  /** 插件版本。 */
  pluginVersion?: string
  /** 扫描时间（ISO 格式）。 */
  scannedAt: string
  /** 发现的规则命中。 */
  findings: Finding[]
  /** 是否被拦截（mode=deny 且命中阈值时为 true）。 */
  blocked: boolean
}
