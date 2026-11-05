/**
 * 市场扫描闸门类型定义（P0 特性）。
 */
import type { Decision } from './domain/types.js'
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
  /**
   * 本次闸门的决策对象（0.5.11）。
   *
   * 与 `blocked` **并排**而不是替代它（施工图 S2-03：先影子对照，真实执行仍走旧函数）。
   * `blocked` 只回答「拦不拦」，`decision` 回答「凭什么、缺什么」：
   * 同样的 `blocked: false`，`decision.action` 可能是 `report`（查了没事，或有事但没拦权），
   * 也可能是 `allow`（九面齐全、什么都没缺）。安装器想区分这两种，只能读这里。
   */
  decision: Decision
}
