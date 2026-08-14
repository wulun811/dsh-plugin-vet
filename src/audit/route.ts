import type { Session } from '@deepseek-ai/dsh-session'
import type { VetConfig } from '../config.js'

export interface AuditRoute {
  provider: string
  model: string
}

/**
 * LLM 路由解析（PLAN.md §5.1）：Config 显式 provider+model（成对）→ 会话 requestHeader
 * 回落（core/session:670）→ 双缺 fail-loud。
 */
export function resolveRoute(config: VetConfig, session: Session | undefined): AuditRoute {
  if (config.provider !== undefined || config.model !== undefined) {
    if (config.provider === undefined || config.model === undefined) {
      throw new Error('vet: provider 与 model 必须成对配置（仅配置其一即 fail-loud）')
    }
    return { provider: config.provider, model: config.model }
  }
  const header = session?.requestHeader()
  const callConfig = header?.config
  if (callConfig !== undefined && typeof callConfig.provider === 'string' && typeof callConfig.model === 'string') {
    return { provider: callConfig.provider, model: callConfig.model }
  }
  throw new Error('vet: 未配置 provider/model 且当前会话无可用模型路由——请在 Config 配 provider+model，或先发起一次会话')
}
