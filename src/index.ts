import type { Context } from '@deepseek-ai/cordis'
import { VetConfigSchema, validateConfig } from './config.js'
import type { VetConfig } from './config.js'
import { createScanPluginTool } from './tools/scan-plugin.js'
import { createAuditPluginTool } from './tools/audit-plugin.js'
import { installInternalPluginGuard } from './guards/internal-plugin.js'
import { installToolExecuteGuard } from './guards/tool-execute.js'
import { installInvariant } from './invariant.js'

export const name = 'plugin-vet'
// sessionPersistence：审计事件走持久化 append + ignorable 信封（coordinator 未知类型拒读闸门，D10）
export const inject = ['tools', 'llm', 'sessions', 'sessionPersistence'] as const
export const Config = VetConfigSchema

export function apply(ctx: Context, config: VetConfig): void {
  validateConfig(config)
  ctx.tools.register(createScanPluginTool())
  ctx.tools.register(createAuditPluginTool({ ctx, config }))
  installInternalPluginGuard(ctx, config)
  installToolExecuteGuard(ctx, config)
  installInvariant(ctx)
}
