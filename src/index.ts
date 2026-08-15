import type { Context } from '@deepseek-ai/cordis'
import { VetConfigSchema, validateConfig } from './config.js'
import type { VetConfig } from './config.js'
import { createScanPluginTool } from './tools/scan-plugin.js'
import { createAuditPluginTool } from './tools/audit-plugin.js'
import { installInternalPluginGuard } from './guards/internal-plugin.js'
import { installToolExecuteGuard } from './guards/tool-execute.js'
import { installInvariant } from './invariant.js'
import { VetStatus } from './guard/status.js'
import { installRuntimeGuard } from './guard/runtime-guard.js'
import { installStatusRoute } from './guard/status-route.js'

export const name = 'plugin-vet'
// sessionPersistence：审计事件走持久化 append + ignorable 信封（coordinator 未知类型拒读闸门，D10）
export const inject = ['tools', 'llm', 'sessions', 'sessionPersistence'] as const
export const Config = VetConfigSchema

export function apply(ctx: Context, config: VetConfig): void {
  validateConfig(config)
  const status = new VetStatus()
  ctx.tools.register(createScanPluginTool())
  ctx.tools.register(createAuditPluginTool({ ctx, config }))
  installRuntimeGuard(ctx, config, status)
  installStatusRoute(ctx, status)
  installInternalPluginGuard(ctx, config, status)
  installToolExecuteGuard(ctx, config, status)
  installInvariant(ctx, config)
}
