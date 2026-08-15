import type { Context } from '@deepseek-ai/cordis'
import { VetConfigSchema } from './config.js'
import type { VetConfig } from './config.js'
import { createScanPluginTool } from './tools/scan-plugin.js'
import { registerAuditProtocolSkill } from './skills/audit-protocol.js'
import { installInternalPluginGuard } from './guards/internal-plugin.js'
import { installToolExecuteGuard } from './guards/tool-execute.js'
import { installInvariant } from './invariant.js'
import { VetStatus } from './guard/status.js'
import { installRuntimeGuard } from './guard/runtime-guard.js'
import { installStatusRoute } from './guard/status-route.js'

export const name = 'plugin-vet'
export const inject = ['tools', 'skills'] as const
export const Config = VetConfigSchema

export function apply(ctx: Context, config: VetConfig): void {
  const status = new VetStatus()
  ctx.tools.register(createScanPluginTool(config))
  registerAuditProtocolSkill(ctx as unknown as { skills?: { register?: (reg: unknown) => () => void } })
  installRuntimeGuard(ctx, config, status)
  installStatusRoute(ctx, config, status)
  installInternalPluginGuard(ctx, config, status)
  installToolExecuteGuard(ctx, config, status)
  installInvariant(ctx, config)
}
