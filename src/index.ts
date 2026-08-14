import type { Context } from '@deepseek-ai/cordis'
import { VetConfigSchema, validateConfig } from './config.js'
import type { VetConfig } from './config.js'
import { createScanPluginTool } from './tools/scan-plugin.js'
import { installInternalPluginGuard } from './guards/internal-plugin.js'
import { installToolExecuteGuard } from './guards/tool-execute.js'
import { installInvariant } from './invariant.js'

export const name = 'plugin-vet'
export const inject = ['tools', 'llm', 'sessions'] as const
export const Config = VetConfigSchema

export function apply(ctx: Context, config: VetConfig): void {
  validateConfig(config)
  ctx.tools.register(createScanPluginTool())
  installInternalPluginGuard(ctx, config)
  installToolExecuteGuard(ctx, config)
  installInvariant(ctx)
}
