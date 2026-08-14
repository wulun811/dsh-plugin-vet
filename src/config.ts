import z from '@deepseek-ai/schemastery'

/** vet 插件配置（PLAN.md §6.2）。fail-open 起步：默认 report，deny 由部署者显式开启。 */
export interface VetConfig {
  mode: 'report' | 'deny'
  autoScan: boolean
  autoAudit: boolean
  provider?: string
  model?: string
  auditMaxTokens: number
  auditTimeoutMs: number
  scannerTimeoutMs: number
  auditCacheTtlHours: number
  rules: Record<string, boolean>
  denyOn: 'critical' | 'suspicious'
  allowlist: string[]
}

export const VetConfigSchema: z<VetConfig> = z.object({
  mode: z.union([z.const('report'), z.const('deny')]).default('report'),
  autoScan: z.boolean().default(true),
  autoAudit: z.boolean().default(false),
  provider: z.string().required(false),
  model: z.string().required(false),
  auditMaxTokens: z.natural().default(2048),
  auditTimeoutMs: z.natural().default(120_000),
  scannerTimeoutMs: z.natural().default(15_000),
  auditCacheTtlHours: z.natural().default(168),
  rules: z.dict(z.boolean()).default({}),
  denyOn: z.union([z.const('critical'), z.const('suspicious')]).default('critical'),
  allowlist: z.array(z.string()).default([]),
})

/** load 时 fail-loud：provider/model 必须成对。 */
export function validateConfig(config: VetConfig): void {
  if ((config.provider === undefined) !== (config.model === undefined)) {
    throw new Error('vet: provider 与 model 必须成对配置（仅配置其一即 fail-loud）')
  }
}
