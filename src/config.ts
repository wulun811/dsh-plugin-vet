import z from '@deepseek-ai/schemastery'

/** vet 插件配置。fail-open 起步：默认 report，deny 由部署者显式开启。 */
export interface VetConfig {
  mode: 'report' | 'deny'
  autoScan: boolean
  scannerTimeoutMs: number
  rules: Record<string, boolean>
  denyOn: 'critical' | 'suspicious'
  allowlist: string[]
  /** D30：审计门槛强制（opt-in）——开启后新插件必须先按 vet-audit-protocol 审查并落盘健康档案，否则 deny 拦截 / report 报警。 */
  requireAudit: boolean
  /** D22：运行时守卫（默认 off——性能/稳定代价 opt-in）。'watch' = T1 哨兵 + T2 钩子，只报警不动作。 */
  runtimeGuard: 'off' | 'watch'
  runtimeIntervalMs: number
  runtimeMemLimitMb: number
  runtimeForkBurstN: number
  runtimeFdLimit: number
  /** D22 补漏：窗口内 RSS 净增长超限 → yellow（持续膨胀/疑似泄漏）。 */
  runtimeGrowthMb: number
  runtimeGrowthWindowMs: number
  /** OSV 已知漏洞核对（谷歌漏洞库，npm 生态）：扫描 package.json 时自动查询已知漏洞（网络，失败静默降级）。 */
  osvCheck: boolean
  /** D27：蜜罐诱饵（opt-in，需 runtimeGuard: watch 才生效）：往 honeypot.dir 放假密钥诱饵，T2 对诱饵路径的触碰单独报警。 */
  honeypot: {
    enabled: boolean
    /** 诱饵目录；空 = $HOME/.dsh/.local（隐蔽位置，反蜜罐：目录/文件名/内容均无蜜罐关键词）。 */
    dir: string
  }
}

export const VetConfigSchema: z<VetConfig> = z.object({
  mode: z.union([z.const('report'), z.const('deny')]).default('report'),
  autoScan: z.boolean().default(true),
  scannerTimeoutMs: z.natural().default(15_000),
  rules: z.dict(z.boolean()).default({}),
  denyOn: z.union([z.const('critical'), z.const('suspicious')]).default('critical'),
  allowlist: z.array(z.string()).default([]),
  requireAudit: z.boolean().default(false),
  runtimeGuard: z.union([z.const('off'), z.const('watch')]).default('off'),
  runtimeIntervalMs: z.natural().default(2000),
  runtimeMemLimitMb: z.natural().default(2048),
  runtimeForkBurstN: z.natural().default(5),
  runtimeFdLimit: z.natural().default(512),
  runtimeGrowthMb: z.natural().default(256),
  runtimeGrowthWindowMs: z.natural().default(600_000),
  osvCheck: z.boolean().default(true),
  honeypot: z.object({
    enabled: z.boolean().default(false),
    dir: z.string().default(''),
  }).default({ enabled: false, dir: '' }),
})
