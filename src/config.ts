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
  /** P-5：官方包内容哈希基线（默认开启）：对 @deepseek-ai/* 包计算内容哈希，与基线比对，防止包名伪造。 */
  contentBaseline: boolean
  /** P-5 补充（0.1.21）：已声明的本机补丁哈希。键为 `name@version`，值为该版本被允许的内容哈希
   * （sha256 hex，可用 computePackageHash 或红警消息里的短 hash 全量获取）。命中 → 豁免基线比对
   * 并记一次性 yellow 提示（透明不静默）；未登记的差异仍按篡改处理。 */
  acknowledgedPackageHashes: Record<string, string[]>
  /** P1：运行时网络出口观测（默认开启）：包装 http/https/net/http2/tls/dgram/fetch，观测插件发起的网络请求。 */
  networkEgress: boolean
  /** P1：传递依赖 OSV 核对（默认关闭）：调用 upstream-radar CLI 扫描传递依赖树。需要安装 upstream-radar。 */
  transitiveDeps: boolean
  /** N7：确认拦截块（0.1.14）：'block'（默认）族 1/2 确认即拦；'alarm' 只报警不拦；'off' 关闭。 */
  confirmBlock: 'block' | 'alarm' | 'off'
  /** N7 族 3 覆写（默认 alarm，仅报警）：显式 'block' 才拦截系统持久化/提权面写入（误拦风险自负）。 */
  confirmBlockFamily3: 'alarm' | 'block'
  /** N7 族 4 覆写（默认 alarm，仅报警）：显式 'block' 才拦截供应链/安装态写入。 */
  confirmBlockFamily4: 'alarm' | 'block'
  /** M1 语义契约（默认开，0.1.21 记录档）：插件存在通过校验的契约时，运行时对账——
   * 越界记 info m1:contract-violation、拒载 yellow m1:contract-rejected、代码事实证伪
   * 时 yellow m1:contract-distrusted（契约永远不压制任何既有报警）。无契约 = 零变化。 */
  contract: {
    enabled: boolean
    /** 契约目录；空 = $HOME/.dsh/vet/contracts（env DSH_PLUGIN_VET_CONTRACTS_DIR 可覆盖）。 */
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
  contentBaseline: z.boolean().default(true),
  acknowledgedPackageHashes: z.dict(z.array(z.string())).default({}),
  networkEgress: z.boolean().default(true),
  transitiveDeps: z.boolean().default(false),
  confirmBlock: z.union([z.const('block'), z.const('alarm'), z.const('off')]).default('block'),
  confirmBlockFamily3: z.union([z.const('alarm'), z.const('block')]).default('alarm'),
  confirmBlockFamily4: z.union([z.const('alarm'), z.const('block')]).default('alarm'),
  contract: z.object({
    enabled: z.boolean().default(true),
    dir: z.string().default(''),
  }).default({ enabled: true, dir: '' }),
})