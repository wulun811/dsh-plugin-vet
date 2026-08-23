import type { Context } from '@deepseek-ai/cordis'
import { VetConfigSchema } from './config.js'
import type { VetConfig } from './config.js'
import { createScanPluginTool } from './tools/scan-plugin.js'
import { createVetDiffTool } from './tools/vet-diff.js'
import { createVetLabelTool } from './tools/vet-label.js'
import { registerAuditProtocolSkill } from './skills/audit-protocol.js'
import { installInternalPluginGuard } from './guards/internal-plugin.js'
import { installToolExecuteGuard } from './guards/tool-execute.js'
import { installInvariant } from './invariant.js'
import { installConfigDiff } from './guard/config-diff.js'
import { VetStatus } from './guard/status.js'
import { installRuntimeGuard } from './guard/runtime-guard.js'
import { installStatusRoute } from './guard/status-route.js'

export const name = 'plugin-vet'
export const inject = ['tools', 'skills'] as const
export const Config = VetConfigSchema

/**
 * 插件装配入口：注册 scan_plugin / vet_diff / vet_label 工具、vet-audit-protocol skill、
 * T1/T2 运行时守卫（含全局资源的显式清理：fs/child_process 补丁与哨兵子进程）、
 * /vet 状态路由、internal/plugin 自动扫描 + tools/execute 执行守卫与包级 invariant。
 */
export function apply(ctx: Context, config: VetConfig): void {
  const status = new VetStatus()
  ctx.tools.register(createScanPluginTool(config))
  ctx.tools.register(createVetDiffTool())
  ctx.tools.register(createVetLabelTool())
  registerAuditProtocolSkill(ctx as unknown as { skills?: { register?: (reg: unknown) => () => void } })
  const guardDisposer = installRuntimeGuard(ctx, config, status)
  // 生命周期（二轮审查发现）：事件监听/工具/skill/路由都随 cordis ctx 销毁自动清理，
  // 但 T2 的 fs/child_process 猴子补丁与 T1 哨兵子进程是全局资源，必须显式卸载——
  // 此前只在重新 apply 时经 prevGuardDisposer 清理；条目被彻底移除（非重载）会遗留
  // 钩子与哨兵直到进程退出。cordis 没有类型化的 dispose 事件，用 ctx.effect 注册
  // disposer：fiber 卸载时（含条目移除/配置热重载）运行。disposer 幂等，与
  // prevGuardDisposer 双保险不冲突。
  ctx.effect(() => () => guardDisposer(), 'vet: runtime guard cleanup')
  installStatusRoute(ctx, config, status)
  installInternalPluginGuard(ctx, config, status)
  installToolExecuteGuard(ctx, config, status)
  // round-13（Phase 3）：遥测配置敏感化（G-3；alarm-only，独立于 runtimeGuard——纯读轮询）
  // 生命周期：清定时器（重载/卸载安全，与 runtime-guard disposer 同纪律）
  const configDiffDisposer = installConfigDiff(ctx, config, status)
  ctx.effect(() => () => configDiffDisposer(), 'vet: config-diff cleanup')
  installInvariant(ctx, config)
}
