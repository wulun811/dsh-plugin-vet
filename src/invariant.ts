import type { Context } from '@deepseek-ai/cordis'
import { scan } from './scanner/client.js'
import type { VetConfig } from './config.js'
import { sidecarSpawned } from './guard/runtime-guard.js'
import { sidecarSupportedOn } from './guard/runtime-sidecar.js'
// 常量定义已拆到 package-meta.ts（断 invariant ↔ runtime-guard 循环依赖）；
// 此处 import 供本模块使用 + re-export 保持外部 import 路径与符号不变（lib/invariant.js API 兼容）。
import { PACKAGE_NAME } from './package-meta.js'
export { PACKAGE_NAME, PLUGIN_ENTRY_ID } from './package-meta.js'

interface InvariantRegistryLike {
  register(packageName: string, installer: (child: Context, fail: (message: string) => never) => void | Promise<void>): () => void
}

/**
 * round-22（T1 平台门修复）：watch 档位 + 平台不支持（Windows 等）时哨兵按设计跳过
 * （runtime-guard 的 sidecarSupportedOn 门，记录 info 日志）——这**不是**故障，invariant
 * 必须同样认平台门：只在「平台支持但哨兵未启动」时 fail。此前硬查 sidecarSpawned 会把
 * Windows + hardened/paranoid 档位的整个插件判定为启动失败（invariant fail → 装配整体
 * 拒绝），静态 deny/T2 钩子等其余防线全部随插件不可用而消失。
 * 纯函数（可单测）：返回 fail 文案或 null。
 */
export function watchInvariantMessage(platform: NodeJS.Platform, spawned: boolean): string | null {
  if (sidecarSupportedOn(platform) && !spawned) {
    return 'vet: runtimeGuard: watch 已配置但 T1 哨兵未启动——检查日志中 vet: T1 哨兵相关报错'
  }
  return null
}

/**
 * 包级运行时 invariant（B2）：断言 scanner 子进程关系——scanner-bin 可执行、空扫返回 ok。
 * 存在性检查按仓库约定改为"事件/数据关系"：插件可用 ⟺ scanner 子进程可产出报告。
 */
export function installInvariant(ctx: Context, config?: VetConfig): void {
  let invariants: InvariantRegistryLike | undefined
  try {
    invariants = (ctx as Context & { invariants?: InvariantRegistryLike }).invariants
  } catch {
    return // harness 未提供 invariants 服务——cordis proxy 对未注入属性直接抛错而非返回 undefined
  }
  if (invariants === undefined) return
  invariants.register(PACKAGE_NAME, async (_child, fail) => {
    const res = await scan({ kind: 'code', language: 'js', code: '' })
    if (!res.ok) {
      fail(`scanner-bin 不可执行: ${res.error ?? 'unknown'}（检查安装完整性或重装 @jieai/dsh-plugin-vet）`)
    }
    const watchMsg = watchInvariantMessage(process.platform, sidecarSpawned)
    if (config?.runtimeGuard !== undefined && config.runtimeGuard === 'watch' && watchMsg !== null) {
      fail(watchMsg)
    }
  })
}
