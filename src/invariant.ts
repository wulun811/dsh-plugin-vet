import type { Context } from '@deepseek-ai/cordis'
import { scan } from './scanner/client.js'
import type { VetConfig } from './config.js'
import { sidecarSpawned } from './guard/runtime-guard.js'

export const PACKAGE_NAME = '@jieai/dsh-plugin-vet'
/** bundle cordis.patch.yml 里 insert 的条目 id（profile patch 层按它覆盖配置）。 */
export const PLUGIN_ENTRY_ID = 'plugin-vet'

interface InvariantRegistryLike {
  register(packageName: string, installer: (child: Context, fail: (message: string) => never) => void | Promise<void>): () => void
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
    if (config?.runtimeGuard !== undefined && config.runtimeGuard === 'watch' && !sidecarSpawned) {
      fail('vet: runtimeGuard: watch 已配置但 T1 哨兵未启动——检查日志中 vet: T1 哨兵相关报错')
    }
  })
}
