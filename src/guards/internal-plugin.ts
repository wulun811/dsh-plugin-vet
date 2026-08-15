import type { Context, Fiber } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { scanSync } from '../scanner/client.js'
import { listSourceFiles, resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'
import { hasAuditRecord, auditRequiredMessage } from '../audit/archive.js'
import type { VetStatus } from '../guard/status.js'

/** typert loader 为 Fiber 附加的 entry 元数据（loader.ts:412 同款访问）。 */
type VetFiber = Fiber & { entry?: { options?: { name?: string } } }

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }
const DENY_RANK: Record<VetConfig['denyOn'], number> = { critical: 3, suspicious: 2 }

function isExempt(packageName: string, config: VetConfig): boolean {
  if (packageName.startsWith('@deepseek-ai/')) return true
  return config.allowlist.includes(packageName)
}

/**
 * internal/plugin 守卫：新装 npm 包自动静态扫描（PLAN.md §6.5）。
 * - dispose 发射（fiber.uid === null）与 entry-less（child/manual）直接忽略（B1）；
 * - report 模式：异步扫描 + 日志；deny 模式：同步扫描（scanSync），命中即同步抛错回滚挂载。
 */
export function installInternalPluginGuard(ctx: Context, config: VetConfig, status?: VetStatus): void {
  ctx.on('internal/plugin', (fiber: Fiber) => {
    const vetFiber = fiber as VetFiber
    if (fiber.uid === null) return
    const entryName = vetFiber.entry?.options?.name
    if (typeof entryName !== 'string') return
    if (entryName === PACKAGE_NAME) return
    if (!config.autoScan) return
    if (isExempt(entryName, config)) return

    // D30 强制层：requireAudit 开启时，无健康档案的第三方插件在加载时被拦截（deny）/报警（report）。
    // 门槛独立于包解析与扫描——档案存在与否只取决于 agent 是否按协议审查过。
    if (config.requireAudit && !hasAuditRecord(entryName)) {
      const msg = auditRequiredMessage(entryName)
      ctx.logger.warn(msg)
      if (config.mode === 'deny') {
        void fiber.dispose()
        throw new Error(msg)
      }
    }

    const check = (): void => {
      // DSH 把插件装进 profile 的 node_modules（vet 可能被符号链接，realpath 解析不到）→
      // 用 loader 的解析基准（ctx.baseUrl = profile 目录）定位第三方插件根目录。
      const profileDir = (ctx as { baseUrl?: string }).baseUrl
      const root = resolvePackageRoot(entryName, profileDir)
      if (root === undefined) return

      const files = listSourceFiles(root)
      if (files.length === 0) return
      const res = scanSync({ kind: 'files', files, osv: config.osvCheck === true }, { timeoutMs: config.scannerTimeoutMs })
      if (!res.ok || res.report === undefined) return
      const { verdict, staticScore } = res.report
      ctx.logger.info(`vet: auto-scan ${entryName} → ${verdict} (${staticScore})`)
      status?.noteScan({ pluginName: entryName, verdict, staticScore, at: Date.now() })
      if (config.mode === 'deny' && RANK[verdict] >= DENY_RANK[config.denyOn]) {
        void fiber.dispose()
        throw new Error(`vet: 拦截 ${entryName}（${verdict}）`)
      }
    }

    if (config.mode === 'deny') {
      check()
    } else {
      void (async () => {
        try {
          check()
        } catch (error) {
          ctx.logger.error(String(error))
        }
      })()
    }
  })
}
