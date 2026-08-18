import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Context, Fiber } from '@deepseek-ai/cordis'
import type { ScanResponse } from '../scanner/protocol.js'
import type { VetConfig } from '../config.js'
import { scan, scanSync } from '../scanner/client.js'
import { listSourceFiles, resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'
import { hasAuditRecord, auditRequiredMessage } from '../audit/archive.js'
import { withVetSelfIo } from '../guard/runtime-hooks.js'
import type { VetStatus } from '../guard/status.js'
import { computePackageHash, checkBaseline, recordBaseline, saveBaseline, getBaseline } from './content-baseline.js'

/** typert loader 为 Fiber 附加的 entry 元数据（loader.ts:412 同款访问）。 */
type VetFiber = Fiber & { entry?: { options?: { name?: string } } }

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }
const DENY_RANK: Record<VetConfig['denyOn'], number> = { critical: 3, suspicious: 2 }

/**
 * 读取插件根目录的装机版本（P-1 档案精确匹配用）。包根在 ~/.dsh 下，
 * withVetSelfIo 直通，避免 .dsh 敏感段下每次装插件产出一条无主 fs-probe 自报警（P2-2）。
 */
function readInstalledVersion(root: string): string | undefined {
  return withVetSelfIo(() => {
    try {
      const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: unknown }
      return typeof pkg.version === 'string' && pkg.version !== '' ? pkg.version : undefined
    } catch {
      return undefined
    }
  })
}

function isExempt(packageName: string, packageRoot: string | undefined, config: VetConfig, status?: VetStatus): boolean {
  // cordis builtin 命名空间（cordis:group 等框架内置分组入口，非可安装的第三方插件）——不扫描不审计
  if (packageName.startsWith('cordis:')) return true
  if (config.allowlist.includes(packageName)) return true
  if (!packageName.startsWith('@deepseek-ai/')) return false
  if (!config.contentBaseline) return true  // 配置关闭时维持旧行为
  if (packageRoot === undefined) return false  // 无法解析包根，不豁免

  // 官方包：内容哈希校验（P-5）
  const hashResult = computePackageHash(packageRoot, { maxFiles: 1000, maxSizeBytes: 50 * 1024 * 1024, timeoutMs: 10000 })
  if (hashResult === null) return false  // 超限/超时：不豁免
  const hash = hashResult.hash
  const version = readInstalledVersion(packageRoot) ?? 'unknown'
  const store = getBaseline()
  const result = checkBaseline(packageName, version, hash, store)
  if (result === 'first-seen') {
    recordBaseline(packageName, version, hash, store)
    saveBaseline(store)  // 原子写
    return true  // 首次见到，自动信任（v5 修订：砍掉白名单，与 VET 信任官方包的定位一致）
  }
  if (result === 'match') return true  // 内容一致，信任
  // mismatch：同名但内容变了 → 不豁免，记录 red 报警
  const msg = `官方包 ${packageName}@${version} 内容哈希与基线不一致（疑似供应链篡改）`
  status?.record({
    id: `baseline-mismatch:${packageName}`,
    severity: 'red',
    source: 'scan',
    kind: 'baseline-mismatch',
    message: msg,
    target: packageName,
    pluginHint: packageName,
    at: Date.now(),
  })
  return false
}

/**
 * internal/plugin 守卫：新装 npm 包自动静态扫描。
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

    // DSH 把插件装进 profile 的 node_modules（vet 可能被符号链接，realpath 解析不到）→
    // 用 loader 的解析基准（ctx.baseUrl = profile 目录）定位第三方插件根目录。
    // P-1：提前解析——requireAudit 需要装机版本做档案精确匹配（升级后旧档案不放行），
    // 扫描复用同一 root，避免重复 resolve。
    const profileDir = (ctx as { baseUrl?: string }).baseUrl
    const root = resolvePackageRoot(entryName, profileDir)
    
    // P-5：isExempt 需要 packageRoot 做内容哈希校验
    if (isExempt(entryName, root, config, status)) return
    
    const installedVersion = root === undefined ? undefined : readInstalledVersion(root)

    // D30 强制层：requireAudit 开启时，无健康档案的第三方插件在加载时被拦截（deny）/报警（report）。
    // 门槛独立于包解析与扫描——档案存在与否只取决于 agent 是否按协议审查过。
    if (config.requireAudit && !hasAuditRecord(entryName, installedVersion)) {
      const msg = auditRequiredMessage(entryName)
      ctx.logger.warn(msg)
      // alarm-only：未审计插件只记录黄色告警（观测/警报），不拦截——除非用户显式选择 deny。
      status?.record({
        id: `audit-required:${entryName}`,
        severity: 'yellow',
        source: 'scan',
        kind: 'audit-required',
        message: msg,
        target: entryName,
        pluginHint: entryName,
        at: Date.now(),
      })
      if (config.mode === 'deny') {
        void fiber.dispose()
        throw new Error(msg)
      }
    }

    // P0-4：扫描与后处理拆分——deny 用同步 scanSync（observer 内需要同步抛错回滚挂载），
    // report 用异步 scan()（spawn 子进程不阻塞事件循环；旧实现 report 也走 scanSync，
    // async IIFE 包不住同步阻塞，大包扫描会冻结整个 DSH 最长 scannerTimeoutMs）。
    const finish = (res: ScanResponse): void => {
      if (!res.ok || res.report === undefined) {
        // M9：deny 模式扫描失败必须 fail-closed（拦截 + 告警），否则恶意包可借
        // 扫描超时/异常静默放行；report 模式记录告警（扫描器失活本身是异常信号）
        const msg = `vet: 扫描失败 ${entryName}：${res.error ?? 'unknown'}`
        ctx.logger.error(msg)
        status?.record({
          id: `scan-fail:${entryName}`,
          severity: 'yellow',
          source: 'scan',
          kind: 'scan-fail',
          message: msg,
          target: entryName,
          pluginHint: entryName,
          at: Date.now(),
        })
        if (config.mode === 'deny') {
          void fiber.dispose()
          throw new Error(`vet: 扫描失败，拒绝加载 ${entryName}（fail-closed）`)
        }
        return
      }
      const { verdict, staticScore } = res.report
      ctx.logger.info(`vet: auto-scan ${entryName} → ${verdict} (${staticScore})`)
      status?.noteScan({ pluginName: entryName, verdict, staticScore, at: Date.now() })
      if (config.mode === 'deny' && RANK[verdict] >= DENY_RANK[config.denyOn]) {
        void fiber.dispose()
        throw new Error(`vet: 拦截 ${entryName}（${verdict}）`)
      }
    }

    if (root === undefined) return
    const files = listSourceFiles(root)
    if (files.length === 0) return
    const request = { kind: 'files' as const, files, osv: config.osvCheck === true }
    // P2-5：engine 的扫描预算 = files×2s；守卫超时若小于它，大包会在 engine 发出 R8-skip 前
    // 被 kill → 扫描静默失败。超时按文件数放大（上限 60s），让 engine 能优雅降级而不是被杀。
    const scanTimeoutMs = Math.min(Math.max(config.scannerTimeoutMs, files.length * 2000), 60_000)

    if (config.mode === 'deny') {
      // 同步路径：observer 内同步抛错才能让 cordis 回滚挂载（拦截语义必须同步）
      // P2-7：同步路径剔除 OSV——spawnSync 冻结宿主期间 OSV 网络查询（每包最多 4s）
      // 会成倍放大冻结；deny 判定只依据确定性静态扫描（OSV 是网络增强，留在 report 异步路径）。
      // 超时封顶 30s（engine 自身按文件预算优雅降级 R8-skip；此前按文件数放大到 60s）。
      // 超时/失败仍走 fail-closed（M9 反扫描规避：恶意大包可借扫描超时静默放行——
      // 拒绝加载是安全方向；已被 report 模式扫描过的包命中缓存，deny 秒回）。
      const res = scanSync({ ...request, osv: false }, { timeoutMs: Math.min(scanTimeoutMs, 30_000) })
      finish(res)
      return
    }
    // report 异步路径：spawn 子进程不阻塞事件循环（P0-4 修复——旧实现 report 也走 scanSync，
    // 大包扫描会冻结整个 DSH 最长 scannerTimeoutMs）。返回 promise 便于测试 await 扫描完成。
    return (async () => {
      try {
        const res = await scan(request, { timeoutMs: scanTimeoutMs })
        finish(res)
      } catch (error) {
        ctx.logger.error(String(error))
      }
    })()
  })
}