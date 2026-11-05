/**
 * 从「这次扫描到底做了什么」推出九个面的结论（施工图 §2 的负责人表）。
 *
 * 原则只有一条：**能从事实推出来的才写，推不出来的写 unknown**。
 * 所以这里没有「默认 covered」这条路径——那是把「没看」说成「没事」的唯一入口。
 *
 * 已知的诚实缺口（是当前实现的真实状态，不是待办）：
 * - `intel_registry`：registry 对账是异步的、且只在官方包上跑，扫描收尾时拿不到结果 → unknown；
 * - `deps_transitive`：`config.transitiveDeps` 默认关，关着就是 excluded，不是「没问题」。
 */
import { hookHeartbeat } from './runtime-heartbeat.js'
import { coverageEntry } from '../domain/coverage.js'
import type { CoverageEntry, CoverageResult } from '../domain/types.js'

/**
 * 0.5.4：扫描器上报的 OSV 相位统计（结构同协议 `OsvOutcome`，这里不 import 协议——
 * 校验器不该因为扫描器换了个协议文件就重新编译整套宿主代码）。
 */
export interface OsvOutcomeLike {
  readonly phase: 'ran' | 'overran' | 'skipped'
  readonly targets: number
  readonly attempted: number
  readonly answered: number
}

export interface CoverageInputs {
  readonly osvEnabled: boolean
  /**
   * 0.5.4：扫描器自述的 OSV 统计（协议 `ScanReport.osv`）。
   * 缺席 = 旧扫描器 / 同步路径——**不能**当成「问到了」，只能继续按「没回报」处置。
   */
  readonly osv?: OsvOutcomeLike
  /**
   * 0.5.4：OSV 相位被**已知原因**跳过（deny 模式的同步扫描不发网络请求）。
   * 与「扫描器没回报」分开说：那是不知道，这是知道没问。
   */
  readonly osvSkipped?: 'sync-mode'
  readonly transitiveDeps: boolean
  readonly runtimeGuard: string
  /** 本次扫描是否失败（扫描器没给出报告）。 */
  readonly scanFailed: boolean
  /** 送进扫描器的源码文件数（report.sourceCount）；0 说明这个包没有可判的源码。 */
  readonly sourceCount: number
  /**
   * 扫描器自己跳过的文件数（`rule: 'R8'` 的元 finding：超预算/过大/单文件异常）。
   * **有跳过就不能说 file_tree 已覆盖**——那些文件没参与判定，而 sourceCount 不会因此变 0。
   */
  readonly skippedFiles?: number
  /**
   * 0.5.3：该包是否含内建模块的 ESM 具名导入（C2 边界）——T2 钩子对这类绑定不生效。
   * 以前这条事实是一条黄牌（`esm-guard-coverage`），现在落在它能被归位的地方：**这个主体的
   * 运行时面是 partial**。黄牌说的是「有个风险」，覆盖率行说的是「我们看不见这一面」——
   * 后者才是事实，前者是它的推论。
   */
  readonly esmNamedBuiltins?: boolean
  /** 命中的具体模块（`fs` / `child_process` / `net`…）。缺席 = 旧扫描器/旧缓存，按「不知哪几个面」处置。 */
  readonly esmNamedModules?: readonly string[]
  /** 该主体是否已被接受为「已知架构边界」（官方内容锚）——只影响呈现档位，不改结论。 */
  readonly esmAcknowledged?: boolean
  /** 0.5.3：网络出口观测是否被关掉（`config.networkEgress === false`）。关掉 = 明确不看这一面。 */
  readonly networkEgress?: boolean
  readonly observedAt: number
  readonly observerVersion?: string
  /**
   * 这次判定发生在哪个上下文：
   * - `guard`（默认）：插件加载时的自动扫描，运行时面与传递依赖都有意义；
   * - `tool`：`scan_plugin` 的单次静态扫描——它不对运行时防线表态，也不跑传递依赖雷达。
   *   这些面留空，由 `withUnknownDefaults` 落成 unknown，而不是编一个 unsupported。
   * - `gate`（0.5.11）：安装闸门。它比 `tool` 做得还少——不跑传递依赖雷达（没有这个
   *   开关）、不做 registry 对账。这两行在这里是 `unsupported`（这个边界没有这项能力），
   *   不是 `excluded`（用户选择不看）：把「我们没有」写成「用户不要」，会让人去找一个
   *   不存在的配置项。
   */
  readonly scope?: 'guard' | 'tool' | 'gate'
}

/** 模块标签 → 面。标签来自 `registerHookTarget` 的第一个参数（module 名）。
 * 0.5.3 补 http2/tls：它们由 `patchNetworkModule` 注册，此前不在集合里——被剥离时
 * `runtime_net` 仍报 covered（只有全局的 runtime_hook_health 塌了），归因是错的。 */
export const FS_MODULES: ReadonlySet<string> = new Set(['fs', 'fs/promises'])
export const NET_MODULES: ReadonlySet<string> = new Set(['net', 'http', 'https', 'http2', 'tls', 'dgram', 'fetch'])
export const SPAWN_MODULES: ReadonlySet<string> = new Set(['child_process'])

/**
 * ESM 具名导入命中的内建模块 → 它让哪个执行面变得不完整。
 *
 * 只列**钩子真的 patch 过**的模块：`vm` / `worker_threads` 在 ESM 盲区集合里，但钩子
 * 本来就不看它们——把它们的具名导入记到 fs/net/spawn 头上，等于把「一直没看」说成
 * 「被 ESM 绕过」，两个都不是好答案。这类模块的盲区是全局的、与 ESM 无关，本表不认领。
 */
const ESM_SURFACE_OF: Readonly<Record<string, 'runtime_fs' | 'runtime_net' | 'runtime_spawn'>> = {
  fs: 'runtime_fs',
  'fs/promises': 'runtime_fs',
  child_process: 'runtime_spawn',
  net: 'runtime_net',
  http: 'runtime_net',
  https: 'runtime_net',
  http2: 'runtime_net',
  tls: 'runtime_net',
  dgram: 'runtime_net',
}

/**
 * 某个面在钩子侧的结论。
 *
 * 三种情况的区分很重要：
 * - 该面根本没有钩子注册 → `unknown`（我们没看，不是「看了没问题」；也不叫 unsupported，
 *   因为没有哪个配置说不看它——注册失败同样会落在这里，那正是要让人看见的）；
 * - 注册了且全部完好 → `covered`；
 * - 注册了但有条目被剥离/替换 → `failed`（这就是 hook-heartbeat 的镜像）。
 */
function hookSurface(
  modules: ReadonlySet<string>,
  checks: ReadonlyArray<{ module: string; op: string; intact: boolean }>,
  observedAt: number,
  observerVersion?: string,
): CoverageEntry | null {
  const relevant = checks.filter((c) => modules.has(c.module))
  if (relevant.length === 0) return null
  const broken = relevant.filter((c) => !c.intact).map((c) => c.module)
  if (broken.length > 0) {
    return coverageEntry(surfaceOf(modules), 'failed', [`hook-stripped:${broken.join(',')}`], observedAt, observerVersion)
  }
  return coverageEntry(surfaceOf(modules), 'covered', [], observedAt, observerVersion)
}

function surfaceOf(modules: ReadonlySet<string>): 'runtime_fs' | 'runtime_net' | 'runtime_spawn' {
  if (modules === FS_MODULES) return 'runtime_fs'
  if (modules === NET_MODULES) return 'runtime_net'
  return 'runtime_spawn'
}

/**
 * 生成一次扫描对应的覆盖面结论（未补齐，调用方用 `withUnknownDefaults` 收口）。
 */
export function coverageForScan(inputs: CoverageInputs): CoverageEntry[] {
  const { observedAt, observerVersion } = inputs
  const out: CoverageEntry[] = []

  // 静态面
  if (inputs.scanFailed) {
    out.push(coverageEntry('file_tree', 'failed', ['scanner-error'], observedAt, observerVersion))
  } else if (inputs.sourceCount === 0) {
    out.push(coverageEntry('file_tree', 'partial', ['no-source-files'], observedAt, observerVersion))
  } else if ((inputs.skippedFiles ?? 0) > 0) {
    // 扫描器跳过了文件（R8）：其余文件判完了，但这一批没参与判定。
    // 这里最容易写成 covered——sourceCount > 0 看着一切正常，可被跳过的那些恰恰是
    // 攻击者最想让我们跳过的（超大文件 / 预算耗尽）。
    out.push(coverageEntry('file_tree', 'partial', [`scan-skipped:${inputs.skippedFiles}`], observedAt, observerVersion))
  } else {
    out.push(coverageEntry('file_tree', 'covered', [], observedAt, observerVersion))
  }

  if (inputs.osvEnabled) {
    // 「问了」与「问到了」是两件事，两个面各说一件：
    // - `deps_direct`：直接依赖**递出去了**吗（0.5.4 起能说出有目标没递出去）；
    // - `intel_osv`：情报**回来了**吗（0.5.4 起扫描器自述尝试/应答条数）。
    // 0.5.4 之前没有统计，这一格只能如实写 partial（「问了不等于问到了」）；现在有统计按事实说，
    // 缺统计（旧扫描器 / 同步路径）仍然不给好话。
    out.push(depsDirectRow(inputs))
    out.push(intelOsvRow(inputs))
  } else {
    out.push(coverageEntry('deps_direct', 'excluded', ['osv-disabled'], observedAt, observerVersion))
    // OSV 关掉时 intel_osv 是「没查过情报」，不是「查过没问题」——这一条最容易被写反。
    out.push(coverageEntry('intel_osv', 'excluded', ['osv-disabled'], observedAt, observerVersion))
  }
  // 单次扫描工具到这里为止：运行时面与传递依赖不在它的回答范围里，留白（→ unknown）。
  if (inputs.scope === 'tool') return out

  // 安装闸门（0.5.11）：传递依赖雷达与 registry 对账都不在这个边界上。写 unsupported
  // 而不是 excluded——这里没有「被谁关掉」的开关，写成 excluded 会指向一个不存在的配置。
  if (inputs.scope === 'gate') {
    out.push(coverageEntry('deps_transitive', 'unsupported', ['not-run-in-gate'], observedAt, observerVersion))
    out.push(coverageEntry('intel_registry', 'unsupported', ['no-registry-check-in-gate'], observedAt, observerVersion))
    return out
  }

  out.push(
    inputs.transitiveDeps
      ? coverageEntry('deps_transitive', 'covered', [], observedAt, observerVersion)
      : coverageEntry('deps_transitive', 'excluded', ['transitive-deps-off'], observedAt, observerVersion),
  )
  out.push(coverageEntry('intel_registry', 'unknown', ['reconcile-only-on-official'], observedAt, observerVersion))

  // 运行时面
  if (inputs.runtimeGuard === 'off') {
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn', 'runtime_hook_health'] as const) {
      out.push(coverageEntry(surface, 'unsupported', ['runtime-guard-off'], observedAt, observerVersion))
    }
    return out
  }

  const heartbeat = hookHeartbeat()
  const fs = hookSurface(FS_MODULES, heartbeat.checks, observedAt, observerVersion)
  const net = inputs.networkEgress === false
    // 网络出口观测被显式关掉：这一面是「明确不看」，不是「没看过」。写成 unknown 会让用户
    // 去查一个自己关掉的功能（0.5.2 修过同款：postureOf 对用户关掉的开关报 unknown）。
    ? coverageEntry('runtime_net', 'unsupported', ['network-egress-off'], observedAt, observerVersion)
    : hookSurface(NET_MODULES, heartbeat.checks, observedAt, observerVersion)
  const spawn = hookSurface(SPAWN_MODULES, heartbeat.checks, observedAt, observerVersion)
  for (const entry of [fs, net, spawn]) {
    if (entry !== null) out.push(entry)
  }

  // 0.5.3：C2 边界从黄牌收敛成 coverage 行。只挂到**钩子真的在看**的面：钩子没注册时那一面
  // 是 unknown、被显式关掉时是 unsupported，两种情况下「ESM 让覆盖变少」都没有可减少的对象，
  // 硬挂一条 partial 反而会把 unsupported 抬成 partial（partial 比 unsupported 差，
  // 聚合取最差就会让「明确不看」看起来像「看了大部分」）。
  const watched = new Set(
    [fs, net, spawn].filter((e) => e !== null && e.result === 'covered').map((e) => e!.surface),
  )
  for (const entry of esmCoverageRows(inputs, observedAt, observerVersion)) {
    if (watched.has(entry.surface)) out.push(entry)
  }

  if (heartbeat.checks.length === 0) {
    out.push(coverageEntry('runtime_hook_health', 'unknown', ['no-hooks-registered'], observedAt, observerVersion))
  } else if (!heartbeat.ok) {
    out.push(coverageEntry('runtime_hook_health', 'failed', ['hook-integrity-broken'], observedAt, observerVersion))
  } else {
    out.push(coverageEntry('runtime_hook_health', 'covered', [], observedAt, observerVersion))
  }
  return out
}

/**
 * 扫描器上报的计数是跨进程 JSON（不可信输入）：负数/小数钳成非负整数。
 * 非有限数在上游整份退回「没回报」（见 osvCounts）——半份数字读出来的结论不如没有。
 * 应答数不能超过发起数、发起数不能超过目标数：计数自相矛盾时按「少答了」处理。
 */
function count(value: number): number {
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

interface OsvCounts {
  phase: 'ran' | 'overran' | 'skipped'
  targets: number
  attempted: number
  answered: number
}

function osvCounts(osv: OsvOutcomeLike | undefined): OsvCounts | undefined {
  if (osv === undefined) return undefined
  // 三个计数有一个不是有限数，就整份统计退回「没回报」：半份数字读出来的结论不如没有。
  if (![osv.targets, osv.attempted, osv.answered].every((n) => Number.isFinite(n))) return undefined
  const targets = count(osv.targets)
  const attempted = Math.min(count(osv.attempted), targets)
  const answered = Math.min(count(osv.answered), attempted)
  // 未知 phase（未来扫描器的新值 / 被篡改）一律按 overran 处置：不许把「看不懂」当成「查完了」。
  const phase = osv.phase === 'ran' || osv.phase === 'skipped' ? osv.phase : 'overran'
  return { phase, targets, attempted, answered }
}

/**
 * `deps_direct`：「我们把直接依赖递给 OSV 了吗」（问了没有）。
 *
 * 与 `intel_osv` 的分工不变，只是从 0.5.4 起能说清「递了几条、几条没递出去」：
 * - 有目标没发出去（预算/条数上限）→ partial（问了一部分）；
 * - 一条都没发出去 → unknown（没有证据，不是「部分证据」）；
 * - OSV 没开 / deny 的同步路径 → excluded（明确不做），与「做了没做到」分开。
 * 缺统计（旧扫描器）时维持 covered：请求确实带着 osv，我们不能凭空说它没递。
 */
function depsDirectRow(inputs: CoverageInputs): CoverageEntry {
  const { observedAt, observerVersion } = inputs
  const row = (result: CoverageResult, reasons: readonly string[]): CoverageEntry =>
    coverageEntry('deps_direct', result, reasons, observedAt, observerVersion)
  if (inputs.osvSkipped === 'sync-mode') return row('excluded', ['osv-not-run-sync'])
  const osv = osvCounts(inputs.osv)
  // 缺统计（旧扫描器）：请求确实带着 osv，我们不能凭空说它没递。
  if (osv === undefined) return row('covered', [])
  if (osv.phase === 'skipped') return row('unknown', ['osv-budget-exhausted'])
  if (osv.attempted === 0) {
    // 没有可递的目标（无 manifest / 无精确版本）是 covered；有目标却一条没递出去是 unknown。
    // overran 时 targets 可能还没枚举完，不能读成「没有可递的」。
    if (osv.phase === 'ran' && osv.targets === 0) return row('covered', [])
    return row('unknown', ['osv-budget-exhausted'])
  }
  const unqueried = osv.targets - osv.attempted
  // overran 但全部目标都发出去了（掐在传递依赖那边）：deps_direct 已经问完了，不记别人的超时账。
  return unqueried > 0 ? row('partial', [`osv-unqueried:${unqueried}`]) : row('covered', [])
}

/**
 * `intel_osv`：「情报真的回来了吗」（问到了没有）。
 *
 * 0.5.4 起扫描器自述尝试/应答条数，这一格终于能区分四种情况：
 * - 全问全答 → covered；
 * - 问了没答全 / 有目标没问 → partial（本来就是 partial 的本义：证据只到一半）；
 * - 一条都没问出去（预算）→ unknown（没有证据）；
 * - 没有可问的目标（无 package.json / 无精确版本）→ excluded（这一面这次不在场）。
 * 缺统计（旧扫描器 / 同步路径）→ 维持 partial：问了没有统计，仍不等于问到了。
 */
function intelOsvRow(inputs: CoverageInputs): CoverageEntry {
  const { observedAt, observerVersion } = inputs
  const row = (result: CoverageResult, reasons: readonly string[]): CoverageEntry =>
    coverageEntry('intel_osv', result, reasons, observedAt, observerVersion)
  if (inputs.osvSkipped === 'sync-mode') return row('excluded', ['osv-not-run-sync'])
  const osv = osvCounts(inputs.osv)
  // 缺统计（旧扫描器 / 旧链路）：问了没有统计，仍不等于问到了。
  if (osv === undefined) return row('partial', ['osv-outcome-not-reported'])
  if (osv.phase === 'skipped') return row('unknown', ['osv-budget-exhausted'])
  if (osv.attempted === 0) {
    // 没有可问的目标 → excluded（这一面这次不在场）。overran 时 targets 还是 0 不能这样读：
    // 那是「没来得及知道有没有」，不是「没有」。
    if (osv.phase === 'ran' && osv.targets === 0) return row('excluded', ['osv-no-target'])
    // 一条都没问出去：没有证据，说 partial 等于暗示「有一部分」。
    return row('unknown', ['osv-budget-exhausted'])
  }
  const reasons: string[] = []
  if (osv.phase === 'overran') reasons.push('osv-phase-overran')
  const unanswered = osv.attempted - osv.answered
  if (unanswered > 0) reasons.push(`osv-unanswered:${unanswered}/${osv.attempted}`)
  const unqueried = osv.targets - osv.attempted
  if (unqueried > 0) reasons.push(`osv-unqueried:${unqueried}`)
  return row(reasons.length === 0 ? 'covered' : 'partial', reasons)
}

/**
 * ESM 具名导入 → 受影响执行面的 partial 行（0.5.3，取代 `esm-guard-coverage` 黄牌）。
 *
 * 三种输入形态，三种处置：
 * - 有模块名且能对上钩子面 → 只标对得上的那几个面（`child_process` 只影响 spawn）；
 * - 有模块名但没有一个对得上的（`vm` / `worker_threads`）→ **不标**。那不是 ESM 造成的
 *   盲区，是钩子本来就不看；把它算到 fs/net/spawn 头上是另一种说谎；
 * - 只有布尔没有模块名（旧扫描器/旧缓存）→ 三个面全标，理由写 `esm-named-import` 不带
 *   模块。这是数据缺失时的保守降级：**不确定就少说好话**，而不是把不知道当没发生。
 */
function esmCoverageRows(
  inputs: CoverageInputs,
  observedAt: number,
  observerVersion?: string,
): CoverageEntry[] {
  if (inputs.runtimeGuard !== 'watch' || inputs.esmNamedBuiltins !== true) return []
  const bySurface = new Map<'runtime_fs' | 'runtime_net' | 'runtime_spawn', string[]>()
  for (const mod of inputs.esmNamedModules ?? []) {
    const surface = ESM_SURFACE_OF[mod]
    if (surface === undefined) continue
    const mods = bySurface.get(surface) ?? []
    if (!mods.includes(mod)) mods.push(mod)
    bySurface.set(surface, mods)
  }
  const acknowledged = inputs.esmAcknowledged === true
  const row = (surface: 'runtime_fs' | 'runtime_net' | 'runtime_spawn', mods: string[]): CoverageEntry => ({
    ...coverageEntry(surface, 'partial', [mods.length > 0 ? `esm-named-import:${mods.join(',')}` : 'esm-named-import'], observedAt, observerVersion),
    ...(acknowledged ? { acknowledged: true } : {}),
  })
  if (bySurface.size > 0) {
    return [...bySurface].map(([surface, mods]) => row(surface, mods))
  }
  // 一个模块名都没对上：要么没有模块名（旧数据），要么命中的模块不归任何执行面管。
  const modules = inputs.esmNamedModules ?? []
  if (modules.length > 0) return []
  return [row('runtime_fs', []), row('runtime_net', []), row('runtime_spawn', [])]
}
