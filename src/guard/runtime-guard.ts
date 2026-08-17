/**
 * 运行时守卫装配（D22）：runtimeGuard: 'watch' 时启用 T1 哨兵（子进程 /proc 监视）
 * + T2 钩子（进程内包装 fs/child_process）。
 * alarm-only：所有报警进 VetStatus；绝不自动拦截/杀进程（PLAN §2.1 D21）。
 */
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import cp from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { VetStatus, type VetAlarm } from './status.js'
import type { WatchAlarm } from './runtime-watch.js'
import { DEFAULT_HOOK_CONFIG, patchModule, setRootIndexing, type HookAlarm } from './runtime-hooks.js'
import { resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'
import { ensureHoneypot } from './honeypot.js'

/** T1 哨兵是否已启动（invariant 断言用）。 */
export let sidecarSpawned = false

/**
 * D30 修漏：哨兵 pid 注册表（process.env，跨模块热重载保留）。
 * dsh 配置热重载会重新 apply vet 插件 → module 级变量（child/sidecarAlive）全部重置，
 * 但 process.env 保留。用 env 记当前哨兵 pid：
 * - watch 分支 spawn 前查 env：已有存活哨兵 → 复用不重复 spawn（根治重复 apply 叠加）；
 * - off 分支查 env：kill 遗留哨兵（关闭守卫必须真正停掉监控）。
 * sidecar 崩溃退出后 env 里的 pid 存活检查失败 → 下次 apply 重新 spawn。
 */
const SIDECAR_PID_ENV = 'DSH_VET_SIDECAR_PID'

/**
 * P0-2：哨兵意外退出后是否重拉（纯函数，可测）。
 * 条件：env 注册表仍指向本哨兵（mine）+ 非 stopping + 未达上限。
 * 旧实现先删 env 再比较 → 恒 false，respawn 死代码；这里由调用方传入注册表 pid，判定与清理解耦。
 */
export function decideRespawn(
  registeredPid: number | undefined,
  childPid: number | undefined,
  stopping: boolean,
  respawnCount: number,
  maxRespawn: number,
): boolean {
  // 两边都要有值才判 mine——undefined === undefined 是「spawn 失败/无注册」不是「本哨兵」
  return registeredPid !== undefined && registeredPid === childPid && !stopping && respawnCount < maxRespawn
}

/** P1-6：T2 报警去重 id——拼 pluginHint，避免不同插件同路径互吞报警。 */
export function t2AlarmId(kind: string, target: string | undefined, pluginHint: string | undefined): string {
  return `t2:${kind}:${target ?? ''}:${pluginHint ?? ''}`
}

function envSidecarPid(): number | undefined {
  const raw = process.env[SIDECAR_PID_ENV]
  if (raw === undefined || raw === '') return undefined
  const pid = Number(raw)
  if (!Number.isInteger(pid) || pid <= 0) return undefined
  return pid
}

/** pid 是否存活（kill(0) 探测；EPERM 也视为存活——存在但不是我们的子进程）。 */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    return code === 'EPERM'
  }
}

/** 按 env 注册表 kill 遗留哨兵（关闭守卫时调用）。 */
function killSidecarFromEnv(logger: { warn: (m: string) => void }): void {
  const pid = envSidecarPid()
  if (pid === undefined) return
  try {
    if (pidAlive(pid)) process.kill(pid, 'SIGTERM')
  } catch {
    // 已退出
  }
  delete process.env[SIDECAR_PID_ENV]
  logger.warn(`vet: 运行时守卫关闭，终止哨兵 (pid=${pid})`)
}

/** 官方包信任（能力授权）：T2 对官方归因的 spawn 降噪（报警留给第三方）。 */
function isOfficial(name: string): boolean {
  return name.startsWith('@deepseek-ai/') || name === PACKAGE_NAME
}

/**
 * A9 归因排除：vet 自身不参与 T2 栈归因。包装器帧（runtime-hooks.js）永远是报警栈的栈顶，
 * 若 vet 根在归因映射里，一切宿主/无主报警都会归到 vet 头上（"vet 把自己算成警报"）。
 * 纯函数便于测试；排除后 vet 自己的敏感操作仍会报警（归因落空显示无主），不隐藏行为。
 */
export function isAttributableEntry(name: string): boolean {
  return name !== PACKAGE_NAME
}

/**
 * 构建 T2 栈归因映射（root→包名），结果缓存（报警风暴不重复 require.resolve）。
 * P1-3：整个构建体（含 loader.entries() 与 ctx.baseUrl 访问）都在 try/finally 内——
 * 任一环节抛错都必须复位 rootIndexing 标志，否则所有 T2 报警被静默 bypass（R31 的
 * 反向失败：护栏防了递归，却可能把 vet 永久搞失明）。归因失败时返回空映射（缓存），
 * 包装器侧另有 try/catch，fs 调用永不因归因失败而中断。
 */
export function createRootIndex(ctx: Context): () => Map<string, string> {
  let rootsCache: Map<string, string> | undefined
  return () => {
    if (rootsCache !== undefined) return rootsCache
    const map = new Map<string, string>()
    // R31：归因阶段自身的 fs 探测（resolvePackageRoot 的 realpathSync）会再次进入
    // T2 包装器；敏感包名（如 dsh-credentials）会再次 alarm → 归因 → 无限递归，
    // 栈深后任意正则编译触发 V8 栈溢出误报 OOM。置标志让包装器直通，断开递归。
    setRootIndexing(true)
    try {
      let loader: LoaderLike | undefined
      try {
        loader = (ctx as Context & { loader?: LoaderLike }).loader
      } catch {
        // cordis proxy 对未注入属性直接抛错而非返回 undefined（与 invariants 同款）
        loader = undefined
      }
      const names: string[] = []
      if (loader !== undefined) {
        for (const entry of loader.entries()) names.push(entry.options.name)
      }
      // vet 被符号链接安装时 realpath 解析不到 profile node_modules → 用 loader 基准（ctx.baseUrl）
      const profileDir = (ctx as { baseUrl?: string }).baseUrl
      for (const name of names) {
        // A9 归因排除 vet 自身（见 isAttributableEntry 注释）
        if (!isAttributableEntry(name)) continue
        const root = resolvePackageRoot(name, profileDir)
        if (root !== undefined) map.set(root, name)
      }
    } finally {
      setRootIndexing(false)
    }
    rootsCache = map
    return map
  }
}

interface LoaderLike {
  entries(): { options: { name: string } }[]
}

/**
 * 安装运行时守卫（T1 + T2）。
 * @returns disposer：恢复钩子并终止哨兵（HMR/卸载安全）。
 */
/** 全局 guard 实例注册表（D30 修漏 H1）：dsh 配置热重载会重复 apply，
 * 若前一个实例的 T2 钩子没被卸载就叠加包装。用模块级变量记住上一个 disposer，
 * 每次 install 前先 dispose 旧实例（恢复 fs/child_process 原始函数 + 终止旧哨兵），再装新的。
 * 与 ctx.on('dispose') 双保险：disposer 幂等（disposed 标志），先到者生效。 */
let prevGuardDisposer: (() => void) | undefined

/** H2：守卫已关闭（off/dispose）——pending 的 respawn 定时器检查此标志，禁止复活孤儿哨兵。 */
let guardDisabled = false

/** 守卫当前是否禁用（供 respawn 定时器/外部查询）。 */
export function isGuardDisabled(): boolean {
  return guardDisabled
}

export function installRuntimeGuard(ctx: Context, config: VetConfig, status: VetStatus): () => void {
  // 先卸载上一个实例（热重载/重复 apply 场景：旧钩子/旧哨兵必须清理，否则叠加）
  if (prevGuardDisposer !== undefined) {
    try {
      prevGuardDisposer()
    } catch {
      // 旧实例清理失败不阻断新实例
    }
    prevGuardDisposer = undefined
  }
  if (config.runtimeGuard !== 'watch') {
    // H2：置位 disabled，pending respawn 定时器将检查并放弃复活
    guardDisabled = true
    // 关闭守卫必须真正停掉监控：kill 遗留哨兵（env 注册表，跨重载有效）
    killSidecarFromEnv(ctx.logger)
    // 蜜罐依赖 T2 钩子：guard 未开时蜜罐静默不生效——显式告警，避免用户以为开了其实没开
    if (config.honeypot?.enabled === true) {
      ctx.logger.warn('vet: honeypot.enabled=true 但 runtimeGuard 非 watch——蜜罐未生效（需先开启运行时守卫）')
    }
    return () => {}
  }
  // P1-1：off→watch 转换（同一模块实例内重复 apply，如配置热重载先关后开）必须复位——
  // spawnSidecar 的 fresh-spawn 分支检查 guardDisabled，不复位则哨兵永不启动且无任何日志/报警
  guardDisabled = false
  const disposers: (() => void)[] = []

  // ── T1 哨兵 ─────────────────────────────────────────────
  const watchArgs = [
    String(config.runtimeIntervalMs),
    String(config.runtimeMemLimitMb),
    String(config.runtimeForkBurstN),
    String(config.runtimeFdLimit),
    String(config.runtimeGrowthMb),
    String(config.runtimeGrowthWindowMs),
  ]
  const sidecarPath = fileURLToPath(new URL('../guard/runtime-watch.js', import.meta.url))
  let child: ReturnType<typeof spawn> | undefined
  let sidecarAlive = false
  let stopping = false
  /** 意外退出重拉：上限 5 次 + 5s 退避（监控器自身失活必须可见，不能静默）。 */
  const MAX_RESPAWN = 5
  const RESPAWN_DELAY_MS = 5000
  let respawnCount = 0
  const spawnSidecar = (): void => {
    if (stopping) return
    // H2：守卫已关（off/dispose）→ 不复活哨兵（pending respawn 定时器触发时走到这里）
    if (guardDisabled) return
    // env 注册表：已有存活哨兵（热重载前的实例/重复安装的旧副本）
    // P1-2：不能复用——旧哨兵的 stdout 管道属于旧模块实例的 child 句柄，新实例没有它的
    // 监听器；复用 = 哨兵继续跑但 T1 报警全部写进已废弃的旧 VetStatus（热重载后静默丢失）。
    // 旧管道无法接管，只能清 env（防旧实例 exit 处理器按 decideRespawn 复活）+ 终止旧哨兵，
    // 再走下方全新 spawn（新管道 + 新监听器）。旧实例的 exit 处理器会记一条 sentinel-down
    // 到它自己的（已废弃）status，无害。
    const existing = envSidecarPid()
    if (existing !== undefined && pidAlive(existing)) {
      ctx.logger.warn(`vet: 检测到既有哨兵 (pid=${existing})——终止并以新实例接管（旧报警通道不可复用）`)
      delete process.env[SIDECAR_PID_ENV]
      try {
        process.kill(existing, 'SIGTERM')
      } catch {
        // 已退出
      }
      sidecarSpawned = false
      sidecarAlive = false
    }
    child = spawn(process.execPath, [sidecarPath, '--vet-sidecar', ...watchArgs], {
      stdio: ['ignore', 'pipe', 'inherit'],
    })
    process.env[SIDECAR_PID_ENV] = String(child.pid ?? '')
    sidecarSpawned = true
    sidecarAlive = true
    child.stdout?.setEncoding('utf8')
    // L2：JSON 行可能跨 chunk 截断——累积行缓冲，只在遇到完整换行时解析
    let lineBuf = ''
    child.stdout?.on('data', (chunk: string) => {
      lineBuf += chunk
      let nl: number
      while ((nl = lineBuf.indexOf('\n')) !== -1) {
        const line = lineBuf.slice(0, nl).trim()
        lineBuf = lineBuf.slice(nl + 1)
        if (line === '') continue
        try {
          const a = JSON.parse(line) as WatchAlarm
          status.record({ ...a, source: 't1' })
        } catch {
          ctx.logger.warn(`vet: 哨兵输出无法解析: ${line.slice(0, 120)}`)
        }
      }
    })
    child.on('error', (err) => {
      // P2-3：spawn 失败（EACCES/无效路径等）不能无监听——未捕获 'error' 事件会崩宿主。
      // 置为未存活并清掉残留 env（从未活过的 pid），不抛不 respawn（下次 apply 重新尝试）。
      sidecarAlive = false
      sidecarSpawned = false
      if (envSidecarPid() === child?.pid) delete process.env[SIDECAR_PID_ENV]
      ctx.logger.error(`vet: T1 哨兵启动失败：${String(err)}`)
      status.record({
        id: 't1:spawn-fail',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵启动失败，运行时内存/子进程/fd 监控未生效',
        at: Date.now(),
      })
    })
    child.on('exit', (code) => {
      sidecarAlive = false
      // P0-2：不再先删 env 再判定——那样 respawn 判定恒 false（env 刚被删），respawn 变死代码，
      // 哨兵意外退出后监控静默中断到下次 apply。这里直接用 exit 时读到的 registered 判定：
      // env 指向已死 pid 无害（spawnSidecar 的 pidAlive 探测失败会重新 spawn 并覆盖 env；
      // off/接管场景 env 已被清/改指，decideRespawn 为 false 不复活）。
      const registered = envSidecarPid()
      const respawn = decideRespawn(registered, child?.pid, stopping, respawnCount, MAX_RESPAWN)
      ctx.logger.warn(`vet: T1 哨兵退出（code=${code ?? 'null'}，respawn=${respawn}）`)
      if (stopping) return
      // 监控器失活本身是黄灯报警（vet 自己的进程挂了，用户该知道守护断了）
      status.record({
        id: 't1:sentinel-down',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵意外退出，运行时内存/子进程/fd 监控中断',
        at: Date.now(),
      })
      // 仅当 env 注册表仍指向本哨兵时才 respawn（off/接管场景不复活）
      if (respawn) {
        respawnCount++
        ctx.logger.warn(`vet: 5s 后重拉哨兵（第 ${respawnCount}/${MAX_RESPAWN} 次）`)
        setTimeout(spawnSidecar, RESPAWN_DELAY_MS).unref?.()
      }
      // P2-3：env 不再指向本实例且指向存活 pid → 哨兵已被其他实例接管/替换（跨模块重复安装
      // + 5s respawn 窗口竞态：旧副本可能 kill 新哨兵并复活自己的）。本实例不 respawn（判定
      // 正确），但接管是否成功不可见——这里记一条 warn + 黄灯，让「监控被换手」可观测而非静默。
      if (!respawn && registered !== undefined && registered !== child?.pid && pidAlive(registered)) {
        ctx.logger.warn(`vet: 哨兵已被其他实例接管（env 注册表指向存活 pid=${registered}，本实例 child=${child?.pid ?? 'none'}）——旧报警通道废弃，接管方负责监控`)
        status.record({
          id: 't1:sentinel-taken-over',
          severity: 'yellow',
          source: 't1',
          kind: 'sentinel',
          message: 'T1 哨兵被其他实例接管，本实例监控通道失效（如重复安装 vet，建议只保留一份）',
          at: Date.now(),
        })
      }
    })
  }
  spawnSidecar()
  disposers.push(() => {
    stopping = true
    const pid = envSidecarPid()
    if (pid !== undefined && pidAlive(pid)) {
      // 复用模式 child=undefined：走 env 注册表 kill（热重载后旧模块的 child 引用已不可靠）
      try {
        process.kill(pid, 'SIGTERM')
      } catch {
        // 已退出
      }
      delete process.env[SIDECAR_PID_ENV]
    } else if (sidecarAlive && child !== undefined) {
      child.kill()
    }
  })

  // ── T2 钩子 ─────────────────────────────────────────────
  // A9 归因映射（root→包名）只建一次并缓存：每个被分类的 fs 调用都会走归因，重建=每条
  // 报警 N×require.resolve 的 CPU 空转（报警风暴时放大）；热重载会重新 apply 生成新闭包，
  // 天然重建，无需失效机制。
  const rootIndex = createRootIndex(ctx)
  const sink = (alarm: HookAlarm): void => {
    // 官方包信任（能力授权，P2-6）：官方归因的报警全部降噪——官方包是平台本体，
    // dsh 自身高频读写 ~/.dsh（会话持久化/配置/存储），.dsh 敏感段加入后若只降噪 spawn
    // 会刷屏成永久黄灯。报警面 = 第三方插件与无主操作；第三方无法伪造归因（按真实栈路径判定）。
    if (alarm.pluginHint !== undefined && isOfficial(alarm.pluginHint)) return
    const entry: VetAlarm = {
      // P1-6：id 拼 pluginHint——两个插件碰同一敏感路径不再同 id 互吞（后到者报警被去重吞掉）
      id: t2AlarmId(alarm.kind, alarm.target, alarm.pluginHint),
      severity: alarm.severity,
      source: 't2',
      kind: alarm.kind,
      message: alarm.message,
      target: alarm.target,
      pluginHint: alarm.pluginHint,
      sessionLog: alarm.sessionLog,
      at: Date.now(),
    }
    status.record(entry)
  }
  const hookCfg = { ...DEFAULT_HOOK_CONFIG }
  // D27 蜜罐：guard watch 时按配置播种诱饵并登记蜜罐根（alarm-only；失败只告警）
  if (config.honeypot.enabled) {
    const hpRoot = ensureHoneypot(config.honeypot.dir, ctx.logger)
    if (hpRoot !== undefined) hookCfg.honeypotRoots = [hpRoot]
  }
  disposers.push(patchModule(fs as unknown as Record<string, unknown>, 'fs', hookCfg, sink, rootIndex))
  // fs.promises 是独立对象（require('fs').promises / node:fs/promises 同一对象），同步包装不覆盖 → 必须单独包装（D26 审核补漏）
  const promisesMod = (fs as unknown as { promises?: Record<string, unknown> }).promises
  if (promisesMod !== undefined) {
    disposers.push(patchModule(promisesMod, 'fs', hookCfg, sink, rootIndex))
  }
  disposers.push(patchModule(cp as unknown as Record<string, unknown>, 'child_process', hookCfg, sink, rootIndex))

  // 幂等：ctx.on('dispose') 与 prevGuardDisposer 都可能触发同一 disposer（重载时旧 ctx
  // 先 dispose、新 apply 再调 prevGuardDisposer）——先到者生效，重复执行是 no-op。
  let disposed = false
  const disposer = (): void => {
    if (disposed) return
    disposed = true
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // 恢复/终止失败不阻断卸载
      }
    }
  }
  prevGuardDisposer = disposer
  return disposer
}