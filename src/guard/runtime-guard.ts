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
import { DEFAULT_HOOK_CONFIG, patchModule, type HookAlarm } from './runtime-hooks.js'
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

interface LoaderLike {
  entries(): { options: { name: string } }[]
}

/**
 * 安装运行时守卫（T1 + T2）。
 * @returns disposer：恢复钩子并终止哨兵（HMR/卸载安全）。
 */
/** 全局 guard 实例注册表（D30 修漏 H1）：dsh 配置热重载会重复 apply，
 * 若前一个实例的 T2 钩子没被卸载就叠加包装。用模块级变量记住上一个 disposer，
 * 每次 install 前先 dispose 旧实例（恢复 fs/child_process 原始函数 + 终止旧哨兵），再装新的。 */
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
    // env 注册表：已有存活哨兵（热重载前的实例）→ 复用，不重复 spawn（D30 单例）
    const existing = envSidecarPid()
    if (existing !== undefined && pidAlive(existing)) {
      sidecarSpawned = true
      child = undefined
      sidecarAlive = true
      ctx.logger.info(`vet: 复用既有哨兵 (pid=${existing})——跳过重复 spawn`)
      guardDisabled = false
      return
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
  const rootIndex = (): Map<string, string> => {
    const map = new Map<string, string>()
    let loader: LoaderLike | undefined
    try {
      loader = (ctx as Context & { loader?: LoaderLike }).loader
    } catch {
      loader = undefined
    }
    const names: string[] = []
    if (loader !== undefined) {
      for (const entry of loader.entries()) names.push(entry.options.name)
    }
    // vet 被符号链接安装时 realpath 解析不到 profile node_modules → 用 loader 基准（ctx.baseUrl）
    const profileDir = (ctx as { baseUrl?: string }).baseUrl
    for (const name of names) {
      const root = resolvePackageRoot(name, profileDir)
      if (root !== undefined) map.set(root, name)
    }
    return map
  }
  const sink = (alarm: HookAlarm): void => {
    // 官方归因的 spawn 降噪（官方能力授权）；第三方与无归因才报警
    if (alarm.kind === 'spawn' && alarm.pluginHint !== undefined && isOfficial(alarm.pluginHint)) return
    const entry: VetAlarm = {
      // P1-6：id 拼 pluginHint——两个插件碰同一敏感路径不再同 id 互吞（后到者报警被去重吞掉）
      id: t2AlarmId(alarm.kind, alarm.target, alarm.pluginHint),
      severity: alarm.severity,
      source: 't2',
      kind: alarm.kind,
      message: alarm.message,
      target: alarm.target,
      pluginHint: alarm.pluginHint,
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

  const disposer = (): void => {
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