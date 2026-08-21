/**
 * T1 哨兵生命周期（P0-4 结构债拆分自 runtime-guard.ts）。
 * 哨兵 pid 注册表（process.env，跨热重载保留）/ 意外退出重拉判定 / 平台支持门 /
 * PID 存活与身份校验（M9：/proc cmdline）/ 安全终止与 env 清理。纯生命周期，无报警侧接线。
 */

import { readFileSync } from 'node:fs'

/** T1 哨兵是否已启动（invariant 断言用）。 */
export let sidecarSpawned = false
/** P0-6：非 Linux 平台门的信息日志只记一次（避免热重载刷屏）。 */
export let sidecarSkippedWarned = false
/**
 * D30 修漏：哨兵 pid 注册表（process.env，跨模块热重载保留）。
 * dsh 配置热重载会重新 apply vet 插件 → module 级变量（child/sidecarAlive）全部重置，
 * 但 process.env 保留。用 env 记当前哨兵 pid：
 * - watch 分支 spawn 前查 env：已有存活哨兵 → 复用不重复 spawn（根治重复 apply 叠加）；
 * - off 分支查 env：kill 遗留哨兵（关闭守卫必须真正停掉监控）。
 * sidecar 崩溃退出后 env 里的 pid 存活检查失败 → 下次 apply 重新 spawn。
 */
export const SIDECAR_PID_ENV = 'DSH_VET_SIDECAR_PID'

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

/**
 * P0-6（0.2.x）：T1 哨兵平台支持判定。侧车依赖 /proc（单例认亲 + 宿主存活看护 + PID 身份校验），
 * 仅 Linux 有；其余平台显式跳过——避免"哨兵首轮 exit(0) → 意外退出 → 重拉×5"的空转与
 * sentinel-down 噪音，且使"非 Linux 无 T1"成为有意设计而非意外命中。进程内 T2 钩子不受影响。
 */
export function sidecarSupportedOn(platform: NodeJS.Platform): boolean {
  return platform === 'linux'
}
export function envSidecarPid(): number | undefined {
  const raw = process.env[SIDECAR_PID_ENV]
  if (raw === undefined || raw === '') return undefined
  const pid = Number(raw)
  if (!Number.isInteger(pid) || pid <= 0) return undefined
  return pid
}

/** pid 是否存活（kill(0) 探测；EPERM 也视为存活——存在但不是我们的子进程）。 */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    return code === 'EPERM'
  }
}

/** M9（0.1.16 加固）：/proc/<pid>/cmdline 是否含 vet 侧车标记（Linux）。 */
export function pidCmdlineIsVetSidecar(pid: number): boolean {
  try {
    return readFileSync('/proc/' + pid + '/cmdline').includes(Buffer.from('vet-sidecar'))
  } catch {
    return false
  }
}

/**
 * M9（0.1.16 加固）：安全终止侧车——先核对 cmdline 再 SIGTERM，防 OS PID 复用误杀无辜进程
 * （旧实现只看 kill(pid,0) 存活即杀：侧车已退出 + 5s 窗口内 PID 被复用时会把别的进程干掉）。
 * 非 Linux（无 /proc）回退存活探测；被杀对象身份存疑时不动手并返回 false。
 */
export function safeKillSidecar(pid: number, signal: NodeJS.Signals = 'SIGTERM'): boolean {
  if (!pidAlive(pid)) return false
  if (process.platform === 'linux' && !pidCmdlineIsVetSidecar(pid)) return false
  try {
    process.kill(pid, signal)
    return true
  } catch {
    return false
  }
}

/** 按 env 注册表 kill 遗留哨兵（关闭守卫时调用）。 */
export function killSidecarFromEnv(logger: { warn: (m: string) => void }): void {
  const pid = envSidecarPid()
  if (pid === undefined) return
  const killed = safeKillSidecar(pid)
  if (!killed && pidAlive(pid)) {
    // M9：存活但身份存疑（PID 复用/找不到 cmdline）——不再误杀，仅告警
    logger.warn(`vet: 哨兵 pid=${pid} 存活但身份存疑（可能被 PID 复用），未终止——请人工确认`)
  }
  delete process.env[SIDECAR_PID_ENV]
  if (killed) logger.warn(`vet: 运行时守卫关闭，终止哨兵 (pid=${pid})`)
}
/** 供 runtime-guard 装配器设置哨兵已启动状态（ESM 导入只读，状态经 setter 变更）。 */
export function setSidecarSpawned(v: boolean): void {
  sidecarSpawned = v
}
/** 供 runtime-guard 装配器设置「非 Linux 平台信息日志只记一次」标志。 */
export function setSidecarSkippedWarned(v: boolean): void {
  sidecarSkippedWarned = v
}
