/**
 * T1 哨兵（D22）：旁路子进程监视宿主进程 /proc——VmRSS（内存）、task children（子进程数）、
 * fd 数。只报警不动作；归因粒度 = 宿主进程全局（插件共用进程，无法到插件级，见 PLAN §14.5）。
 * analyzeSample 是纯函数（可单测）；sidecarMain 是子进程入口（--vet-sidecar argv 触发）。
 */
import { readFileSync, readdirSync } from 'node:fs'

export interface ProcSample {
  rssKb: number
  /** -1 = 不可读（非 Linux / 权限不足）。 */
  childCount: number
  /** -1 = 不可读。 */
  fdCount: number
  at: number
}

export interface WatchConfig {
  intervalMs: number
  /** VmRSS 超限 → red（绝对阈值，内存炸弹）。 */
  memLimitMb: number
  /** 单轮子进程增量超限 → red（fork 炸弹）。 */
  forkBurstN: number
  /** fd 数超限 → yellow。 */
  fdLimit: number
  /** 窗口内 RSS 净增长超限 → yellow（持续膨胀/疑似泄漏），按倍数去重。 */
  growthMb: number
  /** 膨胀检测窗口（ms）。 */
  growthWindowMs: number
}

export interface WatchAlarm {
  id: string
  severity: 'yellow' | 'red'
  source: 't1'
  kind: 'mem' | 'fork' | 'fd' | 'growth'
  message: string
  target?: string
  at: number
}

export const DEFAULT_WATCH_CONFIG: WatchConfig = {
  intervalMs: 2000,
  memLimitMb: 2048,
  forkBurstN: 5,
  fdLimit: 512,
  growthMb: 256,
  growthWindowMs: 600_000,
}

/** 读 /proc/<pid> 快照；不可用（非 Linux / 权限不足）返回 null。 */
export function readProcSample(pid: number): ProcSample | null {
  try {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8')
    const rss = /VmRSS:\s*(\d+)\s*kB/.exec(status)
    if (rss === null) return null
    let childCount = -1
    try {
      const children = readFileSync(`/proc/${pid}/task/${pid}/children`, 'utf8').trim()
      childCount = children === '' ? 0 : children.split(/\s+/).length
    } catch {
      childCount = -1
    }
    let fdCount = -1
    try {
      fdCount = readdirSync(`/proc/${pid}/fd`).length
    } catch {
      fdCount = -1
    }
    return { rssKb: Number(rss[1]), childCount, fdCount, at: Date.now() }
  } catch {
    return null
  }
}

/** 一个 RSS 采样点（膨胀检测用）。 */
export interface RssSample {
  rssKb: number
  at: number
}

/**
 * 持续膨胀检测（纯函数，D22 补漏）：窗口内 RSS 净增长越过 growthMb 的每个整数倍
 * 各报一次（按 prevMultiples 去重，不刷屏）；回落归零则重置倍数。
 * @returns 本轮报警 + 新的已报警倍数。
 */
export function detectGrowth(
  samples: RssSample[],
  cfg: Pick<WatchConfig, 'growthMb' | 'growthWindowMs'>,
  prevMultiples: number,
): { alarms: WatchAlarm[]; multiples: number } {
  if (samples.length < 2) return { alarms: [], multiples: prevMultiples }
  const cutoff = samples[samples.length - 1].at - cfg.growthWindowMs
  const start = samples.find(s => s.at >= cutoff)
  if (start === undefined) return { alarms: [], multiples: prevMultiples }
  const growthKb = samples[samples.length - 1].rssKb - start.rssKb
  if (growthKb <= 0) return { alarms: [], multiples: 0 }
  const multiples = Math.floor(growthKb / (cfg.growthMb * 1024))
  if (multiples <= prevMultiples) return { alarms: [], multiples: prevMultiples }
  const now = samples[samples.length - 1].at
  return {
    alarms: [{
      id: `t1:growth:${cfg.growthMb}`,
      severity: 'yellow',
      source: 't1',
      kind: 'growth',
      message: `内存持续膨胀 ${Math.round(growthKb / 1024)} MB（窗口 ${cfg.growthWindowMs / 60000} 分钟，疑似泄漏）`,
      target: `growth=${Math.round(growthKb / 1024)}MB`,
      at: now,
    }],
    multiples,
  }
}

/** 相邻两样本差分判定（纯函数）：返回本轮报警（跨轮去重由 VetStatus.record 负责）。 */
export function analyzeSample(prev: ProcSample | null, curr: ProcSample, cfg: WatchConfig): WatchAlarm[] {
  const out: WatchAlarm[] = []
  const memMb = curr.rssKb / 1024
  if (memMb > cfg.memLimitMb) {
    out.push({
      id: `t1:mem:${cfg.memLimitMb}`,
      severity: 'red',
      source: 't1',
      kind: 'mem',
      message: `宿主进程内存超限：${memMb.toFixed(0)} MB（阈值 ${cfg.memLimitMb} MB）`,
      target: `VmRSS=${curr.rssKb}kB`,
      at: curr.at,
    })
  }
  if (prev !== null && prev.childCount >= 0 && curr.childCount >= 0
    && curr.childCount - prev.childCount > cfg.forkBurstN) {
    out.push({
      id: `t1:fork:${cfg.forkBurstN}`,
      severity: 'red',
      source: 't1',
      kind: 'fork',
      message: `子进程数突增：${prev.childCount} → ${curr.childCount}（疑似 fork 炸弹）`,
      target: `delta=${curr.childCount - prev.childCount}`,
      at: curr.at,
    })
  }
  if (curr.fdCount > cfg.fdLimit) {
    out.push({
      id: `t1:fd:${cfg.fdLimit}`,
      severity: 'yellow',
      source: 't1',
      kind: 'fd',
      message: `文件描述符数超限：${curr.fdCount}（阈值 ${cfg.fdLimit}）`,
      target: `fds=${curr.fdCount}`,
      at: curr.at,
    })
  }
  return out
}

/**
 * 哨兵子进程入口：监视 PPID（宿主）。宿主退出（/proc/<ppid>/stat 不可读）即自杀。
 * 每轮把报警以 JSON 行写到 stdout，宿主侧按行解析。
 */
/**
 * 单例锁（D30 修漏）：同宿主（PPID）下只允许一个 vet 哨兵。
 * dsh 配置热重载（改 cordis.patch.yml 触发）会重新 apply vet 插件 → installRuntimeGuard
 * 重复执行 → 重复 spawn sidecar。旧实例的 disposer 不一定被调用（重复 apply 而非替换），
 * 导致同宿主堆积多个 sidecar。让哨兵自己认亲：启动时扫 /proc，发现同 PPID 已有
 * vet-sidecar 兄弟（自己除外）即退出——无论宿主怎么重复 apply，同宿主永远只有一个哨兵。
 */
function siblingSidecarPids(hostPid: number): number[] {
  const out: number[] = []
  let entries: string[]
  try {
    entries = readdirSync('/proc')
  } catch {
    return out
  }
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue
    const pid = Number(entry)
    if (pid === process.pid) continue
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, 'utf8')
      const close = stat.lastIndexOf(')')
      if (close === -1) continue
      const fields = stat.slice(close + 2).trim().split(' ')
      if (Number(fields[1]) !== hostPid) continue // 不是本宿主的子进程
      const cmdline = readFileSync(`/proc/${entry}/cmdline`, 'utf8').replace(/\0/g, ' ')
      if (cmdline.includes('runtime-watch.js') && cmdline.includes('--vet-sidecar')) out.push(pid)
    } catch {
      // 进程刚退出（/proc 竞态）——忽略
    }
  }
  return out
}

/**
 * 哨兵子进程入口：监视 PPID（宿主）。宿主退出（/proc/<ppid>/stat 不可读）即自杀。
 * 每轮把报警以 JSON 行写到 stdout，宿主侧按行解析。
 */
export function sidecarMain(cfg: WatchConfig): void {
  const hostPid = process.ppid
  // 单例锁：同宿主已有 vet-sidecar 兄弟 → 自己是重复 spawn 的冗余实例，直接退出
  if (siblingSidecarPids(hostPid).length > 0) {
    process.exit(0)
  }
  let prev: ProcSample | null = null
  let samples: RssSample[] = []
  let growthMultiples = 0
  const startAt = Date.now()
  const tick = (): void => {
    try {
      readFileSync(`/proc/${hostPid}/stat`, 'utf8')
    } catch {
      process.exit(0)
    }
    const curr = readProcSample(hostPid)
    if (curr === null) return
    for (const alarm of analyzeSample(prev, curr, cfg)) {
      process.stdout.write(JSON.stringify(alarm) + '\n')
    }
    prev = curr
    // 持续膨胀检测：冷启动阶段（dsh web 加载 bundle / 进程内构建 client bundle）RSS 会在
    // 几秒内一次性爬升数百 MB，若从启动瞬间起算会把它误报成“疑似泄漏”。等进程进入稳态
    // （启动满 growthWindowMs 之后）再开窗测漂移，基线取稳态后的首个采样。
    if (curr.at - startAt < cfg.growthWindowMs) return
    // 持续膨胀检测：窗口内净增长按倍数报警
    samples.push({ rssKb: curr.rssKb, at: curr.at })
    const cutoff = curr.at - cfg.growthWindowMs
    while (samples.length > 0 && samples[0].at < cutoff) samples.shift()
    const growth = detectGrowth(samples, cfg, growthMultiples)
    growthMultiples = growth.multiples
    for (const alarm of growth.alarms) {
      process.stdout.write(JSON.stringify(alarm) + '\n')
    }
  }
  tick()
  // 不能 unref：哨兵进程唯一句柄就是定时器，unref 后事件循环清空 → 首轮后进程即退出，
  // 持续膨胀检测（需要跨多轮采样）永远无法触发（D22 实测发现）
  setInterval(tick, cfg.intervalMs)
}

// 子进程入口分发：仅当以 --vet-sidecar 启动时进入哨兵模式（vitest/宿主正常 import 不受影响）。
const sidecarIdx = process.argv.indexOf('--vet-sidecar')
if (sidecarIdx !== -1) {
  const intervalMs = Number(process.argv[sidecarIdx + 1] ?? DEFAULT_WATCH_CONFIG.intervalMs)
  const memLimitMb = Number(process.argv[sidecarIdx + 2] ?? DEFAULT_WATCH_CONFIG.memLimitMb)
  const forkBurstN = Number(process.argv[sidecarIdx + 3] ?? DEFAULT_WATCH_CONFIG.forkBurstN)
  const fdLimit = Number(process.argv[sidecarIdx + 4] ?? DEFAULT_WATCH_CONFIG.fdLimit)
  const growthMb = Number(process.argv[sidecarIdx + 5] ?? DEFAULT_WATCH_CONFIG.growthMb)
  const growthWindowMs = Number(process.argv[sidecarIdx + 6] ?? DEFAULT_WATCH_CONFIG.growthWindowMs)
  sidecarMain({ intervalMs, memLimitMb, forkBurstN, fdLimit, growthMb, growthWindowMs })
}