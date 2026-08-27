/**
 * 宿主进程实时指标（D22）：内存（VmRSS）、CPU%（utime+stime / darwin ps TIME 差分）、
 * 文件 I/O（/proc/<pid>/io read_bytes/write_bytes）、子进程数、fd 数。
 * 网络：进程级不可得（/proc/<pid>/net 是网络命名空间级、会误导），明确不提供（面板有说明）。
 *
 * 平台分派（round-20）：
 * - Linux：纯 /proc 读取（本模块原有路径，零行为变化）。
 * - macOS 11+：stock `ps -A -w -w -o pid,ppid,rss,time,command` 采 子进程/CPU/分类内存，
 *   `lsof -w -p PID -Fn` 采 fd（FD_TTL 降频）。本函数在**宿主进程内**被面板轮询（5s）调用，
 *   同步 execFile 会卡宿主事件循环——故走"异步快照缓存 + TTL 触发后台刷新"：readHostMetrics
 *   只读缓存，永不 spawn 同步子进程；面板不轮询 = 不刷新（零成本）。首轮数据未到时
 *   childCount=-1（面板画 —）、其余字段 0/-1 回退，后续轮询自动补齐。
 * - Windows/其他：无 stock 等价数据源（见 README 平台支持），OS 侧字段保持 -1/0 回退
 *   （childCount 自 round-21 起也如实 -1——宿主必然可能有子进程，伪 0 比 — 更误导），
 *   仅 V8 侧数字（rss/heap/external）真实——与 0.1.x 行为一致。
 * io：仅 Linux 可得；macOS 无低开销的按进程字节计数（stock CLI 拿不到），明确 -1（面板画 —），
 * 不再伪装 0。任何失败只回退，绝不抛错。
 */
import { readFileSync, readdirSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { countDarwinLsofFd } from './darwin-sysinfo.js'

export interface HostMetrics {
  /** 进程总 RSS（MB）= DSH 宿主 + 全部插件 + vet 自身（同一进程，OS 仅见总量）。跨平台（V8 自报）。 */
  rssMb: number
  /** V8 堆已用（MB）。 */
  heapUsedMb: number
  /** V8 堆总量（MB）。 */
  heapTotalMb: number
  /** 原生/外部内存（MB）：external + arrayBuffers（Buffer/ArrayBuffer 等）。 */
  externalMb: number
  /** 独立 MCP 服务进程（命令行含 mcp 的子进程，如 dsh-malong-bridge）合计内存（MB）。 */
  mcpRssMb: number
  /** MCP 服务进程数量。 */
  mcpCount: number
  /** vet 自己的子进程（T1 哨兵 + 扫描中 scanner-bin）合计内存（MB）。 */
  vetRssMb: number
  /** vet 子进程数量。 */
  vetCount: number
  cpuPct: number
  /** -1 = 平台不可得（macOS/Windows 无低开销按进程字节计数；受限 /proc 容器同）。 */
  ioReadMb: number
  /** -1 = 不可得，见 ioReadMb。 */
  ioWriteMb: number
  /** -1 = 暂无数据或平台不计数（macOS 首轮采样未完成；Windows/其他无数据源，round-21 起
   *  如实画 —，不再伪装"确实没有子进程"的 0；Linux 读失败为 0，维持原契约）。 */
  childCount: number
  fdCount: number
  at: number
}

/* ------------------------- 子进程分类（Linux/darwin 共用同一口径） ------------------------- */

const MCP_CHILD_RE = /mcp/i
const VET_CHILD_RE = /vet-sidecar|scanner-bin/i

/* ------------------------- 指标历史（P2，面板火花线数据源） ------------------------- */

/** 单个历史采样点：跨进程总占用 + CPU% + fd 数。 */
export interface MetricsHistoryPoint {
  at: number
  /** rss + mcp + vet 跨进程总占用（MB），与触发器 RAM 同口径。 */
  rssTotalMb: number
  cpuPct: number
  fdCount: number
}

const HISTORY_CAP = 64

const metricsHistory: MetricsHistoryPoint[] = []

/** 追加采样（环形上限 HISTORY_CAP；readHostMetrics 与测试共用）。 */
export function recordMetricsSample(point: MetricsHistoryPoint): void {
  if (!Number.isFinite(point.rssTotalMb) || !Number.isFinite(point.cpuPct)) return
  metricsHistory.push(point)
  if (metricsHistory.length > HISTORY_CAP) metricsHistory.shift()
}

/** 指标历史快照（旧→新；只读副本，进程内存态、重启清零可接受——计划 §三-D4）。 */
export function readMetricsHistory(): MetricsHistoryPoint[] {
  return [...metricsHistory]
}

/* ------------------------- darwin 采样（round-20） ------------------------- */

/** 异步一次性命令（cb 收 out|null；返回探活 pid 供子进程计数排除采样进程自身）。 */
export type AsyncCmdRunner = (
  cmd: string,
  args: string[],
  timeoutMs: number,
  cb: (out: string | null, probePid: number | undefined) => void,
) => number | undefined

/** 真实现：异步 execFile 一次性捕获。Linux CI 上也可直接测（execFile 跨平台，命令换成 ps 即可）。 */
export const defaultRunAsync: AsyncCmdRunner = (cmd, args, timeoutMs, cb) => {
  let probePid: number | undefined
  try {
    const cp = execFile(cmd, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout) => cb(err !== null || typeof stdout !== 'string' ? null : stdout, probePid))
    probePid = cp.pid
  } catch {
    return undefined
  }
  return probePid
}

/** ps 全表一调五得：pid/ppid/rss(KB，与 VmRSS 同尺度)/TIME(累计 CPU)/command。-w -w 防列宽截断。 */
export const DARWIN_METRICS_PS_ARGS: string[] = ['-A', '-w', '-w', '-o', 'pid=,ppid=,rss=,time=,command=']
const PS_TIMEOUT_MS = 1500
const LSOF_TIMEOUT_MS = 1500
/** ps 缓存 TTL：面板 5s 轮询 → 基本每轮触发一次后台刷新（刷新是异步的，不阻塞响应）。 */
const PS_TTL_MS = 4000
/** lsof 比 ps 重（且可能卡在 stale 挂载上）→ 15s 一刷（≈每 3 轮），与 T1 每 3 拍同思想。 */
const FD_TTL_MS = 15000

/** ps TIME 列 → 累计 CPU 毫秒（纯函数）。形态：`m:ss.cs`（macOS 常态）、`h:mm:ss`（Linux procps）、
 * `h:mm:ss.cs`（macOS ≥1h）。解析落空 → -1（该字段丢弃，不影响其他列）。 */
export function parseDarwinCpuMs(field: string): number {
  const parts = field.split(':')
  if (parts.length < 2 || parts.length > 3) return -1
  let h = 0
  let m: number
  let s: number
  if (parts.length === 3) {
    h = Number(parts[0])
    m = Number(parts[1])
    s = Number(parts[2])
  } else {
    m = Number(parts[0])
    s = Number(parts[1])
  }
  if (!Number.isFinite(h) || !Number.isFinite(m) || !Number.isFinite(s)) return -1
  if (h < 0 || m < 0 || s < 0) return -1
  // round-21: 空段（如畸形 '12:' / ':30'）——Number('')===0 会静默错算，显式拒绝
  if (parts.length > 0 && parts.some(p => p === '')) return -1
  return Math.round((h * 3600 + m * 60 + s) * 1000)
}

export interface DarwinMetricRow {
  pid: number
  ppid: number
  rssKb: number
  cpuMs: number
  command: string
}

/** 解析 `ps -o pid=,ppid=,rss=,time=,command=` 全表（纯函数）。command 列可含空格（取行余全部）；
 * 不匹配行（如含换行的参数导致的续行、内核异常行）静默跳过——与 T1 各解析器同一容错契约。 */
export function parseDarwinMetricTable(out: string): DarwinMetricRow[] {
  const rows: DarwinMetricRow[] = []
  for (const line of out.split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(line)
    if (m === null) continue
    const cpuMs = parseDarwinCpuMs(m[4])
    if (cpuMs < 0) continue
    rows.push({ pid: Number(m[1]), ppid: Number(m[2]), rssKb: Number(m[3]), cpuMs, command: m[5] })
  }
  return rows
}

export interface DarwinMetricsSummary {
  childCount: number
  mcpRssMb: number
  mcpCount: number
  vetRssMb: number
  vetCount: number
  /** 宿主自身累计 CPU ms（own 行缺失 = undefined → 本轮不更新 CPU 差分）。 */
  hostCpuMs: number | undefined
}

/** 汇总 darwin ps 表（纯函数）。excludePid = 采样探针（ps 自己是宿主的即时子进程，
 * 不排除会每轮给 childCount 掺水 +1；T1 无此问题因其探针挂在哨兵下，见 round-20 注释）。 */
export function summarizeDarwinMetricRows(
  rows: DarwinMetricRow[],
  hostPid: number,
  excludePid: number | undefined,
): DarwinMetricsSummary {
  let childCount = 0
  let mcpKb = 0
  let mcpCount = 0
  let vetKb = 0
  let vetCount = 0
  let hostCpuMs: number | undefined
  for (const r of rows) {
    if (excludePid !== undefined && r.pid === excludePid) continue
    if (r.pid === hostPid) {
      hostCpuMs = r.cpuMs
      continue
    }
    if (r.ppid === hostPid) {
      childCount++
      if (MCP_CHILD_RE.test(r.command)) {
        mcpKb += r.rssKb
        mcpCount++
      }
      if (VET_CHILD_RE.test(r.command)) {
        vetKb += r.rssKb
        vetCount++
      }
    }
  }
  return { childCount, mcpRssMb: mcpKb / 1024, mcpCount, vetRssMb: vetKb / 1024, vetCount, hostCpuMs }
}

interface DarwinCache {
  childCount: number
  mcpRssMb: number
  mcpCount: number
  vetRssMb: number
  vetCount: number
  fdCount: number
  cpuPct: number
  psAt: number
  fdAt: number
  inFlight: boolean
  prevHostCpu: { totalMs: number; at: number } | undefined
}

const darwinCache: DarwinCache = {
  childCount: -1, mcpRssMb: 0, mcpCount: 0, vetRssMb: 0, vetCount: 0,
  fdCount: -1, cpuPct: 0, psAt: 0, fdAt: 0, inFlight: false, prevHostCpu: undefined,
}

/** 后台刷新（fire-and-forget）：ps 成功 → 更新子进程/CPU + 视 TTL 追加 lsof；任何一级失败
 * 保留旧缓存等下次轮询重试（psAt 只在成功时前进）。inFlight 合并并发轮询。 */
function refreshDarwin(now: number, runAsync: AsyncCmdRunner, hostPid: number): void {
  if (darwinCache.inFlight) return
  darwinCache.inFlight = true
  const finish = (): void => {
    darwinCache.inFlight = false
  }
  let spawned: number | undefined
  try {
    spawned = runAsync('ps', DARWIN_METRICS_PS_ARGS, PS_TIMEOUT_MS, (out, probePid) => {
      if (out !== null) {
        const s = summarizeDarwinMetricRows(parseDarwinMetricTable(out), hostPid, probePid)
        darwinCache.childCount = s.childCount
        darwinCache.mcpRssMb = s.mcpRssMb
        darwinCache.mcpCount = s.mcpCount
        darwinCache.vetRssMb = s.vetRssMb
        darwinCache.vetCount = s.vetCount
        if (s.hostCpuMs !== undefined) {
          const prev = darwinCache.prevHostCpu
          if (prev !== undefined && now > prev.at && s.hostCpuMs >= prev.totalMs) {
            darwinCache.cpuPct = Number((((s.hostCpuMs - prev.totalMs) / (now - prev.at)) * 100).toFixed(1))
          }
          darwinCache.prevHostCpu = { totalMs: s.hostCpuMs, at: now }
        }
        darwinCache.psAt = now
        if (now - darwinCache.fdAt >= FD_TTL_MS) {
          try {
            const lsofPid = runAsync('lsof', ['-w', '-p', String(hostPid), '-Fn'], LSOF_TIMEOUT_MS, (lout) => {
              darwinCache.fdAt = now
              if (lout !== null) darwinCache.fdCount = countDarwinLsofFd(lout)
              finish()
            })
            if (lsofPid === undefined) finish() // lsof 也 spawn 失败 → 必须放行下一轮
          } catch {
            finish()
          }
          return
        }
      }
      finish()
    })
  } catch {
    // spawn 同步抛（ps 不存在等）→ 本拍放弃，下次轮询再来
  }
  if (spawned === undefined) finish()
}

/** 测试专用：清空 darwin 快照缓存（用例间隔离——否则前一用例的缓存/inFlight 泄漏进后一用例）。
 * 生产代码禁止调用（无平台判断，误调会多丢一轮 mac 面板数据，但无害可自愈）。 */
export function __resetDarwinMetricsCacheForTest(): void {
  darwinCache.childCount = -1
  darwinCache.mcpRssMb = 0
  darwinCache.mcpCount = 0
  darwinCache.vetRssMb = 0
  darwinCache.vetCount = 0
  darwinCache.fdCount = -1
  darwinCache.cpuPct = 0
  darwinCache.psAt = 0
  darwinCache.fdAt = 0
  darwinCache.inFlight = false
  darwinCache.prevHostCpu = undefined
}

interface ChildInfo {
  pid: number
  rssKb: number
  cmdline: string
}

/** 读取宿主直接子进程（pid + VmRSS + 命令行）；不可读返回空数组。 */
function readChildren(): ChildInfo[] {
  const out: ChildInfo[] = []
  let pids: string[] = []
  try {
    const children = readFileSync(`/proc/${process.pid}/task/${process.pid}/children`, 'utf8').trim()
    pids = children === '' ? [] : children.split(/\s+/)
  } catch {
    return out
  }
  for (const pid of pids) {
    try {
      const cmdline = readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ')
      const status = readFileSync(`/proc/${pid}/status`, 'utf8')
      const rss = /VmRSS:\s*(\d+)\s*kB/.exec(status)
      out.push({ pid: Number(pid), rssKb: rss !== null ? Number(rss[1]) : 0, cmdline: cmdline.slice(0, 200) })
    } catch {
      // 子进程已退出/权限不足 → 跳过
    }
  }
  return out
}

let prevCpu: { total: number; at: number } | undefined

/** 测试注入点（与 sidecarMain 的 deps 同一纪律）：platform/runAsync/now 默认取真实环境。 */
export interface MetricsDeps {
  platform?: NodeJS.Platform
  runAsync?: AsyncCmdRunner
  now?: () => number
}

/** 读取宿主进程实时指标（失败字段回退，绝不抛错；darwin 只读缓存，见文件头）。 */
export function readHostMetrics(deps: MetricsDeps = {}): HostMetrics {
  const platform = deps.platform ?? process.platform
  const runAsync = deps.runAsync ?? defaultRunAsync
  const nowFn = deps.now ?? Date.now
  const pid = process.pid
  const mem = process.memoryUsage()
  const rssMb = mem.rss / 1048576
  const heapUsedMb = mem.heapUsed / 1048576
  const heapTotalMb = mem.heapTotal / 1048576
  const externalMb = (mem.external + (mem.arrayBuffers ?? 0)) / 1048576
  let childCount = -1 // win32/其他：无数据源 → 如实 -1（面板画 —，round-21 反伪 0）
  let mcpRssMb = 0
  let mcpCount = 0
  let vetRssMb = 0
  let vetCount = 0
  let fdCount = -1
  let cpuPct = 0
  let ioRead = -1
  let ioWrite = -1
  if (platform === 'darwin') {
    const now = nowFn()
    if (now - darwinCache.psAt >= PS_TTL_MS) refreshDarwin(now, runAsync, pid)
    childCount = darwinCache.childCount
    mcpRssMb = darwinCache.mcpRssMb
    mcpCount = darwinCache.mcpCount
    vetRssMb = darwinCache.vetRssMb
    vetCount = darwinCache.vetCount
    fdCount = darwinCache.fdCount
    cpuPct = darwinCache.cpuPct
  } else if (platform === 'linux') {
    const children = readChildren()
    childCount = children.length
    const mcpChildren = children.filter(c => MCP_CHILD_RE.test(c.cmdline))
    mcpRssMb = mcpChildren.reduce((sum, c) => sum + c.rssKb, 0) / 1024
    mcpCount = mcpChildren.length
    // vet 自身子进程（T1 哨兵 / 扫描中 scanner-bin）：计入总账，避免"看不见的 vet 内存"
    const vetChildren = children.filter(c => VET_CHILD_RE.test(c.cmdline))
    vetRssMb = vetChildren.reduce((sum, c) => sum + c.rssKb, 0) / 1024
    vetCount = vetChildren.length
    try {
      fdCount = readdirSync(`/proc/${pid}/fd`).length
    } catch {
      fdCount = -1
    }
    try {
      const io = readFileSync(`/proc/${pid}/io`, 'utf8')
      const r = /read_bytes:\s*(\d+)/.exec(io)
      const w = /write_bytes:\s*(\d+)/.exec(io)
      if (r !== null) ioRead = Number(r[1])
      if (w !== null) ioWrite = Number(w[1])
    } catch {
      // io 不可读（受限容器等）→ 保持 -1（明确"不可得"，不再伪装 0）
    }
    // CPU：utime+stime（clock ticks）差分；comm 可能含空格，从最后一个 ')' 后解析
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
      const close = stat.lastIndexOf(')')
      const rest = stat.slice(close + 2).split(' ')
      const total = Number(rest[11] ?? 0) + Number(rest[12] ?? 0)
      const now = nowFn()
      if (prevCpu !== undefined) {
        const dtMs = now - prevCpu.at
        const dtTicks = total - prevCpu.total
        if (dtMs > 0 && dtTicks >= 0) {
          // USER_HZ=100 → 1 tick = 10ms；cpuPct 可 >100（多核）
          cpuPct = Number(((dtTicks * 10) / dtMs * 100).toFixed(1))
        }
      }
      prevCpu = { total, at: now }
    } catch {
      // stat 不可读
    }
  }
  // win32/其他：保持上方回退值（仅 V8 侧数字真实），零 spawn、零噪音——设计如此。
  const at = nowFn()
  // 采样入历史（环形）：跨进程总占用与触发器 RAM 同口径（rss+mcp+vet）
  recordMetricsSample({
    at,
    rssTotalMb: Math.round((rssMb + mcpRssMb + vetRssMb) * 10) / 10,
    cpuPct,
    fdCount,
  })
  return {
    rssMb: Math.round(rssMb * 10) / 10,
    heapUsedMb: Math.round(heapUsedMb * 10) / 10,
    heapTotalMb: Math.round(heapTotalMb * 10) / 10,
    externalMb: Math.round(externalMb * 10) / 10,
    mcpRssMb: Math.round(mcpRssMb * 10) / 10,
    mcpCount,
    vetRssMb: Math.round(vetRssMb * 10) / 10,
    vetCount,
    cpuPct,
    ioReadMb: ioRead >= 0 ? Math.round(ioRead / 1048576) : -1,
    ioWriteMb: ioWrite >= 0 ? Math.round(ioWrite / 1048576) : -1,
    childCount,
    fdCount,
    at,
  }
}
