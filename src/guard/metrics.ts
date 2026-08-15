/**
 * 宿主进程实时指标（D22）：内存（VmRSS）、CPU%（utime+stime 差分）、
 * 文件 I/O（/proc/self/io read_bytes/write_bytes）、子进程数、fd 数。
 * 网络：进程级不可得（/proc/<pid>/net 是网络命名空间级、会误导），明确不提供（面板有说明）。
 * 纯 /proc 读取，Linux 专有；非 Linux 全部回退 -1/0，不抛错。
 */
import { readFileSync, readdirSync } from 'node:fs'

export interface HostMetrics {
  /** 进程总 RSS（MB）= DSH 宿主 + 全部插件 + vet 自身（同一进程，OS 仅见总量）。 */
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
  ioReadMb: number
  ioWriteMb: number
  childCount: number
  fdCount: number
  at: number
}

let prevCpu: { total: number; at: number } | undefined

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

/** 读取宿主进程实时指标（失败字段回退，绝不抛错）。 */
export function readHostMetrics(): HostMetrics {
  const pid = process.pid
  const mem = process.memoryUsage()
  const rssMb = mem.rss / 1048576
  const heapUsedMb = mem.heapUsed / 1048576
  const heapTotalMb = mem.heapTotal / 1048576
  const externalMb = (mem.external + (mem.arrayBuffers ?? 0)) / 1048576
  const children = readChildren()
  const childCount = children.length
  const mcpChildren = children.filter(c => /mcp/i.test(c.cmdline))
  const mcpRssMb = mcpChildren.reduce((sum, c) => sum + c.rssKb, 0) / 1024
  const mcpCount = mcpChildren.length
  // vet 自身子进程（T1 哨兵 / 扫描中 scanner-bin）：计入总账，避免"看不见的 vet 内存"
  const vetChildren = children.filter(c => /vet-sidecar|scanner-bin/i.test(c.cmdline))
  const vetRssMb = vetChildren.reduce((sum, c) => sum + c.rssKb, 0) / 1024
  const vetCount = vetChildren.length
  let fdCount = -1
  let ioRead = 0
  let ioWrite = 0
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
    // io 不可读
  }
  // CPU：utime+stime（clock ticks）差分；comm 可能含空格，从最后一个 ')' 后解析
  let cpuPct = 0
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
    const close = stat.lastIndexOf(')')
    const rest = stat.slice(close + 2).split(' ')
    const total = Number(rest[11] ?? 0) + Number(rest[12] ?? 0)
    const now = Date.now()
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
    ioReadMb: Math.round(ioRead / 1048576),
    ioWriteMb: Math.round(ioWrite / 1048576),
    childCount,
    fdCount,
    at: Date.now(),
  }
}
