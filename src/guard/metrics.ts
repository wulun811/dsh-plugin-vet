/**
 * 宿主进程实时指标（D22）：内存（VmRSS）、CPU%（utime+stime 差分）、
 * 文件 I/O（/proc/self/io read_bytes/write_bytes）、子进程数、fd 数。
 * 网络：进程级不可得（/proc/<pid>/net 是网络命名空间级、会误导），明确不提供（面板有说明）。
 * 纯 /proc 读取，Linux 专有；非 Linux 全部回退 -1/0，不抛错。
 */
import { readFileSync, readdirSync } from 'node:fs'

export interface HostMetrics {
  rssMb: number
  cpuPct: number
  ioReadMb: number
  ioWriteMb: number
  childCount: number
  fdCount: number
  at: number
}

let prevCpu: { total: number; at: number } | undefined

/** 读取宿主进程实时指标（失败字段回退，绝不抛错）。 */
export function readHostMetrics(): HostMetrics {
  const pid = process.pid
  let rssMb = 0
  let childCount = -1
  let fdCount = -1
  let ioRead = 0
  let ioWrite = 0
  try {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8')
    const rss = /VmRSS:\s*(\d+)\s*kB/.exec(status)
    if (rss !== null) rssMb = Number(rss[1]) / 1024
  } catch {
    // /proc 不可用
  }
  try {
    const children = readFileSync(`/proc/${pid}/task/${pid}/children`, 'utf8').trim()
    childCount = children === '' ? 0 : children.split(/\s+/).length
  } catch {
    childCount = -1
  }
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
    cpuPct,
    ioReadMb: Math.round(ioRead / 1048576),
    ioWriteMb: Math.round(ioWrite / 1048576),
    childCount,
    fdCount,
    at: Date.now(),
  }
}
