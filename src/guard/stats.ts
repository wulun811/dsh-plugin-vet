/**
 * 防御统计模块（0.1.20）：记录 vet 的防御行为统计数据。
 * 存储：~/.dsh/vet/stats.json（原子写，0600）。
 * 数据：扫描插件数、警报总数、拦截次数、防御中插件数。
 * 用途：盾牌面板底部展示，让用户知道"被保护了多少次"。
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'

export interface VetStats {
  /** 累计扫描插件次数（recordScan 调用次数） */
  scannedCount: number
  /** 累计警报记录次数（status.record 调用次数） */
  alarmsRecorded: number
  /** 累计拦截次数（deny 模式 throw 次数） */
  blockedCount: number
  /** 当前防御中插件数（内存态，不持久化） */
  activeDefenseCount: number
  /** 最后更新时间 */
  updatedAt: number
}

const DEFAULT_STATS: VetStats = {
  scannedCount: 0,
  alarmsRecorded: 0,
  blockedCount: 0,
  activeDefenseCount: 0,
  updatedAt: 0,
}

/**
 * C3 加固：模块加载时快照 env——vet 先于第三方插件加载，
 * 进程内插件此后改 env 无法重定向统计存储。
 */
const SNAPSHOT_STATS_DIR: string | undefined = (() => {
  const v = process.env.DSH_PLUGIN_VET_STATS_DIR
  return v !== undefined && v !== '' ? v : undefined
})()

let statsDirOverride: string | undefined

/** 持久化计数器的进程内镜像：避免每次报警记录都同步读写 stats.json（sink 在热路径逐 fs/net 事件调用
 *  incrementAlarmsRecorded）。仅由 getStats()（盾牌 5s 轮询）落盘，最多丢失约一个轮询周期；stats 仅为展示，fail-open。
 *  切换统计目录（测试）时失效以重新从文件加载。 */
let memStats: VetStats | undefined

function mem(): VetStats {
  if (memStats === undefined) memStats = loadStats()
  return memStats
}

/** 统计文件路径：~/.dsh/vet/stats.json */
export function statsPath(): string {
  const dir = statsDirOverride ?? SNAPSHOT_STATS_DIR ?? join(homedir(), '.dsh', 'vet')
  return join(dir, 'stats.json')
}

/** 测试专用：覆盖快照目录（同时使内存镜像失效，强制下次从新目录加载） */
export function setStatsDirForTest(dir?: string): void {
  statsDirOverride = dir
  memStats = undefined
}

/** 加载统计（fail-open：异常返回默认值） */
export function loadStats(): VetStats {
  return withVetSelfIo(() => {
    try {
      const p = statsPath()
      if (!existsSync(p)) return { ...DEFAULT_STATS }
      const raw = readFileSync(p, 'utf8')
      const parsed = JSON.parse(raw) as Partial<VetStats>
      return {
        scannedCount: typeof parsed.scannedCount === 'number' ? parsed.scannedCount : 0,
        alarmsRecorded: typeof parsed.alarmsRecorded === 'number' ? parsed.alarmsRecorded : 0,
        blockedCount: typeof parsed.blockedCount === 'number' ? parsed.blockedCount : 0,
        activeDefenseCount: typeof parsed.activeDefenseCount === 'number' ? parsed.activeDefenseCount : 0,
        updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : 0,
      }
    } catch {
      return { ...DEFAULT_STATS }
    }
  })
}

/** 保存统计（原子写：tmp + rename，0600） */
export function saveStats(stats: VetStats): void {
  withVetSelfIo(() => {
    try {
      const p = statsPath()
      const dir = dirname(p)
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
      const tmp = p + '.tmp.' + process.pid
      stats.updatedAt = Date.now()
      writeFileSync(tmp, JSON.stringify(stats, null, 2), { mode: 0o600 })
      renameSync(tmp, p)
    } catch {
      // fail-open：写失败不影响主流程
    }
  })
}

/** 增加扫描计数（仅更新内存镜像，落盘由 getStats 轮询负责） */
export function incrementScanned(): void {
  mem().scannedCount++
}

/** 增加警报计数（仅更新内存镜像，落盘由 getStats 轮询负责） */
export function incrementAlarmsRecorded(): void {
  mem().alarmsRecorded++
}

/** 增加拦截计数（仅更新内存镜像，落盘由 getStats 轮询负责） */
export function incrementBlocked(): void {
  mem().blockedCount++
}

/** 设置当前防御中插件数（内存态更新，不持久化） */
let activeDefenseMemory = 0
export function setActiveDefenseCount(count: number): void {
  activeDefenseMemory = count
}

export function getActiveDefenseCount(): number {
  return activeDefenseMemory
}

/** 获取完整统计（合并内存态并落盘刷新；activeDefenseCount 为内存态、不持久化） */
export function getStats(): VetStats {
  const stats = mem()
  stats.activeDefenseCount = activeDefenseMemory
  // 落盘时把内存态字段归零写回——activeDefenseCount 仅运行时有效，不落盘
  saveStats({ ...stats, activeDefenseCount: 0 })
  return stats
}
