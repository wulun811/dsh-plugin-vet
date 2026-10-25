/**
 * 防御统计模块（0.1.20）：记录 vet 的防御行为统计数据。
 * 存储：~/.dsh/vet/stats.json（原子写，0600）。
 * 数据：已覆盖插件数（去重）、警报总数、拦截次数、防御中插件数。
 *
 * 0.3.18（去重修正）：scannedCount 从「扫描事件累计数」改为「去重后的已覆盖插件数」。旧口径
 * 每次 DSH 重启都把同一批插件重新计一遍，本机实测涨到 6001，而实际只有 77 个不同插件
 * （与 capabilities.json / scan-summaries.json 的去重名集一致）——盾牌上的数字因此不可读。
 * 真值是落盘的 scannedPlugins 名集；0.3.17 及更早的文件没有该字段 → 视作空集重新累计，
 * 下一次自然重启即自愈，不需要停机窗口改数据。
 * 用途：盾牌面板底部展示，让用户知道"被保护了多少次"。
 */
import { readFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { writeTmpExclusive } from './path-utils.js'
import { join, dirname } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'
import { vetStoreRoot } from './store-root.js'

export interface VetStats {
  /** 已覆盖的不同插件数（去重）。0.3.18 前为扫描事件累计数，随每次重启无限增长。 */
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

/** C3（第二轮补漏）：默认目录在模块加载时定值——homedir() 随 $HOME 变，运行时回退
 * 可被进程内插件改 env 重定向。与 archive.ts 同款纪律。
 * 0.3.15：目录统一由 store-root 解析（测试运行时默认落进程私有临时目录）。 */
const SNAPSHOT_DEFAULT_DIR = vetStoreRoot()

/** 持久化计数器的进程内镜像：避免每次报警记录都同步读写 stats.json（sink 在热路径逐 fs/net 事件调用
 *  incrementAlarmsRecorded）。仅由 getStats()（盾牌 5s 轮询）落盘，最多丢失约一个轮询周期；stats 仅为展示，fail-open。
 *  切换统计目录（测试）时失效以重新从文件加载。 */
let memStats: VetStats | undefined

/** scannedCount 的真值：去重后的已覆盖插件名。与 memStats 同批由 loadSnapshot 初始化。 */
let scannedPlugins: Set<string> | undefined

/** 落盘去抖：仅计数器真变化时写。0.3.18 起名集进文件（约 3 KB，25× 于旧的 128 B），
 *  稳态 5s 轮询不再整写；单次变更仍在下一个轮询周期（≤5s）落盘，丢失窗口与旧口径一致。 */
let statsDirty = true

function mem(): VetStats {
  if (memStats === undefined) {
    const snap = loadSnapshot()
    memStats = snap.stats
    scannedPlugins = snap.scanned
  }
  return memStats
}

function scanned(): Set<string> {
  mem()
  return scannedPlugins as Set<string>
}

/** 统计文件路径：~/.dsh/vet/stats.json */
export function statsPath(): string {
  const dir = statsDirOverride ?? SNAPSHOT_STATS_DIR ?? SNAPSHOT_DEFAULT_DIR
  return join(dir, 'stats.json')
}

/** 测试专用：覆盖快照目录（同时使内存镜像失效，强制下次从新目录加载） */
export function setStatsDirForTest(dir?: string): void {
  statsDirOverride = dir
  memStats = undefined
  scannedPlugins = undefined
  statsDirty = true
}

/** 读取落盘快照：计数器 + 去重名集（scannedCount 的真值）。fail-open：异常返回默认值。
 *  注意：文件里的 scannedCount 一律忽略——旧口径的值是事件累计数，回灌会让自愈失效。 */
function loadSnapshot(): { stats: VetStats; scanned: Set<string> } {
  return withVetSelfIo(() => {
    try {
      const p = statsPath()
      if (!existsSync(p)) return { stats: { ...DEFAULT_STATS }, scanned: new Set<string>() }
      const raw = readFileSync(p, 'utf8')
      const parsed = JSON.parse(raw) as Partial<VetStats> & { scannedPlugins?: unknown }
      const scanned = new Set<string>()
      if (Array.isArray(parsed.scannedPlugins)) {
        for (const name of parsed.scannedPlugins) if (typeof name === 'string') scanned.add(name)
      }
      return {
        stats: {
          scannedCount: scanned.size,
          alarmsRecorded: typeof parsed.alarmsRecorded === 'number' ? parsed.alarmsRecorded : 0,
          blockedCount: typeof parsed.blockedCount === 'number' ? parsed.blockedCount : 0,
          activeDefenseCount: typeof parsed.activeDefenseCount === 'number' ? parsed.activeDefenseCount : 0,
          updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : 0,
        },
        scanned,
      }
    } catch {
      return { stats: { ...DEFAULT_STATS }, scanned: new Set<string>() }
    }
  })
}

/** 加载统计（fail-open：异常返回默认值）。 */
export function loadStats(): VetStats {
  return loadSnapshot().stats
}

/** 保存统计（原子写：tmp + rename，0600） */
export function saveStats(stats: VetStats): void {
  withVetSelfIo(() => {
    try {
      const p = statsPath()
      const dir = dirname(p)
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
      const tmp = p + '.tmp.' + process.pid
      const plugins = [...scanned()]
      stats.updatedAt = Date.now()
      stats.scannedCount = plugins.length
      // scannedPlugins 是 scannedCount 的真值；count 冗余写入便于人工查看（读时以名集重算）
      writeTmpExclusive(tmp, JSON.stringify({ ...stats, scannedPlugins: plugins }, null, 2), 0o600)
      renameSync(tmp, p)
    } catch {
      // fail-open：写失败不影响主流程
    }
  })
}

/** 记录一次扫描（按包名去重；仅更新内存镜像，落盘由 getStats 轮询负责）。
 *  去重后该值 = vet 实际覆盖的插件数，不再随每次重启把同一批插件重复计入。 */
export function incrementScanned(pluginName: string): void {
  const stats = mem()
  const set = scanned()
  if (pluginName === '' || set.has(pluginName)) return
  set.add(pluginName)
  stats.scannedCount = set.size
  statsDirty = true
}

/** 增加警报计数（仅更新内存镜像，落盘由 getStats 轮询负责） */
export function incrementAlarmsRecorded(): void {
  mem().alarmsRecorded++
  statsDirty = true
}

/** 增加拦截计数（仅更新内存镜像，落盘由 getStats 轮询负责） */
export function incrementBlocked(): void {
  mem().blockedCount++
  statsDirty = true
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
  // 落盘时把内存态字段归零写回——activeDefenseCount 仅运行时有效，不落盘。
  // 去抖：只有计数器真变化才写（首次调用必定写一次，用于把旧文件规整成新结构）。
  if (statsDirty) {
    saveStats({ ...stats, activeDefenseCount: 0 })
    statsDirty = false
  }
  return stats
}
