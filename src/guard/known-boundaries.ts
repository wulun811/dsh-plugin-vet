/**
 * 已知边界存储（P3，0.3.3 用户警报疲劳反馈）：
 * coverage 类边界提示（esm-guard-coverage 等「架构性限制」观察）的持久化状态化去重。
 *
 * 为什么需要（现场数据）：官方包 14 条 esm-guard-coverage 每次进程重启原样重现——
 * 警报看起来像新发现，实际是零信息量的重放（用户无法消解：官方包不可能为 vet 改
 * require 风格）。round-15 删除「全局持久化忽略」的动机正确（盲区不可静默），但
 * 中间状态机被跳过了：正确形态是 (kind, pkg, version, capabilitiesHash) 落盘——
 * 版本/能力未变不重报（静默的是无信息量重放），能力差分变化才重启（保留有信息量的
 * 变化；与 N6 upgrade-diff 同一变化源）。
 *
 * 与 dismissed-alerts 的区别：
 * - dismissed：用户显式动作（忽略/恢复），作用于任意报警 id；
 * - known-boundaries：vet 自动的知情状态（已提示过且未变），只作用于 coverage 类
 *   边界提示、按 (kind, pkg, version, capabilitiesHash) 自动吊销（能力一变即失效），
 *   无需用户参与、不会全局静默。
 *
 * 失效安全：任何内部错误（存储损坏、路径失败）fail-open——按未知处理（宁可重复
 * 提示，不可静默失明），不打扰插件加载。
 *
 * 存储：~/.dsh/vet/known-boundaries.json
 *   { records: { "<kind>:<pkg>": { version, capabilitiesHash, firstAt, lastAt } } }
 * 原子写（tmp + rename）、0600/0700、C3 目录快照（与 version-diff 同款纪律）。
 * @module dsh-plugin-vet/known-boundaries
 */
import { existsSync, readFileSync, renameSync, mkdirSync } from 'node:fs'
import { writeTmpExclusive } from './path-utils.js'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'

/** C3 同款纪律：默认目录在模块加载时定值——homedir() 随 $HOME 变，运行时回退可被
 * 进程内插件改 env 重定向（伪造 known-boundaries.json 预植静默）。 */
const SNAPSHOT_DEFAULT_DIR = join(homedir(), '.dsh', 'vet')

let boundariesDirOverride: string | undefined

/** 存储文件路径：~/.dsh/vet/known-boundaries.json（测试可用 setKnownBoundariesDirForTest 覆盖）。 */
export function knownBoundariesPath(): string {
  const dir = boundariesDirOverride ?? SNAPSHOT_DEFAULT_DIR
  return join(dir, 'known-boundaries.json')
}

/** 测试专用：覆盖存储目录（生产路径不调用）。 */
export function setKnownBoundariesDirForTest(dir?: string): void {
  boundariesDirOverride = dir
}

interface KnownBoundaryRecord {
  version: string
  capabilitiesHash: string
  firstAt: number
  lastAt: number
}

interface KnownBoundaryStore {
  records: Record<string, KnownBoundaryRecord>
}

function loadStore(): KnownBoundaryStore {
  return withVetSelfIo(() => {
    try {
      if (!existsSync(knownBoundariesPath())) return { records: {} }
      const parsed = JSON.parse(readFileSync(knownBoundariesPath(), 'utf8')) as Partial<KnownBoundaryStore>
      if (parsed !== null && typeof parsed === 'object' &&
          parsed.records !== null && typeof parsed.records === 'object') {
        // 单条最小结构校验：version/hash 是判定依据，残缺记录丢弃（不因坏数据改变判定面）
        const records: Record<string, KnownBoundaryRecord> = {}
        for (const [key, rec] of Object.entries(parsed.records)) {
          if (rec !== null && typeof rec === 'object' &&
              typeof (rec as KnownBoundaryRecord).version === 'string' &&
              typeof (rec as KnownBoundaryRecord).capabilitiesHash === 'string') {
            records[key] = rec as KnownBoundaryRecord
          }
        }
        return { records }
      }
      return { records: {} }
    } catch {
      return { records: {} }
    }
  })
}

function saveStore(store: KnownBoundaryStore): void {
  withVetSelfIo(() => {
    try {
      const path = knownBoundariesPath()
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
      const tmpPath = path + '.tmp.' + process.pid
      writeTmpExclusive(tmpPath, JSON.stringify(store, null, 2), 0o600)
      renameSync(tmpPath, path)
    } catch {
      // 静默：记录失败不影响运行——下次按未知处理（安全方向：宁可重复提示，不可静默）
    }
  })
}

/**
 * 某 (kind, pkg) 的边界是否「已知情」：版本与能力哈希都未变（= 无信息量重放）→ true，
 * 调用方不再重报；任意一项变化 → false，调用方重新报警并更新记录。
 * fail-open：存储不可读 → false（按未知情处理，安全方向）。
 */
export function isKnownBoundary(kind: string, pkg: string, version: string, capabilitiesHash: string): boolean {
  if (version === '' || capabilitiesHash === '') return false
  const rec = loadStore().records[kind + ':' + pkg]
  return rec !== undefined && rec.version === version && rec.capabilitiesHash === capabilitiesHash
}

/** 记录（或刷新）一次已提示的边界观察；版本/能力哈希随之成为下次判定的基线。 */
export function markKnownBoundary(kind: string, pkg: string, version: string, capabilitiesHash: string): void {
  if (version === '' || capabilitiesHash === '') return
  const store = loadStore()
  const key = kind + ':' + pkg
  const now = Date.now()
  const prev = store.records[key]
  store.records[key] = {
    version,
    capabilitiesHash,
    firstAt: prev !== undefined ? prev.firstAt : now,
    lastAt: now,
  }
  saveStore(store)
}