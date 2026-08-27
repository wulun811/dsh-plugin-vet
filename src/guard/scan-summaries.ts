/**
 * 扫描摘要库（P2，计划 §三-D5）：按插件包持久化「最近一次扫描结论」的轻量摘要，
 * 供盾牌插件详情页（规则命中墙 / OSV 行 / 扫描时间）与「最近插件」列表（D7）使用。
 *
 * 为什么需要：扫描完成时 findings（规则命中）、staticScore、OSV 结论只在内存瞬时用掉，
 * 不落盘；此前唯一的记忆是全局单槽 lastScan（带 TTL）。本库补上"按包留档"这一块。
 *
 * 存储：~/.dsh/vet/scan-summaries.json，{ records: { "<name>": ScanSummary } }（每包一条=最新）。
 * 复用既有纪律：原子写（tmp + rename）、0600/0700、目录测试注入、fail-open（损坏/失败静默跳过，
 * 不打扰插件加载——与 version-diff 同款认知）。LRU：上限 MAX_KEPT=200 包，超出按 at 淘汰最旧。
 *
 * 写入策略（防写放大）：仅当 verdict / 版本 / 规则码集合 相比已有记录变化时才覆写落盘；
 * 同版同结论的重扫只刷新内存态不重写文件。列表排序因此反映「最近有动静的包」。
 *
 * 诚实边界：ruleCodes/osv 来自静态扫描报告快照；运行时观测能力不在本库（capability-diff
 * 观测集只在进程内存），详情页展示时须标注口径。
 */
import { mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs'
import { writeTmpExclusive } from './path-utils.js'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'

/** 单包扫描摘要（每包保留最新一条）。 */
export interface ScanSummary {
  name: string
  version?: string
  /** 记录时间 = 该结论产生的时间（变化时才刷新，见头注释写入策略）。 */
  at: number
  verdict: string
  staticScore: number
  sourceCount?: number
  /** 去重后的命中规则码（含 'OSV' 表示有漏洞库命中；空数组 = 零命中）。 */
  ruleCodes: string[]
  /** OSV 命中摘要句（首条）；无命中/未启用时缺省。 */
  osv?: string
}

interface ScanSummaryStore {
  records: Record<string, ScanSummary>
}

const MAX_KEPT = 200

/**
 * round-16（SEC-4）：对象键劫持防护——插件名若为 __proto__/prototype/constructor，
 * 直接作为 records 键会污染原型链/遮蔽 Object 构造（`records['__proto__'] = x` 是
 * 原型赋值，JSON 序列化静默丢弃 → 记录丢失且对象原型被改）。统一加 '_' 前缀归一，
 * 读 / 写 / 查询侧同一函数，两侧永远一致。
 */
function safeRecordKey(name: string): string {
  return name === '__proto__' || name === 'prototype' || name === 'constructor' ? '_' + name : name
}

let summariesDirOverride: string | undefined

/** C3 同款纪律：默认目录模块加载时定值（homedir() 随 $HOME 变，防运行时 env 重定向）。 */
const SNAPSHOT_DEFAULT_DIR = join(homedir(), '.dsh', 'vet')

/** 存储路径：~/.dsh/vet/scan-summaries.json（测试可用 setSummariesDirForTest 覆盖）。 */
export function summariesPath(): string {
  const dir = summariesDirOverride ?? SNAPSHOT_DEFAULT_DIR
  return join(dir, 'scan-summaries.json')
}

/** 测试专用：覆盖存储目录（生产路径不调用）。 */
export function setSummariesDirForTest(dir?: string): void {
  summariesDirOverride = dir
}

function loadStore(): ScanSummaryStore {
  return withVetSelfIo(() => {
    try {
      const raw = readFileSync(summariesPath(), 'utf8')
      const parsed = JSON.parse(raw) as Partial<ScanSummaryStore>
      if (parsed === null || typeof parsed !== 'object' || parsed.records === null || typeof parsed.records !== 'object') {
        return { records: {} }
      }
      // round-16（SEC-4）：文件落盘键也归一（读侧与写侧同键，见 safeRecordKey）
      const records: Record<string, ScanSummary> = {}
      for (const [key, rec] of Object.entries(parsed.records)) {
        const k = safeRecordKey(key)
        // 单条最小结构校验（残缺记录丢弃，不让坏数据污染面板）
        if (
          rec !== null && typeof rec === 'object' &&
          typeof (rec as ScanSummary).name === 'string' &&
          typeof (rec as ScanSummary).at === 'number' &&
          typeof (rec as ScanSummary).verdict === 'string' &&
          typeof (rec as ScanSummary).staticScore === 'number' &&
          Array.isArray((rec as ScanSummary).ruleCodes)
        ) {
          records[k] = rec as ScanSummary
        }
      }
      return { records }
    } catch {
      // 文件不存在/损坏 → 空库起家（fail-open）
      return { records: {} }
    }
  })
}

function saveStore(store: ScanSummaryStore): void {
  withVetSelfIo(() => {
    // Windows：rename 目标被短暂占用（实时扫描/索引/杀软）会抛 EBUSY/EPERM——
    // 高 IO 下偶发丢记录（LRU 边界测试可复现）。短退避重试 3 次；仍失败则
    // 静默跳过（摘要是增强信息，不值得为它打扰插件加载）。Linux 一次成功，无行为变化。
    const path = summariesPath()
    const tmpPath = path + '.tmp.' + process.pid
    let attempt = 0
    while (attempt < 3) {
      try {
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
        writeTmpExclusive(tmpPath, JSON.stringify(store), 0o600)
        renameSync(tmpPath, path)
        return
      } catch {
        attempt++
        if (attempt >= 3) return
        try { rmSync(tmpPath, { force: true }) } catch { /* 残留 tmp 由下轮 writeTmpExclusive 重写 */ }
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20)
      }
    }
  })
}

/** 规则码集合是否等价（顺序无关；比较用）。 */
function sameRuleCodes(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const set = new Set(b)
  return a.every(code => set.has(code))
}

/**
 * 记录一次扫描摘要（自动扫描与 gate 路径共用；决策 ④：被门禁拦过的包也要有记录）。
 * 变化判定：无旧记录 ∪ verdict 变 ∪ 版本变 ∪ ruleCodes 集合变 → 覆写落盘；否则跳过。
 */
export function recordScanSummary(summary: ScanSummary): void {
  withVetSelfIo(() => {
    try {
      const store = loadStore()
      const key = safeRecordKey(summary.name)
      const prev = store.records[key]
      const changed =
        prev === undefined ||
        prev.verdict !== summary.verdict ||
        prev.version !== summary.version ||
        !sameRuleCodes(prev.ruleCodes, summary.ruleCodes)
      if (!changed) return
      store.records[key] = summary
      // LRU：超出上限按 at 淘汰最旧
      const keys = Object.keys(store.records)
      if (keys.length > MAX_KEPT) {
        keys.sort((a, b) => (store.records[a]?.at ?? 0) - (store.records[b]?.at ?? 0))
        for (const key of keys.slice(0, keys.length - MAX_KEPT)) delete store.records[key]
      }
      saveStore(store)
    } catch {
      // fail-open
    }
  })
}

/** 单包摘要（无记录返回 undefined）。 */
export function getScanSummary(name: string): ScanSummary | undefined {
  return loadStore().records[safeRecordKey(name)]
}

/** 最近 limit 条（按 at 倒序）——「最近插件」列表数据源（D7：存 200、展示 20）。 */
export function listRecentScanSummaries(limit: number): ScanSummary[] {
  return Object.values(loadStore().records)
    .sort((a, b) => b.at - a.at)
    .slice(0, Math.max(0, limit))
}

/** 全部记录（audit-summary 聚合用；只读副本）。 */
export function allScanSummaries(): ScanSummary[] {
  return Object.values(loadStore().records)
}
