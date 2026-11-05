/**
 * 有范围的快照（施工图 §6 步骤 4）：把「我们到底看了什么」变成可比较的承诺。
 *
 * 三个问题它要回答：
 * 1. **看了什么**：清单里每一条 (相对路径, 长度, 内容摘要)，按路径排序——顺序不稳定就不是承诺。
 * 2. **没看什么**：`excluded` 逐条记原因（隐藏、node_modules、符号链接、不可读、超预算），
 *    而不是把它们悄悄折进一个总数。`complete: false` 表示声明范围内也没看全。
 * 3. **还是不是同一批字节**：`diffManifests` 比对两次捕获——这就是 TOCTOU 检查的全部。
 *
 * 为什么不在别处复用 `computePackageHash`：那个函数只回一个总哈希，回答不了「哪个文件变了」，
 * 也分不清「没变」与「没看到」。诊断信息正是这个检查的价值所在——一条只说「不一样」的
 * 报警，用户无法处置。
 *
 * 本文件纯函数（无 IO），IO 在 `guard/snapshot.ts`。
 */
import { createHash } from 'node:crypto'
import type { ScopedSnapshot } from './types.js'

/** 纳入/排除策略的版本。策略一变，旧快照不再可比——所以它进摘要的头部。 */
export const SNAPSHOT_POLICY_ID = 'vet/pkg-scan-v1'

/** 清单条目：相对路径（POSIX 分隔符）、字节长度、文件内容摘要。 */
export interface SnapshotEntry {
  readonly path: string
  readonly size: number
  readonly digest: string
}

/** 一次捕获的结果。`entries` 保留下来是为了出差异，不落盘、不进内存语义层。 */
export interface Snapshot {
  readonly snapshot: ScopedSnapshot
  readonly entries: readonly SnapshotEntry[]
}

/**
 * 清单摘要：策略 id + 逐条 (路径, 长度, 内容摘要)，按路径码点序。
 *
 * 分隔符用 `\0` 是因为路径和数字里都不会出现它——用 `:` 的话 `a:1` 与 `a` 加的内容
 * 可能拼出同一个串（长度前缀都不够稳，NUL 是唯一不需要转义的边界）。
 */
export function manifestDigest(policyId: string, entries: readonly SnapshotEntry[]): string {
  const hash = createHash('sha256')
  hash.update(policyId)
  hash.update('\n')
  for (const entry of [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    hash.update(entry.path)
    hash.update('\0')
    hash.update(String(entry.size))
    hash.update('\0')
    hash.update(entry.digest)
    hash.update('\n')
  }
  return hash.digest('hex')
}

/** 组装 `ScopedSnapshot`（id 取摘要前 16 位，够区分且不会长得没法贴进日志）。 */
export function toScopedSnapshot(
  entries: readonly SnapshotEntry[],
  excluded: ReadonlyArray<{ path: string; reason: string }>,
  complete: boolean,
  policyId: string = SNAPSHOT_POLICY_ID,
): Snapshot {
  const digest = manifestDigest(policyId, entries)
  return {
    snapshot: {
      id: `snap-${digest.slice(0, 16)}`,
      digest,
      algorithm: 'sha256',
      includePolicyId: policyId,
      excluded,
      complete,
    },
    entries,
  }
}

/** 两次捕获的差异。路径集合 + 内容/长度变化，各自有上限，避免一条报警刷出几万行。 */
export interface SnapshotDiff {
  readonly added: readonly string[]
  readonly removed: readonly string[]
  readonly changed: readonly string[]
  readonly truncated: boolean
}

const DIFF_LIMIT = 5

/**
 * 比对两次捕获。
 *
 * 只在**同一策略**下可比：策略变了（`includePolicyId` 不同），差异没有意义——
 * 那不是「内容变了」，是「量的尺子变了」。此时返回 `null`，由调用方按 unknown 处理。
 */
export function diffManifests(
  before: Snapshot,
  after: Snapshot,
  limit = DIFF_LIMIT,
): SnapshotDiff | null {
  if (before.snapshot.includePolicyId !== after.snapshot.includePolicyId) return null
  const beforeMap = new Map(before.entries.map((e) => [e.path, e]))
  const afterMap = new Map(after.entries.map((e) => [e.path, e]))
  const added: string[] = []
  const removed: string[] = []
  const changed: string[] = []
  for (const [path, entry] of afterMap) {
    const prev = beforeMap.get(path)
    if (prev === undefined) added.push(path)
    else if (prev.size !== entry.size || prev.digest !== entry.digest) changed.push(path)
  }
  for (const path of beforeMap.keys()) {
    if (!afterMap.has(path)) removed.push(path)
  }
  const sort = (list: string[]): string[] => list.sort()
  sort(added)
  sort(removed)
  sort(changed)
  const truncated = added.length > limit || removed.length > limit || changed.length > limit
  return {
    added: added.slice(0, limit),
    removed: removed.slice(0, limit),
    changed: changed.slice(0, limit),
    truncated,
  }
}

/** 差异是否为空（`null` 不算空——那是不可比，要按 unknown 处置）。 */
export function isEmptyDiff(diff: SnapshotDiff): boolean {
  return diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0
}

/** 人读的一句话，直接进报警文案。 */
export function describeDiff(diff: SnapshotDiff): string {
  const parts: string[] = []
  if (diff.changed.length > 0) parts.push(`改写 ${diff.changed.join('、')}`)
  if (diff.added.length > 0) parts.push(`新增 ${diff.added.join('、')}`)
  if (diff.removed.length > 0) parts.push(`删除 ${diff.removed.join('、')}`)
  const text = parts.join('；')
  return diff.truncated ? `${text}（仅列前 ${DIFF_LIMIT} 项）` : text
}
