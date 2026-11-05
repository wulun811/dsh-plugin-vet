/**
 * 快照捕获（IO 层）。纯逻辑在 `domain/snapshot.ts`——这里只负责走目录、读字节、记排除原因。
 *
 * 排除规则必须与 `content-baseline.ts` 的 `computePackageHash` 保持一致（隐藏文件、node_modules、
 * 符号链接、文档文件、大小/数量/时间预算）。两处不一致会让「基线说没变、快照说变了」
 * 同时出现，而那种矛盾比任何单边判断都难解释。
 *
 * 与 `computePackageHash` 的差别只有一点：它回一个总哈希，这里回**逐文件清单**——
 * 没有清单就答不出「哪个文件变了」，那样的报警没法处置。
 */
import { createHash } from 'node:crypto'
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'
import { describeDiff, diffManifests, isEmptyDiff, toScopedSnapshot, type Snapshot, type SnapshotEntry } from '../domain/snapshot.js'

/** 与 content-baseline 同源默认值（那边是同一批文件的另一把尺子，不该有两套预算）。 */
export interface CaptureOptions {
  readonly maxFiles?: number
  readonly maxSizeBytes?: number
  readonly timeoutMs?: number
  readonly policyId?: string
}

const DEFAULTS = { maxFiles: 1000, maxSizeBytes: 50 * 1024 * 1024, timeoutMs: 10_000 } as const

/** 与 content-baseline 一致的文档类排除。 */
const EXCLUDE_PATTERNS = [/\.md$/i, /\.txt$/i, /LICENSE/i, /README/i]

export type CaptureResult =
  | { readonly ok: true; readonly snapshot: Snapshot }
  | { readonly ok: false; readonly reason: string }

/**
 * 捕获一次快照。
 *
 * 失败（根不可读/不存在）返回 `reason` 而不是 null：调用方要把它记成 coverage=unknown，
 * 而「为什么 unknown」正是用户在面板上要看的。
 */
export function captureSnapshot(packageRoot: string, options: CaptureOptions = {}): CaptureResult {
  const opts = { ...DEFAULTS, ...options }
  const start = Date.now()
  const entries: SnapshotEntry[] = []
  const excluded: { path: string; reason: string }[] = []
  let totalSize = 0
  let complete = true

  const skip = (path: string, reason: string): void => {
    // 排除清单本身也有上限：一个全是隐藏文件的包不该把面板撑爆
    if (excluded.length < 256) excluded.push({ path, reason })
    else complete = false
  }

  const result = withVetSelfIo((): CaptureResult => {
    const walk = (dir: string): boolean => {
      if (Date.now() - start > opts.timeoutMs) {
        skip(relative(packageRoot, dir) || '.', 'timeout')
        return false
      }
      if (entries.length >= opts.maxFiles) {
        skip(relative(packageRoot, dir) || '.', 'max-files')
        return false
      }
      let names: string[]
      try {
        names = readdirSync(dir)
      } catch {
        skip(relative(packageRoot, dir) || '.', 'unreadable-dir')
        complete = false
        return true
      }
      for (const name of names) {
        if (Date.now() - start > opts.timeoutMs) {
          skip(relative(packageRoot, dir) || '.', 'timeout')
          return false
        }
        const fullPath = join(dir, name)
        const relPath = relative(packageRoot, fullPath).split(sep).join('/')
        if (name.startsWith('.')) {
          skip(relPath, 'hidden')
          continue
        }
        if (name === 'node_modules') {
          skip(relPath, 'node_modules')
          continue
        }
        let stat
        try {
          stat = lstatSync(fullPath)
        } catch {
          skip(relPath, 'unreadable-stat')
          complete = false
          continue
        }
        if (stat.isSymbolicLink()) {
          skip(relPath, 'symlink')
          continue
        }
        if (stat.isDirectory()) {
          if (!walk(fullPath)) return false
          continue
        }
        if (!stat.isFile()) {
          skip(relPath, 'not-a-file')
          continue
        }
        if (EXCLUDE_PATTERNS.some((re) => re.test(name))) {
          skip(relPath, 'doc')
          continue
        }
        if (stat.size > opts.maxSizeBytes || totalSize + stat.size > opts.maxSizeBytes) {
          skip(relPath, 'max-bytes')
          return false
        }
        if (entries.length >= opts.maxFiles) {
          skip(relPath, 'max-files')
          return false
        }
        let content: Buffer
        try {
          content = readFileSync(fullPath)
        } catch {
          skip(relPath, 'unreadable-file')
          complete = false
          continue
        }
        totalSize += content.length
        entries.push({ path: relPath, size: content.length, digest: createHash('sha256').update(content).digest('hex') })
      }
      return true
    }

    try {
      if (!walk(packageRoot)) complete = false
    } catch {
      return { ok: false, reason: 'walk-failed' }
    }
    return { ok: true, snapshot: toScopedSnapshot(entries, excluded, complete, opts.policyId) }
  })
  return result
}

/** 漂移判定结果。`detail` 进报警文案——一条只说「不一样」的报警没法处置。 */
export interface DriftVerdict {
  readonly drifted: boolean
  readonly detail?: string
}

/**
 * TOCTOU 检查：把「扫描时捕获的快照」与「现在」比一次。
 *
 * 边界要写清楚：这是**检测**，不是阻止。检查发生在守卫返回之前，之后再改的字节我们看不见
 * （加载器的 import 不在我们的拦截点上）。所以它挡的是「扫描之后、放行之前」这一个窗口——
 * 恰好是扫描结论被误用的那一段。
 *
 * 首次捕获失败（目录不可读）不算漂移：没有基线就没有可比对的东西，那种情况该由覆盖面
 * 记 unknown（步骤 4 的另一半），不该在这里编一个红牌。
 */
export function detectDrift(before: CaptureResult | null, root: string | undefined, options: CaptureOptions = {}): DriftVerdict {
  if (before === null || root === undefined) return { drifted: false }
  if (!before.ok) return { drifted: false }
  const after = captureSnapshot(root, options)
  if (!after.ok) return { drifted: true, detail: `二次捕获失败（${after.reason}）` }
  const diff = diffManifests(before.snapshot, after.snapshot)
  if (diff === null) return { drifted: true, detail: '快照策略变化，两次捕获不可比' }
  if (isEmptyDiff(diff)) return { drifted: false }
  return { drifted: true, detail: describeDiff(diff) }
}
