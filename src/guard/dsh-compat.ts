/**
 * DSH 兼容范围判定（0.4.1）：vet 自我声明的「已复验 DSH 版本」闸门。
 *
 * 为什么需要独立字段而不是复用 peerDependencies：peer 范围只表达**模块 API 依赖**，
 * 实测 0.3.16/0.3.17/0.3.18 三版的 peer 逐字节相同（`^0.1.1-rc.1 || ^0.2.0-rc.1`），
 * 而 rc.2 恰好落在范围内——于是「peer 满足」既不能证明适配、也不能发现不适配。vet 真正
 * 的适配边界还包括 cordis.patch.yml 的 insert 行 id 语义、client 的 slot 契约、
 * 补丁锚点，peer 完全覆盖不到。故引入 package.json 的 dshCompat.tested 作为真值。
 *
 * 零依赖 semver 子集：vet 生产代码**刻意不引入 semver 依赖**（见 version-diff.ts 的
 * 「不引入 semver 依赖」纪律），这里实现判定所需的最小子集——`||` 分隔的 AND 比较器组，
 * 每个比较器支持 `^` `~` `>=` `>` `<=` `<` `=` 与裸版本号。
 *
 * 预发布语义（与 npm semver 一致，差分测试对照 semver@7 校验）：
 * **整组**内若存在「带预发布且 major.minor.patch 与待判版本完全相同」的比较器，才允许
 * 带预发布的版本入选；否则带预发布的版本一律不满足。这是 rc 版本判定的关键——
 * `0.2.0-rc.2` 满足 `^0.2.0-rc.1`（同为 0.2.0 且有预发布），
 * 但不满足 `^0.1.1-rc.1`（组内预发布是 0.1.1 ≠ 0.2.0）、也不满足 `<0.3.0`（组内无预发布）。
 * @module dsh-plugin-vet/dsh-compat
 */

/** 解析后的版本号分段。 */
export interface SemverParts {
  major: number
  minor: number
  patch: number
  /** 预发布标识（`-rc.1` → `['rc','1']`；无预发布 → `[]`）。 */
  pre: string[]
}

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

/** 解析严格三段版本号（容 `v` 前缀与 build metadata）。非法 → null（调用方 fail-open）。 */
export function parseSemver(raw: string): SemverParts | null {
  const m = SEMVER_RE.exec(raw.trim())
  if (m === null) return null
  const major = Number(m[1])
  const minor = Number(m[2])
  const patch = Number(m[3])
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) return null
  return { major, minor, patch, pre: m[4] === undefined ? [] : m[4].split('.') }
}

/** 预发布段比较（semver 规范：纯数字按数值、数字 < 字母、前缀全等则字段多者大）。 */
function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0
  if (a.length === 0) return 1 // 正式版 > 预发布版
  if (b.length === 0) return -1
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const x = a[i]
    const y = b[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const d = Number(x) - Number(y)
      if (d !== 0) return d < 0 ? -1 : 1
      continue
    }
    if (xn) return -1
    if (yn) return 1
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

/** 比较两个已解析版本；a<b → -1，a>b → 1，相等 → 0。 */
export function compareParts(a: SemverParts, b: SemverParts): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1
  return comparePre(a.pre, b.pre)
}

/** 比较两个版本字符串；任一非法 → null（调用方不得据此判定「更新」）。 */
export function compareSemver(a: string, b: string): number | null {
  const pa = parseSemver(a)
  const pb = parseSemver(b)
  if (pa === null || pb === null) return null
  return compareParts(pa, pb)
}

/** a 是否严格新于 b（任一非法 → false：宁可漏提示，不可谎报有新版）。 */
export function isNewer(a: string, b: string): boolean {
  return compareSemver(a, b) === 1
}

type Op = '>=' | '>' | '<=' | '<' | '='

interface Comparator {
  op: Op
  v: SemverParts
  /** 该比较器自身带预发布（预发布闸门用）。 */
  pre: boolean
}

/** 展开一个 token 为原始比较器（`^`/`~` 展开为上下界两条）。非法 → null。 */
function expandToken(token: string): Comparator[] | null {
  const t = token.trim()
  if (t === '' || t === '*' || t === 'x' || t === 'X') return []
  const m = /^(\^|~|>=|<=|>|<|=)?\s*(.+)$/.exec(t)
  if (m === null) return null
  const op = m[1] ?? ''
  const v = parseSemver(m[2])
  if (v === null) return null
  const pre = v.pre.length > 0
  if (op === '^') {
    // npm caret：major>0 → 锁 major；major=0 且 minor>0 → 锁 minor；0.0.x → 锁 patch。
    const upper: SemverParts = v.major > 0
      ? { major: v.major + 1, minor: 0, patch: 0, pre: [] }
      : v.minor > 0
        ? { major: 0, minor: v.minor + 1, patch: 0, pre: [] }
        : { major: 0, minor: 0, patch: v.patch + 1, pre: [] }
    return [{ op: '>=', v, pre }, { op: '<', v: upper, pre: false }]
  }
  if (op === '~') {
    return [{ op: '>=', v, pre }, { op: '<', v: { major: v.major, minor: v.minor + 1, patch: 0, pre: [] }, pre: false }]
  }
  return [{ op: op === '' ? '=' : (op as Op), v, pre }]
}

function testComparator(version: SemverParts, c: Comparator): boolean {
  const cmp = compareParts(version, c.v)
  switch (c.op) {
    case '>=': return cmp >= 0
    case '>': return cmp > 0
    case '<=': return cmp <= 0
    case '<': return cmp < 0
    case '=': return cmp === 0
  }
}

/** 单个 AND 比较器组判定（含预发布闸门）。 */
function satisfiedBySet(version: SemverParts, cmps: Comparator[]): boolean {
  if (version.pre.length > 0) {
    // 预发布闸门：组内必须存在「带预发布且 M.m.p 完全相同」的比较器。
    const allowed = cmps.some(c =>
      c.pre && c.v.major === version.major && c.v.minor === version.minor && c.v.patch === version.patch)
    if (!allowed) return false
  }
  return cmps.every(c => testComparator(version, c))
}

/**
 * 判定版本是否落在范围内（`||` 分隔的 AND 组，任一组成立即满足）。
 * 版本非法 / 范围非法 → false（fail-closed：判不出来就当不满足，走保守的「未复验」措辞）。
 */
export function satisfiesRange(version: string, range: string): boolean {
  const v = parseSemver(version)
  if (v === null) return false
  for (const rawSet of range.split('||')) {
    const cmps: Comparator[] = []
    let valid = true
    for (const token of rawSet.trim().split(/\s+/)) {
      if (token === '') continue
      const expanded = expandToken(token)
      if (expanded === null) { valid = false; break }
      cmps.push(...expanded)
    }
    if (valid && satisfiedBySet(v, cmps)) return true
  }
  return false
}
