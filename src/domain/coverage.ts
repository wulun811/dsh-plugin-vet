/**
 * 覆盖面的纯模型（施工图步骤 4b / 不变式 2）。
 *
 * 不变式 2 的原话：**读不到/被排除的执行面，不得被表述成已扫描 clean**。
 * 这条最容易被实现成一句口号——面板上写一句「部分能力可能未覆盖」，然后照旧显示绿色。
 * 可执行的形式只有一种：每个面都得有**一个明确结论**，而「没表过态」必须落成 `unknown`，
 * 不能被默认成 `covered`。
 *
 * 所以本文件的核心不是 `coverageEntry()` 这个构造器，而是 `withUnknownDefaults()`：
 * 它保证九个面永远九行齐全、顺序固定、缺的那个是 `unknown`。
 */
import { SURFACES, type CoverageEntry, type CoverageResult, type CoverageRow, type Surface } from './types.js'

/** 一个主体（包/skill/本机自己）名下的九行覆盖面。 */
export interface SubjectCoverage {
  readonly subject: string
  readonly entries: readonly CoverageEntry[]
}

/** 构造一条覆盖面声明。`reasons` 至少一条——一个没有理由的结论无法被质疑，也就无法被修正。 */
export function coverageEntry(
  surface: Surface,
  result: CoverageResult,
  reasons: readonly string[],
  observedAt: number,
  observerVersion?: string,
): CoverageEntry {
  return {
    surface,
    result,
    reasons,
    observedAt,
    ...(observerVersion !== undefined ? { observerVersion } : {}),
  }
}

/**
 * 补齐九个面：没表过态的一律 `unknown`，顺序按 `SURFACES` 固定。
 *
 * 同一面出现多条时**取最差的一条**（failed > partial > unknown > excluded > unsupported > covered）：
 * 两个采集点都说覆盖了同一面但结论不同，那本身就是「我们不确定」，按最差计是唯一安全的选择。
 * 结论取最差，**理由取并集**——两条都为真时，丢掉一条就是靠省略说谎（见 `collapse`）。
 */
export function withUnknownDefaults(entries: readonly CoverageEntry[], observedAt = Date.now()): CoverageEntry[] {
  const worst = new Map<Surface, CoverageEntry>()
  for (const entry of entries) {
    const prev = worst.get(entry.surface)
    worst.set(entry.surface, prev === undefined ? entry : collapse(prev, entry))
  }
  return SURFACES.map((surface) =>
    worst.get(surface) ??
    coverageEntry(surface, 'unknown', ['not-reported'], observedAt),
  )
}

/** 结论的严重程度（越大越差）。`unknown` 排在 excluded/unsupported 之上：明确不看是**已知**
 * 状态（用户的选择 / 实现的能力），没看过才是缺口——不知道的事不该显得比知道的事更让人放心。 */
const RESULT_RANK: Record<CoverageResult, number> = {
  covered: 0,
  unsupported: 1,
  excluded: 2,
  unknown: 3,
  partial: 4,
  failed: 5,
}

/**
 * 两个结论里更差的那个。
 *
 * 导出给 `domain/decision.ts`：决策也要做同一件事——同一面收到两条时，按更差的那条判。
 * 两处各写一份排序表，迟早会有一处忘记改（而忘记改的方向通常是「更宽松」）。
 */
export function worseCoverageResult(a: CoverageResult, b: CoverageResult): CoverageResult {
  return RESULT_RANK[a] >= RESULT_RANK[b] ? a : b
}

/**
 * `b` 是否比 `a` 更该代表这个面。
 *
 * 顺序：结论更差 → 同等差时**未承认的**优先（`acknowledged` 是「我们认了这个边界」，
 * 它不该被用来让另一条没被认的结论隐身）→ 更近的观测 → 主体名字典序（同档同时刻时
 * 保证与遍历顺序无关，否则聚合结论会随扫描顺序漂移）。
 */
function worseThan(a: CoverageRow, b: CoverageRow): boolean {
  const ra = RESULT_RANK[a.result]
  const rb = RESULT_RANK[b.result]
  if (ra !== rb) return rb > ra
  const aa = a.acknowledged === true ? 1 : 0
  const ab = b.acknowledged === true ? 1 : 0
  if (aa !== ab) return ab < aa
  if (a.observedAt !== b.observedAt) return b.observedAt > a.observedAt
  const sa = a.subject ?? ''
  const sb = b.subject ?? ''
  return sb !== sa && sb < sa
}

/**
 * 同一主体、同一面的两条结论合成一条：结果取更差的那条，但**理由取并集**。
 *
 * 理由并集不是锦上添花：`runtime_fs` 可能同时被「钩子完好（covered，无理由）」和
 * 「该包 ESM 具名导入 fs（partial）」两条描述，取最差拿到 partial 之后，如果只留
 * 后者的理由，前一条事实就靠省略消失了。两条都为真时，一条都不能丢。
 */
function collapse(a: CoverageEntry, b: CoverageEntry): CoverageEntry {
  const bWins = worseThan(a, b)
  const winner = bWins ? b : a
  const loser = bWins ? a : b
  const reasons = [...winner.reasons]
  for (const reason of loser.reasons) {
    if (!reasons.includes(reason)) reasons.push(reason)
  }
  return { ...winner, reasons }
}

/**
 * 多个主体各自九行 → 一条「整个装机的九行」：每个面取**最差**的那一行，并记住它来自
 * 哪个主体。
 *
 * 这里没有任何「多数决」或「平均」的余地：五十个包里有一个的文件树没看完，`file_tree`
 * 对整个装机就不是 covered。聚合的意义是回答「现在有没有看不见的地方」，而不是
 * 「总体上大概还行」——后者正是这套覆盖面要防的那种说法。
 */
export function aggregateCoverage(subjects: readonly SubjectCoverage[], observedAt = Date.now()): CoverageRow[] {
  return SURFACES.map((surface) => {
    let best: CoverageRow | undefined
    for (const subject of subjects) {
      const entry = subject.entries.find((e) => e.surface === surface)
      if (entry === undefined) continue
      const row: CoverageRow = subject.subject === '' ? { ...entry } : { ...entry, subject: subject.subject }
      if (best === undefined || worseThan(best, row)) best = row
    }
    return best ?? { ...coverageEntry(surface, 'unknown', ['not-reported'], observedAt) }
  })
}

/** 从没被采集过的整体状态：九行全 unknown。状态对象初始化时用它，避免面板读到空数组。 */
export function emptyCoverage(observedAt = Date.now()): CoverageEntry[] {
  return withUnknownDefaults([], observedAt)
}

/** 计数摘要（面板头部一行字用）。 */
export function summarizeCoverage(entries: readonly CoverageEntry[]): Record<CoverageResult, number> {
  const out: Record<CoverageResult, number> = {
    covered: 0,
    partial: 0,
    excluded: 0,
    unsupported: 0,
    failed: 0,
    unknown: 0,
  }
  for (const entry of entries) out[entry.result] += 1
  return out
}

/** 某个面的当前结论；不在表里返回 undefined（调用方自己决定怎么显示）。 */
export function resultOf(entries: readonly CoverageEntry[], surface: Surface): CoverageEntry | undefined {
  return entries.find((entry) => entry.surface === surface)
}
