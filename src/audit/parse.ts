/**
 * 模型输出解析：JSON 提取（容忍 markdown 围栏/前后杂文）+ schema 校验 + 数值钳制（PLAN.md §5.3）。
 */
export function extractJson(text: string): unknown {
  const first = text.indexOf('{')
  const last = text.lastIndexOf('}')
  if (first === -1 || last === -1 || last <= first) {
    throw new Error('输出中未找到 JSON 对象')
  }
  return JSON.parse(text.slice(first, last + 1))
}

export type ParseOutcome<T> = { ok: true; value: T } | { ok: false; error: string }

/** 提取 + JSON.parse + schema 校验（判定函数抛错即失败）。 */
export function parseRoundOutput<T>(text: string, validate: (value: unknown) => T): ParseOutcome<T> {
  try {
    const value = extractJson(text)
    return { ok: true, value: validate(value) }
  } catch (error) {
    return { ok: false, error: String(error) }
  }
}

/** qualityScore 强制 [0,100] 整数；越界钳制。 */
export function clampScore(value: unknown): number {
  const n = Math.round(Number(value))
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(100, n))
}

export function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string')
}
