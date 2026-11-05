/**
 * 生效姿态（施工图 §5.3）：格运算，不是状态机。
 *
 * 四个值来自**四个不同输入**，不是同一个东西的四个阶段：
 *
 *     desired   ← 配置（档位 / mode / confirmBlock）
 *     installed ← 装配结果（钩子真的挂上了吗）
 *     healthy   ← 心跳新鲜度
 *     effective ← worst(desired ∧ supported, installed, healthy)
 *
 * 为什么不是状态机：它没有持久状态（每次算出来）、没有多个写入方（输入变了就变）。
 * 硬写成状态机会暗示「姿态会随时间演进」，接下来就会有人给它建表、做持久化。
 *
 * **规则是不和稀泥**：`desired ≠ effective` 必须显示出来，不能静默对齐成「看着还行」。
 * 这一类不对称正是用户被误导的主要来源——配了档位、面板绿、实际什么都没挂上。
 */
import type { AlarmSeverity } from './types.js'

/** 六个执行面：三个运行时监视 + 三个闸门。 */
export type PostureSurface = 'preload_scan' | 'audit_gate' | 'runtime_fs' | 'runtime_net' | 'runtime_spawn' | 'confirm_block'

export const POSTURE_SURFACES: readonly PostureSurface[] = [
  'preload_scan',
  'audit_gate',
  'runtime_fs',
  'runtime_net',
  'runtime_spawn',
  'confirm_block',
]

/**
 * 生效值。四档，不是三档：`unsupported` 与 `degraded` 必须分开——
 * 「这个功能本版本就没有」和「有但没生效」是两种完全不同的处置。
 */
export type EffectivePosture = 'enforced' | 'degraded' | 'unsupported' | 'off' | 'unknown'

/**
 * 一个面的四个输入。
 *
 * `installed` / `healthy` 允许为 `null`（观测不到）。**不能拿 false 代替**：false 的意思是
 * 「确认没装/确认不健康」，而观测不到是「不知道」——把不知道写成 degraded，用户会去修一个
 * 可能根本不存在的问题；写成 enforced，则是最糟的那种说谎。
 */
export interface PostureInput {
  readonly desired: boolean
  readonly supported: boolean
  readonly installed: boolean | null
  readonly healthy: boolean | null
}

export interface PostureEntry extends PostureInput {
  readonly surface: PostureSurface
  readonly effective: EffectivePosture
  /** `desired !== effective` 时的一句话解释（面板直接显示，不让人猜）。 */
  readonly gap?: string
}

/** 排序：越小保护越少。格运算取最小值。 */
const RANK: Record<Exclude<EffectivePosture, 'unknown'>, number> = {
  off: 0,
  unsupported: 1,
  degraded: 2,
  enforced: 3,
}

/**
 * 格运算：`effective = worst(desired ∧ supported, installed, healthy)`。
 *
 * 三路各自看「这一路有没有把保护减掉」，取最差。
 * `desired=false` 时结果是 `off`——**这不是失败**，是用户明确关掉了；面板要能区分
 * 「关着」与「想让它是开的但没成功」。
 */
export function postureOf(input: PostureInput): EffectivePosture {
  // 关掉的开关先短路：用户没要求的东西不存在「观测不到」的问题，
  // 把它显示成 unknown 只会让人去查一个自己关掉的功能。
  if (!input.desired) return 'off'
  if (input.installed === null || input.healthy === null) return 'unknown'
  const desiredArm: EffectivePosture = !input.desired
    ? 'off'
    : input.supported
      ? 'enforced'
      : 'unsupported'
  const installedArm: EffectivePosture = input.installed ? 'enforced' : 'degraded'
  const healthyArm: EffectivePosture = input.healthy ? 'enforced' : 'degraded'
  let worst: Exclude<EffectivePosture, 'unknown'> = 'enforced'
  for (const arm of [desiredArm, installedArm, healthyArm] as const) {
    if (arm === 'enforced') continue
    if (worst === 'enforced' || RANK[arm] < RANK[worst]) worst = arm
  }
  return worst
}

/** 解释一句「为什么不是你以为的那样」。只在 desired 与 effective 不一致时给出。 */
function gapOf(input: PostureInput, effective: EffectivePosture): string | undefined {
  if (!input.desired || effective === 'enforced') return undefined
  if (effective === 'unsupported') return 'configured but not supported by this build'
  if (effective === 'unknown') return 'configured but not observable right now'
  if (effective === 'off') return undefined
  if (input.installed === false) return 'configured but not installed'
  if (input.healthy === false) return 'configured and installed but unhealthy'
  return undefined
}

export function postureEntry(surface: PostureSurface, input: PostureInput): PostureEntry {
  const effective = postureOf(input)
  const gap = gapOf(input, effective)
  return { surface, ...input, effective, ...(gap !== undefined ? { gap } : {}) }
}

/** 面板头部一句话用的严重度：只有「想要但没得到」才算问题，`off` 不算。 */
export function postureSeverity(entry: PostureEntry): AlarmSeverity | undefined {
  if (entry.effective === 'enforced' || entry.effective === 'off') return undefined
  if (entry.effective === 'unsupported') return 'info'
  return 'yellow'
}

/**
 * 全部六个面的入口。`derivePosture` 的调用方只需给出观测，判定在 `postureOf` 里一处做完。
 */
export function postureSummary(entries: readonly PostureEntry[]): {
  readonly enforced: number
  readonly gaps: readonly PostureEntry[]
} {
  return {
    enforced: entries.filter((e) => e.effective === 'enforced').length,
    gaps: entries.filter((e) => postureSeverity(e) !== undefined),
  }
}
