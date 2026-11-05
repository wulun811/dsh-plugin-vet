/**
 * 盾牌等级的判定（0.5.15，纯函数，从 Shield.tsx 拆出以便断言）。
 *
 * 为什么单独成模块：这段逻辑原来内联在 JSX 上方一行 `snap?.level ?? 'green'` 里，
 * 没有测试能碰到它——而它决定了整个产品最显眼的那一个像素的颜色。把判定拆成纯函数，
 * 「什么时候该说不知道」才有一条会红的断言。
 */
import type { ShieldLevel } from './components/ShieldIcon.tsx'

/** 陈旧阈值：3 个轮询周期（5s × 3）。导出是为了让测试与文档引用同一个数。 */
export const STALE_MS = 15_000

export interface ShieldLevelInput {
  /** 是否曾经成功拿到过快照。 */
  hasSnapshot: boolean
  /** 服务端给的等级；undefined = 字段缺失或协议漂移。 */
  level: ShieldLevel | undefined
  /** 最后一次成功拿到快照的时刻（0 = 从未）。 */
  loadedAt: number
  now: number
}

/**
 * 由「有没有数据 / 数据多新 / 服务端说什么」推导盾牌等级。
 *
 * 三条规则，按优先级：
 * 1. **从未拿到快照 → unknown**。旧实现默认 green，等于把「我不知道」画成「一切正常」。
 * 2. **快照陈旧 → unknown**。陈旧的 red 也不保留——「最后一次是红的」不是「现在还是红的」。
 * 3. 其余采信服务端，但**不认识的 level 一律 unknown**（协议漂移时默认 green 是最坏的默认）。
 */
export function shieldLevel(input: ShieldLevelInput): ShieldLevel {
  if (!input.hasSnapshot) return 'unknown'
  if (input.loadedAt > 0 && input.now - input.loadedAt > STALE_MS) return 'unknown'
  const l = input.level
  return l === 'green' || l === 'yellow' || l === 'red' ? l : 'unknown'
}
