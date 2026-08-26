import type { Confidence, Finding, Severity, Verdict } from './protocol.js'

// info 级（字符串特征/能力触达面/超时跳过）是提示与取证，不构成威胁密度 → 不扣分。
// staticScore 反映 decisive（critical/high/medium）威胁；info 只出现在 findings 里。
const WEIGHTS: Record<Severity, number> = { critical: 45, high: 20, medium: 8, info: 0 }
// P3-3：heuristic 恒用 0.5（computeScore 内联），这里不收录——旧值 0.4 是死值误导
const CONFIDENCE_COEF: Record<Exclude<Confidence, 'heuristic'>, number> = { certain: 1.0, likely: 0.8 }

/**
 * Deterministic static score: 100 - Σ(severity weight × confidence coef × hits).
 * Heuristic confidence always uses 0.5 (info floor).
 */
export function computeScore(findings: Finding[]): number {
  let total = 0
  for (const f of findings) {
    // round-5 review（B-A14）：未知 confidence 与 self-scan 镜像（?? 1）同回退策略——
    // 旧实现此处直接取表值，协议漂移的未知值会 NaN 传播进总分；两侧行为保持一致。
    const coef = f.confidence === 'heuristic' ? 0.5 : CONFIDENCE_COEF[f.confidence] ?? 1
    // round-15 review：WEIGHTS 查表不设回退 → 外部/伪造/未来协议 findings 的未知 severity
    // 会产出 undefined × coef = NaN 总分 → 缓存 validReport 的 isFinite 永拒该条目 →
    // 每次重扫重写一张永不生效的死缓存。未知 severity 按 0 计（与 unknown-confidence 的
    // ?? 1 同款回退纪律：不扣分不 NaN）。
    total += (WEIGHTS[f.severity] ?? 0) * coef
  }
  return Math.max(0, Math.min(100, Math.round(100 - total)))
}

/**
 * The ONLY authoritative verdict. heuristic-confidence findings never change it
 * (R6 never upgrades). critical ≥ 1 → critical; else high ≥ 1 → suspicious.
 */
export function computeVerdict(findings: Finding[]): Verdict {
  const decisive = findings.filter(f => f.confidence !== 'heuristic')
  if (decisive.some(f => f.severity === 'critical')) return 'critical'
  if (decisive.some(f => f.severity === 'high')) return 'suspicious'
  return 'clean'
}
