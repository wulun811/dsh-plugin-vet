import type { Confidence, Finding, Severity, Verdict } from './protocol.js'

// info 级（字符串特征/能力触达面/超时跳过）是提示与取证，不构成威胁密度 → 不扣分。
// staticScore 反映 decisive（critical/high/medium）威胁；info 只出现在 findings 里。
const WEIGHTS: Record<Severity, number> = { critical: 45, high: 20, medium: 8, info: 0 }
// P3-3：heuristic 恒用 0.5（computeScore 内联），这里不收录——旧值 0.4 是死值误导
const CONFIDENCE_COEF: Record<Exclude<Confidence, 'heuristic'>, number> = { certain: 1.0, likely: 0.8 }

/**
 * Deterministic static score: 100 - Σ(severity weight × confidence coef × hits).
 * Heuristic confidence always uses 0.5 (info floor, per PLAN.md §4.4).
 */
export function computeScore(findings: Finding[]): number {
  let total = 0
  for (const f of findings) {
    const coef = f.confidence === 'heuristic' ? 0.5 : CONFIDENCE_COEF[f.confidence]
    total += WEIGHTS[f.severity] * coef
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
