import type { Confidence, Finding, Severity, Verdict } from './protocol.js'

const WEIGHTS: Record<Severity, number> = { critical: 45, high: 20, medium: 8, info: 2 }
const CONFIDENCE_COEF: Record<Confidence, number> = { certain: 1.0, likely: 0.8, heuristic: 0.4 }

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
