import type { PluginScorecard } from './types.js'

const VERDICT_MARK: Record<string, string> = { critical: '🔴', suspicious: '🟠', clean: '🟢' }
// 与 scanner-bin/score.ts 保持同步（KEEP IN SYNC：跨 rootDir 无法单源共享）
// info 级不扣分（提示/取证），score 反映 decisive 威胁密度
const SEV_W: Record<string, number> = { critical: 45, high: 20, medium: 8, info: 0 }
const CONF_C: Record<string, number> = { certain: 1.0, likely: 0.8, heuristic: 0.5 }

/** 分数构成解释：按 severity 聚合扣分 + info 明细，让 clean+低分可读（verdict 只看 decisive）。 */
export function explainScore(findings: { severity: string; confidence: string; rule: string }[]): string {
  if (findings.length === 0) return '无发现，满分'
  const bySev: Record<string, number> = {}
  const infoRules: Record<string, number> = {}
  let total = 0
  for (const f of findings) {
    const coef = f.confidence === 'heuristic' ? 0.5 : (CONF_C[f.confidence] ?? 1)
    const w = SEV_W[f.severity] ?? 0
    bySev[f.severity] = (bySev[f.severity] ?? 0) + w * coef
    total += w * coef
    if (f.severity === 'info') infoRules[f.rule] = (infoRules[f.rule] ?? 0) + 1
  }
  const parts = ['critical', 'high', 'medium', 'info'].map(s => `${s} ${Math.round(bySev[s] ?? 0)}`)
  const infoDetail = Object.entries(infoRules).map(([r, c]) => `${r}×${c}`).join(' + ')
  return `100 - ${Math.round(total)} = ${parts.join(' + ')}${infoDetail !== '' ? `（info 明细: ${infoDetail}）` : ''}（verdict 只由 critical/high 决定）`
}

/** 纯函数渲染评分卡（presentResult 用，不触 IO）。 */
export function renderScorecard(card: PluginScorecard): string {
  const lines: string[] = []
  lines.push(`VET 评分卡: ${card.pluginName}${card.pluginVersion !== undefined ? `@${card.pluginVersion}` : ''}`)
  lines.push(`${VERDICT_MARK[card.static.verdict] ?? ''} verdict: ${card.static.verdict} | staticScore: ${card.static.staticScore}`)
  lines.push(`  静态分构成: ${explainScore(card.static.findings)}`)
  lines.push('静态发现:')
  if (card.static.findings.length === 0) {
    lines.push('  无')
  } else {
    for (const f of card.static.findings) {
      const loc = f.file !== undefined ? ` (${f.file}${f.line !== undefined ? `:${f.line}` : ''})` : ''
      lines.push(`  [${f.rule}] ${f.severity} ${f.message}${loc}`)
    }
  }
  // vet 本体自扫注解（②+①）：Trusted/Review-required 卡；原始 findings 上一段已按原文列出。
  if (card.selfScan !== undefined) {
    const s = card.selfScan
    const pinLabel = s.pin === 'pinned-match' ? '已钉扎' : s.pin === 'dev-tree' ? '开发树（字节≠发布钉扎）' : '未钉扎'
    lines.push('')
    lines.push('🔒 vet 安全层本体' + (s.version !== undefined ? '@' + s.version : '') + ' · ' + pinLabel)
    lines.push('  已声明能力面：模块 {' + s.declared.modules + '} | env {' + s.declared.envVars + '} | 网络 {' + s.declared.hosts + '}')
    const certified = s.pin === 'pinned-match' && s.verdict === 'clean'
    lines.push('  判定：' + (certified ? 'Trusted（已声明能力面 · 有界豁免）' : 'Review-required（' + s.verdict + '，钉扎未背书）') + ' | selfScanScore ' + s.staticScore)
    lines.push('  注解：已声明能力面 ' + s.annotation.declared + ' · 数据集自引用 ' + s.annotation.datasetSelfRef + ' · 开发夹具 ' + s.annotation.devFixtures + ' · 须复查 ' + s.annotation.retained.length + ' — 原始 finding ' + card.static.findings.length + ' 条完全保留、可展开')
    for (const f of s.annotation.retained.slice(0, 20)) {
      const loc = f.file !== undefined ? ' (' + f.file + (f.line !== undefined ? ':' + f.line : '') + ')' : ''
      lines.push('  [须复查] [' + f.rule + '] ' + f.severity + ' ' + f.message + loc)
    }
  }
  return lines.join('\n')
}
