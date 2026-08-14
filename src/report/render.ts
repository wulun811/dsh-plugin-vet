import type { PluginScorecard } from './types.js'

const VERDICT_MARK: Record<string, string> = { critical: '🔴', suspicious: '🟠', clean: '🟢' }

/** 纯函数渲染评分卡（presentResult 用，不触 IO）。 */
export function renderScorecard(card: PluginScorecard): string {
  const lines: string[] = []
  lines.push(`VET 评分卡: ${card.pluginName}${card.pluginVersion !== undefined ? `@${card.pluginVersion}` : ''}`)
  const quality = card.llm !== undefined && 'qualityScore' in card.llm ? ` | qualityScore: ${card.llm.qualityScore}` : ''
  lines.push(`${VERDICT_MARK[card.static.verdict] ?? ''} verdict: ${card.static.verdict} | staticScore: ${card.static.staticScore}${quality}`)
  lines.push('静态发现:')
  if (card.static.findings.length === 0) {
    lines.push('  无')
  } else {
    for (const f of card.static.findings) {
      const loc = f.file !== undefined ? ` (${f.file}${f.line !== undefined ? `:${f.line}` : ''})` : ''
      lines.push(`  [${f.rule}] ${f.severity} ${f.message}${loc}`)
    }
  }
  if (card.llm !== undefined) {
    if ('error' in card.llm) {
      const label = card.llm.error === 'audit-skipped' ? '跳过' : '失败'
      lines.push(`LLM 审计: ${label} (${card.llm.reason})`)
    } else {
      const partial = card.llm.partial ? ' (partial)' : ''
      lines.push(`LLM 审计: quality=${card.llm.qualityScore} recommendation=${card.llm.recommendation} confidence=${card.llm.confidence}${partial}`)
      if (card.llm.summary.length > 0) lines.push(`summary: ${card.llm.summary}`)
    }
  }
  return lines.join('\n')
}
