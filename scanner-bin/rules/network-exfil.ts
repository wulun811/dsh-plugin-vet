import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'

/**
 * R13 network-exfil: hardcoded exfiltration sinks in string literals.
 *
 * Messaging webhooks (Discord/Telegram/Slack), cloud-metadata endpoints
 * (IAM credential exfiltration surface) and Tor hidden services are
 * damning static evidence wherever they appear in a plugin's source, in the
 * same spirit as R7 hardcoded secrets. Regex over string-literal text only
 * (never evaluated), one finding per pattern per literal.
 */
const EXFIL_PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /discord(app)?\.com\/api\/webhooks/, desc: 'Discord webhook（数据外泄端点）' },
  { re: /api\.telegram\.org\/bot[0-9]+:/, desc: 'Telegram bot webhook（数据外泄端点）' },
  { re: /hooks\.slack\.com\/services/, desc: 'Slack webhook（数据外泄端点）' },
  { re: /169\.254\.169\.254/, desc: 'AWS 云元数据端点（IAM 凭据外泄面）' },
  { re: /metadata\.(google|compute)\.internal/, desc: '云元数据端点（IAM 凭据外泄面）' },
  { re: /100\.100\.100\.200/, desc: '阿里云元数据端点（凭据外泄面）' },
  { re: /\.onion\b/, desc: 'Tor 隐藏服务目标（匿名外泄）' },
]

/**
 * R13 hardcoded external exfiltration sinks. high/likely; literals only.
 */
export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isStringLiteral(n) && !ts.isNoSubstitutionTemplateLiteral(n) && !ts.isTemplateExpression(n)) return
    const text = ts.isTemplateExpression(n)
      ? n.head.text + n.templateSpans.map(s => s.literal.text).join('')
      : n.text
    for (const p of EXFIL_PATTERNS) {
      const re = new RegExp(p.re.source, 'g')
      const m = re.exec(text)
      if (m === null) continue
      found.push({
        rule: 'R13',
        severity: 'high',
        confidence: 'likely',
        message: '硬编码外联端点：' + p.desc,
        evidence: text.slice(0, 200),
        line: lineOf(sf, n),
      })
      break // 每个 pattern 每段只报一条
    }
  })
  return found
}
