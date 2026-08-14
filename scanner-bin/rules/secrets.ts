import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'

const KEY_PATTERNS: { re: RegExp; desc: string }[] = [
  { re: /sk-[A-Za-z0-9]{16,}/, desc: 'sk- API key（OpenAI/DeepSeek 系）' },
  { re: /AKIA[0-9A-Z]{16}/, desc: 'AWS access key' },
  { re: /AIza[0-9A-Za-z_-]{20,}/, desc: 'GCP API key' },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/, desc: 'GitHub token' },
  { re: /xox[baprs]-/, desc: 'Slack token' },
  { re: /\b(DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=\s*\S+/, desc: '环境变量密钥赋值' },
  { re: /api\.(deepseek|openai|anthropic)\.com\/[^\s'"]*\?[^'"]*key=/, desc: 'URL 内嵌 API key' },
]

const PLACEHOLDER = /<[^>]*>|xxx|example|your[-_ ]?key|YOUR_/

/**
 * R7 hardcoded secrets. high/likely; placeholders excluded.
 */
export function run(sf: ts.SourceFile, _ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isStringLiteral(n) && !ts.isNoSubstitutionTemplateLiteral(n) && !ts.isTemplateExpression(n)) return
    const text = ts.isTemplateExpression(n)
      ? n.head.text + n.templateSpans.map(s => s.literal.text).join('')
      : n.text
    if (PLACEHOLDER.test(text)) return
    for (const p of KEY_PATTERNS) {
      if (p.re.test(text)) {
        found.push({
          rule: 'R7',
          severity: 'high',
          confidence: 'likely',
          message: `硬编码密钥：${p.desc}`,
          evidence: text.slice(0, 200),
          line: lineOf(sf, n),
        })
      }
    }
  })
  return found
}
