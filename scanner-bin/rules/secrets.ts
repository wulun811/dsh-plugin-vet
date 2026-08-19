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

/** P2-9：占位符片段区间（整串中所有匹配占位符的位置）——key 命中若与占位符段重叠才排除，
 * 不再「整段含 example 就整体跳过」（真实 key 混 example 文本此前漏报）。 */
function placeholderSpans(text: string): [number, number][] {
  const spans: [number, number][] = []
  const re = new RegExp(PLACEHOLDER.source, 'g')
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    spans.push([m.index, m.index + m[0].length])
  }
  return spans
}

/** key 命中段是否与任一占位符段重叠。 */
function overlapsPlaceholder(start: number, end: number, spans: [number, number][]): boolean {
  return spans.some(([s, e]) => start < e && s < end)
}

/**
 * R7 hardcoded secrets. high/likely; placeholders excluded per-segment.
 */
/** 对一段文本跑 KEY_PATTERNS（AST 字面量与 N2 解码语料共用判定逻辑）。 */
function scanText(text: string, decoded = false): Finding[] {
  const out: Finding[] = []
  const spans = placeholderSpans(text)
  for (const p of KEY_PATTERNS) {
    const re = new RegExp(p.re.source, 'g')
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const start = m.index
      const end = start + m[0].length
      if (overlapsPlaceholder(start, end, spans)) continue
      out.push({
        rule: 'R7',
        severity: 'high',
        confidence: 'likely',
        message: decoded ? `硬编码密钥（经解码还原）：${p.desc}` : `硬编码密钥：${p.desc}`,
        evidence: text.slice(0, 200),
      })
      break // 每个 pattern 每段只报一条
    }
  }
  return out
}

export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isStringLiteral(n) && !ts.isNoSubstitutionTemplateLiteral(n) && !ts.isTemplateExpression(n)) return
    const text = ts.isTemplateExpression(n)
      ? n.head.text + n.templateSpans.map(s => s.literal.text).join('')
      : n.text
    for (const f of scanText(text)) {
      f.line = lineOf(sf, n)
      found.push(f)
    }
  })
  // N2：解码语料（还原后的密钥字面量同样判定；message 注明还原来源，保留原始行号）
  for (const d of ctx.decodedLiterals ?? []) {
    for (const f of scanText(d.text, true)) {
      f.decodedFrom = d.method
      f.line = d.line
      f.file = d.file
      found.push(f)
    }
  }
  return found
}
