import type { Context } from '@deepseek-ai/cordis'
import type { FinishReason, GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import { BlockAssembler, createUserMessage, deepFreeze } from '@deepseek-ai/dsh-llm'
import type { Session } from '@deepseek-ai/dsh-session'
import type { VetConfig } from '../config.js'
import type { AuditRoute } from './route.js'
import type { LlmFinding, LlmSection } from '../report/types.js'
import { parseRoundOutput, clampScore, stringArray } from './parse.js'
import { prompts } from './prompts.js'
import { appendAuditEvent, type SessionPersistenceLike } from './session-log.js'

const MAX_CHUNK_BYTES = 32 * 1024
/** 轮 2 最多审计的分块数（超出的代码块不逐块调 LLM，防大包 LLM 成本爆炸；round3/4 仍看全貌截断）。 */
const MAX_AUDIT_CHUNKS = 12

/** 按 ≤32KB（utf8）切分代码块（PLAN.md §5.1 输入字节上限）。 */
export function chunkCode(code: string): string[] {
  const chunks: string[] = []
  let buf = ''
  for (const ch of code) {
    buf += ch
    if (Buffer.byteLength(buf, 'utf8') >= MAX_CHUNK_BYTES) {
      chunks.push(buf)
      buf = ''
    }
  }
  if (buf.length > 0) chunks.push(buf)
  return chunks.length > 0 ? chunks : ['']
}

/** 翻译终止原因（模板=session-title-llm finishError；无 finish 块时 assembler 默认 stop）。 */
function finishError(finish: FinishReason): Error | undefined {
  switch (finish.kind) {
    case 'stop':
      return undefined
    case 'error':
    case 'aborted': {
      const failure = (finish as { failure?: { message?: string } }).failure
      return new Error(failure?.message ?? 'llm call aborted')
    }
    case 'max-tokens':
      return new Error('vet: audit 输出达到 maxTokens 上限')
    case 'tool-calls':
      return new Error('vet: audit 模型意外请求了工具调用')
    default:
      return new Error(`vet: 未支持终止原因 ${String((finish as { kind?: unknown }).kind)}`)
  }
}

/** 单轮 LLM 调用：独立 deadline、独立流、text 块拼接。purpose 省略（闭联合限制，A1）。 */
async function callRound(
  ctx: Context,
  config: VetConfig,
  route: AuditRoute,
  session: Session | undefined,
  system: string,
  input: string,
): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), config.auditTimeoutMs)
  try {
    const options = deepFreeze({
      provider: route.provider,
      model: route.model,
      messages: [createUserMessage({
        content: [{ type: 'text', text: input }],
        source: { kind: 'plugin', plugin: 'dsh-plugin-vet' },
      })],
      system,
      maxTokens: config.auditMaxTokens,
      signal: controller.signal,
      ...(session !== undefined ? { sessionId: session.id } : {}),
    }) as GenerateOptions
    const assembler = new BlockAssembler()
    for await (const chunk of ctx.llm.stream(options) as AsyncIterable<StreamChunk>) assembler.push(chunk)
    const terminalError = finishError(assembler.finish)
    if (terminalError !== undefined) throw terminalError
    return assembler.blocks()
      .filter((block): block is Extract<typeof block, { type: 'text' }> => block.type === 'text')
      .map(block => block.text)
      .join(' ')
  } finally {
    clearTimeout(timer)
  }
}

// ---- 各轮输出校验 ----
interface Round1 { summary: string; dataFlow: string[]; permissionBoundary: string[]; riskNotes: string[] }
function validateRound1(value: unknown): Round1 {
  const o = value as Record<string, unknown>
  if (typeof o?.summary !== 'string') throw new Error('round1: summary 缺失或非字符串')
  return { summary: o.summary, dataFlow: stringArray(o.dataFlow), permissionBoundary: stringArray(o.permissionBoundary), riskNotes: stringArray(o.riskNotes) }
}
const FINDING_CATEGORIES = new Set(['secret', 'exfiltration', 'telemetry', 'obfuscation', 'dangerous-api', 'other'])
const FINDING_RISKS = new Set(['low', 'medium', 'high', 'critical'])

/** 校验 findings/llmFindings 数组（轮 2 与轮 4 键名不同，共用结构校验）。 */
function validateFindings(value: unknown, key: string): LlmFinding[] {
  const o = value as Record<string, unknown>
  const list = o?.[key]
  if (!Array.isArray(list)) throw new Error(`${key} 缺失或非数组`)
  const findings: LlmFinding[] = []
  for (const item of list) {
    const f = item as Record<string, unknown>
    if (typeof f?.category !== 'string' || !FINDING_CATEGORIES.has(f.category)) throw new Error(`${key}: category 非法`)
    if (typeof f?.evidence !== 'string' || typeof f?.risk !== 'string' || !FINDING_RISKS.has(f.risk) || typeof f?.suggestion !== 'string') {
      throw new Error(`${key}: finding 字段非法`)
    }
    findings.push({ category: f.category as LlmFinding['category'], evidence: f.evidence, risk: f.risk as LlmFinding['risk'], suggestion: f.suggestion })
  }
  return findings
}
interface Round2 { findings: LlmFinding[] }
function validateRound2(value: unknown): Round2 {
  return { findings: validateFindings(value, 'findings') }
}
interface Round3 { qualityScore: number; dimensions: Record<string, { score: number; note: string }>; qualityNotes: string[] }
function validateRound3(value: unknown): Round3 {
  const o = value as Record<string, unknown>
  const dims = (o?.dimensions ?? {}) as Record<string, unknown>
  const dimensions: Record<string, { score: number; note: string }> = {}
  for (const [key, entry] of Object.entries(dims)) {
    const e = entry as Record<string, unknown>
    dimensions[key] = { score: clampScore(e?.score), note: typeof e?.note === 'string' ? e.note : '' }
  }
  return { qualityScore: clampScore(o?.qualityScore), dimensions, qualityNotes: stringArray(o?.qualityNotes) }
}
interface Round4 { llmFindings: LlmFinding[]; qualityScore: number; confidence: 'high' | 'medium' | 'low'; summary: string; recommendation: 'approve' | 'review' | 'reject' }
function validateRound4(value: unknown): Round4 {
  const llmFindings = validateFindings(value, 'llmFindings')
  const o = value as Record<string, unknown>
  const CONF = new Set(['high', 'medium', 'low'])
  const REC = new Set(['approve', 'review', 'reject'])
  if (typeof o?.confidence !== 'string' || !CONF.has(o.confidence)) throw new Error('round4: confidence 非法')
  if (typeof o?.summary !== 'string') throw new Error('round4: summary 缺失')
  if (typeof o?.recommendation !== 'string' || !REC.has(o.recommendation)) throw new Error('round4: recommendation 非法')
  return {
    llmFindings,
    qualityScore: clampScore(o?.qualityScore),
    confidence: o.confidence as Round4['confidence'],
    summary: o.summary,
    recommendation: o.recommendation as Round4['recommendation'],
  }
}

interface AuditDeps {
  ctx: Context
  config: VetConfig
  route: AuditRoute
  session: Session | undefined
  persistence: SessionPersistenceLike | undefined
}
export interface AuditInput {
  pluginName: string
  codeChunks: string[]
  staticSummary: string
}

type RoundOutcome<T> = { ok: true; value: T } | { ok: false; error: string }

/** 单轮执行：解析失败重试一次（提示词追加说明），二次失败即该轮失败（不伪造）。 */
async function attemptRound<T>(
  deps: AuditDeps,
  round: number,
  system: string,
  input: string,
  validate: (value: unknown) => T,
): Promise<RoundOutcome<T>> {
  let text: string
  try {
    text = await callRound(deps.ctx, deps.config, deps.route, deps.session, system, input)
  } catch (error) {
    return { ok: false, error: `round${round}: ${String(error)}` }
  }
  const first = parseRoundOutput(text, validate)
  if (first.ok) return first
  if (round === 4) return { ok: false, error: `round4 parse: ${first.error}` }
  try {
    text = await callRound(deps.ctx, deps.config, deps.route, deps.session, system,
      `${input}\n\n[system note] 上一输出无效（${first.error}），请只输出合法 JSON。`)
  } catch (error) {
    return { ok: false, error: `round${round} retry: ${String(error)}` }
  }
  const retry = parseRoundOutput(text, validate)
  return retry.ok ? retry : { ok: false, error: `round${round} parse (retry): ${retry.error}` }
}

function summarizeStatic(staticReport: { verdict: string; staticScore: number; findings: unknown[] }): string {
  return `verdict=${staticReport.verdict}, staticScore=${staticReport.staticScore}, findings=${staticReport.findings.length}`
}

/** 统一轮次输入帧：静态报告 + 有序段落（消重复模板，malong duplication 反馈）。 */
function frame(staticReport: { verdict: string; staticScore: number; findings: unknown[] }, sections: [string, string][]): string {
  const lines = ['静态报告:', summarizeStatic(staticReport)]
  for (const [title, body] of sections) {
    lines.push('', `${title}:`, body)
  }
  return lines.join('\n')
}

/**
 * 4 轮编排（PLAN.md §5.2）：轮 1 必选；轮 2/3 失败 → partial 继续；轮 4 失败 → 用已完成的
 * 轮次组装（保守默认，不伪造 LLM 输出）。轮 1 失败 → 整体失败（fail-loud）。
 * @param mode 'all' 跑满 4 轮；'basic' 只跑轮 1+2（deep: false）。
 */
export async function runAudit(
  deps: AuditDeps,
  input: AuditInput,
  staticReport: { verdict: string; staticScore: number; findings: unknown[] },
  mode: 'all' | 'basic' = 'all',
): Promise<LlmSection> {
  const log = (type: 'audit-plugin-vet/request' | 'audit-plugin-vet/result', data: Record<string, unknown>): void =>
    appendAuditEvent(deps.persistence, deps.session, type, data)

  let partial = false

  // 轮 1 总览（代码全貌截断到审计上限块——大包总览不能只基于第一块）
  const overviewCode = input.codeChunks.slice(0, MAX_AUDIT_CHUNKS).join('\n---\n') || ''
  const r1 = await attemptRound(deps, 1, prompts.round1,
    frame(staticReport, [['代码', overviewCode]]),
    validateRound1)
  if (!r1.ok) return { error: 'audit-failed', reason: r1.error }
  log('audit-plugin-vet/request', { pluginName: input.pluginName, round: 1, inputBytes: overviewCode.length, provider: deps.route.provider, model: deps.route.model })

  // 轮 2 敏感点（代码分块，封顶 MAX_AUDIT_CHUNKS——大包不逐块烧 LLM，超出标记 partial）
  const findings: LlmFinding[] = []
  const auditChunks = input.codeChunks.slice(0, MAX_AUDIT_CHUNKS)
  if (input.codeChunks.length > MAX_AUDIT_CHUNKS) partial = true
  for (const chunk of auditChunks) {
    const r2 = await attemptRound(deps, 2, prompts.round2,
      frame(staticReport, [['轮 1 总览', JSON.stringify(r1.value)], ['代码块', chunk]]),
      validateRound2)
    if (r2.ok) {
      findings.push(...r2.value.findings)
    } else {
      partial = true
      break
    }
  }

  if (mode === 'basic') {
    return {
      findings,
      summary: r1.value.summary,
      recommendation: 'review',
      confidence: 'low',
      partial: true,
    }
  }

  // 轮 3 质量（代码全貌截断到审计上限块，防上下文超限）
  const r3 = await attemptRound(deps, 3, prompts.round3,
    frame(staticReport, [['轮 1 总览', JSON.stringify(r1.value)], ['轮 2 发现', JSON.stringify(findings)], ['代码', auditChunks.join('\n---\n')]]),
    validateRound3)
  if (r3.ok) partial = partial || false
  else partial = true

  // 轮 4 汇总
  const r4 = await attemptRound(deps, 4, prompts.round4,
    frame(staticReport, [['轮 1 总览', JSON.stringify(r1.value)], ['轮 2 发现', JSON.stringify(findings)], ['轮 3 质量', r3.ok ? JSON.stringify(r3.value) : '(轮 3 失败)']]),
    validateRound4)
  log('audit-plugin-vet/result', { pluginName: input.pluginName, llmSection: r4.ok ? r4.value : { error: 'round4-failed' } })

  if (r4.ok) {
    return {
      qualityScore: r4.value.qualityScore,
      findings: r4.value.llmFindings,
      summary: r4.value.summary,
      recommendation: r4.value.recommendation,
      confidence: r4.value.confidence,
      partial,
    }
  }
  // r4 失败：用 r1-r3 组装（保守默认 review/low，不伪造）
  return {
    qualityScore: r3.ok ? r3.value.qualityScore : undefined,
    findings,
    summary: r1.value.summary,
    recommendation: 'review',
    confidence: 'low',
    partial: true,
  }
}
