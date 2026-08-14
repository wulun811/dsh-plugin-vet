import { describe, expect, it, vi } from 'vitest'
import type { GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import { extractJson, parseRoundOutput, clampScore } from '../lib/audit/parse.js'
import { resolveRoute } from '../lib/audit/route.js'
import { chunkCode, runAudit } from '../lib/audit/orchestrator.js'
import { appendAuditEvent } from '../lib/audit/session-log.js'
import { createAuditPluginTool } from '../lib/tools/audit-plugin.js'
import type { VetConfig } from '../lib/config.js'

const cfg = (over: Partial<VetConfig> = {}): VetConfig => ({
  mode: 'report', autoScan: true, autoAudit: false,
  auditMaxTokens: 2048, auditTimeoutMs: 120_000, scannerTimeoutMs: 15_000,
  auditCacheTtlHours: 168, rules: {}, denyOn: 'critical', allowlist: [],
  ...over,
})

const ESCAPE = 'TextEncoder.constructor("return process")().cwd()'
const CLEAN = 'module.exports = { ok: true }'

// ---- parse ----
describe('parse', () => {
  it('提取 markdown 围栏内的 JSON', () => {
    const text = 'Sure! Here is the result:\n\n\\`\\`\\`json\n{"summary":"x","dataFlow":[],"permissionBoundary":[],"riskNotes":[]}\n\\`\\`\\`'
    expect(extractJson(text)).toMatchObject({ summary: 'x' })
  })

  it('schema 校验失败返回错误而非抛异常', () => {
    const r = parseRoundOutput('{"summary":42}', (v) => {
      if (typeof (v as { summary: unknown }).summary !== 'string') throw new Error('bad')
      return v
    })
    expect(r.ok).toBe(false)
  })

  it('clampScore 钳制到 [0,100] 整数', () => {
    expect(clampScore(150)).toBe(100)
    expect(clampScore(-5)).toBe(0)
    expect(clampScore('abc')).toBe(0)
    expect(clampScore(75.6)).toBe(76)
  })
})

// ---- route ----
describe('route', () => {
  it('Config 成对优先', () => {
    const route = resolveRoute(cfg({ provider: 'deepseek', model: 'deepseek-chat' }), undefined)
    expect(route).toEqual({ provider: 'deepseek', model: 'deepseek-chat' })
  })

  it('回落会话 requestHeader().config', () => {
    const session = { requestHeader: () => ({ config: { provider: 'p', model: 'm' } }) } as never
    expect(resolveRoute(cfg(), session)).toEqual({ provider: 'p', model: 'm' })
  })

  it('双缺 fail-loud', () => {
    expect(() => resolveRoute(cfg(), undefined)).toThrow(/vet: 未配置/)
  })
})

// ---- chunkCode ----
describe('chunkCode', () => {
  it('按 32KB 切块', () => {
    const big = 'x'.repeat(40 * 1024)
    const chunks = chunkCode(big)
    expect(chunks.length).toBeGreaterThan(1)
    expect(chunks.join('')).toBe(big)
  })
})

// ---- session-log ----
describe('session-log', () => {
  it('走 persistence.append 完整信封 + ignorable: true', async () => {
    const append = vi.fn(async () => {})
    const session = { id: 's1', log: { length: 3 } } as never
    appendAuditEvent({ append } as never, session, 'audit-plugin-vet/request', { pluginName: 'x', round: 1, inputBytes: 10, provider: 'p', model: 'm' })
    expect(append).toHaveBeenCalledTimes(1)
    const events = append.mock.calls[0][1] as { type: string; ignorable?: boolean; seq: number }[]
    expect(events[0].type).toBe('audit-plugin-vet/request')
    expect(events[0].ignorable).toBe(true)
    expect(events[0].seq).toBe(3)
  })

  it('persistence 或 session 缺失时静默跳过', () => {
    expect(() => appendAuditEvent(undefined, undefined, 'audit-plugin-vet/request', {})).not.toThrow()
  })
})

// ---- orchestrator (fake ctx.llm) ----
const CANNED: Record<number, string> = {
  1: '{"summary":"demo plugin","dataFlow":["input→output"],"permissionBoundary":["none"],"riskNotes":[]}',
  2: '{"findings":[]}',
  3: '{"dimensions":{"errorHandling":{"score":80,"note":""},"boundaryChecks":{"score":70,"note":""},"dependencies":{"score":90,"note":""},"maintainability":{"score":75,"note":""},"docs":{"score":60,"note":""}},"qualityScore":75,"qualityNotes":[]}',
  4: '{"llmFindings":[],"qualityScore":75,"confidence":"medium","summary":"final","recommendation":"review"}',
}

function fakeLlm(overrides: Record<number, string> = {}) {
  const map = { ...CANNED, ...overrides }
  return {
    stream: async function* (options: GenerateOptions): AsyncIterable<StreamChunk> {
      const system = String(options.system)
      const round = system.includes('FINAL audit summary') ? 4
        : system.includes('CODE QUALITY') ? 3
        : system.includes('security-sensitive spots') ? 2 : 1
      const text = map[round] ?? '{}'
      yield { type: 'block-start', index: 0, blockType: 'text' } as StreamChunk
      yield { type: 'text-delta', index: 0, text } as StreamChunk
      yield { type: 'block-end', index: 0, block: { type: 'text', text } } as StreamChunk
      yield { type: 'finish', reason: { kind: 'stop' } } as StreamChunk
    },
  }
}

function auditDeps(llm: { stream(options: GenerateOptions): AsyncIterable<StreamChunk> }) {
  return {
    ctx: { llm } as never,
    config: cfg(),
    route: { provider: 'p', model: 'm' },
    session: undefined,
    persistence: undefined,
  }
}

describe('orchestrator (fake llm)', () => {
  it('4 轮全通 → 完整评分卡', async () => {
    const deps = auditDeps(fakeLlm())
    const llm = await runAudit(deps, { pluginName: 'x', codeChunks: [CLEAN], staticSummary: 'clean' },
      { verdict: 'clean', staticScore: 100, findings: [] })
    expect('qualityScore' in llm && llm.qualityScore).toBe(75)
    if ('qualityScore' in llm) {
      expect(llm.partial).toBe(false)
      expect(llm.recommendation).toBe('review')
      expect(llm.confidence).toBe('medium')
    }
  })

  it('轮 1 失败 → audit-failed（fail-loud）', async () => {
    const deps = auditDeps(fakeLlm({ 1: 'not json at all' }))
    const llm = await runAudit(deps, { pluginName: 'x', codeChunks: [CLEAN], staticSummary: 'clean' },
      { verdict: 'clean', staticScore: 100, findings: [] })
    expect('error' in llm).toBe(true)
  })

  it('轮 2 两次无效 → partial，findings 为空，流程继续', async () => {
    const deps = auditDeps(fakeLlm({ 2: '{{{{bad' }))
    const llm = await runAudit(deps, { pluginName: 'x', codeChunks: [CLEAN], staticSummary: 'clean' },
      { verdict: 'clean', staticScore: 100, findings: [] })
    if ('qualityScore' in llm) {
      expect(llm.partial).toBe(true)
      expect(llm.findings).toEqual([])
    }
  })

  it('basic 模式（deep:false）只跑轮 1+2 → 无 qualityScore + partial', async () => {
    const deps = auditDeps(fakeLlm())
    const llm = await runAudit(deps, { pluginName: 'x', codeChunks: [CLEAN], staticSummary: 'clean' },
      { verdict: 'clean', staticScore: 100, findings: [] }, 'basic')
    if ('qualityScore' in llm) {
      expect(llm.qualityScore).toBeUndefined()
      expect(llm.partial).toBe(true)
    }
  })
})

// ---- audit_plugin tool ----
describe('audit_plugin tool', () => {
  const fakeExec = (agent?: unknown) => ({
    agent, signal: new AbortController().signal, callId: 'c', rootCallId: 'c', token: Symbol('t'),
  })

  it('静态 critical → 短路返回，无 llm 段（不调 LLM）', async () => {
    const llm = vi.fn()
    const tool = createAuditPluginTool({ ctx: { llm } as never, config: cfg() })
    const value = await tool.execute({ target: 'dynamic-code', source: ESCAPE } as never, fakeExec() as never)
    expect(value.static.verdict).toBe('critical')
    expect(value.llm).toEqual({ error: 'audit-skipped', reason: 'static verdict is critical' })
    expect(llm).not.toHaveBeenCalled()
  })

  it('静态 clean + fake LLM → 完整 llm 段', async () => {
    const tool = createAuditPluginTool({
      ctx: { llm: fakeLlm(), sessionPersistence: undefined } as never,
      config: cfg({ provider: 'p', model: 'm' }),
    })
    const session = { id: 's1', requestHeader: () => undefined, log: { length: 0 } }
    const value = await tool.execute(
      { target: 'dynamic-code', source: CLEAN, deep: true } as never,
      fakeExec({ session }) as never,
    )
    expect(value.static.verdict).toBe('clean')
    expect(value.llm).toBeDefined()
    expect('qualityScore' in value.llm!).toBe(true)
  })
});
