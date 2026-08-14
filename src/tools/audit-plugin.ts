import { readFileSync } from 'node:fs'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import type { Context } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { scan } from '../scanner/client.js'
import { buildRequest, type ScanPluginArgs } from './scan-plugin.js'
import type { ScanRequest } from '../scanner/protocol.js'
import type { PluginScorecard } from '../report/types.js'
import { renderScorecard } from '../report/render.js'
import { resolveRoute } from '../audit/route.js'
import { chunkCode, runAudit } from '../audit/orchestrator.js'
import type { SessionPersistenceLike } from '../audit/session-log.js'

function collectCode(request: ScanRequest): string {
  if (request.kind === 'code' && typeof request.code === 'string') return request.code
  if (request.kind === 'files') {
    const parts: string[] = []
    for (const file of request.files ?? []) {
      try {
        parts.push(readFileSync(file, 'utf8'))
      } catch {
        // 不可读文件跳过（与扫描器一致）
      }
    }
    return parts.join('\n')
  }
  return ''
}

/**
 * audit_plugin：先静态扫描，verdict=critical 直接短路（省 token，不调 LLM）；
 * 否则按 deep 跑 4 轮 / 轮 1+2。LLM 全部轮失败 → fail-loud 附原因，不装成功。
 */
export function createAuditPluginTool(deps: { ctx: Context; config: VetConfig }) {
  return defineTool({
    name: 'audit_plugin',
    description: 'Deep-audit plugin code: deterministic static scan first, then a 4-round LLM audit (overview, security-sensitive spots, code quality, final scorecard). Skips the LLM rounds entirely when the static verdict is critical. 静态 verdict 权威，LLM 只补充上下文与质量分。',
    parameters: {
      target: {
        type: 'string', required: true,
        description: '扫描目标类型：dynamic-code（源码字符串）| package（插件包目录）| file（单文件路径）',
      },
      source: { type: 'string', description: 'dynamic-code 的源码字符串 / file 的文件路径' },
      packagePath: { type: 'string', description: 'package 的插件包目录（绝对路径）' },
      deep: { type: 'boolean', description: '默认 true：跑满 4 轮；false：只跑轮 1+2（更快更省）' },
      reason: { type: 'string', description: '审计原因（审计留痕）' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          pluginName: { type: 'string', required: true },
          pluginVersion: { type: 'string' },
          scannedAt: { type: 'string', required: true },
          static: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              verdict: { type: 'string', required: true },
              staticScore: { type: 'number', required: true },
              findings: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
            },
          },
          llm: { type: 'object', additionalProperties: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderScorecard(value as unknown as PluginScorecard) }],
    },
    timeoutMs: 600_000,
    isConcurrencySafe: () => false,
    async execute(args, exec) {
      const { request, pluginName } = buildRequest(args as unknown as ScanPluginArgs)
      const staticRes = await scan(request, { timeoutMs: 60_000 })
      if (!staticRes.ok || staticRes.report === undefined) {
        throw new Error(`vet: 静态扫描失败 ${staticRes.error ?? 'unknown'}`)
      }
      const base = {
        pluginName,
        scannedAt: new Date().toISOString(),
        static: {
          verdict: staticRes.report.verdict,
          staticScore: staticRes.report.staticScore,
          // 输出 schema 推断的 findings 项为开放对象，静态 Finding[] 断言为 JSON 值形状
          findings: staticRes.report.findings as unknown as Record<string, JsonValue>[],
        },
      }
      // verdict=critical 直接短路：不调 LLM，附注 audit-skipped（PLAN.md §6.4）
      if (base.static.verdict === 'critical') {
        return { ...base, llm: { error: 'audit-skipped', reason: 'static verdict is critical' } as unknown as Record<string, JsonValue> }
      }

      const session = exec.agent?.session
      const route = resolveRoute(deps.config, session)
      const code = collectCode(request)
      const persistence = (deps.ctx as Context & { sessionPersistence?: SessionPersistenceLike }).sessionPersistence
      const llm = await runAudit(
        { ctx: deps.ctx, config: deps.config, route, session, persistence },
        {
          pluginName,
          codeChunks: chunkCode(code),
          staticSummary: `verdict=${base.static.verdict} score=${base.static.staticScore} findings=${base.static.findings.length}`,
        },
        { verdict: base.static.verdict, staticScore: base.static.staticScore, findings: staticRes.report.findings },
        (args as unknown as { deep?: boolean }).deep === false ? 'basic' : 'all',
      )
      return { ...base, llm: llm as unknown as Record<string, JsonValue> }
    },
    presentCall: (args) => ({ card: 'generic', title: `Audit plugin: ${args.target}`, kind: 'read', rawInput: args.target }),
  })
}
