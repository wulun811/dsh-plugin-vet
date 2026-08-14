import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { VetConfig } from '../config.js'
import { scan } from '../scanner/client.js'
import type { ScanRequest, Verdict } from '../scanner/protocol.js'

/** 拦截目标：三大模型代码执行入口 + workflow（PLAN.md §6.6 A4）。 */
const TARGET_TOOLS = new Set(['cordis_define', 'cordis_run', 'run_code', 'workflow'])

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }
const DENY_RANK: Record<VetConfig['denyOn'], number> = { critical: 3, suspicious: 2 }

interface Payload {
  code: string
  runtime: 'host' | 'sandbox'
}

/** 从工具参数中提取代码字符串与 runtime 映射（run_code→host；cordis_run/workflow→sandbox）。 */
function codePayloads(exec: ToolExecution): Payload[] {
  const args = (exec.arguments ?? {}) as Record<string, unknown>
  const code = args.code as Record<string, unknown> | undefined
  switch (exec.name) {
    case 'run_code': {
      const src = typeof args.code === 'string' ? args.code : undefined
      return src !== undefined ? [{ code: src, runtime: 'host' }] : []
    }
    case 'cordis_define': {
      const out: Payload[] = []
      if (code !== undefined && typeof code.host === 'string') out.push({ code: code.host, runtime: 'sandbox' })
      if (code !== undefined && typeof code.client === 'string') out.push({ code: code.client, runtime: 'sandbox' })
      return out
    }
    case 'cordis_run': {
      if (code !== undefined && typeof code.host === 'string') return [{ code: code.host, runtime: 'sandbox' }]
      return []
    }
    case 'workflow': {
      const script = typeof args.script === 'string' ? args.script : undefined
      return script !== undefined ? [{ code: script, runtime: 'sandbox' }] : []
    }
    default:
      return []
  }
}

/**
 * tools/execute 守卫（timeout-policy 模式）。report：结果文本加 VET 前缀，不拦截；
 * deny + verdict ≥ denyOn：不调 next() 直接返回 isError（短路链路）。
 */
export function installToolExecuteGuard(ctx: Context, config: VetConfig): void {
  ctx.on('tools/execute', async (exec: ToolExecution, next) => {
    if (!TARGET_TOOLS.has(exec.name)) return next()
    const payloads = codePayloads(exec)
    if (payloads.length === 0) return next()

    const notes: string[] = []
    let worst: Verdict = 'clean'
    for (const p of payloads) {
      const request: ScanRequest = { kind: 'code', language: 'js', runtime: p.runtime, code: p.code }
      const res = await scan(request, { timeoutMs: config.scannerTimeoutMs })
      if (res.ok && res.report !== undefined) {
        notes.push(`VET ${exec.name}: ${res.report.verdict} (${res.report.staticScore})`)
        if (RANK[res.report.verdict] > RANK[worst]) worst = res.report.verdict
      } else {
        notes.push(`VET ${exec.name}: scan-error (${res.error ?? 'unknown'})`)
      }
    }

    if (config.mode === 'deny' && RANK[worst] >= DENY_RANK[config.denyOn]) {
      return {
        content: [{ type: 'text', text: `VET BLOCKED: ${notes.join('; ')}` }],
        isError: true,
        error: { message: `vet: ${exec.name} 被拦截（${worst}）` },
      } as ToolExecutionResult
    }

    const result = await next()
    const first = result.content[0]
    if (first !== undefined && first.type === 'text') {
      return {
        ...result,
        content: [{ ...first, text: `${notes.join('; ')}\n\n${first.text}` }, ...result.content.slice(1)],
      }
    }
    return result
  })
}
