import ts from 'typescript'
import type { Finding, RuleContext } from '../protocol.js'
import { walk, lineOf } from '../ast.js'

/** The sandbox ctx whitelist (guard.ts:636) — legitimate fiber verbs, NOT dangerous. */
const CTX_VERBS = new Set(['effect', 'on', 'once', 'provide', 'timeout', 'interval', 'setTimeout', 'setInterval', 'throttle', 'debounce'])
/**
 * round-5（实测评估）：ctx.logger 是 cordis 官方注入服务（cordis/lib/types/logger.d.ts），
 * DSH 官方插件（mcp-client 等）到处用 ctx.logger.info/warn/error——旧白名单漏了它，
 * 任何用 logger 的正常插件都被 R5 报 medium。日志不是危险面，放行。
 */
const CTX_SERVICES = new Set(['logger'])
/** The façade's own API (guard.ts:738-756). */
const CTX_FAÇADE = new Set(['tools', 'get'])
/** Common ctx variable names (heuristic). */
const CTX_NAMES = new Set(['ctx', 'context', 'self', 'pluginCtx'])

/**
 * R5 (A3-reworked) ctx escape-attempt signal, code scenario only by default.
 * Anything not in the whitelist or the façade is withheld by the sandbox
 * proxy (guard.ts:723-735, 753-767): reaching for it is an intent signal.
 * Documented false positive: legitimately injected services (ctx.fs etc.)
 * cannot be known statically — report mode only, deny defaults to critical.
 */
export function run(sf: ts.SourceFile, ctx: RuleContext): Finding[] {
  if (ctx.request.kind !== 'code' && ctx.request.rules?.['R5'] !== true) return []
  const found: Finding[] = []
  walk(sf, n => {
    if (!ts.isPropertyAccessExpression(n)) return
    const obj = n.expression
    if (!ts.isIdentifier(obj) || !CTX_NAMES.has(obj.text)) return
    // 不查 isShadowed：apply(ctx) 的 ctx 恰是函数参数，遮蔽检查会把参数当"用户遮蔽"而漏报（现场审计发现）
    const prop = n.name.text
    if (CTX_VERBS.has(prop) || CTX_FAÇADE.has(prop) || CTX_SERVICES.has(prop)) return
    found.push({
      rule: 'R5',
      severity: 'medium',
      confidence: 'likely',
      message: `ctx 逃逸尝试信号：访问被 withheld 的框架成员/未声明服务 ctx.${prop}（沙箱运行时会拒绝）`,
      evidence: n.getText(sf).slice(0, 200),
      line: lineOf(sf, n),
    })
  })
  return found
}
