import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { VetConfig } from '../config.js'
import { scan } from '../scanner/client.js'
import type { ScanRequest, Verdict } from '../scanner/protocol.js'
import type { VetStatus } from '../guard/status.js'

/** 拦截目标：三大模型代码执行入口 + workflow。 */
const TARGET_TOOLS = new Set(['cordis_define', 'cordis_run', 'run_code', 'workflow'])

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }
const DENY_RANK: Record<VetConfig['denyOn'], number> = { critical: 3, suspicious: 2 }

/** round-5 review（A#14）：重复 apply 防叠——与 internal-plugin/runtime-guard 同款认知：
 * DSH 配置热重载可能对同一 ctx 重复 apply 而不清理旧监听器，叠加会让同一次 tools/execute
 * 被扫描多次（双重扫描 + VET 前缀叠加 + deny 双份拦截结果）。模块级记住上一个 off。
 */
let prevExecuteListenerOff: (() => void) | undefined

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
      // M6：host 半区在宿主进程内激活执行 → 'host'（R3 不降级，deny 阈值正确）
      if (code !== undefined && typeof code.host === 'string') out.push({ code: code.host, runtime: 'host' })
      if (code !== undefined && typeof code.client === 'string') out.push({ code: code.client, runtime: 'sandbox' })
      return out
    }
    case 'cordis_run': {
      // 真实 schema 是 pluginId/packageId/mode（无 code 字段）——past 空分支避免误匹配其他工具。
      // round-16 review（S8）：把「死条目」变成 tripwire——若未来 DSH schema 给 cordis_run
      // 增加代码形载荷（code/source/script），立即进入扫描面（P3-11 同步的守卫位真正生效）；
      // 当前 schema 无这些字段 → payloads 恒空，零误报零开销。
      const src = typeof args.code === 'string' ? args.code
        : typeof args.source === 'string' ? args.source
          : typeof args.script === 'string' ? args.script : undefined
      return src !== undefined ? [{ code: src, runtime: 'sandbox' }] : []
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
export function installToolExecuteGuard(ctx: Context, config: VetConfig, status?: VetStatus): void {
  prevExecuteListenerOff?.()
  prevExecuteListenerOff = ctx.on('tools/execute', async (exec: ToolExecution, next) => {
    if (!TARGET_TOOLS.has(exec.name)) return next()
    const payloads = codePayloads(exec)
    if (payloads.length === 0) return next()

    const notes: string[] = []
    let worst: Verdict = 'clean'
    let scanFailed = false
    for (const p of payloads) {
      const request: ScanRequest = { kind: 'code', language: 'js', runtime: p.runtime, code: p.code }
      const res = await scan(request, { timeoutMs: config.scannerTimeoutMs })
      if (res.ok && res.report !== undefined) {
        status?.noteScan({ pluginName: exec.name, verdict: res.report.verdict, staticScore: res.report.staticScore, at: Date.now() })
        // round-5 review（A#15）：扫描器协议漂移出现未知 verdict 时 RANK 查表为
        // undefined——`undefined > RANK[worst]` 恒 false，deny 判定静默失效（fail-open）
        // 且无任何日志。未知 verdict 视为扫描结果不可信，走与 scanFailed 相同的
        // fail-closed 路径（与 internal-plugin 的 M9 判定可判定性对齐）。
        if (!(res.report.verdict in RANK)) {
          scanFailed = true
          notes.push(`VET ${exec.name}: scan-error (unknown verdict ${res.report.verdict})`)
        } else if (RANK[res.report.verdict] > RANK[worst]) {
          worst = res.report.verdict
          // M5：只对非 clean 结果加前缀——干净执行不污染机器可读输出（JSON 解析/管道消费方）
          if (res.report.verdict !== 'clean') notes.push(`VET ${exec.name}: ${res.report.verdict} (${res.report.staticScore})`)
        }
      } else {
        // round-4 review（M3）：扫描失败在 deny 模式必须 fail-closed——旧实现只记
        // scan-error note、worst 保持 clean → deny 模式下扫描器故障/超时等于守卫洞开
        // （与 internal-plugin 的 M9「deny 扫描失败必须 fail-closed」语义对齐：代码执行
        // 面比装插件更危险，不能静默放行未扫描代码）。
        scanFailed = true
        notes.push(`VET ${exec.name}: scan-error (${res.error ?? 'unknown'})`)
      }
    }

    // deny：verdict 达阈值，或扫描失败（fail-closed，M9 对齐）→ 拦截
    if (config.mode === 'deny' && (scanFailed || RANK[worst] >= DENY_RANK[config.denyOn])) {
      return {
        content: [{ type: 'text', text: `VET BLOCKED: ${notes.join('; ')}` }],
        isError: true,
        error: { message: `vet: ${exec.name} 被拦截（${scanFailed ? '扫描失败' : worst}）` },
      } as ToolExecutionResult
    }

    const result = await next()
    // round-22：宿主契约漂移防护——next() 返回非 ToolExecutionResult 形态（content
    // 缺失/非数组/空）时按原样透传，不在此处二次抛错（下游 handler 的真实异常仍按
    // 原有语义向上传播，不受影响）。此前 result.content 解引用会在宿主异常形态下
    // 把「宿主返回异常」伪装成「vet 守卫抛错」。
    if (result === null || typeof result !== 'object' || !Array.isArray(result.content)) {
      return result as ToolExecutionResult
    }
    const first = result.content[0]
    // P2-5：notes 为空（全部 clean）时原样返回——旧实现即使 notes 为空也会前置 '\n\n'，
    // 与 M5「干净执行不污染机器可读输出」矛盾（JSON 解析/管道消费方看到脏前缀）
    // round-4 review（M4）：notes 非空但 content 首元素非 text（image/空 content）时，
    // 旧实现整个 notes 静默丢弃（扫描失败/非 clean 的提示对用户不可见）——兜底为把
    // notes 作为独立文本 content 前置（不覆盖原内容，仅追加说明）。
    if (notes.length > 0) {
      if (first !== undefined && first.type === 'text') {
        return {
          ...result,
          content: [{ ...first, text: `${notes.join('; ')}\n\n${first.text}` }, ...result.content.slice(1)],
        }
      }
      return {
        ...result,
        content: [{ type: 'text', text: notes.join('; ') }, ...result.content],
      } as ToolExecutionResult
    }
    return result
  })
}