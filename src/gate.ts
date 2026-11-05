/**
 * 市场扫描闸门（P0 特性）：可被 dsh-plugin-hub 等安装流程回调的扫描接口。
 * VET 不自己做市场，但提供可被安装路径回调的扫描位。
 */
import { scan, scanBudget } from './scanner/client.js'
import type { ScanReport } from './scanner/protocol.js'
import { buildRequest } from './tools/scan-plugin.js'
import { recordScanSummary } from './guard/scan-summaries.js'
import { gateDecision } from './gate-decision.js'
import type { Decision } from './domain/types.js'
import type { GateRequest, GateResult } from './gate-types.js'

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }

/**
 * 这个结论是否在三值之内。
 *
 * 0.5.11：`'constructor' in RANK` 为真（原型链）且 `RANK['constructor']` 是个函数——
 * 于是「协议漂移」被当成已知结论，`RANK[verdict] >= denyRank` 又恒为 false，两步都错。
 * `Object.hasOwn` 只认自有键，把「没见过」交回给调用方按 fail-closed 处置。
 */
export function isKnownVerdict(verdict: string): boolean {
  return Object.hasOwn(RANK, verdict)
}

/**
 * 运行扫描闸门。
 * @param request 扫描请求
 * @returns 扫描结果
 */
export async function runGate(request: GateRequest): Promise<GateResult> {
  const { request: scanReq, pluginName, pluginVersion } = buildRequest({
    target: 'package',
    packagePath: request.packagePath,
  })
  
  // OSV 默认关闭（安装流程期望秒级反馈）
  scanReq.osv = request.osvCheck === true
  
  // round-5 review（B-A5）：预算公式收敛到 scanBudget（按文件数放大、60s 封顶）；
  // gate 语义保持「显式 timeout 优先」，无显式时走公式。
  const fileCount = scanReq.files?.length ?? 0
  const timeoutMs = request.timeoutMs ?? scanBudget(fileCount)
  
  const res = await scan(scanReq, { timeoutMs })
  if (!res.ok || res.report === undefined) {
    throw new Error('vet gate: scan failed ' + (res.error ?? 'unknown'))
  }
  
  const { verdict, staticScore, findings } = res.report
  // 一次判定只取一个时刻：摘要里的 `at` 与决策里的 `decidedAt` 必须是同一秒，否则事后
  // 对账时会看到「扫描摘要比决策晚 3ms」，然后开始怀疑是不是同一次运行。
  const decidedAt = Date.now()
  // P2（决策 ④）：gate 扫描同样留档——被门禁拦过的包也要在面板详情/最近插件里有记录。
  noteGateSummary(pluginName, pluginVersion, res.report, decidedAt)
  const { blocked, decision } = judgeGate(request, res.report, pluginName, pluginVersion, decidedAt)

  return {
    verdict,
    staticScore,
    pluginName,
    pluginVersion,
    scannedAt: new Date(decidedAt).toISOString(),
    findings,
    blocked,
    decision,
  }
}

/**
 * 扫描报告 → 判定。
 *
 * `blocked`（真实执行）与 `decision`（并排陈述）在这里同时产出，因为它们读的是同一份
 * `ScanReport`：分成两处各读一遍，迟早会有一处忘了同步新字段。
 */
function judgeGate(
  request: GateRequest,
  report: ScanReport,
  pluginName: string,
  pluginVersion: string | undefined,
  decidedAt: number,
): { readonly blocked: boolean; readonly decision: Decision } {
  const mode = request.mode ?? 'report'
  // round-15 review（A#15 同款 fail-closed 对齐）：扫描器协议漂移出现未知 verdict 时
  // RANK[verdict] 为 undefined——`undefined >= RANK[denyOn]` 恒 false，deny 判定静默
  // 失效（fail-open）且无任何日志。未知 verdict = 扫描结果不可信 → deny 模式按拦截处理
  // （与 tool-execute/internal-plugin 的 M9 可判定性纪律一致），report 模式保持原样返回。
  // 0.5.11：`in` 会走原型链（`'constructor' in RANK` 为真且 `RANK['constructor']` 是个函数），
  // 协议漂移成这种名字时旧写法既「已知」又不拦——两步都错。改 `Object.hasOwn` 只认自有键。
  const blocked = decideDenyBlock(mode, request.denyOn, report.verdict, isKnownVerdict(report.verdict))
  // 0.5.11（施工图 S2-03）：决策对象并排挂上，`blocked` 仍由上面那个旧函数给出。
  // 两者的等价性由 `test/gate-decision.test.ts` 在 mode×denyOn×verdict 全组合上钉死。
  const decision = gateDecision({
    mode,
    ...(request.denyOn !== undefined ? { denyOn: request.denyOn } : {}),
    report,
    packagePath: request.packagePath,
    ...(pluginName !== '' ? { pluginName } : {}),
    ...(pluginVersion !== undefined ? { pluginVersion } : {}),
    osvRequested: request.osvCheck === true,
    decidedAt,
  })
  return { blocked, decision }
}

/**
 * 落一条「最近扫描」摘要（P2 决策 ④）。
 *
 * 变化才落盘的纪律与自动扫描路径一致（`recordScanSummary` 内部判定）；无名字不记录——
 * 一个没有名字的条目在面板里只能显示成路径，那不是「最近插件」。
 */
function noteGateSummary(
  pluginName: string,
  pluginVersion: string | undefined,
  report: ScanReport,
  at: number,
): void {
  if (pluginName === '') return
  const findings = report.findings ?? []
  const osv = findings.find((f) => f.rule === 'OSV')
  recordScanSummary({
    name: pluginName,
    ...(pluginVersion !== undefined ? { version: pluginVersion } : {}),
    at,
    verdict: report.verdict,
    staticScore: report.staticScore,
    sourceCount: report.sourceCount,
    engine: report.engine,
    ruleCodes: [...new Set(findings.map((f) => f.rule))],
    ...(osv !== undefined && osv.message !== undefined ? { osv: osv.message } : {}),
  })
}

/**
 * deny 门禁判定（round-22 拆出为可测纯函数）。
 * fail-closed 两点：未知 verdict（扫描结果不可信 → deny 必拦）；非法 denyOn（未类型化
 * 调用方传入时 RANK[denyOn] 为 undefined——`x >= undefined` 恒 false 会让 deny 对任何
 * 判定都静默失效）→ 归位最严档位 critical（至少按默认策略拦，绝不比默认更松）。
 */
export function decideDenyBlock(mode: string | undefined, denyOn: string | undefined, verdict: string, verdictKnown: boolean): boolean {
  const denyRank = RANK[denyOn ?? 'critical'] ?? RANK.critical
  return (mode ?? 'report') === 'deny' && (verdictKnown ? RANK[verdict] >= denyRank : true)
}
