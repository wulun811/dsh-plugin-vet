/**
 * 市场扫描闸门（P0 特性）：可被 dsh-plugin-hub 等安装流程回调的扫描接口。
 * VET 不自己做市场，但提供可被安装路径回调的扫描位。
 */
import { scan, scanBudget } from './scanner/client.js'
import { buildRequest } from './tools/scan-plugin.js'
import { recordScanSummary } from './guard/scan-summaries.js'
import type { GateRequest, GateResult } from './gate-types.js'

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }

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
  // P2（决策 ④）：gate 扫描同样留档——被门禁拦过的包也要在面板详情/最近插件里有记录。
  // 变化才落盘的纪律与自动扫描路径一致（recordScanSummary 内部判定）；无名字不记录。
  if (pluginName !== undefined && pluginName !== '') {
    recordScanSummary({
      name: pluginName,
      ...(pluginVersion !== undefined ? { version: pluginVersion } : {}),
      at: Date.now(),
      verdict,
      staticScore,
      sourceCount: res.report.sourceCount,
      ruleCodes: [...new Set((findings ?? []).map(f => f.rule))],
      ...(findings ?? []).some(f => f.rule === 'OSV') ? { osv: (findings ?? []).find(f => f.rule === 'OSV')?.message } : {},
    })
  }
  const mode = request.mode ?? 'report'
  // round-15 review（A#15 同款 fail-closed 对齐）：扫描器协议漂移出现未知 verdict 时
  // RANK[verdict] 为 undefined——`undefined >= RANK[denyOn]` 恒 false，deny 判定静默
  // 失效（fail-open）且无任何日志。未知 verdict = 扫描结果不可信 → deny 模式按拦截处理
  // （与 tool-execute/internal-plugin 的 M9 可判定性纪律一致），report 模式保持原样返回。
  const verdictKnown = verdict in RANK
  const blocked = decideDenyBlock(mode, request.denyOn, verdict, verdictKnown)

  return {
    verdict,
    staticScore,
    pluginName,
    pluginVersion,
    scannedAt: new Date().toISOString(),
    findings,
    blocked,
  }
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
