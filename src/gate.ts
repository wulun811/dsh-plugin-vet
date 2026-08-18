/**
 * 市场扫描闸门（P0 特性）：可被 dsh-plugin-hub 等安装流程回调的扫描接口。
 * VET 不自己做市场，但提供可被安装路径回调的扫描位。
 */
import { scan } from './scanner/client.js'
import { buildRequest } from './tools/scan-plugin.js'
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
  
  // 超时按文件数动态计算（与 scan_plugin 工具一致的预算对齐逻辑）
  const fileCount = scanReq.files?.length ?? 0
  const timeoutMs = request.timeoutMs ?? Math.min(Math.max(15_000, fileCount * 2000), 60_000)
  
  const res = await scan(scanReq, { timeoutMs })
  if (!res.ok || res.report === undefined) {
    throw new Error('vet gate: scan failed ' + (res.error ?? 'unknown'))
  }
  
  const { verdict, staticScore, findings } = res.report
  const mode = request.mode ?? 'report'
  const denyOn = request.denyOn ?? 'critical'
  const blocked = mode === 'deny' && RANK[verdict] >= RANK[denyOn]
  
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
