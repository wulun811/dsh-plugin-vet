import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * 审计档案检查（D30 强制层）：agent 按 AUDIT_PROTOCOL 审查后落盘健康档案到
 * ~/.dsh/vet/audits/<plugin-name>-<version>-<ts>.md。vet 用本模块检查某插件
 * 是否已有档案——requireAudit 开启时，无档案的插件在加载时被拦截/报警。
 */

/** 档案目录（可用 DSH_PLUGIN_VET_ARCHIVE_DIR 覆盖，测试友好）。
 * M2：快照 env——vet 是插件 bundle，加载早于第三方插件；vet 模块加载后 env 值固定，
 * 恶意插件无法再通过设 DSH_PLUGIN_VET_ARCHIVE_DIR 重定向门槛（deny 门禁 bypass）。
 * 测试需要改目录时用 setArchiveDirForTest（只在测试路径暴露）。 */
let ARCHIVE_DIR: string = process.env.DSH_PLUGIN_VET_ARCHIVE_DIR ?? join(homedir(), '.dsh', 'vet', 'audits')

export function archiveDir(): string {
  return ARCHIVE_DIR
}

/** 测试专用：覆盖快照目录（生产路径不调用）。 */
export function setArchiveDirForTest(dir: string): void {
  ARCHIVE_DIR = dir
}

/**
 * 某插件是否已有健康档案。匹配规则（D30 修漏 M1）：档案名必须严格是
 * <pluginName>-<version>-<yyyyMMdd-HHmmss>.md——只靠前缀匹配会被伪造：
 * 存在 'lodash-foo-1.0.0-ts.md' 时 'lodash' 也会命中（前缀 'lodash-' 撞上）。
 * 这里要求 pluginName 转义后紧跟 '-(version 段)-<ts>.md' 完整形态。
 */
export function hasAuditRecord(pluginName: string): boolean {
  const dir = archiveDir()
  if (!existsSync(dir)) return false
  const esc = pluginName.replace(/@/g, '').replace(/\//g, '-').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // 完整形态：<esc>-<version>-<8位日期>-<6位时间>.md（version 段宽松匹配）
  const re = new RegExp('^' + esc + '-(\\d[\\w.+-]*)-\\d{8}-\\d{6}\\.md$')
  try {
    return readdirSync(dir).some(name => re.test(name))
  } catch {
    return false
  }
}

/** 提示消息（拦截/报警共用）：引用协议 skill，说明如何完成审查。 */
export function auditRequiredMessage(pluginName: string): string {
  return `vet: 插件 ${pluginName} 尚未完成审计（无健康档案）。` +
    `启用 requireAudit 后，新插件应先按 vet-audit-protocol 审查并落盘档案到 ${archiveDir()}；` +
    `未审计插件加载时触发黄色告警（deny 模式则拦截）。`
}
