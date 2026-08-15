import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * 审计档案检查（D30 强制层）：agent 按 AUDIT_PROTOCOL 审查后落盘健康档案到
 * ~/.dsh/vet/audits/<plugin-name>-<version>-<ts>.md。vet 用本模块检查某插件
 * 是否已有档案——requireAudit 开启时，无档案的插件在加载时被拦截/报警。
 */

/** 档案目录（可用 DSH_PLUGIN_VET_ARCHIVE_DIR 覆盖，测试友好）。 */
export function archiveDir(): string {
  return process.env.DSH_PLUGIN_VET_ARCHIVE_DIR ?? join(homedir(), '.dsh', 'vet', 'audits')
}

/**
 * 某插件是否已有健康档案。匹配规则：档案文件名以 <pluginName>- 开头（含 scoped 名，@scope/name → @scope-name）。
 */
export function hasAuditRecord(pluginName: string): boolean {
  const dir = archiveDir()
  if (!existsSync(dir)) return false
  const prefix = pluginName.replace(/@/g, '').replace(/\//g, '-') + '-'
  try {
    return readdirSync(dir).some(name => name.startsWith(prefix) && name.endsWith('.md'))
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