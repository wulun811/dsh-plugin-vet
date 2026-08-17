import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { withVetSelfIo } from '../guard/runtime-hooks.js'

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
 * 某插件是否已有健康档案。匹配规则（D30 修漏 M1 + P-1 版本精确绑定）：
 * 档案名必须严格是 <pluginName>-<version>-<yyyyMMdd-HHmmss>.md——只靠前缀匹配会被伪造
 * （存在 'lodash-foo-…' 时 'lodash' 也会命中）。P-1：传入装机版本时要求版本段 == 装机
 * 版本——插件升级（1.0.0→1.2.0）后旧档案不再放行，新版本必须重新审计；不传 version
 * （兼容旧调用/无法解析版本）时沿用宽松版本段。
 * P2-2：目录在 ~/.dsh 下，readdir 属 vet 自查 IO——withVetSelfIo 直通，避免 .dsh 敏感段
 * 下每次装插件都产生一条无主 fs-probe 自报警。
 */
export function hasAuditRecord(pluginName: string, version?: string): boolean {
  const esc = escapeName(pluginName)
  return withVetSelfIo(() => {
    const dir = archiveDir()
    if (!existsSync(dir)) return false
    // 时间戳尾：-8位日期-6位时刻.md（字符类写法，避免反斜杠）
    const tsRe = /-[0-9]{8}-[0-9]{6}[.]md$/
    try {
      return readdirSync(dir).some(name => {
        if (!tsRe.test(name)) return false
        const prefix = name.slice(0, name.length - 19) // 去掉 -yyyyMMdd-HHmmss.md
        if (version !== undefined) return prefix === esc + '-' + version
        // 宽松：版本段必须以数字开头（保持 M1 反前缀伪造——lodash-foo-… 不命中 lodash）
        if (!prefix.startsWith(esc + '-')) return false
        const rest = prefix.slice(esc.length + 1)
        return rest.length > 0 && rest[0] >= '0' && rest[0] <= '9'
      })
    } catch {
      return false
    }
  })
}

/** 包名/版本归一化：@ 剥掉、/ 转 -（其余原样，不引入正则元字符）。 */
function escapeName(name: string): string {
  let out = ''
  for (let i = 0; i < name.length; i++) {
    const c = name[i]
    if (c === '@') continue
    if (c === '/') out += '-'
    else out += c
  }
  return out
}

/** 提示消息（拦截/报警共用）：引用协议 skill，说明如何完成审查。 */
export function auditRequiredMessage(pluginName: string): string {
  return 'vet: 插件 ' + pluginName + ' 尚未完成审计（无健康档案）。' +
    '请让 agent 执行 vet-audit-protocol skill 完成审查并落盘档案到 ' + archiveDir() + '。'
}