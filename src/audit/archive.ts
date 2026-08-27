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

/** round-16 review（S9）：档案目录不可读告警钩子（installInternalPluginGuard 注入，默认空）。
 * readdir 失败此前完全静默——requireAudit 判定按「无档案」处理，deny 模式会以假阴性理由
 * 拦截合法插件，用户却不知道是目录权限问题。一次性告警（进程内只提醒一次，避免每个插件
 * 加载都刷一条）。 */
let archiveIoWarn: ((msg: string) => void) | undefined
export function setArchiveIoWarn(fn: ((msg: string) => void) | undefined): void {
  archiveIoWarn = fn
}
let readDirWarned = false
function warnUnreadable(dir: string): void {
  if (readDirWarned) return
  readDirWarned = true
  try {
    archiveIoWarn?.(`vet: 审计档案目录不可读：${dir}——requireAudit 将按无档案判定（deny 会拦截第三方插件），请检查目录权限`)
  } catch {
    // 告警自身失败不影响主流程
  }
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
    try {
      return readdirSync(dir).some(name => matchesArchiveFile(name, esc, version))
    } catch {
      // S9：目录存在但不可读（权限/损坏）——不再是静默 false，告警一次
      warnUnreadable(dir)
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

/** 档案文件名匹配（单条与批量共用）：时间戳尾解析 + 前缀/版本段校验（语义同 hasAuditRecord 注释）。 */
function matchesArchiveFile(fileName: string, escName: string, version?: string): boolean {
  let tsLen = 0
  //   v0.2.1 规范：-yyyyMMdd-HHmmss.md（19 字符，中间有 -）
  //   旧格式兼容：-yyyyMMddHHmmss.md（18 字符，无中间 -）——升级后不误报 audit-required
  if (/-[0-9]{8}-[0-9]{6}[.]md$/.test(fileName)) tsLen = 19
  else if (/-[0-9]{14}[.]md$/.test(fileName)) tsLen = 18
  if (tsLen === 0) return false
  const prefix = fileName.slice(0, fileName.length - tsLen)
  if (version !== undefined) return prefix === escName + '-' + version
  // 宽松：版本段必须以数字开头（保持 M1 反前缀伪造——lodash-foo-… 不命中 lodash）。
  // round-22：纯「数字开头」不够——包名以「-<数字>」结尾的其它包（aws-sdk-2 的档案
  // aws-sdk-2-3.1.0-…）会把「2-3.1.0」当作 aws-sdk 的版本段命中，伪审计通过（deny
  // fail-closed 分支恰好以无版本路径探测「疑似冒名」包）。数字版本段后紧跟 '-' 即
  // 判为其它包名；预发布版本（1.0.0-beta.1）不受影响（段后是 '.'）。
  if (!prefix.startsWith(escName + '-')) return false
  const rest = prefix.slice(escName.length + 1)
  const m = /^(\d+)(.*)$/.exec(rest)
  if (m === null) return false
  return !m[2].startsWith('-')
}

export interface AuditRecordProbe {
  name: string
  version?: string
}

/**
 * 批量审计档案探测（P2 审计中心/插件索引用）：一次 readdir 判多个包。
 * 面板 5s 轮询 × N 包场景下，逐包调 hasAuditRecord 会放大为 N 次目录扫描——本函数一次读完共享。
 * 匹配语义与 hasAuditRecord 完全一致（传版本要求精确；不传走宽松数字开头规则）。
 */
export function hasAuditRecordBatch(entries: AuditRecordProbe[]): Record<string, boolean> {
  return withVetSelfIo(() => {
    const result: Record<string, boolean> = {}
    for (const e of entries) result[e.name] = false
    const dir = archiveDir()
    if (!existsSync(dir) || entries.length === 0) return result
    let files: string[] = []
    try {
      files = readdirSync(dir)
    } catch {
      // S9：目录存在但不可读（权限/损坏）——告警一次
      warnUnreadable(dir)
      return result
    }
    for (const e of entries) {
      const esc = escapeName(e.name)
      result[e.name] = files.some(f => matchesArchiveFile(f, esc, e.version))
    }
    return result
  })
}

/** 提示消息（拦截/报警共用）：引用协议 skill，说明如何完成审查。 */
export function auditRequiredMessage(pluginName: string): string {
  return 'vet: 插件 ' + pluginName + ' 尚未完成审计（无健康档案）。' +
    '请让 agent 执行 vet-audit-protocol skill 完成审查并落盘档案到 ' + archiveDir() + '。'
}