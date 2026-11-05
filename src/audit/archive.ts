import { closeSync, existsSync, openSync, readdirSync, readSync } from 'node:fs'
import { join } from 'node:path'
import { withVetSelfIo } from '../guard/runtime-hooks.js'
import { vetStoreRoot } from '../guard/store-root.js'
import { getScanSummary, type ScanSummary } from '../guard/scan-summaries.js'
import { CURRENT_ENGINE } from '../scanner/protocol.js'
import { INITIAL_QUALIFICATION, transition, type QualificationState } from '../domain/qualify.js'

/**
 * 审计档案检查（D30 强制层）：agent 按 AUDIT_PROTOCOL 审查后落盘健康档案到
 * ~/.dsh/vet/audits/<plugin-name>-<version>-<ts>.md。vet 用本模块检查某插件
 * 是否已有档案——requireAudit 开启时，无档案的插件在加载时被拦截/报警。
 */

/** 档案目录（可用 DSH_PLUGIN_VET_ARCHIVE_DIR 覆盖，测试友好）。
 * M2：快照 env——vet 是插件 bundle，加载早于第三方插件；vet 模块加载后 env 值固定，
 * 恶意插件无法再通过设 DSH_PLUGIN_VET_ARCHIVE_DIR 重定向门槛（deny 门禁 bypass）。
 * 测试需要改目录时用 setArchiveDirForTest（只在测试路径暴露）。
 * 0.3.15：默认目录由 store-root 解析（测试运行时默认落进程私有临时目录，不写用户真实档案）。 */
let ARCHIVE_DIR: string = process.env.DSH_PLUGIN_VET_ARCHIVE_DIR ?? join(vetStoreRoot(), 'audits')

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

/**
 * 档案里声明的被审内容摘要（0.5.1 起的新约定）。档案正文里一行
 * `subject_sha256: <64 位十六进制>` 即声明「这条结论是对着这份字节得出的」。
 *
 * 没有这一行的老档案一律按 `legacy` 处理——**不是**判它无效。0.4.x 从来没有要求过这一行，
 * 拿一条今天才立的规矩去追溯昨天的档案，结果就是升级当天全体拒载。
 */
const SUBJECT_DIGEST_RE = /^subject_sha256:\s*([0-9a-f]{64})\s*$/im

/**
 * 规则集版本（0.5.20）：档案里一行 `rule_set_version: static-v27`，说明这份判读是哪套规则
 * 产出的。缺这一行的档案（0.5.20 之前写的全部档案）按「标准未知」处理——不是判它无效，
 * 和 `subject_sha256` 一样：拿今天才立的规矩追溯昨天的档案，结果是升级当天全体拒载。
 */
const RULE_SET_RE = /^rule_set_version:\s*([A-Za-z0-9._-]{1,64})\s*$/im

/**
 * 审计当时那条扫描结论（0.5.20）：`scan_verdict: clean|suspicious|critical`。
 * 与 `rule_set_version` 成对使用——只有知道「旧规则集当时怎么说」，下一句
 * 「新规则集会不会改判」才有得比。
 */
const SCAN_VERDICT_RE = /^scan_verdict:\s*(clean|suspicious|critical)\s*$/im

/** 结论强度序（只用于比较，不参与判定本身）。表外的值一律视为不可比。 */
const VERDICT_RANK: Readonly<Record<string, number>> = { clean: 0, suspicious: 1, critical: 2 }

/** 只读档案头部：摘要行按协议就写在开头，读全文既慢又把无关内容带进内存。 */
const ARCHIVE_HEAD_BYTES = 16 * 1024

/** 只读文件头 N 字节。整份 readFileSync 再 slice 会把一个几十 MB 的档案先读进内存。 */
function readHead(path: string, bytes: number): string {
  const fd = openSync(path, 'r')
  try {
    const buf = Buffer.alloc(bytes)
    const read = readSync(fd, buf, 0, bytes, 0)
    return buf.subarray(0, read).toString('utf8')
  } finally {
    closeSync(fd)
  }
}

export interface QualificationProbe {
  readonly name: string
  readonly version?: string
  /**
   * 惰性内容摘要。**只有档案里真的写了 subject_sha256 才会被调用**——
   * 否则给每个 requireAudit 的包都多算一次全量哈希，为一条还没人用的约定付钱。
   */
  readonly contentDigest?: () => string | undefined
}

export interface QualificationProbeResult {
  readonly state: QualificationState
  /** 命中的档案绝对路径（迁移/排障时要说清「凭哪份档案放行」）。 */
  readonly recordPath?: string
}

/** 档案名里的时间戳 → 可排序键（兼容 18/19 两种历史格式）。 */
function timestampKey(fileName: string): string {
  const m = /-(\d{8})-?(\d{6})[.]md$/.exec(fileName)
  return m === null ? '' : m[1] + m[2]
}

/**
 * 计算某插件当前的资格状态（施工图步骤 6）。
 *
 * 与 `hasAuditRecord` 的分工：
 * - `hasAuditRecord` 回答「历史上有没有审过」——升级差分抑制、审计中心列表都用它，语义不变；
 * - `probeQualification` 回答「现在能不能加载」——requireAudit 只认它。
 *
 * 两者在今天的结果几乎一样（有档案 = 合格），差别在档案带摘要时：摘要对不上就落
 * RECHECK_REQUIRED，而不再是「有文件就放行」。
 */
export function probeQualification(probe: QualificationProbe): QualificationProbeResult {
  const esc = escapeName(probe.name)
  return withVetSelfIo((): QualificationProbeResult => {
    const dir = archiveDir()
    if (!existsSync(dir)) return { state: INITIAL_QUALIFICATION }
    let files: string[]
    try {
      files = readdirSync(dir)
    } catch {
      // 目录不可读：按未评估处理（与 hasAuditRecord 的 fail-closed 一致——deny 会拦）
      warnUnreadable(dir)
      return { state: INITIAL_QUALIFICATION }
    }
    const matched = files.filter(f => matchesArchiveFile(f, esc, probe.version))
    if (matched.length === 0) return { state: INITIAL_QUALIFICATION }
    const newest = matched.slice().sort((a, b) => (timestampKey(a) < timestampKey(b) ? 1 : timestampKey(a) > timestampKey(b) ? -1 : 0))[0]
    const recordPath = join(dir, newest)

    let head = ''
    try {
      head = readHead(recordPath, ARCHIVE_HEAD_BYTES)
    } catch {
      // 档案存在但读不出：按无摘要的老档案处理（fail-open 到 0.4.x 行为，不因权限问题拒载）
      return { state: transition(INITIAL_QUALIFICATION, { type: 'legacy_record_found' }), recordPath }
    }

    const declared = SUBJECT_DIGEST_RE.exec(head)?.[1].toLowerCase()
    const legacyState = (): QualificationState => transition(INITIAL_QUALIFICATION, { type: 'legacy_record_found' })
    if (declared === undefined) {
      return { state: withStandardChange(legacyState(), head, probe), recordPath }
    }
    const actual = probe.contentDigest?.()
    if (actual === undefined) {
      // 档案声明了摘要，但我们算不出来（目录解析失败/超预算）：这是「验证不了」，
      // 不是「对不上」。按老档案放行并留理由，避免把一次 IO 失败变成拒载。
      const legacy = legacyState()
      const state: QualificationState = { ...legacy, reasons: [...legacy.reasons, 'digest-unverifiable'] }
      return { state: withStandardChange(state, head, probe), recordPath }
    }
    const verified: QualificationState = { status: 'qualified', basis: 'digest', reasons: ['audit-passed'] }
    if (actual.toLowerCase() !== declared) {
      // 摘要对不上 = 内容变了 → 走状态机的 content_changed，而不是在这里特判一个状态
      return { state: transition(verified, { type: 'content_changed' }), recordPath }
    }
    return { state: withStandardChange(verified, head, probe), recordPath }
  })
}

/**
 * 影响函数（0.5.20）：档案写下的规则集版本与当前构建不同时，**只在「新规则集确实会改判」
 * 的前提下**把状态推成 `recheck_required`。
 *
 * 为什么必须带影响函数：不带它的版本是「规则集一变，全体重审」——那是一次大规模拒载，
 * 而不是严谨。判据只能是这个主体上的具体结论：旧规则集当时说 `scan_verdict`，当前规则集
 * 对这个包最近一次说的是什么（`scan-summaries` 里那条同版本、当前引擎的记录）。新的更差
 * 才算改判；相同或更松都不值得让用户重审一遍。
 *
 * **一次加载的窗口，写在明处**：门槛跑在扫描之前（拦截必须在挂载之前发生），所以它能用的
 * 只有**已经记下来**的结论。升级引擎后的第一次加载，摘要还是旧引擎写的 → 判不了 → 放行；
 * 那次加载的扫描会把摘要刷成新引擎的结论，第二次加载才据此要求重审。这个窗口不是漏洞：
 * 第一次加载本来就会被静态扫描（`autoScan` 默认开）覆盖，新规则集若真看到什么，
 * 走的是既有的 `scan-verdict` 告警，不依赖审计门槛。`autoScan: false` 的用户没有这条兜底，
 * 也就永远等不到重审——这是知情选择，不是静默：这里给出的 reason 会说明「未评估」。
 *
 * 三处「说不出话」都落成 `standard-unevaluated`，绝不升级成重审：档案没写判读、摘要不是
 * 当前引擎产的、版本对不上。判不了就说判不了。
 */
function withStandardChange(state: QualificationState, head: string, probe: QualificationProbe): QualificationState {
  if (state.status !== 'qualified') return state
  const recordEngine = RULE_SET_RE.exec(head)?.[1]
  // 档案没写规则集版本 = 0.5.20 之前的档案：不知道，就不判。与引擎相同则是明摆着的「没变」。
  if (recordEngine === undefined || recordEngine === CURRENT_ENGINE) return state

  const recordVerdict = SCAN_VERDICT_RE.exec(head)?.[1]?.toLowerCase()
  const recordRank = recordVerdict === undefined ? undefined : VERDICT_RANK[recordVerdict]
  const summary = recordRank === undefined ? undefined : usableSummary(probe)
  const nowRank = summary === undefined ? undefined : VERDICT_RANK[summary.verdict]

  // 判不了就**不进状态机**：`standard_changed{impacts:false}` 会留下 `standard-irrelevant`
  // （「这次标准变化与本包无关」），而我们此刻并没有资格这么断言。只加一条「未评估」。
  if (recordRank === undefined || nowRank === undefined) {
    const reason = 'standard-unevaluated'
    return state.reasons.includes(reason) ? state : { ...state, reasons: [...state.reasons, reason] }
  }
  return transition(state, { type: 'standard_changed', impacts: nowRank > recordRank })
}

/** 只有「同一版本、由当前引擎产出」的摘要才配当对照物；其余不可比，宁可不说。 */
function usableSummary(probe: QualificationProbe): ScanSummary | undefined {
  const summary = getScanSummary(probe.name)
  if (summary === undefined) return undefined
  if (summary.engine !== CURRENT_ENGINE) return undefined
  if (probe.version !== undefined && summary.version !== probe.version) return undefined
  return summary
}

/**
 * 提示消息（拦截/报警共用）：引用协议 skill，说明如何完成审查。
 *
 * `hint` 只在「有档案但不能用」时出现——那正是一条只写「尚未完成审计」的消息最容易骗人的地方：
 * 用户明明审过，面板却说他没审。
 */
export function auditRequiredMessage(pluginName: string, hint?: string): string {
  const head = hint === undefined
    ? 'vet: 插件 ' + pluginName + ' 尚未完成审计（无健康档案）。'
    : 'vet: 插件 ' + pluginName + ' 的审计档案不能作为当前放行依据——' + hint + '。'
  return head + '请让 agent 执行 vet-audit-protocol skill 完成审查并落盘档案到 ' + archiveDir() + '。'
}