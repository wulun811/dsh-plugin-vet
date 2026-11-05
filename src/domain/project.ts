/**
 * 投影器（施工图 §4）：七类对象 → 报警行。
 *
 * 存在的理由：今天「一条报警长什么样」这件事被重复了 37 次——每个采集点各写一遍
 * `{id, severity, source, kind, message, target, pluginHint, mergeKey, at}`，其中
 * severity 的判据、mergeKey 的拼法、谁该有 pluginHint，全靠在 37 个地方保持一致。
 * 收缩不是把 37 处搬进一个文件，而是把那 8 个字段里**能从语义对象推出来的**推出来，
 * 只让采集点回答它真正知道的事：看到了什么（code）、在哪儿（subject）、什么事（message）。
 *
 * 推不出来的两条留在采集点，因为它们是**观测**不是**主体**（见 kinds.ts 的分界线）：
 * - `from-site` 行的严重度；
 * - 合并键里那一段不是主体名的分量（`esm-guard-coverage` 的 `official`、
 *   `m1-contract-violation` 的字段名）。
 *
 * 本文件无 IO、无 Date.now()：时间只从证据上读。这条不是洁癖——等价性测试要求
 * 「同输入同输出」，任何一处偷偷读时钟，重放就不可能逐字段相等。
 */
import type {
  AlarmSeverity,
  AlarmSource,
  Assessment,
  AssessmentSeverity,
  Evidence,
  ProjectionInput,
  SubjectRef,
  TrustOrigin,
  VetAlarm,
} from './types.js'
import { specFor, tierOfSource, type KindSpec, type MergeRule } from './kinds.js'

/**
 * 采集点给出的主体维度与观测分量。
 *
 * `official` 由采集点算（现有实现是 `inCatalog && exempt`，不是名字前缀猜的）——投影器
 * 不看包名，看调用方说了什么。名字前缀判定会随官方目录变化而错，而目录是运行期拉取的。
 */
export interface ProjectionContext {
  readonly official?: boolean
  /** 仅 `from-site` 的行使用；未给时按 `yellow`（不因缺省而升级为红）。 */
  readonly severity?: AlarmSeverity
  /** 合并键的主体段覆盖（历史上 `esm-guard-coverage` 跨包折叠时用 `'official'` 而不是包名）。
   * 0.5.3 起没有生产调用点（那个码已改成覆盖面行）——留着是因为它是模型「这个键不指某个主体」
   * 的表达能力，且 0.4.2 等价性夹具要能逐字复现旧 mergeKey。 */
  readonly mergeSubject?: string
  /** 合并键的第四段（`m1-contract-violation` 用字段名）。 */
  readonly mergeExtra?: string
  /** 目标是否会话日志（归因分层文案用）。 */
  readonly sessionLog?: boolean
}

/** 证据来源 → 报警通道。 `sentinel` 是 T1 子进程，其余非扫描来源目前不存在。 */
export function sourceChannelOf(origin: TrustOrigin): AlarmSource {
  switch (origin) {
    case 'local_scan':
      return 'scan'
    case 'runtime_hook':
      return 't2'
    case 'sentinel':
      return 't1'
    default:
      // external_advisory / plugin_claim / agent_review / human_attestation 今天没有任何调用方。
      // 真出现时该给 AlarmSource 加成员（那是合同变更，要过 §9 那张表），不是在这里悄悄塞进 scan。
      return 'scan'
  }
}

/**
 * 稳定主体标识：`<name>@<version>#<digest 前 12>`；无版本省 `@`，无摘要省 `#`。
 *
 * 摘要缺席是**信息**（thirdPartyBaseline 关 = 没绑过），不是缺省值——所以不补占位串。
 */
export function subjectIdOf(name: string, version?: string, digest?: string): string {
  const atVersion = version !== undefined && version !== '' ? `${name}@${version}` : name
  const digestBit = digest !== undefined && digest !== '' ? `#${digest.slice(0, 12)}` : ''
  return atVersion + digestBit
}

/** 普通 npm 包主体。版本可缺（本地条目、解析失败）。 */
export function npmSubject(name: string, version?: string): SubjectRef {
  const base = { subjectId: subjectIdOf(name, version), kind: 'npm' as const, name }
  return version !== undefined && version !== '' ? { ...base, version } : base
}

/** 本地文件条目（profile 自置 / link 挂载）：`entryName` 是路径，不是包名。 */
export function localSubject(path: string): SubjectRef {
  return { subjectId: subjectIdOf(path), kind: 'local', name: path }
}

/**
 * 是否该给 `pluginHint`。
 *
 * `self` 是 vet 自己、`other` 目前只有宿主进程：两者都不是「某个插件干了这事」，
 * 给了 hint 会让面板把 host 级告警归到某个不存在的包上（错误归因比没有归因更糟）。
 */
function hintOf(subject: SubjectRef): string | undefined {
  if (subject.kind === 'self' || subject.kind === 'other') return undefined
  return subject.name !== '' ? subject.name : undefined
}

/** 合并键。形状与现有四种写法逐字对齐（施工图 R4），不重新发明。 */
export function mergeKeyOf(merge: MergeRule, spec: KindSpec, evidence: Evidence, context: ProjectionContext): string | undefined {
  if (merge === 'none') return undefined
  if (merge === 'id') return evidence.id
  const literalPrefix = 'literal:'
  if (merge.startsWith(literalPrefix)) return merge.slice(literalPrefix.length)
  const tier = spec.tier ?? tierOfSource(evidence.source)
  if (merge === 'code') return `${tier}:${spec.code}`
  const subjectPart = context.mergeSubject ?? evidence.subject.name
  if (merge === 'code:subject') return `${tier}:${spec.code}:${subjectPart}`
  // code:subject:extra
  return `${tier}:${spec.code}:${subjectPart}:${context.mergeExtra ?? ''}`
}

/**
 * 投影一条证据。**永不返回 null**：丢告警是安全上的 fail-open。
 * 注册表里查不到这个 code 时按「不合并、严重度取采集点」处理——一条形状不完整的报警
 * 仍然比一条消失的报警强。
 */
export function projectAlarm(evidence: Evidence, context: ProjectionContext = {}): VetAlarm {
  const spec = specFor(evidence.code, { official: context.official })
  const severity = resolveSeverity(spec?.severity, context.severity)
  const alarm: VetAlarm = {
    id: evidence.id,
    severity,
    source: sourceChannelOf(evidence.source),
    kind: evidence.code,
    message: evidence.message !== undefined && evidence.message !== '' ? evidence.message : evidence.code,
    at: evidence.observedAt,
  }
  if (evidence.target !== undefined && evidence.target !== '') alarm.target = evidence.target
  const hint = hintOf(evidence.subject)
  if (hint !== undefined) alarm.pluginHint = hint
  if (context.sessionLog === true) alarm.sessionLog = true
  const mergeKey = spec === undefined ? undefined : mergeKeyOf(spec.merge, spec, evidence, context)
  if (mergeKey !== undefined) alarm.mergeKey = mergeKey
  return alarm
}

function resolveSeverity(rule: KindSpec['severity'] | undefined, fromSite: AlarmSeverity | undefined): AlarmSeverity {
  if (fromSite !== undefined) return fromSite
  if (rule === undefined || rule === 'from-site') return 'yellow'
  return rule
}

/** 评估严重度 → 报警严重度。`unknown` 返回 undefined：定不了级就不该压过注册表。 */
function alarmSeverityOf(severity: AssessmentSeverity): AlarmSeverity | undefined {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'red'
    case 'medium':
    case 'low':
      return 'yellow'
    case 'info':
      return 'info'
    default:
      return undefined
  }
}

const SEVERITY_RANK: Record<AlarmSeverity, number> = { red: 3, yellow: 2, info: 1 }

function worst(a: AlarmSeverity, b: AlarmSeverity): AlarmSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b
}

/** 证据 id → 引用它的评估。一条证据可能被多条评估引用（不同规则、不同角度）。 */
function indexAssessments(assessments: readonly Assessment[]): Map<string, Assessment[]> {
  const index = new Map<string, Assessment[]>()
  for (const assessment of assessments) {
    for (const id of assessment.evidenceIds) {
      const bucket = index.get(id)
      if (bucket === undefined) index.set(id, [assessment])
      else bucket.push(assessment)
    }
  }
  return index
}

/**
 * 批量投影（施工图 §4 的签名）。
 *
 * 与单条投影的差别只有一处：严重度可以由引用该证据的 `Assessment` 给出——这正是
 * 「判定能力从采集点上移到评估对象」的那一步。评估没给出可用的严重度时回落到注册表。
 */
export function projectAlarms(input: ProjectionInput & { readonly official?: boolean }): VetAlarm[] {
  const index = indexAssessments(input.assessments)
  const out: VetAlarm[] = []
  for (const evidence of input.evidence) {
    let severity: AlarmSeverity | undefined
    for (const assessment of index.get(evidence.id) ?? []) {
      const mapped = alarmSeverityOf(assessment.severity)
      if (mapped === undefined) continue
      severity = severity === undefined ? mapped : worst(severity, mapped)
    }
    out.push(projectAlarm(evidence, { official: input.official, severity }))
  }
  return out
}
