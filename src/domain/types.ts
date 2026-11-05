/**
 * 0.5.x 语义归宗：七个对象的形状（方案见 docs/local/0.5.x，施工图 §1）。
 *
 * 本文件是**纯数据定义**：没有 IO、没有 Date.now()、没有 process.env，也不 import 任何
 * src/ 下的其它模块。理由不是洁癖——七类对象要能被投影器、状态机、面板三处同时消费，
 * 任何一处能偷偷读环境，等价性测试就不再是「同输入同输出」。
 *
 * 与施工图 §1 草案的三处偏离，均已在 02-实施细则 记明：
 * 1. `Qualification` 用 5 态 + `basis`，草案里的 `legacy_record_only` 不是状态（§5.1）；
 *    `revoked` 也不是状态——撤销是事件，落到 unassessed，痕迹留在事件日志。
 * 2. `Evidence.message` 存在。文案由采集点按事实拼装（包名@版本、hash 前 12 位），
 *    无法由 `code` 推导；`suggest.<code>` 仍是面板侧的「建议」行，两者不是一回事。
 *    消息是呈现，不是原始载荷——不存文件内容的那条约束由 `payloadDigest` 承担。
 * 3. 严重度合并进 `AlarmSeverity` 一处定义（原先在 guard/status.ts），避免两个同形联合漂移。
 */

/** 报警严重度（原 guard/status.ts 定义，0.5.0 起以本文件为唯一来源）。 */
export type AlarmSeverity = 'yellow' | 'red' | 'info'

/**
 * 证据的可信来源。**不含 `'self'`**——「这条证据说的是 vet 自己坏了」由 `Subject.kind` 表达，
 * 不由 source 表达：一个来源为 local_scan 的证据同样可以以 vet 自己为主体（自查扫描），
 * 两个维度混成一个会让投影器写出特例（施工图 R3）。
 */
export type TrustOrigin =
  | 'local_scan'
  | 'runtime_hook'
  | 'sentinel'
  | 'external_advisory'
  | 'plugin_claim'
  | 'agent_review'
  | 'human_attestation'

/** 主体种类。`'self'` 是本进程（vet 自身）——`vet-store-tamper` 一类告警的真实主语。 */
export type SubjectKind = 'npm' | 'local' | 'skill' | 'remote_mcp' | 'native' | 'other' | 'self'

/** 观测面（九格，词表固定；采集点不标 → 记 `unknown`，不许默认 covered）。 */
export type Surface =
  | 'file_tree'
  | 'deps_direct'
  | 'deps_transitive'
  | 'runtime_fs'
  | 'runtime_net'
  | 'runtime_spawn'
  | 'runtime_hook_health'
  | 'intel_osv'
  | 'intel_registry'

/** 覆盖面结论。`unknown` 与 `covered` 的区分是 fail-closed 语义的核心。 */
export type CoverageResult = 'covered' | 'partial' | 'excluded' | 'unsupported' | 'failed' | 'unknown'

/** 证据观察到的结果。注意 `blocked` 是**观测**，不是「我们阻止了」——后者要回执。 */
export type EvidenceOutcome = 'observed' | 'attempted' | 'completed' | 'failed' | 'blocked' | 'unknown'

/** 归因强度：exact 能指到具体调用点，correlated 靠时序，host_only 只能指到宿主，unattributed 无主。 */
export type Attribution = 'exact' | 'correlated' | 'host_only' | 'unattributed'

/** 评估状态。`not_observed` 与 `insufficient_evidence` 不同：前者是查了没看到，后者是没查成。 */
export type AssessmentState =
  | 'finding'
  | 'corroborated'
  | 'disputed'
  | 'insufficient_evidence'
  | 'not_observed'

/** 决策边界。`none` 表示这条决策不针对任何真实边界（纯记录），其回执只可能是 not_covered。 */
export type Boundary = 'pre_load' | 'tool_call' | 'fs_write' | 'net' | 'none'

/** 策略动作。`deny` 是可施加动作的下限；`allow`/`report` 没有「施加」可言。 */
export type PolicyAction = 'allow' | 'report' | 'require_review' | 'deny' | 'unknown'

/** 回执结果。`applied` 的判据见施工图 §5.2 三条守卫。 */
export type ReceiptResult = 'applied' | 'failed' | 'not_requested' | 'not_covered' | 'unknown'

/** 资格状态（5 态）。 */
export type QualificationStatus =
  | 'unassessed'
  | 'qualified'
  | 'recheck_required'
  | 'insufficient_evidence'
  | 'rejected'

/** 资格的凭据来源：digest=绑内容摘要（0.4.3 起），legacy=旧档案仅按名字匹配（兼容期）。 */
export type QualificationBasis = 'digest' | 'legacy'

/**
 * 主体引用。
 *
 * `snapshotId` 缺席**本身是信息**：`thirdPartyBaseline` 关闭时我们没有基线与摘要可比，
 * 此时不许填一个假 id 装作绑过——覆盖面记 `unknown`，面板照实显示。
 */
export interface SubjectRef {
  /** 稳定标识：`<name>@<version>#<digest 前 12>`；无摘要时省去 `#…`；self 固定 `'vet-self'`。 */
  readonly subjectId: string
  readonly kind: SubjectKind
  readonly name: string
  readonly version?: string
  readonly snapshotId?: string
  /** 同一次装载的运行期实例标识（opt-in，用于把观测归到具体装载）。 */
  readonly instanceId?: string
}

/**
 * 有范围的快照承诺。
 *
 * `excluded` 与 `complete` 一起构成「我们看过什么」的完整回答：`complete: true` 只对
 * `includePolicyId` 声明的范围成立，不代表整个包都看过。把这两者合成一个布尔，
 * 面板就再也无法区分「全都看了」与「该看的都看了（没该看的）」。
 */
export interface ScopedSnapshot {
  readonly id: string
  /** 排序承诺后的内容摘要（路径+类型+长度+内容，按路径排序；见施工图步骤 4）。 */
  readonly digest: string
  readonly algorithm: 'sha256'
  /** 纳入/排除策略的版本号。策略一变，旧快照不再可比。 */
  readonly includePolicyId: string
  readonly excluded: ReadonlyArray<{ readonly path: string; readonly reason: string }>
  readonly complete: boolean
}

/** 一条覆盖面声明：某个观测面在本次判定里被覆盖到了什么程度。 */
export interface CoverageEntry {
  readonly surface: Surface
  readonly result: CoverageResult
  readonly reasons: readonly string[]
  readonly observedAt: number
  readonly observerVersion?: string
  /** 原 `known-boundaries` 的归宿：已声明为边界的排除项。仍记为 excluded/partial，不升格为 covered。 */
  readonly acknowledged?: boolean
}

/**
 * 聚合后的一行：某面的结论 + **它来自哪个主体**。
 *
 * 单主体时 `subject` 是冗余的（外壳已经写了是谁）；多主体时它是这行唯一的出处——
 * 「九个面里有一个 partial」如果不说是哪个包，读者只能自己猜，而猜的内容通常是
 * 「大概是那个我最近装的东西」，这正是这张表要消灭的含糊。
 */
export interface CoverageRow extends CoverageEntry {
  readonly subject?: string
}

/**
 * 一条证据 = 一次观测事实。
 *
 * `code` 沿用旧 `kind` 的字面量（`n3-exfil`、`baseline-mismatch`…）——这是兼容缝：
 * mergeKey、忽略记录、i18n 建议行全部以它为准，改名等于让所有用户的历史忽略失效。
 */
export interface Evidence {
  readonly id: string
  readonly subject: SubjectRef
  readonly source: TrustOrigin
  /** 采集者标识，如 `runtime-hooks/2.1`、`scanner/0.5.0`。用于事后归责与版本比对。 */
  readonly producer: string
  /** 旧 kind 原样放这里。必须命中 `kinds.ts` 注册表。 */
  readonly code: string
  readonly observedAt: number
  readonly occurredAt?: number
  readonly surface?: Surface
  readonly outcome: EvidenceOutcome
  readonly attribution: Attribution
  /** 原始载荷（文件内容等）不进账本，只存摘要。 */
  readonly payloadDigest?: string
  /** 被触碰的对象：敏感路径、命令行、主机:端口。它就是观测内容本身，不是展示细节。 */
  readonly target?: string
  /** 呈现文案，由采集点按事实拼装；空则判为无效证据（面板上一条无字报警没有意义）。 */
  readonly message?: string
}

/** 一条评估 = 对证据的判读。severity 在这里，不在 code 上（R2）。 */
export interface Assessment {
  readonly id: string
  readonly subject: SubjectRef
  readonly claim: string
  readonly state: AssessmentState
  readonly severity: AssessmentSeverity
  readonly evidenceIds: readonly string[]
  /** 产出这条判读的规则集版本。资格的影响函数要拿它做比较（§5.1）。 */
  readonly ruleSetVersion: string
  readonly evaluatedAt: number
  readonly limitations: readonly string[]
}

/**
 * 评估严重度：比报警严重度多两档「轻」（medium/low）与一档「定不了」（unknown），
 * 且不直接用 yellow/red —— 评估是判读，报警是呈现，两者的档位不该同名（同名就会有人
 * 直接把 critical 塞进 VetAlarm.severity 而不经过映射）。
 */
export type AssessmentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

/** 一条决策 = 按策略算出的动作。它是**意图**，不是结果。 */
export interface Decision {
  readonly id: string
  readonly subject: SubjectRef
  readonly action: PolicyAction
  readonly boundary: Boundary
  /** 生效配置的快照 id。配置一变，这条决策就不再代表当前策略。 */
  readonly policyId: string
  readonly assessmentIds: readonly string[]
  readonly reasonCodes: readonly string[]
  /**
   * 做这个决定时**已知不知道**的输入（对照清单 B-9），形状 `<class>:<detail>`。
   *
   * 为什么它必须在对象里、而不是在注释和实现者的记忆里：一条 `report` 与一条 `allow`
   * 在面板上长得几乎一样，差别全在「我当时不知道什么」。写成隐性知识，事后只能靠猜——
   * 而猜出来的通常是「大概没问题吧」。空数组是**声明**（我什么都没缺），缺席不是。
   *
   * 两条由校验器强制的契约：
   * - `allow` 不许带未知输入（不知道就不能说可以）；
   * - `unknown` 必须带（否则它和「懒得判」没有区别）。
   *
   * 注意它**不包含** `excluded`/`unsupported` 这类「明确不看」的面——那些是已知边界，
   * 记在覆盖面里。它们拦 `allow` 用的是 `scope-not-fully-covered`，不是这个字段。
   */
  readonly unknownInputs: readonly string[]
  readonly decidedAt: number
}

/**
 * 一条回执 = 边界上实际发生了什么。
 *
 * `decisionId` 可空：`not_covered` 先于决策存在——N7 某些路径在产生决策对象之前就抛了，
 * 硬要求 decisionId 会逼着实现者伪造一条决策（T4 的直接后果）。
 * `operationId` 是「原调用未进入」的 oracle：包装器递增的调用序号（§5.2 第三条守卫）。
 */
export interface Receipt {
  readonly id: string
  readonly decisionId?: string
  readonly boundary: Boundary
  readonly attemptedAt: number
  readonly result: ReceiptResult
  readonly operationId?: string
}

/** 一条资格 = 某主体当前是否被允许加载，以及凭什么。 */
export interface Qualification {
  readonly subjectId: string
  readonly status: QualificationStatus
  /** qualified 的凭据来源；非 qualified 态可省。 */
  readonly basis?: QualificationBasis
  /** 0.4.3 的 subject_sha256：审计时绑定的内容摘要。 */
  readonly subjectDigest?: string
  readonly reviewScope: string
  /** 被审证据集的摘要（审计包含了哪些事实）。规则集或证据集变了它就变。 */
  readonly evidenceDigest: string
  readonly reviewer: string
  readonly policyId: string
  readonly assessedAt: number
  readonly invalidationReasons: readonly string[]
}

/** 报警来源通道。面板按它分组；与合并键前缀（tier）不是一回事——观察类告警是 scan 来源 + obs 前缀。 */
export type AlarmSource = 't1' | 't2' | 'scan'

/**
 * 投影产物：盾牌与面板消费的报警行。
 *
 * 0.5.0 起这个形状归域所有（原定义在 `guard/status.ts`），`guard/status.ts` 只做再导出。
 * 字段一个都没动——它是**已发布合同**的一部分：`/vet/status.json` 的消费方与
 * `dismissed-alerts.json` 的键都依赖它。
 */
export interface VetAlarm {
  /** 去重键（source+kind+target）；VetStatus 在 dedupeWindowMs 内按 id 去重。 */
  id: string
  severity: AlarmSeverity
  source: AlarmSource
  kind: string
  message: string
  target?: string
  /** T2 栈归因 best-effort：插件包名（@scope/name 或 name）。 */
  pluginHint?: string
  /** 目标是否为会话日志文件（用于归因分层文案：无归因 + 会话日志 → 轮换提示）。 */
  sessionLog?: boolean
  /** 同类报警累计次数（合并去重后展示用；同一 (source,kind,plugin) 跨 target 折叠为一条）。 */
  count?: number
  /**
   * 合并键：显式设置时，VetStatus.record 按 (source,kind,plugin) 聚合该报警，忽略 target。
   * 用于关联签名类（n3-/canary-leak）——跨主机/跨密钥的同类报警折叠为一条并累计 count，
   * 防止单个插件刷满 20 槽缓冲（事件风暴降噪）。未设置则退化为精确 id 去重。
   */
  mergeKey?: string
  at: number
}

/** 投影输入：七类对象里真正参与报警投影的五类。Decision/Receipt 不进报警面。 */
export interface ProjectionInput {
  readonly subject: SubjectRef
  readonly evidence: readonly Evidence[]
  readonly assessments: readonly Assessment[]
  readonly coverage: readonly CoverageEntry[]
}

/** 声明的观测面全集，用于「九个面是否都表过态」的完整性检查。 */
export const SURFACES: readonly Surface[] = [
  'file_tree',
  'deps_direct',
  'deps_transitive',
  'runtime_fs',
  'runtime_net',
  'runtime_spawn',
  'runtime_hook_health',
  'intel_osv',
  'intel_registry',
]

export const SUBJECT_KINDS: readonly SubjectKind[] = [
  'npm',
  'local',
  'skill',
  'remote_mcp',
  'native',
  'other',
  'self',
]

/** vet 自身作为主体时的固定 subjectId。 */
export const SELF_SUBJECT_ID = 'vet-self'

/**
 * 宿主进程作为主体：T1 资源类观测（mem / fd / growth / fork 突增）说的是「这个进程怎么了」，
 * 不属于任何插件，也不是 vet 自己。缺了它，这些告警要么被迫挂到某个插件头上（错误归因），
 * 要么在投影器里开特例。
 */
export const HOST_SUBJECT: SubjectRef = {
  subjectId: 'dsh-host',
  kind: 'other',
  name: 'dsh-host',
}

/** vet 自身的主体引用（唯一合法构造点，避免各处各写一份）。 */
export const SELF_SUBJECT: SubjectRef = {
  subjectId: SELF_SUBJECT_ID,
  kind: 'self',
  name: 'vet',
}
