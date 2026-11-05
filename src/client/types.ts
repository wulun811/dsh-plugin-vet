/**
 * vet 盾牌 wire 类型：status.json 反序列化目标（client 侧视图）。
 * 从 Shield.tsx 拆出（P0 目录化），避免面板组件反向依赖编排层形成循环导入。
 * 全部字段对旧后端可选容忍：新客户端遇到未重启的旧 vet 必须降级渲染。
 */

export interface VetAlarmWire {
  /** 去重键（source+kind+target），忽略/恢复按它寻址。 */
  id: string
  kind: string
  message: string
  severity?: 'yellow' | 'red' | 'info'
  pluginHint?: string
  /** 目标是否为会话日志文件（归因分层文案用，见 status.ts VetAlarm）。 */
  sessionLog?: boolean
  /** 触发告警的目标（主机:端口、文件路径等），见 status.ts VetAlarm.target。 */
  target?: string
  /** 同类报警合并后的累计次数（跨 target 折叠，见 status.ts VetAlarm.count）。 */
  count?: number
  at: number
}

export interface VetMetricsWire {
  rssMb: number
  heapUsedMb: number
  heapTotalMb: number
  externalMb: number
  mcpRssMb: number
  mcpCount: number
  vetRssMb: number
  vetCount: number
  cpuPct: number
  ioReadMb: number
  ioWriteMb: number
  childCount: number
  fdCount: number
  at: number
}

/** 0.1.20：防御统计数据 */
export interface VetStatsWire {
  scannedCount: number
  alarmsRecorded: number
  blockedCount: number
  activeDefenseCount: number
  updatedAt: number
}

/** 0.4.1：自动更新适配提示（两层）。旧后端无此字段时客户端整块隐藏。 */
export interface VetUpdateWire {
  /** 本机运行中的 DSH 版本（读不到 = ''）。 */
  dshVersion: string
  /** 本版 vet 自己声明的已复验 DSH 范围。 */
  testedRange: string
  /** 离线兼容层结论：ok = 在范围内；out-of-range = 超出已复验；unknown = 判不出来。 */
  compat: 'ok' | 'out-of-range' | 'unknown'
  /** 在线层结论：update-available 才提示可升级。 */
  status: 'up-to-date' | 'update-available' | 'unknown'
  currentVersion: string
  latestVersion: string
  latestTestedRange: string
  checkedAt: number
}

/** 0.5.0：九个观测面的结论（后端 `VetStatusSnapshot.coverage`，永远九行）。
 * 0.5.3 起这九行是**跨主体取最差**的聚合（每主体各存一份，见 `coverageBySubject`）。 */
export interface VetCoverageWire {
  surface: string
  result: 'covered' | 'partial' | 'excluded' | 'unsupported' | 'failed' | 'unknown'
  reasons: string[]
  observedAt: number
  observerVersion?: string
  /** 已声明为已知边界（原 known-boundaries）。仍是未覆盖，只是不再算「意外」。 */
  acknowledged?: boolean
  /** 这一行（最差结论）出自哪个主体。多主体时是唯一出处；单主体时外壳已经写了是谁。 */
  subject?: string
}

/** 0.5.2：六个执行面的生效姿态（后端 `effectivePosture`）。 */
export interface VetPostureWire {
  surface: string
  desired: boolean
  supported: boolean
  installed: boolean | null
  healthy: boolean | null
  effective: 'enforced' | 'degraded' | 'unsupported' | 'off' | 'unknown'
  /** desired ≠ effective 时的解释（后端给出，面板原样显示）。 */
  gap?: string
}

/** 0.5.20：你动过的键里，哪些当前真的在起作用（后端 `effectiveConfig`，0.5.12 起就在 JSON 里）。 */
export interface VetConfigKeyWire {
  key: string
  status: 'active' | 'inert' | 'partial'
  /** `status !== 'active'` 时：支配它的那个键。 */
  because?: string
  /** `status !== 'active'` 时：后端写好的那句人话，面板原样显示。 */
  note?: string
}

export interface VetEffectiveConfigWire {
  profile: string
  keys: VetConfigKeyWire[]
  counts: { changed: number; active: number; inert: number; partial: number }
}

/** 0.5.20：投影与旧字面量的比对计数（后端 `domainProjection`）。 */
export interface VetDomainProjectionWire {
  mode: 'shadow' | 'active' | 'legacy'
  /** 本次进程内不等的次数。严格模式下第一条即抛，所以那里最多看到 0/1。 */
  mismatches: number
  /** 第一条差异的字段级说明。 */
  first?: string
}

/** 0.5.7：最近一次拦截判定的回执（后端 `receipts`）。 */
export interface VetReceiptWire {
  boundary: string
  result: 'applied' | 'failed' | 'not_requested' | 'not_covered' | 'unknown'
  /** 后端算好的「这句话能不能说」（result === 'applied'）。面板不再自己推一遍。 */
  claimsBlocked: boolean
  operationId?: string
  attemptedAt: number
}

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
  /** 用户已忽略的报警（可恢复）。 */
  dismissed?: VetAlarmWire[]
  lastScan?: { pluginName: string; verdict: string; staticScore: number; at?: number }
  /** 0.5.0：九面覆盖面。旧后端无此字段 → 整块不渲染（降级，不报错）。 */
  coverage?: VetCoverageWire[]
  /** 上面九行只描述一个包时给出它的名字；多主体时不给出（用个数代替，不许冒充某一个）。 */
  coverageSubject?: string
  /** 上面九行聚合了几个主体（≥2 时给出）。 */
  coverageSubjects?: number
  /** 0.5.2：六面生效姿态。同样缺席即不渲染。 */
  effectivePosture?: VetPostureWire[]
  /** 0.5.7：最近一次拦截判定的回执。缺席或空 → 整块不渲染（没有判定，不等于一切正常）。 */
  receipts?: VetReceiptWire[]
  /** 0.5.20：生效配置视图。缺席 = 旧后端，整块不渲染。 */
  effectiveConfig?: VetEffectiveConfigWire
  /** 0.5.20：投影比对的差异计数。缺席 = 旧后端。 */
  domainProjection?: VetDomainProjectionWire
  runtimeGuard?: 'off' | 'watch'
  /** 0.3：安全档位（standard/hardened/paranoid）。 */
  profile?: 'standard' | 'hardened' | 'paranoid'
  metrics?: VetMetricsWire
  /** 0.1.20：防御统计 */
  stats?: VetStatsWire
  /** 0.4.1：自动更新适配提示（离线兼容层 + 在线升级提示）。 */
  update?: VetUpdateWire
  /* —— P2 增量（旧后端无此字段时全部降级）—— */
  /** 指标历史（旧→新，≤64 点；复合卡火花线）。 */
  metricsHistory?: MetricsHistoryPointWire[]
  /** 审计 & 蜜罐聚合（审计中心 / 最近插件列表）。 */
  audit?: AuditSummaryWire
  /** 最近一次升级差分（浮动卡）。 */
  lastUpgradeDiff?: UpgradeDiffWire
}

/* —— P2 wire 类型（与服务端 guard/metrics.ts、guard/audit-summary.ts 对齐）—— */

export interface MetricsHistoryPointWire {
  at: number
  rssTotalMb: number
  cpuPct: number
  fdCount: number
}

export interface HoneypotSummaryWire {
  armed: boolean
  touches: number
  lastTouch?: { plugin: string; file: string; at: number }
}

export interface PendingAuditWire {
  name: string
  version?: string
  reason: string
  firstSeenAt: number
}

export interface NewPluginWire {
  name: string
  version?: string
  firstSeenAt: number
}

export interface PluginIndexEntry {
  name: string
  version?: string
  verdict?: string
  staticScore?: number
  at: number
  audited?: boolean
  blocked?: boolean
}

export interface AuditSummaryWire {
  honeypot: HoneypotSummaryWire
  pendingAudits: PendingAuditWire[]
  newPlugins: NewPluginWire[]
  plugins: PluginIndexEntry[]
}

export interface UpgradeDiffWire {
  plugin: string
  severity: 'yellow' | 'red' | 'info'
  at: number
  from: string | null
  to: string | null
  added: string[]
}

/** GET /vet/plugin?name= 响应（插件详情三级面板数据源）。 */
export interface PluginDetailWire {
  ok: boolean
  plugin?: {
    name: string
    version?: string
    present: boolean
    scan?: {
      version?: string
      at: number
      verdict: string
      staticScore: number
      ruleCodes: string[]
      sourceCount?: number
      osv?: string
    }
    capabilities?: {
      hosts: string[]
      fsPaths: string[]
      spawnCmds: string[]
      imports: string[]
      hasNetwork: boolean
      hasExec: boolean
      esmNamedBuiltins?: boolean
      /** 0.5.3：命中的具体内建模块（缺席 = 旧记录，按「不知哪个执行面」处置）。 */
      esmNamedBuiltinModules?: string[]
      ghostDeps?: string[]
      zombieDeps?: string[]
      /** C4（0.3.8）：含预编译原生二进制（.node/.so/.dll 等，JS 规则面不可审）。 */
      hasNativeBinary?: boolean
      nativeBinaries?: string[]
    } | null
    versions: { version: string; recordedAt: number }[]
    diffSummary?: { from: string; to: string; added: string[] } | null
    audited?: boolean
    blocked?: boolean
    /** round-18：官方/受信包（随 DSH 分发）——详情页展示「官方插件」chip。 */
    official?: boolean
    note?: string
  }
}
