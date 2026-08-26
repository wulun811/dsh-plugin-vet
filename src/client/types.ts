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

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
  /** 用户已忽略的报警（可恢复）。 */
  dismissed?: VetAlarmWire[]
  lastScan?: { pluginName: string; verdict: string; staticScore: number; at?: number }
  runtimeGuard?: 'off' | 'watch'
  /** 0.3：安全档位（standard/hardened/paranoid）。 */
  profile?: 'standard' | 'hardened' | 'paranoid'
  metrics?: VetMetricsWire
  /** 0.1.20：防御统计 */
  stats?: VetStatsWire
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
      ghostDeps?: string[]
      zombieDeps?: string[]
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
