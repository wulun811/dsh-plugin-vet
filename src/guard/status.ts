/**
 * vet 盾牌状态聚合器（D22）：T1/T2 运行时报警与扫描回显的统一收口。
 * alarm-only：只记录与暴露状态，绝不产生任何拦截/杀进程/卸载行为（PLAN §2.1 D21）。
 * level 派生：任一 red 报警 → red；任一 yellow 报警或最近扫描 suspicious → yellow；否则 green。
 */
export type ShieldLevel = 'green' | 'yellow' | 'red'
export type AlarmSeverity = 'yellow' | 'red'
export type AlarmSource = 't1' | 't2' | 'scan'

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
  at: number
}

export interface ScanEcho {
  pluginName: string
  verdict: string
  staticScore: number
  at: number
}

export interface VetStatusSnapshot {
  level: ShieldLevel
  alarmCount: number
  alarms: VetAlarm[]
  lastScan?: ScanEcho
}

export interface VetStatusOptions {
  /** 报警环形缓冲上限（默认 20）。 */
  alarmMax?: number
  /** 同 id 报警去重窗口 ms（默认 60s）。 */
  dedupeWindowMs?: number
}

export class VetStatus {
  private readonly alarmMax: number
  private readonly dedupeWindowMs: number
  private readonly alarms: VetAlarm[] = []
  private lastScanValue: ScanEcho | undefined

  constructor(options: VetStatusOptions = {}) {
    this.alarmMax = options.alarmMax ?? 20
    this.dedupeWindowMs = options.dedupeWindowMs ?? 60_000
  }

  /** 记录一条报警；同 id 在去重窗口内返回 'deduped'。 */
  record(alarm: VetAlarm): 'new' | 'deduped' {
    const now = Date.now()
    const recent = this.alarms.find(a => a.id === alarm.id && now - a.at < this.dedupeWindowMs)
    if (recent !== undefined) return 'deduped'
    this.alarms.unshift({ ...alarm })
    if (this.alarms.length > this.alarmMax) this.alarms.length = this.alarmMax
    return 'new'
  }

  /** 记录一次扫描回显（suspicious 会把盾牌抬到 yellow）。 */
  noteScan(echo: ScanEcho): void {
    this.lastScanValue = echo
  }

  snapshot(): VetStatusSnapshot {
    const level: ShieldLevel =
      this.alarms.some(a => a.severity === 'red') ? 'red'
      : (this.alarms.some(a => a.severity === 'yellow') || (this.lastScanValue !== undefined && this.lastScanValue.verdict !== 'clean')) ? 'yellow'
      : 'green'
    return { level, alarmCount: this.alarms.length, alarms: [...this.alarms], lastScan: this.lastScanValue }
  }
}
