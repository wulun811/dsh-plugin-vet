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
  /** 目标是否为会话日志文件（用于归因分层文案：无归因 + 会话日志 → 轮换提示）。 */
  sessionLog?: boolean
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
  /** 用户已忽略的报警（id → 记录，供面板「已忽略」分区展示/恢复）。 */
  dismissed: VetAlarm[]
  lastScan?: ScanEcho
}

export interface VetStatusOptions {
  /** 报警环形缓冲上限（默认 20）。 */
  alarmMax?: number
  /** 同 id 报警去重窗口 ms（默认 60s）。 */
  dedupeWindowMs?: number
  /** 报警有效期 ms（默认 24h，P2-2）：超龄报警从缓冲与盾牌 level 判定中淘汰——
   * 一次误报不再让盾牌永久黄/红；持续攻击会持续产生新报警，天然续期。 */
  alarmTtlMs?: number
}

export class VetStatus {
  private readonly alarmMax: number
  private readonly dedupeWindowMs: number
  private readonly alarmTtlMs: number
  private readonly alarms: VetAlarm[] = []
  /** 用户主动忽略的报警 id（alarm-only 的延伸：报警可以「看不见」，但从不被 vet 删除）。 */
  private readonly dismissedIds = new Set<string>()
  private lastScanValue: ScanEcho | undefined

  constructor(options: VetStatusOptions = {}) {
    this.alarmMax = options.alarmMax ?? 20
    this.dedupeWindowMs = options.dedupeWindowMs ?? 60_000
    this.alarmTtlMs = options.alarmTtlMs ?? 24 * 60 * 60 * 1000
  }

  /** 淘汰超龄报警（TTL 过期）；level 与列表都只看存活报警。 */
  private expire(now: number): void {
    const cutoff = now - this.alarmTtlMs
    for (let i = this.alarms.length - 1; i >= 0; i--) {
      if (this.alarms[i].at < cutoff) this.alarms.splice(i, 1)
    }
    // 忽略状态随报警记录存活：对应报警全部过期/消失后自动清除忽略，将来再次触发会重新
    // 可见（用户可再忽略）；持续复发的报警记录不断续期，忽略保持有效。
    for (const id of [...this.dismissedIds]) {
      if (!this.alarms.some(a => a.id === id)) this.dismissedIds.delete(id)
    }
  }

  /** 用户忽略一条报警：从盾牌 level 与活动列表隐藏，记录保留（可恢复）。 */
  dismiss(id: string): void {
    this.dismissedIds.add(id)
  }

  /** 恢复一条被忽略的报警。 */
  restore(id: string): void {
    this.dismissedIds.delete(id)
  }

  /** 某条报警当前是否被忽略。 */
  isDismissed(id: string): boolean {
    return this.dismissedIds.has(id)
  }

  /** 记录一条报警；同 id 在去重窗口内返回 'deduped'。 */
  record(alarm: VetAlarm): 'new' | 'deduped' {
    const now = Date.now()
    this.expire(now)
    const recent = this.alarms.find(a => a.id === alarm.id && now - a.at < this.dedupeWindowMs)
    if (recent !== undefined) return 'deduped'
    // P2-4：replace 语义——窗口外的同 id 重发时先移除旧副本再入列。旧实现直接 unshift 新副本，
    // 持续报警（每 ~62s 一次）会把 20 槽环形缓冲占满 → alarmCount 虚高、其他报警被挤出。
    for (let i = this.alarms.length - 1; i >= 0; i--) {
      if (this.alarms[i].id === alarm.id) this.alarms.splice(i, 1)
    }
    this.alarms.unshift({ ...alarm })
    if (this.alarms.length > this.alarmMax) this.alarms.length = this.alarmMax
    return 'new'
  }

  /** 记录一次扫描回显（suspicious 会把盾牌抬到 yellow）。 */
  noteScan(echo: ScanEcho): void {
    this.lastScanValue = echo
  }

  snapshot(): VetStatusSnapshot {
    const now = Date.now()
    this.expire(now)
    const active = this.alarms.filter(a => !this.dismissedIds.has(a.id))
    const dismissed = this.alarms.filter(a => this.dismissedIds.has(a.id))
    // P3-2：lastScan 加 TTL（复用 alarmTtlMs）——一次 suspicious 扫描不再让盾牌永久 yellow，
    // 插件已移除/长时间未再扫描时自动恢复 green。持续扫描会不断刷新 at，天然续期。
    const lastScan = this.lastScanValue !== undefined && now - this.lastScanValue.at < this.alarmTtlMs
      ? this.lastScanValue
      : undefined
    const level: ShieldLevel =
      active.some(a => a.severity === 'red') ? 'red'
      : (active.some(a => a.severity === 'yellow') || (lastScan !== undefined && lastScan.verdict !== 'clean')) ? 'yellow'
      : 'green'
    return { level, alarmCount: active.length, alarms: active, dismissed, lastScan }
  }
}
