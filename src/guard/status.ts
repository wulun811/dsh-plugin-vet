/**
 * vet 盾牌状态聚合器（D22）：T1/T2 运行时报警与扫描回显的统一收口。
 * alarm-only：只记录与暴露状态，绝不产生任何拦截/杀进程/卸载行为（PLAN §2.1 D21）。
 * level 派生：任一 red 报警 → red；任一 yellow 报警或最近扫描 suspicious → yellow；否则 green。
 */
import { isPersistentlyDismissed, persistentlyDismiss, restorePersistentDismissal } from './dismissed-alerts.js'
export type ShieldLevel = 'green' | 'yellow' | 'red'
export type AlarmSeverity = 'yellow' | 'red' | 'info'
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

/** 序列化前剥离内部合并键（mergeKey 仅用于 VetStatus.record 聚合，不必暴露给盾牌前端）。 */
function stripMergeKey(a: VetAlarm): VetAlarm {
  const { mergeKey: _mk, ...rest } = a
  void _mk
  return rest
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
    // round-5 review（B-A8）：构造参数 clamp——内部/测试脏输入（alarmMax<0 会使
    // `this.alarms.length = alarmMax` 抛 RangeError；负 TTL 会让 expire 全删）不再
    // 可能让 record 崩溃，记录路径在报警风暴时保持健壮。
    this.alarmMax = options.alarmMax !== undefined && Number.isFinite(options.alarmMax) && options.alarmMax >= 1
      ? Math.floor(options.alarmMax)
      : 20
    this.dedupeWindowMs = options.dedupeWindowMs !== undefined && Number.isFinite(options.dedupeWindowMs) && options.dedupeWindowMs >= 0
      ? Math.floor(options.dedupeWindowMs)
      : 60_000
    this.alarmTtlMs = options.alarmTtlMs !== undefined && Number.isFinite(options.alarmTtlMs) && options.alarmTtlMs >= 1
      ? Math.floor(options.alarmTtlMs)
      : 24 * 60 * 60 * 1000
  }

  /** 淘汰超龄报警（TTL 过期）；level 与列表都只看存活报警。 */
  private expire(now: number): void {
    const cutoff = now - this.alarmTtlMs
    for (let i = this.alarms.length - 1; i >= 0; i--) {
      if (this.alarms[i].at < cutoff) this.alarms.splice(i, 1)
    }
    // 忽略状态随报警记录存活：对应报警全部过期/消失后自动清除忽略，将来再次触发会重新
    // 可见（用户可再忽略）；持续复发的报警记录不断续期，忽略保持有效。
    // 0.3.9：内存键可能存的是 mergeKey（见 dismiss 修复）——按 id **或** mergeKey 匹配保留。
    for (const id of [...this.dismissedIds]) {
      if (!this.alarms.some(a => a.id === id || (a.mergeKey ?? a.id) === id)) this.dismissedIds.delete(id)
    }
  }

  /** 用户忽略一条报警：从盾牌 level 与活动列表隐藏，记录保留（可恢复）。
   *  0.2.1：同时持久化忽略状态，DSH 重启后仍生效。
   *  对于有 mergeKey 的警报（如 N3 无主警报），使用 mergeKey 作为持久化 key，
   *  这样忽略一个警报后，所有同类警报都会被忽略。
   *  0.3.9（审查修复）：**内存集合与 snapshot.isFold 同键**——此前 dismissedIds 存原始 id
   *  而 isFold 按 mergeKey 查内存集合，平时被持久化层掩盖；saveDismissed 写盘失败（只读/
   *  满盘，写失败时缓存不更新）时「忽略」对聚合行完全无效（行留在 active、继续计黄/红）。 */
  dismiss(id: string): void {
    const alarm = this.alarms.find(a => a.id === id)
    const dismissKey = alarm?.mergeKey ?? id
    this.dismissedIds.add(dismissKey)
    persistentlyDismiss(dismissKey)
  }

  /** 恢复一条被忽略的报警。
   *  0.2.1：同时从持久化存储中恢复。
   *  对于有 mergeKey 的警报，使用 mergeKey 作为持久化 key。 */
  restore(id: string): void {
    const alarm = this.alarms.find(a => a.id === id)
    const dismissKey = alarm?.mergeKey ?? id
    this.dismissedIds.delete(id)
    this.dismissedIds.delete(dismissKey)
    restorePersistentDismissal(dismissKey)
  }

  /** 某条报警当前是否被忽略（内存 + 持久化）。
   *  0.2.1：同时检查持久化忽略列表，用户忽略后跨 session 生效。 */
  isDismissed(id: string): boolean {
    return this.dismissedIds.has(id) || isPersistentlyDismissed(id)
  }

  /**
   * 记录一条报警。去重/合并规则：
   * - 设置了 mergeKey 的关联签名类报警（n3-/canary-leak）按 (source,kind,plugin) 聚合，
   *   忽略 target——跨主机/跨密钥的同类报警折叠为一条并累计 count（事件风暴降噪）；
   * - 其余报警仍按精确 id 去重（P2-4：窗口外的同键重发先移除旧副本再入列，避免占满缓冲）。
   * 返回 'deduped' 表示未新增独立行（被去重或合并进已有行）。
   */
  record(alarm: VetAlarm): 'new' | 'deduped' {
    const now = Date.now()
    this.expire(now)
    // round-15 review（持久化忽略跨 session 不可恢复修复）：此前检查 isPersistentlyDismissed
    // 短路不入列——重启后该 id 的警报永远进不了 alarms，snapshot().dismissed（只读内存
    // dismissedIds）恒空 → 「已忽略分区可恢复」（0.2.1 文档承诺）跨 session 失效，且被忽略
    // 的警报再次真实发生时完全不可见（外泄/破坏继续静默）。现已删除短路：照常记录入列，
    // 展示层按 isDismissed（内存 ∪ 持久化）折叠进「已忽略」区——忽略 = 折叠 + 不参与
    // level/alarmCount，但记录保留且可恢复；量级最坏 = 已忽略区一条（mergeKey 聚合）。
    const groupKey = alarm.mergeKey ?? alarm.id
    const matchGroup = (a: VetAlarm): boolean => (a.mergeKey ?? a.id) === groupKey
    const recent = this.alarms.find(a => matchGroup(a) && now - a.at < this.dedupeWindowMs)
    if (recent !== undefined) {
      // 合并：累计次数、刷新时间、严重度取高者、保留最新一次 target 便于查看
      recent.count = (recent.count ?? 1) + 1
      recent.at = now
      if (alarm.severity === 'red') {
        recent.severity = 'red'
        // 0.3.9：升级到 red 时同步换掉旧文案——scan:upgrade 桶先 info 后 red 时，
        // 行变红但文案仍是「…蓝色提示，已聚合」会误导（呈现错位）。
        recent.message = alarm.message
      }
      if (alarm.target !== undefined) recent.target = alarm.target
      return 'deduped'
    }
    // P2-4：replace 语义——窗口外的同组合重发时先移除旧副本再入列。
    for (let i = this.alarms.length - 1; i >= 0; i--) {
      if (matchGroup(this.alarms[i])) this.alarms.splice(i, 1)
    }
    this.alarms.unshift({ ...alarm, count: Math.max(1, alarm.count ?? 1) })
    if (this.alarms.length > this.alarmMax) this.trimToMax()
    return 'new'
  }

  /**
   * round-16（SA2-3）：环形缓冲裁剪保护红色报警——风暴期从尾部（最旧）裁剪时跳过 red：
   * 红色（破坏/外泄等高置信信号）不被黄色/信息噪声挤出缓冲（此前 `length = alarmMax` 直裁
   * 尾部，黄色风暴可把唯一的红色挤出——盾牌级别与告警列表同时失明于最严重信号）。
   * 全红时退让最旧一条（否则缓冲永不收容新报警，record 进入活锁）。
   */
  private trimToMax(): void {
    while (this.alarms.length > this.alarmMax) {
      const last = this.alarms.length - 1
      if (this.alarms[last].severity !== 'red') {
        this.alarms.pop()
        continue
      }
      let idx = -1
      for (let i = last; i >= 0; i--) {
        if (this.alarms[i].severity !== 'red') { idx = i; break }
      }
      if (idx === -1) idx = last
      this.alarms.splice(idx, 1)
    }
  }

  /** 记录一次扫描回显（suspicious 会把盾牌抬到 yellow）。 */
  noteScan(echo: ScanEcho): void {
    this.lastScanValue = echo
  }

  snapshot(): VetStatusSnapshot {
    const now = Date.now()
    this.expire(now)
    // round-15 review：分区改用 isDismissed（内存 ∪ 持久化）——被持久化忽略的警报在
    // 重启后再触发时仍会入列，此处正确折叠进 dismissed 区（此前只认内存 dismissedIds，
    // 持久化忽略的条目跨 session 既不显示也无法恢复）。
    // 注意 mergeKey 语义：dismiss() 持久化时用 mergeKey ?? id 为键（status.ts Vetalarm
    // 注释），折叠判定必须同键——只查 a.id 会让 mergeKey 报警重启后永远进 active。
    const isFold = (a: VetAlarm): boolean => {
      const key = a.mergeKey ?? a.id
      return this.dismissedIds.has(key) || isPersistentlyDismissed(key)
    }
    const active = this.alarms.filter(a => !isFold(a))
    const dismissed = this.alarms.filter(a => isFold(a))
    // P3-2：lastScan 加 TTL（复用 alarmTtlMs）——一次 suspicious 扫描不再让盾牌永久 yellow，
    // 插件已移除/长时间未再扫描时自动恢复 green。持续扫描会不断刷新 at，天然续期。
    const lastScan = this.lastScanValue !== undefined && now - this.lastScanValue.at < this.alarmTtlMs
      ? this.lastScanValue
      : undefined
    const level: ShieldLevel =
      active.some(a => a.severity === 'red') ? 'red'
      : (active.some(a => a.severity === 'yellow') || (lastScan !== undefined && lastScan.verdict !== 'clean')) ? 'yellow'
      : 'green'
    // 0.3.3（P1 双层通道，用户警报疲劳反馈）：alarmCount 只计「可行动风险」（yellow/red）——
    // info 观察（官方包 C2 边界等 capability/coverage 类）不参与警报计价与 level，但保留在
    // alarms 列表（面板 logged 区可见、可 dismiss、可恢复），避免「警报数」被无法消解的
    // 架构事实污染（15 条黄 = 同一 C2 边界 × 14 官方包，而非 15 处风险）。
    const actionable = active.filter(a => a.severity !== 'info')
    return { level, alarmCount: actionable.length, alarms: active.map(stripMergeKey), dismissed: dismissed.map(stripMergeKey), lastScan }
  }
}