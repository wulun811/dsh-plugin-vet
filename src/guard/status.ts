/**
 * vet 盾牌状态聚合器（D22）：T1/T2 运行时报警与扫描回显的统一收口。
 * alarm-only：只记录与暴露状态，绝不产生任何拦截/杀进程/卸载行为（PLAN §2.1 D21）。
 * level 派生：任一 red 存活报警 → red；任一 yellow 存活报警 → yellow；否则 green。
 * 扫描结论（0.4.1 起）走 `noteScan` → 显式 scan-verdict 告警：可读、可忽略、可跨重启持久化。
 * 旧实现用 lastScan 隐式抬升 level——用户看得到黄、却没有任何可忽略的条目（0.2.1 官方包
 * 命中上游 zod 漏洞时就是这种「黄得没有出路」的状态）。
 */
import { isPersistentlyDismissed, persistentlyDismiss, restorePersistentDismissal } from './dismissed-alerts.js'
import { scanVerdictAlarm, scanVerdictSubjectTag, type ScanVerdictEcho } from './scan-verdict.js'

/** 按公告聚合的结论告警 id 前缀（`scan-verdict:agg:osv:<公告>:<依赖>:<结论>`）。
 * 与对象行（`scan-verdict:plugin:<name>:…` / `scan-verdict:tool:<name>:…`）结构不相交，
 * 「是不是聚合行」由前缀判断而非猜名字——否则一个叫 `osv` 的包就与聚合行撞命名空间。 */
const AGGREGATE_PREFIX = 'scan-verdict:agg:'
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

/** 扫描回显：结论 + 证据（规则码 / OSV 坐标），告警文案与指纹都由 `scan-verdict.ts` 生成。 */
export interface ScanEcho extends ScanVerdictEcho {}

export interface VetStatusSnapshot {
  level: ShieldLevel
  alarmCount: number
  alarms: VetAlarm[]
  /** 用户已忽略的报警（id → 记录，供面板「已忽略」分区展示/恢复）。 */
  dismissed: VetAlarm[]
  lastScan?: ScanEcho
}

export interface VetStatusOptions {  /** 报警环形缓冲上限（默认 20）。 */
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
  /** 聚合行 id → 仍支撑它的包名集合（全部转 clean 时整行撤销，不必等 TTL）。 */
  private readonly groupMembers = new Map<string, Set<string>>()
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
    // 聚合行的成员集合跟着告警一起淘汰，避免 Map 无限增长。
    for (const id of [...this.groupMembers.keys()]) {
      if (!this.alarms.some(a => a.id === id)) this.groupMembers.delete(id)
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
    // 忽略是对「当时那条观察」的答复，不是对升级的预先批准：同一合并键把严重度升到 red 时
    // 解除折叠并撤销持久化忽略。少了这一步，一次「忽略」会把 mergeKey 恒定的桶永久封住
    // （升级提示升级成 red 能力变更、n3 外泄、canary 命中都走同一个桶），盾牌仍是绿的。
    if (alarm.severity === 'red') {
      // 只在**观察到升级**时解除折叠：同一条已忽略的红牌再次复报仍按原语义保持折叠（否则
      // 一次忽略会被下一次复报立刻推翻，用户永远消不掉）；而没有存活行的（TTL 过期后重来）
      // 也不动——没有可比对的旧等级，按 0.2.1 起的既有语义保持忽略。
      const row = this.alarms.find(a => (a.mergeKey ?? a.id) === groupKey)
      if (row !== undefined && row.severity !== 'red') {
        for (const key of new Set([groupKey, row.mergeKey ?? row.id])) {
          this.dismissedIds.delete(key)
          if (isPersistentlyDismissed(key)) restorePersistentDismissal(key)
        }
      }
    }
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

  /**
   * 记录一次扫描回显：结论 → 显式告警（suspicious=yellow / critical=red），
   * clean → 撤销该对象仍存活的结论告警并回绿。
   *
   * 0.4.1：以前这里只写 lastScanValue，由 snapshot() 隐式抬 level。结果是盾牌变黄却
   * 没有一条可点「忽略」的告警——面对「官方包命中上游依赖 CVE」这类无法靠用户行动
   * 消解的情况，用户只能在永久黄和改代码之间选。现在结论本身就是告警，走既有折叠/
   * 持久化语义：忽略后不参与 level，且跨重启有效。
   */
  noteScan(echo: ScanEcho): void {
    this.lastScanValue = echo
    const alarm = scanVerdictAlarm(echo)
    const tag = scanVerdictSubjectTag(echo)
    if (alarm === null) {
      this.clearScanVerdict(echo.pluginName, tag)
      return
    }
    this.record({
      id: alarm.id,
      severity: alarm.severity,
      source: 'scan',
      kind: alarm.kind,
      message: alarm.message,
      target: echo.pluginName,
      pluginHint: echo.pluginName,
      // 证据即身份：同一组证据折叠为一行（含 count 累计）；证据变化 → 新 id → 重新提醒。
      mergeKey: alarm.id,
      at: echo.at,
    })
    // 成员登记必须在 record **之后**：record 开头就 expire()，而 expire() 会丢掉「没有对应
    // 告警行」的成员集合——先登记再 record，首条聚合行刚建好就被清空（实测后果：单成员转
    // clean 撤不掉行，多成员乱序 clean 会提前撤行 → 仍受影响的包漏报）。
    this.anchorGroup(echo.pluginName, tag, alarm.id)
  }

  /**
   * 登记「这个对象当前由哪条结论支撑」。
   * - 先脱离所有**旧**聚合行（结论 id 变了，例如从「依赖命中」转为「自身命中」），否则旧行
   *   会一直把它算作成员，直到 24h TTL；
   * - 再挂到当前行（仅聚合行），并把 count 校正为**仍受影响的包数**。record 的 count 累计受
   *   60s 去重窗口约束（0.2.1 的 54 个包扫过一分钟就会重置成 1，面板于是显示「多个官方包」
   *   却没有 ×N）；成员集合是去重后的名字，天然是准确口径。
   */
  private anchorGroup(pluginName: string, tag: 'plugin' | 'tool', alarmId: string): void {
    // 证据换了但仍非 clean（新公告、依赖升级后另有问题）→ 旧行立刻撤掉，不留到 TTL。
    this.dropStaleVerdicts(pluginName, tag, alarmId)
    for (const [id, members] of [...this.groupMembers]) {
      if (id === alarmId) continue
      if (!members.delete(pluginName)) continue
      if (members.size > 0) continue
      this.groupMembers.delete(id)
      const idx = this.alarms.findIndex(a => a.id === id)
      if (idx >= 0) this.alarms.splice(idx, 1)
    }
    if (!alarmId.startsWith(AGGREGATE_PREFIX)) return
    const members = this.groupMembers.get(alarmId) ?? new Set<string>()
    members.add(pluginName)
    this.groupMembers.set(alarmId, members)
    const row = this.alarms.find(a => a.id === alarmId)
    if (row !== undefined) row.count = members.size
  }

  /**
   * 撤掉这个对象**仍然存活**的旧结论行（`scan-verdict:<name>:*`），保留 `keepId`。
   * 证据变了但仍非 clean（换了一条公告、依赖升级后还有别的问题）时用得到——否则旧行会一直
   * 留到 24h TTL：面板上同一个包两行，且旧行还点着已经修好的那条公告。
   * 已忽略的行不撤：它不参与 level，留在「已忽略」区供恢复/审计。
   */
  private dropStaleVerdicts(pluginName: string, tag: 'plugin' | 'tool', keepId?: string): void {
    const prefix = `scan-verdict:${tag}:${pluginName}:`
    for (let i = this.alarms.length - 1; i >= 0; i--) {
      const alarm = this.alarms[i]
      if (alarm.id === keepId || !alarm.id.startsWith(prefix)) continue
      if (this.isDismissed(alarm.mergeKey ?? alarm.id)) continue
      this.alarms.splice(i, 1)
    }
  }

  /**
   * 撤销某对象**仍存活**的扫描结论告警（重扫转 clean 时调用）。
   * 逐包告警若已被用户忽略则保留：它不参与 level，留在「已忽略」区供恢复/审计。
   * 聚合行按「成员」撤销：最后一个成员也转 clean 时才移除整行——此时证据已经消解，不再
   * 区分是否被忽略（没有可恢复的对象，留着只会让「已忽略」区堆一条已解决的历史）。
   */
  private clearScanVerdict(pluginName: string, tag: 'plugin' | 'tool'): void {
    this.dropStaleVerdicts(pluginName, tag)
    for (const [id, members] of [...this.groupMembers]) {
      if (!members.delete(pluginName)) continue
      if (members.size === 0) {
        this.groupMembers.delete(id)
        const idx = this.alarms.findIndex(a => a.id === id)
        if (idx >= 0) this.alarms.splice(idx, 1)
        continue
      }
      // 计数口径 = 仍受影响的包数（见 anchorGroup）：成员退场时同步校正。
      const row = this.alarms.find(a => a.id === id)
      if (row !== undefined) row.count = members.size
    }
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
    // P3-2：lastScan 加 TTL（复用 alarmTtlMs）——只作「最近扫描」展示回显，不再参与 level；
    // 插件已移除/长时间未再扫描时自动从快照消失。持续扫描会不断刷新 at，天然续期。
    const lastScan = this.lastScanValue !== undefined && now - this.lastScanValue.at < this.alarmTtlMs
      ? this.lastScanValue
      : undefined
    // level 只看存活且未被忽略的告警（0.4.1）——扫描结论已由 noteScan 落成告警，
    // 若仍让 lastScan 直接抬 level，则「忽略」对黄牌永远无效（用户实测的问题）。
    const level: ShieldLevel =
      active.some(a => a.severity === 'red') ? 'red'
      : active.some(a => a.severity === 'yellow') ? 'yellow'
      : 'green'
    // 0.3.3（P1 双层通道，用户警报疲劳反馈）：alarmCount 只计「可行动风险」（yellow/red）——
    // info 观察（官方包 C2 边界等 capability/coverage 类）不参与警报计价与 level，但保留在
    // alarms 列表（面板 logged 区可见、可 dismiss、可恢复），避免「警报数」被无法消解的
    // 架构事实污染（15 条黄 = 同一 C2 边界 × 14 官方包，而非 15 处风险）。
    const actionable = active.filter(a => a.severity !== 'info')
    return { level, alarmCount: actionable.length, alarms: active.map(stripMergeKey), dismissed: dismissed.map(stripMergeKey), lastScan }
  }
}