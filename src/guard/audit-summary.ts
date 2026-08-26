/**
 * 审计 & 蜜罐聚合器（P2，盾牌「审计中心」数据源）：
 * - 蜜罐状态：armed（配置开 + watch 生效）+ 触碰事件（报警流 kind='honeypot'）；
 * - 待审清单：「vet 见过的第三方包」∩ 无审计档案（§十一① 口径——已装未加载的枚举口待 spike，
 *   v1 用 capabilities ∪ scan-summaries 的并集，口径自洽）；官方包门槛 = 内容哈希基线 +
 *   静态扫描，不要求人工档案；
 * - 新装清单：72h 内首次出现的第三方包（官方包随 DSH 分发，不属于走廊）；
 * - 插件索引：最近扫描/记录的**第三方**包列表（「最近插件」列表取前 20；审计中心复用）。
 *   round-19：官方/受信包（@deepseek-ai/* 与 vet 自身）整体移出走廊——审计走廊的语义是
 *   「用户装的第三方里哪些要留意/待审」，官方包的防护走内容基线+扫描+报警，不占走廊格子。
 *
 * 只读聚合：不触发扫描、不联网、不写盘。fail-open：任何内部错误返回空结构。
 */
import { loadCapabilities, type CapabilityRecord } from './version-diff.js'
import { allScanSummaries } from './scan-summaries.js'
import { hasAuditRecordBatch, type AuditRecordProbe } from '../audit/archive.js'
import { isOfficial } from './runtime-attrib.js'
import type { VetAlarm } from './status.js'

/** 新装判定窗口：首次出现在 72h 内视为"新插件"。 */
const NEW_PLUGIN_WINDOW_MS = 72 * 60 * 60 * 1000

/** 列表上限：插件索引 200（round-21：从 50 提高——与 scan-summaries LRU 200 对齐，
 * 第三方多时不截断；status.json 每 5s 全量轮询 ~200 条 JSON 仅几十 KB，本地握手无感），
 * 待审/新装同 200（客户端分页逐页渲染，不一次性画全）。 */
export const PLUGIN_INDEX_CAP = 200
const LIST_CAP = 200

export interface HoneypotSummaryWire {
  /** 配置开启且 watch 生效。 */
  armed: boolean
  /** 报警流中的触碰次数（合并计数累计）。 */
  touches: number
  lastTouch?: { plugin: string; file: string; at: number }
}

export interface PendingAuditWire {
  name: string
  version?: string
  /** 静态结论摘要（suspicious/critical 置顶理由）。 */
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
  /** 最近一次有动静的时间（扫描结论变化 / 能力清单记录）。 */
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

const EMPTY: AuditSummaryWire = {
  honeypot: { armed: false, touches: 0 },
  pendingAudits: [],
  newPlugins: [],
  plugins: [],
}

interface SeenPackage {
  name: string
  version?: string
  verdict?: string
  staticScore?: number
  firstSeenAt: number
  lastAt: number
}

/** 从报警流提取蜜罐触碰摘要。 */
function honeypotFromAlarms(alarms: VetAlarm[], armed: boolean): HoneypotSummaryWire {
  const touches = alarms.filter(a => a.kind === 'honeypot')
  let touchesTotal = 0
  let last: HoneypotSummaryWire['lastTouch']
  for (const t of touches) {
    touchesTotal += Math.max(1, t.count ?? 1)
    if (last === undefined || t.at > last.at) {
      last = { plugin: t.pluginHint ?? '(unattributed)', file: t.target ?? '', at: t.at }
    }
  }
  return { armed, touches: touchesTotal, ...(last !== undefined ? { lastTouch: last } : {}) }
}

/**
 * 构建审计 & 蜜罐聚合快照。
 * @param opts.alarms 当前活跃+已忽略报警（status.snapshot() 已含去重合并）
 * @param opts.honeypotArmed 配置侧蜜罐开关生效值（enabled && runtimeGuard==='watch'）
 * @param opts.isBlocked 插件是否在拦截名单（N7 family1 集合，进程内存态）
 */
export function buildAuditSummary(opts: {
  alarms: VetAlarm[]
  honeypotArmed: boolean
  isBlocked: (name: string) => boolean
}): AuditSummaryWire {
  return failOpen(() => {
    // —— vet 见过的包：能力清单 ∪ 扫描摘要（并集口径，§十一①）——
    const seen = new Map<string, SeenPackage>()
    const absorb = (name: string | undefined, version: string | undefined, at: number, verdict?: string, staticScore?: number): void => {
      // round-15 review（name-less 记录崩溃）：能力清单里形状残缺的无 name 记录此前
      // 被 absorb 收进 seen（key=undefined），随后 hasAuditRecordBatch → escapeName(undefined)
      // 抛 TypeError → failOpen 吞掉 → 整个审计中心每 5s 轮询空白，且坏记录不被跳过。
      // 无名字的插件条目毫无展示意义——直接丢弃（bad-record 隔离，不拖垮整张表）。
      if (typeof name !== 'string' || name === '') return
      const prev = seen.get(name)
      if (prev === undefined) {
        seen.set(name, { name, version, verdict, staticScore, firstSeenAt: at, lastAt: at })
        return
      }
      if (at < prev.firstSeenAt) prev.firstSeenAt = at
      if (at > prev.lastAt) {
        prev.lastAt = at
        // 结论跟随最新一次动静
        if (verdict !== undefined) prev.verdict = verdict
        if (staticScore !== undefined) prev.staticScore = staticScore
        if (version !== undefined) prev.version = version
      }
    }
    let capRecords: CapabilityRecord[] = []
    try {
      capRecords = Object.values(loadCapabilities().records)
    } catch { /* fail-open */ }
    for (const rec of capRecords) absorb(rec.name, rec.version, rec.recordedAt)
    for (const sum of allScanSummaries()) absorb(sum.name, sum.version, sum.at, sum.verdict, sum.staticScore)

    const now = Date.now()
    const pendingAudits: PendingAuditWire[] = []
    const newPlugins: NewPluginWire[] = []
    const plugins: PluginIndexEntry[] = []

    // 批量审计档案探测：一次 readdir 判全部 seen 包（5s 轮询下防 N 次目录扫描放大）
    const probes: AuditRecordProbe[] = [...seen.values()].map(p => ({
      name: p.name,
      ...(p.version !== undefined ? { version: p.version } : {}),
    }))
    const auditMap = hasAuditRecordBatch(probes)

    for (const pkg of seen.values()) {
      // round-19：官方/受信包（随 DSH 分发）整个移出走廊——不占插件索引/新装/待审任一格子。
      // 走廊的语义是「用户装的第三方插件里，哪些要留意/待审/新出现」；官方包的防护走
      // 内容哈希基线 + 静态扫描 + 报警（D1），与用户要看的列表无关。round-17/18 的
      // 标签化展示是治标——标签再好看，20 格索引/14 行审计还是被官方包挤满，
      // 真正要审的第三方沉底。警报面不受影响：官方包 mismatch/存疑仍照常报警。
      if (isOfficial(pkg.name)) continue
      const audited = auditMap[pkg.name] === true
      // 新装清单：72h 内首见的第三方包。
      if (!audited && now - pkg.firstSeenAt <= NEW_PLUGIN_WINDOW_MS) {
        newPlugins.push({ name: pkg.name, ...(pkg.version !== undefined ? { version: pkg.version } : {}), firstSeenAt: pkg.firstSeenAt })
      }
      // 待审 = 见过但无档案（critical/suspicious 理由更醒目；clean 也算欠账——冷启动只存不报的包）
      // round-17 修正（官方包告警风暴）：待审只列第三方——官方包（@deepseek-ai/*）的门槛是
      // 内容哈希基线 + 静态扫描（决策 1），不要求人工审计档案；round-19 起官方包整体不进走廊。
      if (!audited) {
        pendingAudits.push({
          name: pkg.name,
          ...(pkg.version !== undefined ? { version: pkg.version } : {}),
          reason: pkg.verdict === 'critical' || pkg.verdict === 'suspicious'
            ? '静态存疑 · 待 agent 按 AUDIT_PROTOCOL 审查'
            : '已安装未见审计档案',
          firstSeenAt: pkg.firstSeenAt,
        })
      }
      plugins.push({
        name: pkg.name,
        ...(pkg.version !== undefined ? { version: pkg.version } : {}),
        ...(pkg.verdict !== undefined ? { verdict: pkg.verdict } : {}),
        ...(pkg.staticScore !== undefined ? { staticScore: pkg.staticScore } : {}),
        at: pkg.lastAt,
        audited,
        blocked: opts.isBlocked(pkg.name),
      })
    }

    // 排序：待审按"静态存疑优先 + 时间新优先"；索引按时间新优先
    pendingAudits.sort((a, b) => scorePending(b) - scorePending(a) || b.firstSeenAt - a.firstSeenAt)
    newPlugins.sort((a, b) => b.firstSeenAt - a.firstSeenAt)
    plugins.sort((a, b) => b.at - a.at)

    return {
      honeypot: honeypotFromAlarms(opts.alarms, opts.honeypotArmed),
      pendingAudits: pendingAudits.slice(0, LIST_CAP),
      newPlugins: newPlugins.slice(0, LIST_CAP),
      plugins: plugins.slice(0, PLUGIN_INDEX_CAP),
    }
  }) ?? EMPTY
}

function scorePending(p: PendingAuditWire): number {
  return p.reason.startsWith('静态存疑') ? 1 : 0
}

/** fail-open 包装：聚合任一环节抛错 → undefined → 调用方拿 EMPTY（vet 自查 IO 已由内层函数自包）。 */
function failOpen<T>(fn: () => T): T | undefined {
  try {
    return fn()
  } catch {
    return undefined
  }
}
