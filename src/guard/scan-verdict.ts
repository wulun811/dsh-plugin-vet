/**
 * 扫描结论 → 可忽略的盾牌告警（0.4.1）。
 *
 * ## 要解决的问题
 * 0.2.1 的 DSH 有多个官方包把 `zod` 精确钉在 `4.4.3`，而 OSV 的 `GHSA-mrhx-c7xc-m3w5`
 * （影响 zod ≤ 4.6.5）对该版本成立。扫描结论因此是 suspicious，旧实现用 `lastScan`
 * **隐式**把盾牌压成黄色：没有告警行、没有可点的「忽略」，于是黄得没有出路。
 *
 * 用户的选择是「不降级，但要说得清、忽略得掉」——降级会掩盖真问题，永久黄则是噪音。
 * 本模块把扫描结论做成一条**显式告警**：
 * - 文案先说**证据**（命中直接依赖时点名 `依赖 zod@4.4.3`，官方包附处置建议），再说结论；
 * - 告警 id 带**证据指纹**：同一组证据重复扫描折叠为一条；证据变化（新公告、新规则码）
 *   会生成新 id 并重新变黄——一次忽略不会让插件永久失明；
 * - 忽略沿用既有语义（`status.ts` 的折叠区）：不参与 level/alarmCount，且持久化到
 *   `dismissed-alerts.json`，跨重启有效。
 *
 * 纯函数、无 IO、无 DOM：`status.ts` 与单测共用同一份实现（与 `shield-shape.ts` 同纪律）。
 * @module dsh-plugin-vet/scan-verdict
 */

/** 扫描回显：`VetStatus.noteScan` 的输入（也是 `/vet/status.json` 的 lastScan 载荷）。 */
export interface ScanVerdictEcho {
  pluginName: string
  verdict: string
  staticScore: number
  at: number
  /** 报告里出现过的规则码（去重后用于展示与指纹）。 */
  rules?: readonly string[]
  /** OSV finding 原文（未能结构化时的兜底文案）。 */
  osv?: string
  /** OSV 命中坐标：命中**直接依赖**时为 `zod@4.4.3`，命中包自身时缺省。 */
  osvDependency?: string
  /** OSV 公告 id（GHSA-…）：命中多条时是**排序后的第一条**，全量见 `osvIds`。 */
  osvId?: string
  /** OSV 公告别名（CVE-…）。 */
  osvAlias?: string
  /**
   * 本次扫描命中的**全部**公告 id（排序、去重）。
   * `checkOsv` 一个包最多吐 10 条 finding（同一个依赖上可能挂着多条公告）。只取第一条会让
   * 第二条既进不了文案、也进不了指纹——用户忽略第一条之后，第二条公告永远不提醒。
   * 因此指纹与聚合 id 都用**集合**，而不是单条。
   */
  osvIds?: readonly string[]
  /** 官方信任家族：文案给出「通常随上游升级修复」的处置建议，并允许按公告聚合。 */
  official?: boolean
  /** 扫描对象：插件包（默认）或工具执行的代码。 */
  subject?: 'plugin' | 'tool'
  /**
   * 按**公告**聚合（仅官方包 + 命中直接依赖时由调用方置 true）。
   * 0.2.1 实测：54 个官方包都钉了同一个 zod@4.4.3，逐包一行会一次刷满面板与缓冲——
   * 告警的单位应该是「一条公告」，不是「一个包」。第三方包永不聚合：同一条 CVE 出现在
   * 第三方包里值得单独看，不能被官方包的行一起忽略掉。
   */
  aggregate?: boolean
}

export interface ScanVerdictAlarm {
  id: string
  severity: 'yellow' | 'red'
  kind: 'scan-verdict'
  message: string
}

/**
 * 命中公告集合（排序、去重）：优先 `osvIds`，兼容只给了单条的调用方。
 * 集合而非单条——同一个依赖上可能出现第二条公告，忽略第一条不能把第二条一起封住。
 */
function advisoryIds(e: ScanVerdictEcho): string[] {
  const all = e.osvIds !== undefined && e.osvIds.length > 0
    ? [...e.osvIds]
    : (e.osvId !== undefined && e.osvId !== '' ? [e.osvId] : [])
  return [...new Set(all.filter(id => id !== ''))].sort()
}

/**
 * 证据指纹：同一组证据 → 同一 id（重复扫描折叠）；证据变化 → 新 id（重新提醒）。
 * 规则码与公告集合都排序后再拼接，避免 finding 顺序不同造成假「新证据」。
 * OSV **自由文本**只在拿不到结构化公告 id 时才进指纹：公告摘要会随上游编辑而变，
 * 把它算进指纹会让一次无关的文案修订复活一条已被忽略的告警。
 */
export function scanVerdictEvidenceKey(e: ScanVerdictEcho): string {
  const rules = [...new Set(e.rules ?? [])].sort().join(',')
  const ids = advisoryIds(e)
  return [e.verdict, rules, e.osvDependency ?? '', ids.join('+'), ids.length === 0 ? (e.osv ?? '') : ''].join('|')
}

/** djb2 的 32 位无符号版本：只为稳定短 id，不做安全用途。 */
function digest(text: string): string {
  let hash = 5381
  for (let i = 0; i < text.length; i++) hash = ((hash * 33) ^ text.charCodeAt(i)) >>> 0
  return hash.toString(36)
}

/**
 * 结论告警的对象**类别**：插件包 / 工具执行的代码。必须进 id 与撤销前缀。
 *
 * 反例（审查实测）：扁平命名空间下 `scan-verdict:<name>:` 里 name 可以是任意字符串，
 * 于是 ①一个恰好叫 `osv` 的包，其撤销前缀 `scan-verdict:osv:` 命中**每一条**聚合行
 * （`scan-verdict:osv:<公告>...`），一次 clean 扫描就能把 54 个官方包的 CVE 行全部抹掉；
 * ②一个叫 `workflow` 的插件与同名工具（`run_code`/`workflow` 都是真实工具名）互相撤销。
 * 因此类别是 id 的结构位，不是从名字里猜出来的。
 */
export function scanVerdictSubjectTag(e: ScanVerdictEcho): 'plugin' | 'tool' {
  return e.subject === 'tool' ? 'tool' : 'plugin'
}

export function scanVerdictAlarmId(e: ScanVerdictEcho): string {
  const ids = advisoryIds(e)
  // 官方包 + 依赖命中：id 由「公告集合 + 依赖坐标 + 结论」决定，不含包名——54 个包折叠成
  // 一行；公告集合/依赖/结论变化才生成新 id 重新提醒。规则码**不进**聚合 id：官方包按字节
  // 基线可信，代码一变就离开 trusted family（走 mismatch 黄牌 + 严格扫描），所以这里的规则
  // 集不会在用户不知情的情况下漂移；而各包规则码本就不同，写进来只会把一行拆成几十行。
  // `agg:` 前缀同时保证聚合行与任何对象行（`plugin:` / `tool:`）在结构上不相交。
  if (e.aggregate === true && ids.length > 0 && e.osvDependency !== undefined && e.osvDependency !== '') {
    return `scan-verdict:agg:osv:${ids.join('+')}:${e.osvDependency}:${e.verdict}`
  }
  return `scan-verdict:${scanVerdictSubjectTag(e)}:${e.pluginName}:${digest(scanVerdictEvidenceKey(e))}`
}

/** 中文主语直接接谓语（「多个包判定」）；拉丁包名与谓语之间留一个空格。 */
function joinSubject(subject: string, verdict: string): string {
  return /^[\x20-\x7e]/.test(subject) ? `${subject} ${verdict}` : `${subject}${verdict}`
}

/**
 * 告警文案：**证据在前、结论在后**——面板行默认只显示前 64 字符（点击展开），
 * 所以「依赖 zod@4.4.3 命中 GHSA-…」必须落在第一屏，而不是被规则码挤到后面。
 */
export function scanVerdictMessage(e: ScanVerdictEcho): string {
  const who = e.subject === 'tool' ? `工具 ${e.pluginName} 执行的代码` : e.pluginName
  const aggregate = e.aggregate === true && e.osvDependency !== undefined && e.osvDependency !== ''
  // 聚合行不引用任何单个包的分数——那会是「最先扫到的那个包」的分数，对「多个包」没有意义。
  const verdict = aggregate ? `判定 ${e.verdict}` : `判定 ${e.verdict}（${e.staticScore} 分）`
  const subject = aggregate
    ? `本机多个${e.official === true ? '官方' : ''}包`
    : who
  const ids = advisoryIds(e)
  const alias = e.osvAlias !== undefined && e.osvAlias !== '' ? `（${e.osvAlias}）` : ''
  const advisory = ids.length > 0
    ? `已知漏洞 ${ids[0]}${alias}${ids.length > 1 ? ` 等 ${ids.length} 条` : ''}`
    : (e.osv !== undefined && e.osv !== '' ? e.osv : undefined)
  const head = e.osvDependency !== undefined && e.osvDependency !== '' && advisory !== undefined
    ? `依赖 ${e.osvDependency} 命中${advisory} → ${joinSubject(subject, verdict)}`
    : advisory !== undefined
      ? `${advisory} → ${joinSubject(subject, verdict)}`
      : `${subject} 扫描结论 ${e.verdict}（${e.staticScore} 分）`
  // 聚合行不谈规则码：不同包的静态规则各不相同，写进来会让人以为规则也适用于所有包。
  const rules = aggregate ? [] : [...new Set(e.rules ?? [])].filter(r => r !== 'OSV')
  const rulesBit = rules.length > 0 ? `规则 ${rules.slice(0, 4).join('/')}${rules.length > 4 ? ' 等' : ''}` : ''
  const advice = e.official === true
    ? '官方包：这类命中通常来自上游依赖，随 DSH 升级修复；确认知悉后可点「忽略」，该条不再计入黄牌。'
    : '确认知悉后可点「忽略」，该条不再计入黄牌。'
  return `${head}${rulesBit !== '' ? '；' + rulesBit : ''}。${advice}`
}

/** 非 clean → 待记录告警；clean → null（调用方据此撤销该对象既有结论并回绿）。 */
export function scanVerdictAlarm(e: ScanVerdictEcho): ScanVerdictAlarm | null {
  if (e.verdict === 'clean') return null
  return {
    id: scanVerdictAlarmId(e),
    severity: e.verdict === 'critical' ? 'red' : 'yellow',
    kind: 'scan-verdict',
    message: scanVerdictMessage(e),
  }
}

/** 面板/详情页展示的 OSV 坐标集合（scanner 写在 finding.evidence 里的结构化串）。 */
export interface OsvEvidence {
  dependency?: string
  id?: string
  alias?: string
}

/** 单个坐标值的长度上限：公告 id / 别名 / `name@version` 都远短于此。 */
const OSV_VALUE_MAX = 200

/**
 * 解析 scanner 写入 `finding.evidence` 的 `key=value;key=value` 串。
 * 容错：未知键忽略、缺项跳过、非字符串返回空对象——evidence 是跨进程载荷，不信任其形状。
 */
export function parseOsvEvidence(evidence: unknown): OsvEvidence {
  if (typeof evidence !== 'string' || evidence === '') return {}
  const out: OsvEvidence = {}
  for (const part of evidence.split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const key = part.slice(0, eq)
    const value = part.slice(eq + 1)
    // 公告 id / 别名 / `name@version` 都远短于此；超长值只可能是畸形载荷，别让它一路
    // 变成告警 Map 的键、再写进 dismissed-alerts.json。
    if (value === '' || value.length > OSV_VALUE_MAX) continue
    if (key === 'dependency') out.dependency = value
    else if (key === 'id') out.id = value
    else if (key === 'alias') out.alias = value
  }
  return out
}
