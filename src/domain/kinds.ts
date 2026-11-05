/**
 * 告警码注册表（施工图 §3）——「新增一个检测器只改一处」的那一处。
 *
 * 这张表的键**不是** `code`。实测反例（施工图 R2）：
 *
 *     { severity: 'info',   kind: 'esm-guard-coverage', mergeKey: 'scan:esm-guard-coverage:official' }  // 0.5.3 起该码不再发出，例子保留为历史
 *     { severity: 'yellow', kind: 'esm-guard-coverage' }            // 第三方
 *     { severity: 'info',   kind: 'scan-fail' }                     // 官方家族
 *     { severity: 'yellow', kind: 'scan-fail' }                     // 第三方
 *
 * 所以键是 `(code, 主体维度)`，用 `when` 表达，表里同一个 code 可以有多行，**顺序敏感、
 * 具体的在前、无条件的兜底在后**。
 *
 * 另一类变动的严重度不是主体带来的，而是**观测本身**带来的：`fs-destroy` 删的是会话日志还是
 * 普通文件、`upgrade-diff` 新增的是执行还是执行+网络组合、`scan-verdict` 是 critical 还是
 * suspicious。这类写成 `'from-site'`——判定点给的，不在这里重新推导一遍。分界线是：
 * **主体带来的差异进表，观测带来的差异留在采集点。**
 *
 * 关于 `semantic`：0.5.0 里它是元数据（投影器不按它分支），0.5.1 的资格与 0.5.2 的回执才真正
 * 消费它。现在写下来是为了让「这条告警到底属于哪一类事实」在加检测器时就必须回答一次，
 * 而不是等到面板上出现一条说不清归哪儿的行。
 */
import type { AlarmSeverity } from './types.js'

/** 合并键前缀。与现有的四种写法逐字对齐（施工图 R4），不重新发明。 */
export type AlarmTier = 't1' | 't2' | 'scan' | 'obs'

/** 七类语义里能产生告警面的五类（Decision / Receipt 之外，Receipt 只产 n7-block 一条）。 */
export type SemanticClass = 'evidence' | 'assessment' | 'coverage' | 'receipt' | 'qualification'

/**
 * 合并规则。形状必须与现有 mergeKey 逐字一致——mergeKey 参与去重与「已忽略」持久化键，
 * 改格式等于让所有用户的历史忽略失效（施工图 R4 / §9）。
 *
 * - `none`              不合并，按 id 精确去重
 * - `code`              `<tier>:<code>`（全局一条）
 * - `code:subject`      `<tier>:<code>:<主体名>`
 * - `code:subject:extra` 再多一维（`m1-contract-violation` 按字段名）
 * - `id`                合并键 = 证据 id（`scan-verdict` 的「证据即身份」语义）
 * - `literal:<串>`      固定串（`scan:upgrade` / `t2:official-housekeeping-probe`）
 */
export type MergeRule = 'none' | 'code' | 'code:subject' | 'code:subject:extra' | 'id' | `literal:${string}`

/**
 * 严重度规则。
 * - 常量：这一档的严重度由 code（与主体维度）唯一决定
 * - `'from-site'`：不是 code 的函数（施工图 R2），由判定点在采集时给出
 */
export type SeverityRule = AlarmSeverity | 'from-site'

export interface KindSpec {
  readonly code: string
  readonly semantic: SemanticClass
  readonly severity: SeverityRule
  readonly merge: MergeRule
  /**
   * 是否允许用户忽略。今天全表为 `true`（现行实现没有「不可忽略」的告警，红牌也可忽略）。
   * 保留这个字段是因为 0.5.2 要动忽略语义——那时改的是这张表，不是散在面板里的分支。
   */
  readonly dismissable: boolean
  /** 合并键前缀；缺省由 source 推导（见 `tierOfSource`）。 */
  readonly tier?: AlarmTier
  /** 主体维度匹配条件。缺省 = 无条件匹配（兜底行）。 */
  readonly when?: { readonly official?: boolean }
}

/** 一次查表需要的主体维度（不是所有维度每次都知道——不知道就不匹配带 when 的行）。 */
export interface KindContext {
  readonly official?: boolean
}

/**
 * 注册表。按语义分组，组内按字母序——排序不是美学，是为了让「这个码在不在表里」肉眼可查。
 */
export const KIND_SPECS: readonly KindSpec[] = [
  // ── 静态供应链：内容基线 / 官方目录 / 本机条目 ──────────────────────────────
  { code: 'baseline-mismatch', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true, when: { official: true } },
  { code: 'baseline-mismatch', semantic: 'evidence', severity: 'red', merge: 'none', dismissable: true },
  { code: 'baseline-patch-ack', semantic: 'evidence', severity: 'info', merge: 'none', dismissable: true },
  { code: 'baseline-refreshed', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'baseline-save-fail', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  // 官方/第三方两档；第三方的 merge 与文案都不同，见 project.ts 的「官方观测行」注释
  // 0.5.3 起这两个码不再有任何采集点：C2 边界改成该主体运行时面上的 partial（见 guard/coverage.ts）。
  // 行保留不删——注册表同时是「这个码曾经表示什么」的记录，且 0.4.2 等价性夹具仍要能被表达。
  { code: 'esm-guard-coverage', semantic: 'coverage', severity: 'info', merge: 'code:subject', dismissable: true, when: { official: true } },
  { code: 'esm-guard-coverage', semantic: 'coverage', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'local-entry', semantic: 'evidence', severity: 'info', merge: 'code', dismissable: true },
  { code: 'official-catalog-merged', semantic: 'evidence', severity: 'info', merge: 'none', dismissable: true },
  { code: 'official-match-suspected', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'official-not-in-catalog', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'official-verified', semantic: 'evidence', severity: 'info', merge: 'none', dismissable: true },
  { code: 'official-verify-mismatch', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'scan-fail', semantic: 'coverage', severity: 'info', merge: 'none', dismissable: true, when: { official: true } },
  { code: 'scan-fail', semantic: 'coverage', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'telemetry-config-change', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },

  // ── 快照：扫描到加载之间字节变了（TOCTOU）────────────────────────────────────
  // 只在非官方包上产生（官方包的内容信任锚另有基线），因此按第三方篡改信号计红：
  // 正常 npm 包躺在 node_modules 里不会被并发编辑，重合就意味着有人在我们判定之后动过手。
  { code: 'snapshot-drift', semantic: 'evidence', severity: 'red', merge: 'none', dismissable: true },

  // ── 资格：审计档案 ──────────────────────────────────────────────────────────
  { code: 'audit-required', semantic: 'qualification', severity: 'yellow', merge: 'none', dismissable: true },

  // ── 静态观测（0.3 档位下从 info 抬成黄牌）────────────────────────────────────
  { code: 'r17-observation', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true, tier: 'obs' },
  { code: 'r18-observation', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true, tier: 'obs' },
  { code: 'r19-observation', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true, tier: 'obs' },

  // ── 版本差分（N6）：同一桶 `scan:upgrade` ────────────────────────────────────
  { code: 'upgrade-cold', semantic: 'assessment', severity: 'info', merge: 'literal:scan:upgrade', dismissable: true },
  { code: 'upgrade-diff', semantic: 'assessment', severity: 'from-site', merge: 'literal:scan:upgrade', dismissable: true },

  // ── vet 自身：存储被改写 / 归因被篡改 ────────────────────────────────────────
  { code: 'attribution-tampered', semantic: 'evidence', severity: 'red', merge: 'none', dismissable: true },
  { code: 'vet-store-foreign-write', semantic: 'evidence', severity: 'info', merge: 'none', dismissable: true },
  { code: 'vet-store-tamper', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },

  // ── 扫描结论（scan-verdict.ts 产出，noteScan 落账）───────────────────────────
  { code: 'scan-verdict', semantic: 'assessment', severity: 'from-site', merge: 'id', dismissable: true },

  // ── 运行时 T2：契约 / 隐藏能力 / 金丝雀 ──────────────────────────────────────
  { code: 'canary-leak', semantic: 'evidence', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'm1-contract-distrusted', semantic: 'assessment', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'm1-contract-rejected', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'm1-contract-violation', semantic: 'evidence', severity: 'info', merge: 'code:subject:extra', dismissable: true },
  { code: 'n1-hidden', semantic: 'evidence', severity: 'red', merge: 'none', dismissable: true },
  { code: 'official-housekeeping-probe', semantic: 'evidence', severity: 'info', merge: 'literal:t2:official-housekeeping-probe', dismissable: true },

  // ── 运行时 T2：N3 关联签名（跨事件序列，因此是评估不是证据）─────────────────────
  // 0.5.16：六个**单签名**档是常量 yellow，此前全表误抄成 red（见 FAILURES.md F16）。
  // 语义上它们是「一类破坏行为在窗口内达到阈值」，本来就只够黄；红是**多类同时命中**
  // 的组合档 n3-ransom —— 那里 `destroyChecks` 还会把单条 yellow 过滤掉，单签名永远
  // 不会以 red 出现。抄成 red 的后果不是文案问题：切到 active 投影后这六类会悄悄变红，
  // 而影子模式因为采集点不喂常量行的严重度，全程看不到差异。
  { code: 'n3-exfil', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-exfil-match', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-high-freq-read', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-in-place', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-key-leak', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-mass-delete', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-mass-rename', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-ransom', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-seq-read-net', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-seq-read-spawn', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-spawn-net-match', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },
  { code: 'n3-write-amplify', semantic: 'assessment', severity: 'yellow', merge: 'code:subject', dismissable: true },
  { code: 'n3-write-then-delete', semantic: 'assessment', severity: 'red', merge: 'code:subject', dismissable: true },

  // ── 运行时健康：看不见 ≠ 没问题（coverage 语义）────────────────────────────────
  { code: 'hook-heartbeat', semantic: 'coverage', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'loopback-control', semantic: 'evidence', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'sentinel', semantic: 'coverage', severity: 'yellow', merge: 'none', dismissable: true },
  { code: 'vet-self-broken', semantic: 'evidence', severity: 'red', merge: 'none', dismissable: true },

  // ── 运行时规则表（runtime-classify）：严重度随 syscall 与路径变化 ────────────────
  { code: 'fs-destroy', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'fs-probe', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'fs-read', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'fs-write', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'honeypot', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'install-write', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'integrity', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'net-egress', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'persistence-write', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'spawn', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },

  // ── T1 哨兵：宿主进程级资源观测（主语是宿主，不是插件也不是 vet）────────────────
  { code: 'fd', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'fork', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'growth', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },
  { code: 'mem', semantic: 'evidence', severity: 'from-site', merge: 'none', dismissable: true },

  // ── 回执：N7 确认拦截 ───────────────────────────────────────────────────────
  { code: 'n7-block', semantic: 'receipt', severity: 'red', merge: 'none', dismissable: true },
]

/**
 * 查表。顺序敏感：先匹配带 `when` 的具体行，再落到无条件行。
 * 返回 `undefined` 表示这个码不在注册表里——调用方必须**照记不误**（丢告警是 fail-open），
 * 只是不能从表里推出合并/严重度，此时按 `none` + 采集点给的严重度处理。
 */
export function specFor(code: string, context: KindContext = {}): KindSpec | undefined {
  for (const spec of KIND_SPECS) {
    if (spec.code !== code) continue
    if (spec.when === undefined) return spec
    if (spec.when.official !== undefined && spec.when.official !== context.official) continue
    return spec
  }
  return undefined
}

const CODE_SET: ReadonlySet<string> = new Set(KIND_SPECS.map((s) => s.code))

/** 注册表里的全部 code（供 validate.ts 的 `knownCodes` 使用）。 */
export function knownCodes(): ReadonlySet<string> {
  return CODE_SET
}

/** 某个 code 的语义分类；未登记返回 `undefined`。 */
export function semanticOf(code: string): SemanticClass | undefined {
  return specFor(code)?.semantic
}

/** 由证据来源推导合并键前缀（施工图 §4 的 tier 映射，补齐 `sentinel→t1`）。 */
export function tierOfSource(source: string): AlarmTier {
  switch (source) {
    case 'local_scan':
      return 'scan'
    case 'runtime_hook':
      return 't2'
    case 'sentinel':
      return 't1'
    default:
      return 'obs'
  }
}
