import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import type { Context, Fiber } from '@deepseek-ai/cordis'
import type { ScanResponse } from '../scanner/protocol.js'
import type { VetConfig } from '../config.js'
import { scan, scanSync, scanBudget } from '../scanner/client.js'
import { listSourceFiles, listInstructionFiles, resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../package-meta.js'
import { isVetSelfPath } from '../pkg-root.js'
import { incrementScanned, incrementBlocked } from '../guard/stats.js'
import { hasAuditRecord, auditRequiredMessage, setArchiveIoWarn } from '../audit/archive.js'
import { withVetSelfIo, markOfficialTrusted } from '../guard/runtime-hooks.js'
import { capabilityDiff } from '../guard/capability-diff.js'
import { recordScan as recordVersionScan, consumeCapabilitiesTamper } from '../guard/version-diff.js'
import { recordScanSummary } from '../guard/scan-summaries.js'
import { isKnownBoundary, markKnownBoundary } from '../guard/known-boundaries.js'
import type { VetStatus } from '../guard/status.js'
import { computePackageHash, checkBaseline, recordBaseline, saveBaseline, getBaseline, consumeBaselineTamper, setRecordSuspected, isRecordSuspected } from './content-baseline.js'
import { verifyAgainstRegistry } from './registry-verify.js'
import { isOfficialPackageName, refreshOfficialCatalogFromRegistry } from './official-catalog.js'

/** typert loader 为 Fiber 附加的 entry 元数据（loader.ts:412 同款访问）。 */
type VetFiber = Fiber & { entry?: { options?: { name?: string } } }

/**
 * 0.3 档位观察抬升（round-16）：hardened/paranoid 下把 R17/R18/R19 的 info 观测报告为黄牌
 * （alarm-only；verdict 不变——静态层产出恒为 info 观测，这里只是把「已经看见的」抬到报警面，
 * 不改任何判定）。standard 档不产生任何额外报警。
 */
export interface ObservationAlarm {
  kind: 'r17-observation' | 'r18-observation' | 'r19-observation'
  message: string
}

export function observationAlarmsFor(
  findings: readonly { rule: string; severity: string; message?: string; evidence?: string }[],
): ObservationAlarm[] {
  const groups = new Map<string, { rule: string; n: number; sample: string }>()
  for (const f of findings) {
    if (f.severity !== 'info') continue
    if (f.rule === 'R17' || f.rule === 'R18' || f.rule === 'R19') {
      const g = groups.get(f.rule) ?? { rule: f.rule, n: 0, sample: '' }
      g.n += 1
      if (g.sample === '') g.sample = (f.evidence ?? f.message ?? '').slice(0, 80)
      groups.set(f.rule, g)
    }
  }
  const label: Record<string, string> = {
    R17: '!!js 配置注入观测',
    R18: '指令/技能注入观测',
    R19: '包名仿冒观测',
  }
  const out: ObservationAlarm[] = []
  for (const g of groups.values()) {
    const sample = g.sample !== '' ? `（例：${g.sample}）` : ''
    out.push({
      kind: (g.rule.toLowerCase() + '-observation') as ObservationAlarm['kind'],
      message: `${g.rule} ${label[g.rule]} ${g.n} 条${sample}`,
    })
  }
  return out
}

const RANK: Record<string, number> = { critical: 3, suspicious: 2, clean: 1 }
const DENY_RANK: Record<VetConfig['denyOn'], number> = { critical: 3, suspicious: 2 }

/**
 * 读取插件根目录的装机版本（P-1 档案精确匹配用）。包根在 ~/.dsh 下，
 * withVetSelfIo 直通，避免 .dsh 敏感段下每次装插件产出一条无主 fs-probe 自报警（P2-2）。
 */
function readInstalledVersion(root: string): string | undefined {
  return withVetSelfIo(() => {
    try {
      const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: unknown }
      return typeof pkg.version === 'string' && pkg.version !== '' ? pkg.version : undefined
    } catch {
      return undefined
    }
  })
}

/**
 * 提取包名（处理 rc.8 引入的子模块路径格式）。
 * - '@deepseek-ai/dsh-tool-subagent-control/list-agents' → '@deepseek-ai/dsh-tool-subagent-control'
 * - '@deepseek-ai/dsh-web-app' → '@deepseek-ai/dsh-web-app'
 * - '/path/to/file.mjs' → 原样返回（本地文件路径）
 */
function extractPackageName(packageName: string): string {
  // @scope/name/subpath 格式
  if (packageName.startsWith('@') && packageName.includes('/')) {
    const parts = packageName.split('/')
    // @scope/name 至少 3 段（@scope, name, 可能更多）
    if (parts.length >= 3) {
      return parts.slice(0, 2).join('/')
    }
  }
  // name/subpath 格式（非 scoped）
  if (!packageName.startsWith('@') && packageName.includes('/')) {
    // 检查是否是本地文件路径（以 / 或 ./ 开头）
    if (packageName.startsWith('/') || packageName.startsWith('./')) {
      return packageName  // 本地文件路径，原样返回
    }
    // npm 包名带子路径
    return packageName.split('/')[0]
  }
  return packageName
}

/** P-5 判定结果：官方包是否豁免；mismatch 携带上下文供 report 模式 registry 对账。
 * round-16 review（决策 1）：exempt 细分原因——first-seen/match 只豁免 deny 升级、
 * 仍跑静态扫描（TOFU 窗口修复）；allowlist/cordis builtin/内容基线关闭（用户显式选择）
 * 才完全跳过。
 * 0.3.5（M2）：first-seen/match 增带 hash/version——首见入锚验证（verifyFirstSeenOfficial）
 * 复用 classify 已算好的哈希，避免二次 computePackageHash（预算 10s/1000 文件）。 */
type OfficialVerdict =
  | { kind: 'exempt'; reason: 'cordis' | 'allowlist' | 'config-off' }
  | { kind: 'exempt'; reason: 'first-seen' | 'match'; hash?: string; version?: string }
  | { kind: 'not-official' }
  | { kind: 'mismatch'; version: string; hash: string; acknowledged: boolean }

/**
 * 官方包判定（P-5，0.1.21 重构）：内容哈希基线 + 已声明本机补丁。
 * - first-seen 自动信任并记录基线（v5 方案）→ 但仍跑扫描（决策 1，deny 升级豁免）；
 * - match 豁免 → 同样仍跑扫描（内容与记录一致，扫描结果留档/差分）；
 * - mismatch 且 hash 在 acknowledged-package-hashes 登记 → 豁免 + 一次性 yellow（透明不静默）；
 * - 其余 mismatch 不豁免：report 由调用方异步对账 registry 后定性（0.3.5：统一黄牌观察——
 *   用户决策「哈希对不上也只是黄，别红了——误报比漏报更消耗信任」；deny 模式零网络记黄）。
 * 0.3.5（M2，官方全集判据）：新增 inCatalog——官方目录（official-catalog）成员判定。
 * 目录外（@deepseek-ai/* 但官方全集没有的名字 = "多出来的那个"）不写信任锚（即使本地基线
 * match），黄牌观察由调用方在 observer 里补发；目录内 match 才入锚。 */
function classifyOfficial(packageName: string, packageRoot: string | undefined, config: VetConfig, status?: VetStatus, inCatalog = true): OfficialVerdict {
  // cordis builtin 命名空间（cordis:group 等框架内置分组入口，非可安装的第三方插件）——不扫描不审计
  if (packageName.startsWith('cordis:')) return { kind: 'exempt', reason: 'cordis' }
  if (config.allowlist.includes(packageName)) return { kind: 'exempt', reason: 'allowlist' }
  if (!packageName.startsWith('@deepseek-ai/')) return { kind: 'not-official' }
  if (!config.contentBaseline) return { kind: 'exempt', reason: 'config-off' }  // 配置关闭时维持旧行为
  if (packageRoot === undefined) return { kind: 'not-official' }  // 无法解析包根，不豁免

  // 官方包：内容哈希校验（P-5）
  // round-5 review（B-A4）：预算参数取函数默认值（content-baseline 单点维护），
  // 不再三处重复字面量（maxFiles/maxSizeBytes/timeoutMs 漂移即 DoS 口径分歧）。
  const hashResult = computePackageHash(packageRoot)
  if (hashResult === null) return { kind: 'not-official' }  // 超限/超时：不豁免
  const hash = hashResult.hash
  const version = readInstalledVersion(packageRoot) ?? 'unknown'
  const result = checkBaseline(packageName, version, hash, getBaseline())
  if (result === 'first-seen') {
    const store = getBaseline()
    recordBaseline(packageName, version, hash, store)
    // round-16 review（S10）：落盘失败不再静默——基线不落盘 = 每次加载都 first-seen
    // （严格全扫，安全方向，但性能退化 + 用户无感知）；黄色告警让事实可见。
    if (!saveBaseline(store)) {
      status?.record({
        id: 'baseline-save-fail:' + packageName,
        severity: 'yellow',
        source: 'scan',
        kind: 'baseline-save-fail',
        message: `官方包基线落盘失败（${packageName}@${version}）——磁盘满/权限问题？后续加载将重复首次全量判定`,
        target: packageName,
        pluginHint: packageName,
        at: Date.now(),
      })
    }
    // 首次见到：携带 hash/version 供调用方做首见入锚验证（verifyFirstSeenOfficial——
    // 目录内 + registry 字节一致 → 本进程即入内容信任锚，TOFU 窗口合上；不再强制等第二次 match）
    return { kind: 'exempt', reason: 'first-seen', hash, version }
  }
  if (result === 'match') {
    // round-16（SEC-1）：内容哈希与历史基线一致 → 写入官方信任锚（运行时防线抑制的
    // 真值源之一；first-seen 由 0.3.5 的 verifyFirstSeenOfficial 异步补锚）。
    // 0.3.5（M2）：目录外（冒充/官方新包）不给锚——名字不在官方全集，本地自证基线不作数。
    // 0.3.5（审查加固）：首见 registry 校验不一致的疑标（suspected）持久化后，本地自证
    // match 不再自动入锚——「哈希对不上只是黄」的黄必须粘滞，否则伪造包第二载即获运行时
    // 全域静默（首见黄牌一次性 + match 自证入锚 = 洞）。已登记 hash 的补丁 = 用户声明负责，
    // 照常入锚并黄牌提示；未登记 → 不入锚 + 每次会话黄牌，直到 ack 或字节更新为官方。
    if (inCatalog && isRecordSuspected(packageName, version)) {
      const ackList = config.acknowledgedPackageHashes[`${packageName}@${version}`] ?? []
      if (ackList.includes(hash)) {
        markOfficialTrusted(packageName)
        status?.record({
          id: `baseline-patch-ack:${packageName}`,
          severity: 'yellow',
          source: 'scan',
          kind: 'baseline-patch-ack',
          message: `官方包 ${packageName}@${version} 内容与官方 registry 不一致但已在 acknowledged-package-hashes 登记补丁（hash ${hash.slice(0, 12)}…）——内容信任锚按用户声明授予，请确保补丁来源可信`,
          target: packageName,
          pluginHint: packageName,
          at: Date.now(),
        })
      } else {
        status?.record({
          id: `official-match-suspected:${packageName}`,
          severity: 'yellow',
          source: 'scan',
          kind: 'official-match-suspected',
          message: `官方包 ${packageName}@${version} 首见 registry 校验不一致（本机字节 ≠ 官方 tarball），本地基线自证 match 不授予内容信任锚——如为本机合法补丁请在 acknowledged-package-hashes 登记 hash ${hash.slice(0, 12)}…；如为冒充/篡改请更新为官方字节后清除疑标`,
          target: packageName,
          pluginHint: packageName,
          at: Date.now(),
        })
      }
      return { kind: 'exempt', reason: 'match', hash, version }
    }
    if (inCatalog) markOfficialTrusted(packageName)
    return { kind: 'exempt', reason: 'match', hash, version }  // 内容一致，信任
  }
  const ackList = config.acknowledgedPackageHashes[`${packageName}@${version}`] ?? []
  return { kind: 'mismatch', version, hash, acknowledged: ackList.includes(hash) }
}

/**
 * mismatch 告警（deny 同步路径 / report 对账失败路径共用）。
 * 0.3.5（用户决策）：官方侧一律黄牌（不红）——哈希对不上先按「可能误报」对待，误报比漏报更
 * 消耗信任；第三方 P7 安装后基线（变更检测，高置信供应链信号）仍传 'red'。
 */
function recordMismatchAlarm(status: VetStatus | undefined, name: string, version: string, hash: string, why: string, severity: 'red' | 'yellow' = 'red'): void {
  status?.record({
    id: `baseline-mismatch:${name}`,
    severity,
    source: 'scan',
    kind: 'baseline-mismatch',
    message: `官方包 ${name}@${version} 内容哈希与基线不一致（${why}）。若为本机合法修改（如 LAN 补丁），在配置 acknowledged-package-hashes 登记 hash ${hash.slice(0, 12)}…；否则疑似供应链篡改`,
    target: name,
    pluginHint: name,
    at: Date.now(),
  })
}

/**
 * round-13（Phase 4）：第三方安装后完整性基线（P7 强化，默认关）。
 * 对非官方包记录首装内容哈希，后续加载同版本内容变化（字节不一致）→ red。
 * 复用 P-5 的 content-baseline 存储与 acknowledgedPackageHashes 豁免（用户本地 patch 零误报）。
 * 定位是"变更检测"而非信任锚：first-seen 自动信任仍有窗口（PLAN §5.2 明示），
 * 与 deny/requireAudit 叠加才有完整语义。无论结果如何都**不跳过静态扫描**（与官方包
 * exempt 语义不同——第三方包仍要过 verdict）。
 */
export function checkThirdPartyBaseline(packageName: string, packageRoot: string, version: string | undefined, config: VetConfig, status?: VetStatus): 'ok' | 'mismatch' | 'acknowledged' | 'first-seen' {
  if (config.thirdPartyBaseline !== true) return 'ok'
  const hashResult = computePackageHash(packageRoot)
  if (hashResult === null) return 'ok' // 超限/超时：不参与（静默，不阻断）
  const v = version ?? 'unknown'
  const store = getBaseline()
  const result = checkBaseline(packageName, v, hashResult.hash, store)
  if (result === 'first-seen') {
    recordBaseline(packageName, v, hashResult.hash, store)
    // S10：落盘失败可见（磁盘满/权限）；基线不落盘 = 每次加载重复 first-seen 判定（安全方向）
    if (!saveBaseline(store)) {
      status?.record({
        id: 'baseline-save-fail:' + packageName,
        severity: 'yellow',
        source: 'scan',
        kind: 'baseline-save-fail',
        message: `第三方包基线落盘失败（${packageName}@${v}）——后续加载将重复首次判定`,
        target: packageName,
        pluginHint: packageName,
        at: Date.now(),
      })
    }
    return 'first-seen'
  }
  if (result === 'match') return 'ok'
  const ackList = config.acknowledgedPackageHashes[`${packageName}@${v}`] ?? []
  if (ackList.includes(hashResult.hash)) {
    status?.record({
      id: `third-party-patch-ack:${packageName}`,
      severity: 'yellow',
      source: 'scan',
      kind: 'baseline-patch-ack',
      message: `第三方包 ${packageName}@${v} 内容与首装基线不同但已在 acknowledged-package-hashes 登记（hash ${hashResult.hash.slice(0, 12)}…）——豁免基线比对，请确保变更来源可信`,
      target: packageName,
      pluginHint: packageName,
      at: Date.now(),
    })
    return 'acknowledged'
  }
  recordMismatchAlarm(status, packageName, v, hashResult.hash, '第三方包内容被修改（首装基线不一致，P7 形态）')
  return 'mismatch'
}

/**
 * report 模式 registry 对账（0.1.21）：npm 同版本发布内容不可变 = 内容真值。
 * - 本机字节 == registry → 基线陈旧（记录早于官方发布/来自开发通道），刷新基线 + yellow；
 * - 本机字节 != registry → 非官方修改（0.3.5：黄牌观察，不再红——用户决策「哈希对不上
 *   也只是黄，别红了」；误报比漏报更消耗信任）；
 * - 对账不可用 → 黄牌（fail-open，提示可登记补丁；不再红——对账不可用 ≠ 篡改坐实）。
 */
async function reconcileMismatch(status: VetStatus | undefined, name: string, verdict: Extract<OfficialVerdict, { kind: 'mismatch' }>): Promise<void> {
  const v = await verifyAgainstRegistry(name, verdict.version)
  if (v.status === 'resolved' && v.officialHash === verdict.hash) {
    const store = getBaseline()
    recordBaseline(name, verdict.version, verdict.hash, store)
    // round-16（SEC-1）：本机字节 == 官方 registry tarball → 内容验证通过，登记官方信任锚
    // （运行时防线抑制的真值源之一；registry-verify 自身不感知本机 hash，故信任登记在
    // 「哈希相等」成立的本分支——resolved 但字节不一致是坐实篡改，绝不能给信任）
    markOfficialTrusted(name)
    // 0.3.5（审查加固）：字节已与官方一致 → 清除疑标（若此前置位）
    setRecordSuspected(name, verdict.version, false)
    if (!saveBaseline(store)) {
      status?.record({
        id: 'baseline-save-fail:' + name,
        severity: 'yellow',
        source: 'scan',
        kind: 'baseline-save-fail',
        message: `官方包基线刷新后落盘失败（${name}@${verdict.version}）——磁盘满/权限问题？`,
        target: name,
        pluginHint: name,
        at: Date.now(),
      })
    }
    status?.record({
      id: `baseline-refreshed:${name}`,
      severity: 'yellow',
      source: 'scan',
      kind: 'baseline-refreshed',
      message: `官方包 ${name}@${verdict.version} 本机字节与官方 registry 一致——原基线记录已过期，已自动刷新（此前 baseline-mismatch 为基线陈旧，非篡改）`,
      target: name,
      pluginHint: name,
      at: Date.now(),
    })
    return
  }
  if (v.status === 'resolved') {
    recordMismatchAlarm(status, name, verdict.version, verdict.hash, '与官方 registry 字节也不一致', 'yellow')
    // 0.3.5（审查加固）：registry 坐实本机 ≠ 官方 → 置疑标（后续 match 自证不再入锚）
    setRecordSuspected(name, verdict.version, true)
  } else {
    recordMismatchAlarm(status, name, verdict.version, verdict.hash, `registry 对账不可用：${v.detail ?? 'unknown'}`, 'yellow')
  }
}

/**
 * 0.3.5（M2 首见入锚验证）：目录内官方包 first-seen 时异步对账官方 registry——
 * 本机字节 == 官方 tarball → **首见即入内容信任锚**（TOFU 窗口合上，官方家务不再等
 * 第二次加载 match 才静默）；不一致 → 黄牌观察 + 基线疑标（suspected，持久——match
 * 自证不再入锚，见 classifyOfficial）；对账不可用（离线/网络失败）→ 静默维持
 * first-seen 观察（运行时 Tier B info 地板兜噪，不打扰；疑标不置位）。
 * 仅 report 模式调用（P2-7：deny 同步路径零网络）。classifyOfficial 首次见到时已把
 * 哈希记入基线并随 verdict 返回 hash/version（见 OfficialVerdict），此处复用不重复计算。
 */
async function verifyFirstSeenOfficial(
  status: VetStatus | undefined,
  name: string,
  version: string,
  localHash: string,
): Promise<void> {
  await withVerifySlot(async () => {
    const v = await verifyAgainstRegistry(name, version)
    if (v.status !== 'resolved') return // 离线/不可用：维持观察（fail-open，绝不误伤）
    if (v.officialHash !== localHash) {
      status?.record({
        id: `official-verify-mismatch:${name}`,
        severity: 'yellow',
        source: 'scan',
        kind: 'official-verify-mismatch',
        message: `官方包 ${name}@${version} 首见内容与官方 registry 不一致——疑为官方包被修改或本机补丁；黄牌观察不拦截，可在 acknowledged-package-hashes 登记补丁或联系核对`,
        target: name,
        pluginHint: name,
        at: Date.now(),
      })
      // 审查加固：疑标持久化——下次加载的本地基线自证 match 不再自动授予内容信任锚
      // （黄必须粘滞，否则伪造包第二载即获运行时全域静默）；落盘失败 fail-open（下次加载
      // 重新首见校验路径，黄牌重来一次，安全方向不损失）。
      setRecordSuspected(name, version, true)
      return
    }
    // 本机字节 == 官方 registry：内容验证通过 → 登记信任锚（无需等第二次 match）；
    // 疑标在位时顺带清除（字节已更新为官方）。
    markOfficialTrusted(name)
    setRecordSuspected(name, version, false)
    status?.record({
      id: `official-verified:${name}`,
      severity: 'info',
      source: 'scan',
      kind: 'official-verified',
      message: `官方包 ${name}@${version} 首见验证通过（本机字节与官方 registry 一致）——已纳入内容信任锚`,
      target: name,
      pluginHint: name,
      at: Date.now(),
    })
  })
}

/**
 * 0.3.5（审查加固）：首见 registry 验证的并发限流——全新 profile 首批官方包逐包 verify
 * （2 fetch + tar 解包），无界并发会在启动期造成网络/CPU 突发；小池限 4，超限排队。
 */
const VERIFY_MAX_CONCURRENCY = 4
let verifyActive = 0
const verifyWaiters: Array<() => void> = []
async function withVerifySlot<T>(fn: () => Promise<T>): Promise<T> {
  if (verifyActive >= VERIFY_MAX_CONCURRENCY) {
    await new Promise<void>((resolve) => { verifyWaiters.push(resolve) })
  }
  verifyActive += 1
  try {
    return await fn()
  } finally {
    verifyActive -= 1
    verifyWaiters.shift()?.()
  }
}

/**
 * C2 边界提示的会话级去重（0.1.20 引入，0.3.3 升级）：
 * ESM 具名导入的 T2 不覆盖是架构性限制（C2 边界），反复提醒只会造成警报疲劳。
 * 0.3.3（P3 持久化状态化去重）：主去重层移到 known-boundaries 落盘（(kind, pkg,
 * version, capabilitiesHash) 版本不变不重报）；本 Map 保留两层兜底语义——
 * - known 落盘失败时（此时 isKnownBoundary 恒 false）防会话内同能力刷屏；
 * - 记录值 = 上次已报的 capabilitiesHash：能力差分变化时（hash 不同）允许重报，
 *   与 N6 差分同一变化源（「版本/能力未变不重报，变化才重启」在两级去重下都成立）。
 */
const esmGuardReported = new Map<string, string>()

/** 能力清单的确定性指纹（P3 变化源）：结构化序列化 + sha256。CLI 工具/测试可复用。 */
export function hashCapabilities(capabilities: unknown): string {
  return createHash('sha256').update(JSON.stringify(capabilities ?? null)).digest('hex')
}

/**
 * round-5 review（A#14）：重复 apply 防叠——DSH 配置热重载对同一 ctx 重复 apply 时
 * 旧 ctx 的监听器不保证被自动清理（与 runtime-guard 的 prevGuardDisposer 同款认知），
 * 叠加会让每个插件触发 N 次扫描/审计判定。模块级记住上一个 off，重新装配前先卸。
 */
let prevPluginListenerOff: (() => void) | undefined

/**
 * internal/plugin 守卫：新装 npm 包自动静态扫描。
 * - dispose 发射（fiber.uid === null）与 entry-less（child/manual）直接忽略（B1）；
 * - report 模式：异步扫描 + 日志；deny 模式：同步扫描（scanSync），命中即同步抛错回滚挂载。
 */
export function installInternalPluginGuard(ctx: Context, config: VetConfig, status?: VetStatus): void {
  prevPluginListenerOff?.()
  // P6（0.3.3）：启动扫描 C2 边界汇总——官方包边界观察按 info 聚合一条 + 三方包黄色
  // 警报的计数，防抖输出一行话（避免每包一条刷屏、也让「14 官方包同一 C2 边界」的
  // 合并认知可见：不是 14 处风险，是 1 处架构边界 × 14 包）。
  const bootBoundary = { official: 0, third: 0 }
  let boundarySummaryTimer: ReturnType<typeof setTimeout> | undefined
  const scheduleBoundarySummary = (): void => {
    if (boundarySummaryTimer !== undefined) clearTimeout(boundarySummaryTimer)
    boundarySummaryTimer = setTimeout(() => {
      boundarySummaryTimer = undefined
      const { official, third } = bootBoundary
      if (official + third === 0) return
      ctx.logger.info(
        `vet: 启动扫描 C2 边界汇总——官方包 ${official} 个（info 观察，面板折叠为一条；详情见插件页/营养标签），第三方包 ${third} 个（黄色警报：版本/能力差分变化才重报）`,
      )
    }, 800)
    boundarySummaryTimer.unref?.()
  }
  // S9：档案目录不可读告警接线（一次性，注入即可）
  setArchiveIoWarn((msg) => {
    try {
      ctx.logger.warn(msg)
    } catch {
      // 日志失败不影响主流程
    }
  })
  prevPluginListenerOff = ctx.on('internal/plugin', (fiber: Fiber) => {
    const vetFiber = fiber as VetFiber
    if (fiber.uid === null) return
    const rawEntryName = vetFiber.entry?.options?.name
    if (typeof rawEntryName !== 'string') return
    // rc.8 起部分插件 entryName 带子模块路径（如 @deepseek-ai/dsh-tool-subagent-control/list-agents），
    // 提取包名用于解析/豁免/档案匹配，保留原始名用于日志
    const entryName = extractPackageName(rawEntryName)
    if (!config.autoScan) return

    // DSH 把插件装进 profile 的 node_modules（vet 可能被符号链接，realpath 解析不到）→
    // 用 loader 的解析基准（ctx.baseUrl = profile 目录）定位第三方插件根目录。
    // P-1：提前解析——requireAudit 需要装机版本做档案精确匹配（升级后旧档案不放行），
    // 扫描复用同一 root，避免重复 resolve。
    const profileDir = (ctx as { baseUrl?: string }).baseUrl
    const root = resolvePackageRoot(entryName, profileDir)
    // round-5 review（B-A1）：vet 自身豁免按「身份」而非「名字」——同名冒名包
    // （恶意 tarball 把 name 写成 @jieai/dsh-plugin-vet）此前直接 return 跳过
    // autoScan/requireAudit/三方基线全部检查（与 scan-plugin 的 isSelfPackage realpath
    // 校验不对称）。root 解析失败（vet 为 bundle 形态，不在 profile node_modules）→
    // 按本体豁免（保守：bundle 是 vet 自身）；解析成功则必须 realpath 命中本体才豁免，
    // 冒名包继续走完整检查与扫描（verdict 判定）。
    // round-16（SA2-6）：root===undefined 不再豁免——「名字 + 无法解析的根」同样可以是
    // 冒名构造（损坏 package.json / 非常规安装位置），身份无法自证时名字匹配不作数；
    // 换为「root 可解析且 realpath 命中 vet 本体」唯一豁免形态。
    if (entryName === PACKAGE_NAME && root !== undefined && isVetSelfPath(root)) return
    const installedVersion = root === undefined ? undefined : readInstalledVersion(root)

    // P-5：官方包内容哈希判定（0.1.21：report 模式 mismatch 异步对账 registry 定性）
    // round-16 review（决策 1）：first-seen/match 不再完全跳过——静态扫描是唯一能识别
    // 伪造官方名的确定性检查（自生哈希基线首见即记录，挡不住伪装 tarball）；只豁免
    // deny 升级。allowlist/cordis builtin/config-off（用户显式选择关闭）仍完全跳过。
    // 0.3.5（M2，官方全集判据）：目录成员判定——名字在官方全集（seed ∪ registry 覆盖层）里
    // 才算可信官方名候选；目录外多出来的 @deepseek-ai/* = 冒充官方，或官方新包尚未纳入目录。
    // 集外的一律不入内容信任锚（即使本地基线自证 match）；给出黄牌观察 + 有界 registry 核对。
    const inCatalog = entryName.startsWith('@deepseek-ai/') && isOfficialPackageName(entryName)
    const official = classifyOfficial(entryName, root, config, status, inCatalog)
    // 集外官方名：黄牌观察（不拦、不入锚、不静默）——「多出来的那个」。捕获时惰性触发一次
    // 有界 registry scope 核对（不在启动出网；deny 模式零网络 P2-7）；核对后确认真官方 →
    // 纳入目录覆盖层并补一次首见验证（锚定与 info 提示）。
    // allowlist/config-off（用户显式选择）不触发——用户已表态，不再叠加黄牌噪音。
    const optOutByUser = official.kind === 'exempt'
      && (official.reason === 'allowlist' || official.reason === 'config-off' || official.reason === 'cordis')
    if (entryName.startsWith('@deepseek-ai/') && !inCatalog && !optOutByUser) {
      // 0.3.5（审查修正）：deny 模式零网络（P2-7 同步路径）不触发 registry 核对——文案按
      // 模式分流，不再对 deny 用户声称「已触发核对」。
      const reconcileNote = config.mode === 'deny'
        ? 'deny 模式零网络不自动核对（可切 report 模式核对确认）'
        : '将自动核对并入目录'
      status?.record({
        id: 'official-not-in-catalog:' + entryName,
        severity: 'yellow',
        source: 'scan',
        kind: 'official-not-in-catalog',
        message: `官方目录外的 @deepseek-ai 包名（${entryName}）——要么是官方新包尚未纳入目录（${reconcileNote}），要么是冒充官方名的包（不拦截，仅黄牌观察）`,
        target: entryName,
        pluginHint: entryName,
        at: Date.now(),
      })
      if (config.mode !== 'deny') {
        void refreshOfficialCatalogFromRegistry().then((merged) => {
          if (!merged.has(entryName)) return
          // 核对后已纳入目录：补首见验证（哈希一致 → 本进程入锚）或 info 提示
          if (official.kind === 'exempt' && (official.reason === 'first-seen' || official.reason === 'match')
            && official.hash !== undefined && official.version !== undefined) {
            void verifyFirstSeenOfficial(status, entryName, official.version, official.hash)
          } else {
            status?.record({
              id: 'official-catalog-merged:' + entryName,
              severity: 'info',
              source: 'scan',
              kind: 'official-catalog-merged',
              message: `官方包 ${entryName} 已通过 registry 核对确认并在官方目录中登记（覆盖层）——此前 official-not-in-catalog 黄牌可忽略`,
              target: entryName,
              pluginHint: entryName,
              at: Date.now(),
            })
          }
        }).catch(() => {
          // 核对网络异常：静默——维持黄牌观察（fail-open，不误伤）
        })
      }
    }
    // 首见入锚验证（M2）：目录内官方包 first-seen → report 模式异步对账 registry，字节一致
    // 即入锚——TOFU 窗口合上；离线/失败静默回退（Tier B info 地板兜噪）。mismatch 走下方既有
    // acknowledge/对账路径（已降黄）。
    if (inCatalog && official.kind === 'exempt' && official.reason === 'first-seen'
      && config.mode !== 'deny' && official.hash !== undefined && official.version !== undefined && official.version !== 'unknown') {
      void verifyFirstSeenOfficial(status, entryName, official.version, official.hash).catch(() => {
        // 对账异常静默（不影响加载主流程）
      })
    }
    if (official.kind === 'exempt') {
      if (official.reason === 'cordis' || official.reason === 'allowlist' || official.reason === 'config-off') return
      // reason ∈ first-seen/match：继续走下方扫描路径（deny 升级豁免，扫失败也不拦截）
    }
    // 0.3.5（M2）注：集外官方名（冒充/未核对）不额外新增拦截——deny 升级豁免沿用 round-16
    // 语义（first-seen/match 豁免 deny 升级），用户口径「本来就不拦」：冒充由「不入内容信任锚
    // + 黄牌观察 + 静态扫描」暴露，不靠运行时拦截。
    const officialDenyExempt = official.kind === 'exempt'
    if (official.kind === 'mismatch') {
      if (official.acknowledged) {
        const alertId = `baseline-patch-ack:${entryName}`
        // round-15 review（持久化忽略跨 session 可恢复修复）：不再前置短路——
        // 照常 record，由 VetStatus 按 isDismissed 折叠进「已忽略」区（旧行为：
        // 被忽略后干脆不入列 → 跨 session 彻底消失且无恢复入口）
        status?.record({
          id: alertId,
          severity: 'yellow',
          source: 'scan',
          kind: 'baseline-patch-ack',
          message: `官方包 ${entryName}@${official.version} 处于已声明的本机补丁状态（hash ${official.hash.slice(0, 12)}… 已在配置 acknowledged-package-hashes 登记）——豁免基线比对；请确保补丁来源可信`,
          target: entryName,
          pluginHint: entryName,
          at: Date.now(),
        })
        return
      }
      if (config.mode === 'deny') {
        // deny：同步记黄（不做网络对账——同步路径零网络，P2-7 同款约束；0.3.5 降黄不红）
        recordMismatchAlarm(status, entryName, official.version, official.hash, 'deny 模式不做网络对账', 'yellow')
      } else {
        // report：异步对账官方 registry 再定性（红 / 基线刷新黄）；独立于扫描路径，
        // 即使后续 files 为空提前返回也不会丢警报
        void reconcileMismatch(status, entryName, official).catch((error: unknown) => {
          ctx.logger.error(`vet: registry 对账失败 ${entryName}: ${String(error)}`)
          recordMismatchAlarm(status, entryName, official.version, official.hash, 'registry 对账异常', 'yellow')
        })
      }
    }

    // round-13（Phase 4）：第三方安装后完整性基线（默认关）——非官方包也做内容哈希对账，
    // 但**不豁免扫描**（第三方包仍要静态 verdict；与官方 exempt 语义不同）
    if (official.kind === 'not-official' && config.thirdPartyBaseline === true && root !== undefined) {
      checkThirdPartyBaseline(entryName, root, installedVersion, config, status)
    }

    // D30 强制层：requireAudit 开启时，无健康档案的第三方插件在加载时被拦截（deny）/报警（report）。
    // 门槛独立于包解析与扫描——档案存在与否只取决于 agent 是否按协议审查过。
    // round-17 修正（官方包告警风暴）：门槛严格限第三方——官方包（first-seen/match）的门槛是
    // 内容哈希基线 + 静态扫描（决策 1：首见也全扫、只豁免 deny 升级），不要求人工落盘审计档案；
    // round-16 放开官方包跳过路径后，requireAudit:true 的用户在 DSH 自带官方插件加载时会收到
    // 一屏 audit-required（文档口径本就是「第三方插件」，与 round-16 前 exempt 短路行为一致）。
    if (config.requireAudit && official.kind === 'not-official' && !hasAuditRecord(entryName, installedVersion)) {
      const msg = auditRequiredMessage(entryName)
      ctx.logger.warn(msg)
      const alertId = `audit-required:${entryName}`
      // round-15 review（持久化忽略可恢复修复）：同 baseline-patch-ack——不短路，
      // 入列后由 VetStatus 折叠进「已忽略」区（可恢复；旧行为跨 session 静默消失）
      // alarm-only：未审计插件只记录黄色告警（观测/警报），不拦截——除非用户显式选择 deny。
      status?.record({
        id: alertId,
        severity: 'yellow',
        source: 'scan',
        kind: 'audit-required',
        message: msg,
        target: entryName,
        pluginHint: entryName,
        at: Date.now(),
      })
      if (config.mode === 'deny') {
        incrementBlocked()
        void fiber.dispose()
        throw new Error(msg)
      }
    }

    // P0-4：扫描与后处理拆分——deny 用同步 scanSync（observer 内需要同步抛错回滚挂载），
    // report 用异步 scan()（spawn 子进程不阻塞事件循环；旧实现 report 也走 scanSync，
    // async IIFE 包不住同步阻塞，大包扫描会冻结整个 DSH 最长 scannerTimeoutMs）。
    const finish = (res: ScanResponse): void => {
      if (!res.ok || res.report === undefined) {
        // M9：deny 模式扫描失败必须 fail-closed（拦截 + 告警），否则恶意包可借
        // 扫描超时/异常静默放行；report 模式记录告警（扫描器失活本身是异常信号）
        const msg = `vet: 扫描失败 ${entryName}：${res.error ?? 'unknown'}`
        ctx.logger.error(msg)
        status?.record({
          id: `scan-fail:${entryName}`,
          severity: 'yellow',
          source: 'scan',
          kind: 'scan-fail',
          message: msg,
          target: entryName,
          pluginHint: entryName,
          at: Date.now(),
        })
        // round-16 review（决策 1）：官方包（first-seen/match）扫描失败只记告警不拦截——
        // 官方信任锚豁免 deny 升级；第三方仍 fail-closed（M9：恶意包可借扫描超时/异常静默放行）
        if (config.mode === 'deny' && !officialDenyExempt) {
          incrementBlocked()
          void fiber.dispose()
          throw new Error(`vet: 扫描失败，拒绝加载 ${entryName}（fail-closed）`)
        }
        return
      }
      const { verdict, staticScore } = res.report
      ctx.logger.info(`vet: auto-scan ${entryName} → ${verdict} (${staticScore})`)
      status?.noteScan({ pluginName: entryName, verdict, staticScore, at: Date.now() })
      // P2：扫描摘要留档（详情页规则墙/OSV 行 + 「最近插件」列表数据源）。
      // 变化才落盘（verdict/版本/规则码集合），同版同结论重扫不重写（防写放大）。
      const findingsAll = res.report.findings ?? []
      recordScanSummary({
        name: entryName,
        ...(installedVersion !== undefined ? { version: installedVersion } : {}),
        at: Date.now(),
        verdict,
        staticScore,
        sourceCount: res.report.sourceCount,
        ruleCodes: [...new Set(findingsAll.map(f => f.rule))],
        // OSV 命中在报告里是 rule='OSV' 的 finding（scanner-bin checkOsv）
        ...(findingsAll.some(f => f.rule === 'OSV') ? { osv: findingsAll.find(f => f.rule === 'OSV')?.message } : {}),
      })
      // 0.3（档位）：hardened/paranoid 抬升 R17/R18/R19 的 info 观测为黄牌（alarm-only，verdict 不变；
      // 按 kind+插件聚合，重复扫描合并计数，不刷缓冲）
      if ((config.profile ?? 'standard') !== 'standard') {
        for (const obs of observationAlarmsFor(res.report.findings ?? [])) {
          status?.record({
            id: 'obs:' + obs.kind + ':' + entryName,
            severity: 'yellow',
            source: 'scan',
            kind: obs.kind,
            message: obs.message,
            target: entryName,
            pluginHint: entryName,
            mergeKey: 'obs:' + obs.kind + ':' + entryName,
            at: Date.now(),
          })
        }
      }
      // 0.1.20：防御统计——扫描计数
      incrementScanned()
      // N1：注册静态能力清单（声明侧）——T2 观测与此对账，差分出隐藏能力
      capabilityDiff.registerStatic(entryName, res.report.capabilities)
      // N6：版本行为差分——同名异版清单对比，新增敏感能力 → info(蓝)/red 报警（首次记录只存不报）
      // 0.3.6：mergeKey 聚合——升级类报警（upgrade-diff/upgrade-cold）折叠为一行、跨包累计
      // count（DSH 模块化升级一次升几十个官方包，逐包一行会刷满 20 槽缓冲）；status.ts 合并
      // 时 severity 取高（任一 red 组合 → 整行 red），普通新增 → info 蓝色，不参与盾牌
      // level/alarmCount。dismiss 同样按 mergeKey：一次忽略 = 整桶升级观察折叠。
      const nav = recordVersionScan(entryName, installedVersion, res.report.capabilities)
      if (nav.alarm !== null) {
        status?.record({
          id: 'upgrade-diff:' + entryName + ':' + (nav.from ?? 'cold') + ':' + nav.to,
          severity: nav.alarm.severity,
          source: 'scan',
          kind: nav.alarm.kind,
          message: nav.alarm.message,
          target: entryName,
          pluginHint: entryName,
          mergeKey: 'scan:upgrade',
          at: Date.now(),
        })
      }
      // M7（0.1.16 加固）：vet 存储被进程内插件改写（capabilities/baseline hash 与自写不符）→ yellow
      if (consumeCapabilitiesTamper() || consumeBaselineTamper()) {
        status?.record({
          id: 'vet-store-tamper',
          severity: 'yellow',
          source: 'scan',
          kind: 'vet-store-tamper',
          message: 'vet 存储文件被外部改写（capabilities.json/baseline.json 与 vet 自写内容不一致）——疑似进程内插件篡改 vet 状态，升级差分/基线保护可能已失效（M7）',
          target: '~/.dsh/vet',
          at: Date.now(),
        })
      }
      // C2（0.1.16 加固）：插件使用内建模块的 ESM 具名导入 → T2 钩子对该绑定不生效（Node 快照互操作），
      // 运行时防线仅剩 T1 哨兵——显式提示边界，不静默
      // 0.1.20：session 级去重（架构性限制反复提醒 = 警报疲劳）；0.3.2 用户侧实测（14 官方包 +
      // 1 fs-probe 黄色警报重启必复现、不可消解）→ 0.3.3 呈现层重构（P1/P2/P3）：
      // - 官方包（内容信任锚 first-seen/match）：coverage 类观察降为 info——官方锚语义 =
      //   接受其架构事实，呈现层不再把「已知边界」当风险从报（round-16 官方豁免的呈现级联
      //   兑现；检测/留档层未关闭：插件详情页、营养标签持续可见，N6 升级差分照常重报）；
      //   mergeKey 跨包折叠为一条聚合（count 累计），不计 alarmCount、不参与 level；
      // - 三方包（含 mismatch 未确认的官方名——未验证即不享信任呈现）：维持 yellow（这条
      //   边界正是三方审计价值所在），升级为持久化状态化去重（P3）：(kind, pkg, version,
      //   capabilitiesHash) 落盘，版本/能力未变不重报；能力差分变化（唯一有信息量场景）重报。
      if (res.report.capabilities?.esmNamedBuiltins === true && config.runtimeGuard === 'watch') {
        const alertId = 'esm-guard-coverage:' + entryName
        // 走到 finish 的官方豁免只可能是 first-seen/match（cordis/allowlist/config-off 已提前 return；
        // mismatch 未确认不给信任呈现）
        const officialTrusted = official.kind === 'exempt'
        if (officialTrusted) {
          status?.record({
            id: alertId,
            severity: 'info',
            source: 'scan',
            kind: 'esm-guard-coverage',
            message: `官方包 ${entryName} 使用内建模块 ESM 具名导入（fs/child_process/网络）——内容信任锚内的已知架构边界（C2：T2 钩子对该绑定不生效，Node 互操作快照；运行时防线仅剩 T1 哨兵与审计协议）。此为观察提示非风险报警；详情见插件详情页与营养标签`,
            target: entryName,
            pluginHint: entryName,
            mergeKey: 'scan:esm-guard-coverage:official',
            at: Date.now(),
          })
          bootBoundary.official += 1
          scheduleBoundarySummary()
        } else {
          // 三方包：P3 持久化去重（版本/能力差分未变 → 不重报；known 落盘失败时 session Map 兜底）
          const v = installedVersion ?? 'unknown'
          const capHash = hashCapabilities(res.report.capabilities)
          if (!isKnownBoundary('esm-guard-coverage', entryName, v, capHash)) {
            markKnownBoundary('esm-guard-coverage', entryName, v, capHash)
            if (esmGuardReported.get(entryName) !== capHash) {
              esmGuardReported.set(entryName, capHash)
              status?.record({
                id: alertId,
                severity: 'yellow',
                source: 'scan',
                kind: 'esm-guard-coverage',
                message: entryName + ' 使用内建模块 ESM 具名导入（fs/child_process/网络）——T2 运行时钩子对该绑定不生效（Node 互操作快照，C2 边界），运行时防线仅剩 T1 哨兵与审计协议',
                target: entryName,
                pluginHint: entryName,
                at: Date.now(),
              })
              bootBoundary.third += 1
              scheduleBoundarySummary()
            }
          }
        }
      }
      // round-15 review（A#15 对齐）：unknown verdict 的 deny 判定——verdict 来自扫描器协议，
      // 若漂移/被替换产生未知字符串，RANK[verdict] undefined >= n 恒 false → deny 静默
      // 失效（fail-open）。与 tool-execute.ts A#15、gate.ts 同款纪律：不可判定 = 拦截。
      // round-16 review（决策 1）：官方包（first-seen/match）豁免 deny 升级（官方信任锚
      // 不因静态 verdict 拦截；扫描结果照常留档/差分/观测告警）。
      if (config.mode === 'deny' && !officialDenyExempt &&
          (verdict === undefined || !(verdict in RANK) ? true : RANK[verdict] >= DENY_RANK[config.denyOn])) {
        incrementBlocked()
        void fiber.dispose()
        throw new Error(`vet: 拦截 ${entryName}（${verdict}）`)
      }
    }

    // round-16（SA2-6）：root 解析失败（包不在任一解析基准链上/package.json 损坏）——
    // requireAudit / 三方基线等身份无关的检查已在上方执行完毕；此处是扫描门禁尾巴：
    // deny 模式对「无法解析根的包」必须 fail-closed（此前直接 return 静默放行——该类包
    // 逃脱静态门禁；根无法解析正是冒名者可能的构造形态：claimed 名与实际安装位置分离）。
    // 例外（D30 契约）：requireAudit 开启且已有健康档案 = 人工审查放行（档案是人的批准，
    // 无根时这是唯一的信任信号；保守维持既有契约）；无档案或 requireAudit 关闭 → 拦截。
    // vet 自身条目（非常规布局无法自证身份）不拦截——拦截会让引导承载方随 vet 一起失败，
    // 但同样不豁免（上方身份豁免已收窄到 realpath 命中）。
    if (root === undefined) {
      const audited = config.requireAudit === true && hasAuditRecord(entryName, undefined)
      if (config.mode === 'deny' && entryName !== PACKAGE_NAME && !audited) {
        incrementBlocked()
        void fiber.dispose()
        throw new Error(`vet: 无法定位 ${entryName} 的包根（resolvePackageRoot 失败）——deny 模式拒绝加载（fail-closed）`)
      }
      return
    }
    const files = listSourceFiles(root)
    // round-12（R17/R18 扫描面扩展）：配置面已由 listSourceFiles 根级配置名带出；
    // 指令/技能文件按 config.scanSurface.instructionFiles 追加（默认开）
    const surfaceFiles = config.scanSurface?.instructionFiles === false
      ? files
      : [...files, ...listInstructionFiles(root)]
    if (surfaceFiles.length === 0) return
    const request = {
      kind: 'files' as const,
      files: surfaceFiles,
      osv: config.osvCheck === true,
      // surface 显式传入（与缓存 key 联动）：关闭的面不参与扫描也不命中旧形状缓存
      ...(config.scanSurface !== undefined ? { surface: { configFiles: config.scanSurface.configFiles, instructionFiles: config.scanSurface.instructionFiles } } : {}),
    }
    // P2-5：engine 的扫描预算 = files×2s；守卫超时若小于它，大包会在 engine 发出 R8-skip 前
    // 被 kill → 扫描静默失败。超时按文件数放大（上限 60s，round-5 review B-A5 收敛 scanBudget），
    // 让 engine 能优雅降级而不是被杀。
    const scanTimeoutMs = scanBudget(files.length, config.scannerTimeoutMs)

    if (config.mode === 'deny') {
      // 同步路径：observer 内同步抛错才能让 cordis 回滚挂载（拦截语义必须同步）
      // P2-7：同步路径剔除 OSV——spawnSync 冻结宿主期间 OSV 网络查询（每包最多 4s）
      // 会成倍放大冻结；deny 判定只依据确定性静态扫描（OSV 是网络增强，留在 report 异步路径）。
      // 超时封顶 30s（engine 自身按文件预算优雅降级 R8-skip；此前按文件数放大到 60s）。
      // 超时/失败仍走 fail-closed（M9 反扫描规避：恶意大包可借扫描超时静默放行——
      // 拒绝加载是安全方向；已被 report 模式扫描过的包命中缓存，deny 秒回）。
      const res = scanSync({ ...request, osv: false }, { timeoutMs: Math.min(scanTimeoutMs, 30_000) })
      finish(res)
      return
    }
    // report 异步路径：spawn 子进程不阻塞事件循环（P0-4 修复——旧实现 report 也走 scanSync，
    // 大包扫描会冻结整个 DSH 最长 scannerTimeoutMs）。返回 promise 便于测试 await 扫描完成。
    return (async () => {
      try {
        const res = await scan(request, { timeoutMs: scanTimeoutMs })
        finish(res)
      } catch (error) {
        ctx.logger.error(String(error))
      }
    })()
  })
}