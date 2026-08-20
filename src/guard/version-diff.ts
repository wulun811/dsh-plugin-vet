/**
 * N6 版本行为差分（Upgrade Behavioral Diff）。
 * 靶子 G4：供应链投毒几乎都发生在"老包的新版本"——每版独立扫描看不到"这一版比上一版多要了什么"。
 * 本模块把 N1 的静态能力清单（CapabilityManifest，声明侧）按 `name@version` 记入本地存储，
 * 同一包出现新版本时与该包上一个版本（按 recordedAt 选取，不引入 semver 依赖）的能力清单做
 * 纯本地 JSON 差分：**只报"能力变了"**（新增敏感能力 → yellow/red），不报"代码变了"。
 * 完全离线、alarm-only（N6 只产生报警，从不拦截）。
 *
 * 存储（复用 content-baseline 基建，原子写临时文件 + rename，0600/0700）：
 *   ~/.dsh/vet/capabilities.json   { records: { "<name>@<version>": { name, version, recordedAt, capabilities } } }
 * 规划书写的 `capabilities/<name>@<version>.json` 单文件布局合并为单 JSON 存储：
 * 原子写与 LRU 清理在同一结构内完成、可整库审计，key 仍是 name@version 粒度（实施方案决策）。
 * 存储治理：LRU 保留最近 MAX_KEPT（1000）个版本，超出的按 recordedAt 淘汰最旧。
 * 冷启动：首次安装无旧清单 → 只记录不报警；但新清单含 exec + network 双高组合时给一条
 * yellow `upgrade-cold` 提示，不完全静默。
 * 失效安全：任何内部错误（存储损坏、路径失败）都静默跳过（返回 no-op 结果），不打扰插件加载。
 * @module dsh-plugin-vet/version-diff
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import type { CapabilityManifest } from '../scanner/protocol.js'
import { withVetSelfIo } from './runtime-hooks.js'
import { hasAuditRecord } from '../audit/archive.js'

export interface CapabilityRecord {
  name: string
  version: string
  recordedAt: number
  capabilities: CapabilityManifest
}

export interface CapabilityStore {
  records: Record<string, CapabilityRecord>
}

/** 差分只关心"新增"（能力收窄是良性，报警只用 added）；布尔字段 = 该能力是否新增。 */
export interface ManifestDelta {
  hosts: string[]
  fsPaths: string[]
  spawnCmds: string[]
  imports: string[]
  hasNetwork: boolean
  hasExec: boolean
}

export interface VersionDiffAlarm {
  kind: 'upgrade-diff' | 'upgrade-cold'
  severity: 'yellow' | 'red'
  message: string
}

/** recordScan 的结果：调用方据此决定是否写一条盾牌报警（alarm 为 null = 只记录不报）。 */
export interface VersionDiffOutcome {
  plugin: string
  /** 上一个被记录的版本；冷启动为 null。 */
  from: string | null
  to: string
  /** 相对上一版的新增能力（无旧版时为 null）。 */
  added: ManifestDelta | null
  /** 相对上一版的移除能力（仅审计展示，不报警）。 */
  removed: ManifestDelta | null
  severity: 'yellow' | 'red' | null
  alarm: VersionDiffAlarm | null
}

/** vet_diff 工具输出：某包的全部版本历史 + 最近两版差分（供审计）。 */
export interface VersionDiffHistory {
  package: string
  records: { version: string; recordedAt: number }[]
  latest: string | null
  prior: string | null
  diff: { from: string; to: string; added: ManifestDelta; removed: ManifestDelta } | null
  note: string | null
}

/** LRU 上限：保留最近 N 个版本（规划 v2：约 1000）。 */
export const VERSION_DIFF_MAX_KEPT = 1000

/**
 * C3（0.1.16 加固）：模块加载时快照 DSH_PLUGIN_VET_BASELINE_DIR——vet 先于第三方插件加载，
 * 进程内插件此后改 env 无法重定向能力清单存储（archive.ts 同款快照语义）。
 * 测试通过 setCapabilitiesDirForTest 覆盖（生产路径不调用；C1 发布物不包含 guard 内部模块）。
 */
const SNAPSHOT_BASELINE_DIR: string | undefined = (() => {
  const v = process.env.DSH_PLUGIN_VET_BASELINE_DIR
  return v !== undefined && v !== '' ? v : undefined
})()

let baselineDirOverride: string | undefined

/** 存储文件路径：~/.dsh/vet/capabilities.json（快照 env；测试可用 setCapabilitiesDirForTest 覆盖）。 */
export function capabilitiesPath(): string {
  const dir = baselineDirOverride ?? SNAPSHOT_BASELINE_DIR ?? join(homedir(), '.dsh', 'vet')
  return join(dir, 'capabilities.json')
}

/** 测试专用：覆盖快照目录（生产路径不调用）。 */
export function setCapabilitiesDirForTest(dir?: string): void {
  baselineDirOverride = dir
}

/** M7（0.1.16 加固）：vet 自写 store 的内容哈希——进程内插件若直接改写 capabilities.json（
 * 中和升级差分/投毒基线），load 时 hash 与自写记录不符 → 记篡改标志。多进程写路径（另一 vet
 * 实例）会误标，DSH 单 profile 单实例场景可接受（注释为边界）。 */
const writtenStoreHashes = new Map<string, string>()
let storeTampered = false

/** 加载存储；文件不存在/损坏 → 空存储。文件被外部（非 vet 自写）改写 → 置篡改标志（可消费）。 */
export function loadCapabilities(): CapabilityStore {
  return withVetSelfIo(() => {
    try {
      const path = capabilitiesPath()
      const content = readFileSync(path, 'utf8')
      const recorded = writtenStoreHashes.get(path)
      if (recorded !== undefined && sha256Of(content) !== recorded) storeTampered = true
      const parsed = JSON.parse(content) as { records?: Record<string, CapabilityRecord> }
      if (parsed.records !== undefined && typeof parsed.records === 'object') {
        return { records: parsed.records }
      }
      return { records: {} }
    } catch {
      // 自写过但文件读不到（被删除/损坏）→ 同样是篡改信号
      const path = capabilitiesPath()
      if (writtenStoreHashes.has(path)) storeTampered = true
      return { records: {} }
    }
  })
}

/** 读取并复位篡改标志（一次消费；internal/plugin 完成时上报 yellow）。 */
export function consumeCapabilitiesTamper(): boolean {
  const t = storeTampered
  storeTampered = false
  return t
}

function sha256Of(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/** 保存存储（原子写：临时文件 + rename；目录 0700、文件 0600）。保存失败静默（下次重录）。 */
export function saveCapabilities(store: CapabilityStore): void {
  withVetSelfIo(() => {
    try {
      const path = capabilitiesPath()
      try {
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
      } catch {
        // 目录已存在
      }
      const tmpPath = path + '.tmp.' + process.pid
      const serialized = JSON.stringify(store, null, 2)
      writeFileSync(tmpPath, serialized, { mode: 0o600 })
      renameSync(tmpPath, path)
      writtenStoreHashes.set(path, sha256Of(serialized))
    } catch {
      // 静默：记录失败不阻塞插件加载
    }
  })
}

/** LRU 清理：按 recordedAt 降序保留最近 maxKept 个记录，超出部分删除。 */
export function pruneCapabilities(store: CapabilityStore, maxKept = VERSION_DIFF_MAX_KEPT): void {
  if (maxKept <= 0) {
    store.records = {}
    return
  }
  const entries = Object.entries(store.records)
  if (entries.length <= maxKept) return
  entries.sort((a, b) => b[1].recordedAt - a[1].recordedAt)
  const keptKeys = new Set(entries.slice(0, maxKept).map(e => e[0]))
  for (const key of entries.map(e => e[0])) {
    if (!keptKeys.has(key)) delete store.records[key]
  }
}

/** 上一个版本：同名、异版、recordedAt 最大者（不引入 semver 解析，规划 v2）。 */
export function findPreviousRecord(store: CapabilityStore, name: string, version: string): CapabilityRecord | null {
  let best: CapabilityRecord | null = null
  for (const record of Object.values(store.records)) {
    if (record.name !== name || record.version === version) continue
    // >=：同毫秒记录的 tie-break 取后插入者（object key 保持插入序，确定性）
    if (best === null || record.recordedAt >= best.recordedAt) best = record
  }
  return best
}

/**
 * 敏感文件路径判定（N6 抬升组合用，0.1.16 M8 加固）：路径段级匹配，不再用宽泛子串——
 * 旧实现 'credentials' 命中 'my-credentials-app' 等普通路径 → red 误抬升。
 * 匹配规则：整段相等，或段以 marker 为前缀/后缀（连字符或点作边界），如 my-credentials、
 * credentials-app、.ssh/config（段 .ssh 整段）。裸 'key'/'token' 等宽泛词仍不入表。
 */
export function isSensitiveFsPath(path: string): boolean {
  const segs = path.toLowerCase().split('/')
  const markers = [
    '.ssh', '.aws', '.dsh', '.gnupg', '.kube',
    'credentials', 'credential', 'authorized_keys',
    'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
    '.netrc', '.pgpass', '.git-credentials', '.npmrc',
    'passwd', 'shadow', 'keystore', 'vault',
  ]
  const hit = (s: string, m: string): boolean =>
    s === m || s.startsWith(m + '-') || s.endsWith('-' + m) || s.startsWith(m + '.') || s.endsWith('.' + m)
  return markers.some(m => segs.some(s => hit(s, m)))
}

function arrayDelta(prev: string[], next: string[]): { added: string[]; removed: string[] } {
  const p = new Set(prev)
  const n = new Set(next)
  return { added: next.filter(x => !p.has(x)), removed: prev.filter(x => !n.has(x)) }
}

/** 两份清单的差分（added/removed；布尔字段 = 是否新增/移除该能力）。 */
export function diffManifests(prev: CapabilityManifest, next: CapabilityManifest): { added: ManifestDelta; removed: ManifestDelta } {
  const hosts = arrayDelta(prev.hosts ?? [], next.hosts ?? [])
  const fsPaths = arrayDelta(prev.fsPaths ?? [], next.fsPaths ?? [])
  const spawnCmds = arrayDelta(prev.spawnCmds ?? [], next.spawnCmds ?? [])
  const imports = arrayDelta(prev.imports ?? [], next.imports ?? [])
  return {
    added: {
      hosts: hosts.added, fsPaths: fsPaths.added, spawnCmds: spawnCmds.added, imports: imports.added,
      hasNetwork: (prev.hasNetwork === false || prev.hasNetwork === undefined) && next.hasNetwork === true,
      hasExec: (prev.hasExec === false || prev.hasExec === undefined) && next.hasExec === true,
    },
    removed: {
      hosts: hosts.removed, fsPaths: fsPaths.removed, spawnCmds: spawnCmds.removed, imports: imports.removed,
      hasNetwork: prev.hasNetwork === true && next.hasNetwork !== true,
      hasExec: prev.hasExec === true && next.hasExec !== true,
    },
  }
}

export function hasAnyAddition(delta: ManifestDelta): boolean {
  return delta.hosts.length > 0 || delta.fsPaths.length > 0 || delta.spawnCmds.length > 0 ||
    delta.imports.length > 0 || delta.hasNetwork || delta.hasExec
}

function describeDelta(delta: ManifestDelta): string[] {
  const parts: string[] = []
  for (const h of delta.hosts) parts.push('网络主机 ' + h)
  for (const f of delta.fsPaths) parts.push('敏感路径 ' + f)
  for (const s of delta.spawnCmds) parts.push('子进程 ' + s)
  for (const i of delta.imports) parts.push('新依赖 ' + i + '（能力未知）')
  if (delta.hasNetwork) parts.push('网络能力')
  if (delta.hasExec) parts.push('执行能力')
  return parts
}

/** 升级差分的严重度：新增能力 → yellow；新增构成高敏感组合（执行+网络 / 敏感路径+网络 / 敏感路径+执行）→ red。 */
export function upgradeSeverity(added: ManifestDelta): 'yellow' | 'red' | null {
  if (!hasAnyAddition(added)) return null
  const sensitiveFs = added.fsPaths.some(isSensitiveFsPath)
  const combo = (added.hasNetwork && added.hasExec) || (added.hasNetwork && sensitiveFs) || (added.hasExec && sensitiveFs)
  return combo ? 'red' : 'yellow'
}

function buildUpgradeAlarm(plugin: string, from: string, to: string, added: ManifestDelta): VersionDiffAlarm | null {
  const severity = upgradeSeverity(added)
  if (severity === null) return null
  const parts = describeDelta(added)
  // 0.1.20 A 方案：red 级别 → 明确告知用户需要重新审计（审查完成后警报自动解除）
  const suffix = severity === 'red'
    ? '——已构成 高敏感能力组合（执行+网络 / 敏感路径+网络），请让 agent 执行 vet-audit-protocol skill 重新审查（审查完成后警报自动解除）'
    : '——升级前请审查（N6）'
  return { kind: 'upgrade-diff', severity, message: '升级行为差分：' + plugin + ' ' + from + ' → ' + to + ' 新增 ' + parts.join('；') + suffix }
}

/**
 * 记录一次扫描的能力清单并产出版本差分结果。
 * - 无版本/无清单 → no-op（不写存储）；
 * - 冷启动（无旧版）→ 只记录；exec+network 双高时附 yellow upgrade-cold 提示；
 * - 升级（有旧版）→ 计算差分，新增敏感能力 → upgrade-diff 报警（yellow/red）；
 * - 同版本重录 → 刷新 recordedAt，不差分。
 * fail-open：任何异常返回 no-op，不打扰插件加载。
 */
export function recordScan(
  plugin: string,
  version: string | undefined,
  manifest: CapabilityManifest | undefined | null,
): VersionDiffOutcome {
  const noop: VersionDiffOutcome = {
    plugin, from: null, to: version ?? 'unknown', added: null, removed: null, severity: null, alarm: null,
  }
  if (typeof version !== 'string' || version === '') return noop
  if (manifest === undefined || manifest === null) return noop
  return withVetSelfIo(() => {
    try {
      const store = loadCapabilities()
      const prev = findPreviousRecord(store, plugin, version)
      const key = plugin + '@' + version
      store.records[key] = { name: plugin, version, recordedAt: Date.now(), capabilities: manifest }
      pruneCapabilities(store)
      saveCapabilities(store)
      if (prev === null) {
        // 冷启动：只记录；exec + network 双高组合给一条提示，不完全静默
        // 0.1.20：upgrade-cold 联审计——已有审计档案则不报（用户审查行为有可见回报）
        const alarm: VersionDiffAlarm | null =
          manifest.hasNetwork === true && manifest.hasExec === true && !hasAuditRecord(plugin, version)
            ? {
                kind: 'upgrade-cold',
                severity: 'yellow',
                message: '新安装插件 ' + plugin + '@' + version + ' 声明 执行+网络 双高能力（首次记录，无旧版本可差分）——建议审查其能力面（N6 冷启动提示）',
              }
            : null
        return { plugin, from: null, to: version, added: null, removed: null, severity: alarm?.severity ?? null, alarm }
      }
      const { added, removed } = diffManifests(prev.capabilities, manifest)
      const alarm = buildUpgradeAlarm(plugin, prev.version, version, added)
      return { plugin, from: prev.version, to: version, added, removed, severity: alarm?.severity ?? null, alarm }
    } catch {
      return noop
    }
  })
}

/** 某包的全部版本历史 + 最近两版差分（vet_diff 工具数据源；只读，不写存储）。 */
export function history(pkg: string): VersionDiffHistory {
  return withVetSelfIo(() => {
    try {
      const store = loadCapabilities()
      const records = Object.values(store.records)
        .filter(r => r.name === pkg)
        .sort((a, b) => a.recordedAt - b.recordedAt)
      const versions = records.map(r => ({ version: r.version, recordedAt: r.recordedAt }))
      if (records.length === 0) {
        return { package: pkg, records: versions, latest: null, prior: null, diff: null, note: '无任何版本记录（该包尚未被 vet 自动扫描）' }
      }
      if (records.length === 1) {
        return { package: pkg, records: versions, latest: records[0].version, prior: null, diff: null, note: '仅一条版本记录，无旧版本可差分（冷启动：本次之后的下一次升级将产出差分）' }
      }
      const prev = records[records.length - 2]
      const cur = records[records.length - 1]
      const { added, removed } = diffManifests(prev.capabilities, cur.capabilities)
      return {
        package: pkg,
        records: versions,
        latest: cur.version,
        prior: prev.version,
        diff: { from: prev.version, to: cur.version, added, removed },
        note: null,
      }
    } catch {
      return { package: pkg, records: [], latest: null, prior: null, diff: null, note: '能力清单存储不可读' }
    }
  })
}
