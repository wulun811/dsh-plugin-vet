/**
 * N3 敏感读 → 网络写 字节台账 + 破坏模式签名（Exfiltration & Destruction Ledger）。
 * 按插件归因的轻量计数器（生命周期累积）+ 10s 滑动窗口 + 确定性坏序列签名。
 * alarm-only：台账只产生报警，从不拦截、从不干预调用。
 * 诚实边界（v2，如实标注）：
 *   - 绝不读取/解析/记录任何会话/聊天内容——只计数 fs 读写的字节量与网络写出字节量，
 *     以及操作形状（删除/改名/原地覆写/写法）的摘要特征；
 *   - 跨会话/超低速外泄（插件生命周期内读与写不同时发生）不在覆盖内；
 *   - 原生二进制内部行为不可见（系统层监控不做）；fd 级读（fs.read(fd)）不在包装面。
 * @module dsh-plugin-vet/exfil-ledger
 */
import { isLockSiblingPath, isTransientTempPath } from './runtime-hooks.js'
import type { HookModule } from './runtime-hooks.js'

// ── 事件（T2 包装器 → 台账；hooks 组装，台账消费）──────────────────────

export interface LedgerFsEvent {
  /** 栈归因插件包名；undefined = 无主操作（官方/宿主/归因失败），不建桶。 */
  plugin?: string
  module: HookModule
  op: string
  /** 首个字符串参数（路径/命令）。 */
  target: string
  /** 全部字符串参数（rename/cp 的 src+dest）。 */
  paths: string[]
  /** target 是否敏感路径（read 模式：密钥特征）。 */
  sensitive: boolean
  /** 本次操作的字节量（读结果长度 / 写数据长度；流操作由包装器按 chunk 发事件）。 */
  bytes: number
}

export interface LedgerNetEvent {
  plugin?: string
  module: string
  op: string
  hostname: string
  bytes: number
}

export interface LedgerAlarm {
  severity: 'yellow' | 'red'
  kind: string
  message: string
  target?: string
}

// ── 阈值（保守起步：宁可漏、不误报；suspected 后除以 4 降为最低）─────────

export interface LedgerOptions {
  /** 破坏签名滑动窗口 ms（默认 10s）。 */
  windowMs?: number
  /** 外泄序列签名窗口 ms（默认 30s）。 */
  seqWindowMs?: number
  /** MASS_DELETE：窗口内删除数阈值。 */
  massDeleteN?: number
  /** MASS_RENAME_EXT：窗口内「改名 + 加密标记」阈值。 */
  massRenameN?: number
  /** IN_PLACE_OVERWRITE：窗口内「读→写同路径」去重对阈值。 */
  inPlaceN?: number
  /** WRITE_AMPLIFY：窗口内写入字节阈值。 */
  writeAmplifyBytes?: number
  /** 外泄量级红：netWriteBytes/sensitiveReadBytes 比值下界。 */
  exfilRatioMin?: number
  /** 外泄量级红：比值上界。 */
  exfilRatioMax?: number
  /** 参与量级判定的最小敏感读/网写字节。 */
  exfilMinBytes?: number
  /** 台账空闲清理 TTL（随 VetStatus 的 24h TTL 对齐）。 */
  ttlMs?: number
  /** 疑似恶意（蜜罐/金丝雀确认）后阈值除数。 */
  suspectedFactor?: number
}

const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream'])
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'])
const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])

/** 外联工具词（序列签名 SPAWN_NET 用；与 runtime-hooks shellTokens 对齐）。 */
const NET_TOOL_RE = /\b(?:curl|wget|nc|ncat|telnet)\b/i

/** 降噪目录段：node_modules/.git/构建产物——构建/清理流程的删除与写入不参与破坏签名。 */
const NOISE_SEGMENTS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.nuxt', '.next', '.output', '.turbo', '.cache'])

/** 加密标记：目标扩展名变成疑似加密标记，或改名后末段为随机 hex 形态。 */
const ENCRYPT_MARK_RE = /\.(?:encrypted|locked|crypt)$/i
const RANDOM_HEX_EXT_RE = /\.([0-9a-f]{8,})$/i

/** 路径是否被降噪（破坏签名不计数）：目录段命中 / 原子写锁 / 工具链临时产物。 */
export function isNoisePath(p: string): boolean {
  const norm = p.replace(/\\/g, '/')
  const parts = norm.split('/')
  if (parts.some(seg => NOISE_SEGMENTS.has(seg))) return true
  return isLockSiblingPath(p) || isTransientTempPath(p)
}

function trimWindow<T extends { at: number }>(arr: T[], now: number, windowMs: number): void {
  const cutoff = now - windowMs
  while (arr.length > 0 && arr[0].at < cutoff) arr.shift()
}

/** 改名是否呈现加密特征：扩展名变化 + 目标为加密标记/随机 hex 形态。 */
export function isEncryptionRename(from: string, to: string): boolean {
  if (from === to) return false
  const extOf = (p: string): string => {
    const base = p.slice(p.lastIndexOf('/') + 1).replace(/\\/g, '/')
    const dot = base.lastIndexOf('.')
    return dot === -1 ? '' : base.slice(dot + 1)
  }
  const fromExt = extOf(from)
  const toExt = extOf(to)
  if (toExt === fromExt) return false
  return ENCRYPT_MARK_RE.test(to) || RANDOM_HEX_EXT_RE.test(to)
}

interface LedgerRow {
  sensitiveReadBytes: number
  netWriteBytes: number
  lastSecretReadAt: number
  lastSpawnNetAt: number
  lastNetWriteAt: number
  deletes: { at: number }[]
  renames: { at: number; from: string; to: string }[]
  writeEvents: { at: number; bytes: number }[]
  readTimes: Map<string, number>
  inPlace: { at: number; path: string }[]
  suspected: boolean
  lastSeen: number
}

function newRow(now: number): LedgerRow {
  return {
    sensitiveReadBytes: 0,
    netWriteBytes: 0,
    lastSecretReadAt: 0,
    lastSpawnNetAt: 0,
    lastNetWriteAt: 0,
    deletes: [],
    renames: [],
    writeEvents: [],
    readTimes: new Map(),
    inPlace: [],
    suspected: false,
    lastSeen: now,
  }
}

/**
 * 台账：plugin → 计数器 + 窗口。模块级单例（守卫进程内共享）。
 * SPAWN_NET / READ_SECRET / NET_WRITE 序列签名为确定性有限状态（时间戳先后 + 窗口）。
 */
export class ExfilLedger {
  private readonly ledgers = new Map<string, LedgerRow>()
  private readonly windowMs: number
  private readonly seqWindowMs: number
  private readonly massDeleteN: number
  private readonly massRenameN: number
  private readonly inPlaceN: number
  private readonly writeAmplifyBytes: number
  private readonly exfilRatioMin: number
  private readonly exfilRatioMax: number
  private readonly exfilMinBytes: number
  private readonly ttlMs: number
  private readonly suspectedFactor: number

  constructor(options: LedgerOptions = {}) {
    this.windowMs = options.windowMs ?? 10_000
    this.seqWindowMs = options.seqWindowMs ?? 30_000
    this.massDeleteN = options.massDeleteN ?? 20
    this.massRenameN = options.massRenameN ?? 5
    this.inPlaceN = options.inPlaceN ?? 10
    this.writeAmplifyBytes = options.writeAmplifyBytes ?? 128 * 1024 * 1024
    this.exfilRatioMin = options.exfilRatioMin ?? 0.4
    this.exfilRatioMax = options.exfilRatioMax ?? 3.0
    this.exfilMinBytes = options.exfilMinBytes ?? 512
    this.ttlMs = options.ttlMs ?? 24 * 60 * 60 * 1000
    this.suspectedFactor = options.suspectedFactor ?? 4
  }

  /** 空闲台账清理（随 VetStatus TTL 对齐；observe 时惰性触发）。 */
  prune(now: number): void {
    const cutoff = now - this.ttlMs
    for (const [plugin, row] of this.ledgers) {
      if (row.lastSeen < cutoff) this.ledgers.delete(plugin)
    }
  }

  /** （N4）蜜罐/金丝雀确认恶意：该插件阈值降为最低 + 详细取证模式由上层接管。 */
  markSuspected(plugin: string): void {
    let row = this.ledgers.get(plugin)
    if (row === undefined) {
      row = newRow(Date.now())
      this.ledgers.set(plugin, row)
    }
    row.suspected = true
  }

  private thresholds(row: LedgerRow): { massDelete: number; massRename: number; inPlace: number; writeAmplify: number } {
    if (!row.suspected) {
      return { massDelete: this.massDeleteN, massRename: this.massRenameN, inPlace: this.inPlaceN, writeAmplify: this.writeAmplifyBytes }
    }
    return {
      massDelete: Math.max(3, Math.floor(this.massDeleteN / this.suspectedFactor)),
      massRename: Math.max(2, Math.floor(this.massRenameN / this.suspectedFactor)),
      inPlace: Math.max(2, Math.floor(this.inPlaceN / this.suspectedFactor)),
      writeAmplify: Math.max(1024, Math.floor(this.writeAmplifyBytes / this.suspectedFactor)),
    }
  }

  /** fs 操作观测：返回新生报警（由调用方补 pluginHint 与去重 id）。 */
  observeFs(evt: LedgerFsEvent): LedgerAlarm[] {
    if (evt.plugin === undefined) return []
    const now = Date.now()
    this.prune(now)
    let row = this.ledgers.get(evt.plugin)
    if (row === undefined) {
      row = newRow(now)
      this.ledgers.set(evt.plugin, row)
    }
    const out: LedgerAlarm[] = []

    // 1) 敏感读字节 + READ_SECRET token
    if (isReadDataOp(evt.op) && evt.sensitive && evt.bytes > 0) {
      row.sensitiveReadBytes += evt.bytes
      row.lastSecretReadAt = now
    }
    // 2) SPAWN_NET token（spawn 外联工具）
    if (evt.module === 'child_process' && PROC_OPS.has(evt.op) && NET_TOOL_RE.test(evt.paths.join(' '))) {
      row.lastSpawnNetAt = now
    }
    // 3) 破坏窗口事件（仅 fs 模块、非降噪路径）
    if (evt.module === 'fs' && evt.target !== '') {
      const subject = evt.target
      if (!isNoisePath(subject)) {
        if (DESTROY_OPS.has(evt.op)) {
          row.deletes.push({ at: now })
          trimWindow(row.deletes, now, this.windowMs)
        } else if (WRITE_OPS.has(evt.op)) {
          if (evt.bytes > 0) {
            row.writeEvents.push({ at: now, bytes: evt.bytes })
            trimWindow(row.writeEvents, now, this.windowMs)
          }
          const readAt = row.readTimes.get(subject)
          const already = row.inPlace.some(p => p.path === subject && now - p.at <= this.windowMs)
          if (readAt !== undefined && now - readAt <= this.windowMs && !already) {
            row.inPlace.push({ at: now, path: subject })
          }
          if ((evt.op === 'rename' || evt.op === 'renameSync') && evt.paths.length >= 2 && isEncryptionRename(evt.paths[0], evt.paths[1])) {
            row.renames.push({ at: now, from: evt.paths[0], to: evt.paths[1] })
            trimWindow(row.renames, now, this.windowMs)
          }
        }
      }
      if (READ_OPS.has(evt.op) && !isNoisePath(subject)) {
        row.readTimes.set(subject, now)
      }
    }

    row.lastSeen = now
    out.push(...this.exfilChecks(row))
    out.push(...this.destroyChecks(row, now))
    return out
  }

  /** 网络写出观测：累计字节 + NET_WRITE token + 外泄判定。 */
  observeNet(evt: LedgerNetEvent): LedgerAlarm[] {
    if (evt.plugin === undefined) return []
    const now = Date.now()
    this.prune(now)
    let row = this.ledgers.get(evt.plugin)
    if (row === undefined) {
      row = newRow(now)
      this.ledgers.set(evt.plugin, row)
    }
    row.netWriteBytes += evt.bytes
    row.lastNetWriteAt = now
    row.lastSeen = now
    return this.exfilChecks(row)
  }

  private exfilChecks(row: LedgerRow): LedgerAlarm[] {
    const out: LedgerAlarm[] = []
    let red = false
    // 序列签名（强证据 → red）：比较「读 → 事件」的时间间隔，而非距当前时间——
    // 读后紧接外联/网写才构成序列；慢速（间隔 > seqWindowMs）不算强证据。
    if (row.lastSecretReadAt !== 0) {
      const spawnGap = row.lastSpawnNetAt - row.lastSecretReadAt
      if (row.lastSpawnNetAt !== 0 && spawnGap >= 0 && spawnGap <= this.seqWindowMs) {
        out.push({
          severity: 'red',
          kind: 'n3-seq-read-spawn',
          message: `外泄序列签名：读取敏感文件后 ${spawnGap / 1000}s 内调用 curl/wget/nc 等外联工具（N3 台账）`,
        })
        red = true
      }
      const netGap = row.lastNetWriteAt - row.lastSecretReadAt
      if (row.lastNetWriteAt !== 0 && netGap >= 0 && netGap <= this.seqWindowMs) {
        out.push({
          severity: 'red',
          kind: 'n3-seq-read-net',
          message: `外泄序列签名：读取敏感文件后 ${netGap / 1000}s 内向非白名单主机发起网络写（N3 台账）`,
        })
        red = true
      }
    }
    // 量级匹配（疑似整包外传 → red）
    if (row.sensitiveReadBytes >= this.exfilMinBytes && row.netWriteBytes >= this.exfilMinBytes) {
      const ratio = row.netWriteBytes / row.sensitiveReadBytes
      if (ratio >= this.exfilRatioMin && ratio <= this.exfilRatioMax) {
        out.push({
          severity: 'red',
          kind: 'n3-exfil-match',
          message: `疑似整包外传：敏感读 ${row.sensitiveReadBytes}B、网络写 ${row.netWriteBytes}B，量级相近（N3 台账）`,
        })
        red = true
      }
    }
    // 基础黄：读写都发生过（生命周期累积，无时间窗）
    if (!red && row.sensitiveReadBytes > 0 && row.netWriteBytes > 0) {
      out.push({
        severity: 'yellow',
        kind: 'n3-exfil',
        message: `敏感读 ${row.sensitiveReadBytes}B 且网络写 ${row.netWriteBytes}B——读敏感数据后对外发送数据流（N3 台账）`,
      })
    }
    return out
  }

  private destroyChecks(row: LedgerRow, now: number): LedgerAlarm[] {
    const th = this.thresholds(row)
    const deletes = row.deletes.length
    const renames = row.renames.length
    trimWindow(row.inPlace, now, this.windowMs)
    const inPlace = row.inPlace.length
    const writeBytes = row.writeEvents.reduce((s, e) => s + e.bytes, 0)
    const out: LedgerAlarm[] = []
    let red = false
    if (deletes >= th.massDelete) {
      out.push({ severity: 'yellow', kind: 'n3-mass-delete', message: `破坏签名 MASS_DELETE：10s 窗口内删除 ${deletes} 个文件（N3 台账）` })
    }
    if (renames >= th.massRename) {
      out.push({ severity: 'yellow', kind: 'n3-mass-rename', message: `破坏签名 MASS_RENAME_EXT：10s 窗口内 ${renames} 次改名且目标呈加密标记（疑似勒索重命名，N3 台账）` })
    }
    if (inPlace >= th.inPlace) {
      out.push({ severity: 'yellow', kind: 'n3-in-place', message: `破坏签名 IN_PLACE_OVERWRITE：10s 窗口内 ${inPlace} 个文件被读后原地覆写（疑似原地加密，N3 台账）` })
    }
    if (writeBytes >= th.writeAmplify) {
      out.push({ severity: 'yellow', kind: 'n3-write-amplify', message: `破坏签名 WRITE_AMPLIFY：10s 窗口内写入 ${(writeBytes / 1024 / 1024).toFixed(1)}MB（疑似批量落盘，N3 台账）` })
    }
    const active = (deletes >= th.massDelete ? 1 : 0) + (renames >= th.massRename ? 1 : 0)
      + (inPlace >= th.inPlace ? 1 : 0) + (writeBytes >= th.writeAmplify ? 1 : 0)
    if (active >= 2) {
      out.push({
        severity: 'red',
        kind: 'n3-ransom',
        message: `勒索破坏组合签名：删除/改名/原地覆写/放大写入中 ${active} 类同时命中（疑似勒索加密实锤，N3 台账）`,
      })
      red = true
    }
    // 组合 red 时吞掉单个 yellow（同一次检查内去噪）
    return red ? out.filter(a => a.severity === 'red') : out
  }

  /** 测试/取证辅助：某插件累积计数快照。 */
  snapshot(plugin: string): { sensitiveReadBytes: number; netWriteBytes: number } | undefined {
    const row = this.ledgers.get(plugin)
    if (row === undefined) return undefined
    return { sensitiveReadBytes: row.sensitiveReadBytes, netWriteBytes: row.netWriteBytes }
  }

  /** 单测辅助：清空全部状态。 */
  clear(): void {
    this.ledgers.clear()
  }
}

/** readFile 族（含流，字节由字节字段承载）才计敏感读字节；open/openSync 无数据。 */
function isReadDataOp(op: string): boolean {
  return op === 'readFile' || op === 'readFileSync' || op === 'createReadStream'
}

/** 进程级单例（runtime-guard 接线共用）。 */
export const exfilLedger = new ExfilLedger()

/** 单测辅助：重置模块级单例（fixture 隔离）。 */
export function resetExfilLedger(): void {
  exfilLedger.clear()
}
