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
  /** 外泄软黄关联窗口 ms（默认 120s）：读敏感数据后「读→写」间隔超过序列红窗口、但在本窗口内，
   * 仍视为可疑黄灯（n3-exfil）；超过本窗口（如启动读一次密钥、之后终身网写）不再触发，避免终身误报。 */
  exfilAssocWindowMs?: number
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
  /** 高频读取：窗口内读取次数阈值（默认 5 次）。 */
  highFreqReadN?: number
  /** 写后删除：窗口内写入后删除同一文件的阈值（默认 3 次）。 */
  writeThenDeleteN?: number
  /** spawn + network 关联窗口 ms（默认 10s）。 */
  spawnNetWindowMs?: number
}

const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream'])
/** 纯内容写（写后删除/放大写入的字节依据）；copy/rename 是移动/复制不产生内容写，不进台账。 */
const WRITE_CONTENT_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'])
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'])
const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])

/** 外联工具词（序列签名 SPAWN_NET 用；与 runtime-hooks shellTokens 对齐）。 */
const NET_TOOL_RE = /\b(?:curl|wget|nc|ncat|telnet)\b/i

/** 0.1.20 密钥外泄内容匹配（N3）：PEM 私钥头 / AWS Access Key Id。 */
const PEM_KEY_RE = /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/
const AWS_KEY_RE = /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/
/** AWS 文档/示例里出现的永无效示例 key（含 EXAMPLE 字样）——命中不算泄漏。 */
const AWS_EXAMPLE_RE = /EXAMPLE/i

/**
 * 0.1.20 在文本中检测密钥格式（纯函数；只扫传入字符串，不读文件）。
 * 返回所有匹配的密钥（PEM + AWS），每个包含 kind、match 和上下文位置。
 * 供 runtime-guard 的 recordKeyLeak 与单测共用。
 */
export function detectKeyLeaks(text: string): Array<{ kind: 'pem' | 'aws'; match: string; index: number }> {
  const results: Array<{ kind: 'pem' | 'aws'; match: string; index: number }> = []
  
  // 查找所有 PEM 匹配
  const pemMatches = [...text.matchAll(new RegExp(PEM_KEY_RE, 'g'))]
  for (const match of pemMatches) {
    results.push({ kind: 'pem', match: match[0], index: match.index ?? 0 })
  }
  
  // 查找所有 AWS 匹配（排除 EXAMPLE）
  const awsMatches = [...text.matchAll(new RegExp(AWS_KEY_RE, 'g'))]
  for (const match of awsMatches) {
    if (!AWS_EXAMPLE_RE.test(match[0])) {
      results.push({ kind: 'aws', match: match[0], index: match.index ?? 0 })
    }
  }
  
  return results
}

/**
 * 向后兼容：detectKeyLeak 返回第一个匹配（用于简单场景）。
 */
export function detectKeyLeak(text: string): { kind: 'pem' | 'aws'; match: string } | null {
  const leaks = detectKeyLeaks(text)
  return leaks.length > 0 ? { kind: leaks[0].kind, match: leaks[0].match } : null
}

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

/** readTimes 修剪触发阈值（键数超过才考虑扫描，热路径零开销）。 */
export const READ_TIMES_PRUNE_THRESHOLD = 256

/** 是否该对 readTimes 做全表惰性修剪（round-21，纯函数便于单测）。
 * 旧逻辑 `size > 256` 每次读事件无条件全扫：被观测面正是恶意主场景（凭据狩猎 = 窗口内
 * 扫几万条不同路径），窗口未过时键不删、size 不降 → 之后**每次读都付 O(size) 扫描**，
 * 观测自身退化为 O(n²) 且可被被观测者放大成对宿主的 DoS。加时间闸：每 windowMs 至多
 * 扫一次——窗口内键数上限即被观测者读事件速率上限×窗口，内存有界（每键 ~50B），
 * 而修剪频率与窗口语义匹配（窗口外的键反正不参与判定，留着只是晚删）。 */
export function shouldPruneReadTimes(size: number, now: number, lastPruneAt: number, minGapMs: number): boolean {
  if (size <= READ_TIMES_PRUNE_THRESHOLD) return false
  return now - lastPruneAt >= minGapMs
}

/** 窗口数组计数上限（round-16 review S2）：窗口内事件爆发（如 10s 内 100 万次 unlink）
 * 会让 deletes/writeEvents 等数组无界增长——内存 O(n) 且每次检查的线性扫描/reduce
 * 变成 O(n²)。阈值最高只有 20 量级，截断到 2048 不影响任何签名判定；只丢最旧样本。
 */
const WINDOW_CAP = 2048
function pushCap<T>(arr: T[], item: T): void {
  arr.push(item)
  if (arr.length > WINDOW_CAP) arr.splice(0, arr.length - WINDOW_CAP)
}

/** 改名是否呈现加密特征：扩展名变化 + 目标为加密标记/随机 hex 形态。 */
export function isEncryptionRename(from: string, to: string): boolean {
  if (from === to) return false
  const extOf = (p: string): string => {
    // 0.3.9（审查修复）：先统一反斜杠再取 basename——此前先按 '/' 切再替换反斜杠，
    // Windows 路径 `C:\v 1.2\notes` 的 basename 取到整段 `v 1.2\notes`，目录里的点
    // （v1.2）被当成扩展名 → 加密改名签名漏报。
    const norm = p.replace(/\\/g, '/')
    const base = norm.slice(norm.lastIndexOf('/') + 1)
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
  writeEvents: { at: number; bytes: number; path: string }[]
  readTimes: Map<string, number>
  /** readTimes 上次全表修剪时刻（round-21 时间闸；初始 0 = 首次越阈即扫）。 */
  lastReadPruneAt: number
  inPlace: { at: number; path: string }[]
  suspected: boolean
  lastSeen: number
  // 0.1.20 新增：关联检测字段
  smallFileReads: { at: number; path: string }[]
  writeThenDeletes: { at: number; path: string }[]
  spawnTargets: { at: number; target: string }[]
  netTargets: { at: number; target: string }[]
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
    lastReadPruneAt: 0,
    inPlace: [],
    suspected: false,
    lastSeen: now,
    // 0.1.20 新增
    smallFileReads: [],
    writeThenDeletes: [],
    spawnTargets: [],
    netTargets: [],
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
  private readonly exfilAssocWindowMs: number
  private readonly massDeleteN: number
  private readonly massRenameN: number
  private readonly inPlaceN: number
  private readonly writeAmplifyBytes: number
  private readonly exfilRatioMin: number
  private readonly exfilRatioMax: number
  private readonly exfilMinBytes: number
  private readonly ttlMs: number
  private readonly suspectedFactor: number
  // 0.1.20 新增阈值
  private readonly highFreqReadN: number
  private readonly writeThenDeleteN: number
  private readonly spawnNetWindowMs: number

  constructor(options: LedgerOptions = {}) {
    this.windowMs = options.windowMs ?? 10_000
    this.seqWindowMs = options.seqWindowMs ?? 30_000
    this.exfilAssocWindowMs = options.exfilAssocWindowMs ?? 120_000
    this.massDeleteN = options.massDeleteN ?? 20
    this.massRenameN = options.massRenameN ?? 5
    this.inPlaceN = options.inPlaceN ?? 10
    this.writeAmplifyBytes = options.writeAmplifyBytes ?? 128 * 1024 * 1024
    this.exfilRatioMin = options.exfilRatioMin ?? 0.4
    this.exfilRatioMax = options.exfilRatioMax ?? 3.0
    this.exfilMinBytes = options.exfilMinBytes ?? 512
    this.ttlMs = options.ttlMs ?? 24 * 60 * 60 * 1000
    this.suspectedFactor = options.suspectedFactor ?? 4
    // 0.1.20 新增
    this.highFreqReadN = options.highFreqReadN ?? 5
    this.writeThenDeleteN = options.writeThenDeleteN ?? 3
    this.spawnNetWindowMs = options.spawnNetWindowMs ?? 10_000
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

  private thresholds(row: LedgerRow): { massDelete: number; massRename: number; inPlace: number; writeAmplify: number; highFreqRead: number; writeThenDelete: number } {
    if (!row.suspected) {
      return { massDelete: this.massDeleteN, massRename: this.massRenameN, inPlace: this.inPlaceN, writeAmplify: this.writeAmplifyBytes, highFreqRead: this.highFreqReadN, writeThenDelete: this.writeThenDeleteN }
    }
    return {
      massDelete: Math.max(3, Math.floor(this.massDeleteN / this.suspectedFactor)),
      massRename: Math.max(2, Math.floor(this.massRenameN / this.suspectedFactor)),
      inPlace: Math.max(2, Math.floor(this.inPlaceN / this.suspectedFactor)),
      writeAmplify: Math.max(1024, Math.floor(this.writeAmplifyBytes / this.suspectedFactor)),
      highFreqRead: Math.max(2, Math.floor(this.highFreqReadN / this.suspectedFactor)),
      writeThenDelete: Math.max(1, Math.floor(this.writeThenDeleteN / this.suspectedFactor)),
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
    // 2) SPAWN_NET token + spawn 外联目标（0.1.20 关联检测）——
    //    仅外联工具（curl/wget 等）计入；从参数 URL 提取目标并经 new URL 规范化（小写、去端口），
    //    与网络侧 extractNetworkTarget 的输出一致，避免大小写/端口差异导致漏报。
    //    Issue L 修复：IPv6 地址去括号（[2001:db8::1] → 2001:db8::1），与 net 侧对齐。
    if (evt.module === 'child_process' && PROC_OPS.has(evt.op)) {
      const cmdline = evt.paths.join(' ')
      if (NET_TOOL_RE.test(cmdline)) {
        row.lastSpawnNetAt = now
        const urlMatch = cmdline.match(/https?:\/\/[^\s/]+/i)
        if (urlMatch !== null) {
          try {
            const u = new URL(urlMatch[0])
            // IPv6 去括号：url.hostname 对 IPv6 返回 [addr]，net 侧返回 addr
            const hostname = u.hostname.replace(/^\[|\]$/g, '')
            pushCap(row.spawnTargets, { at: now, target: hostname })
            trimWindow(row.spawnTargets, now, this.spawnNetWindowMs)
          } catch {
            // URL 解析失败（罕见）——不记录，宁可漏不误报
          }
        }
      }
    }
    // 3) 破坏窗口事件（仅 fs 模块、非降噪路径）
    if (evt.module === 'fs' && evt.target !== '') {
      const subject = evt.target
      if (!isNoisePath(subject)) {
        if (DESTROY_OPS.has(evt.op)) {
          pushCap(row.deletes, { at: now })
          trimWindow(row.deletes, now, this.windowMs)
          // 0.1.20：写后删除关联检测
          const recentWrite = row.writeEvents.find(w => w.path === subject && now - w.at <= this.windowMs)
          if (recentWrite !== undefined) {
            pushCap(row.writeThenDeletes, { at: now, path: subject })
            trimWindow(row.writeThenDeletes, now, this.windowMs)
          }
        } else if (WRITE_OPS.has(evt.op)) {
          // 仅纯内容写计入 writeEvents（copy/rename 是移动/复制——「写后删除」与放大写入
          // 的字节依据只针对真正落盘的内容写，避免 copy 后删源文件这类正常清理误报）
          if (WRITE_CONTENT_OPS.has(evt.op) && evt.bytes > 0) {
            pushCap(row.writeEvents, { at: now, bytes: evt.bytes, path: subject })
            trimWindow(row.writeEvents, now, this.windowMs)
          }
          const readAt = row.readTimes.get(subject)
          const already = row.inPlace.some(p => p.path === subject && now - p.at <= this.windowMs)
          if (readAt !== undefined && now - readAt <= this.windowMs && !already) {
            pushCap(row.inPlace, { at: now, path: subject })
          }
          if ((evt.op === 'rename' || evt.op === 'renameSync') && evt.paths.length >= 2 && isEncryptionRename(evt.paths[0], evt.paths[1])) {
            pushCap(row.renames, { at: now, from: evt.paths[0], to: evt.paths[1] })
            trimWindow(row.renames, now, this.windowMs)
          }
        }
      }
      if (READ_OPS.has(evt.op) && !isNoisePath(subject)) {
        row.readTimes.set(subject, now)
        // round-5 review（A#10）：readTimes 是唯一不修剪的增长面（deletes/renames/
        // writeEvents 都在 push 时 trimWindow；readTimes 只靠 24h TTL 整行淘汰）——
        // 插件遍历大量不同敏感路径时 Map 键线性累积。按窗口惰性修剪（保窗口内判定
        // 所需），写到 256 键以上才触发扫描，兼顾热路径零开销。
        // round-21 review：补时间闸（每 windowMs 至多一扫）——无闸时"窗口内扫大量
        // 不同路径"这一恶意主场景会让 size 恒 >256，每次读都付全表扫描 → O(n²)。
        if (shouldPruneReadTimes(row.readTimes.size, now, row.lastReadPruneAt, this.windowMs)) {
          row.lastReadPruneAt = now
          for (const [p, at] of row.readTimes) {
            if (now - at > this.windowMs) row.readTimes.delete(p)
          }
        }
        // 0.1.20：高频小文件读取检测（< 1KB 视为小文件；同窗口内按 path 去重——
        // 轮询同一文件不累加，只有扫描不同小文件才计数，贴近「凭据狩猎」语义）
        if (evt.bytes > 0 && evt.bytes < 1024) {
          const dup = row.smallFileReads.some(s => s.path === subject && now - s.at <= this.windowMs)
          if (!dup) {
            pushCap(row.smallFileReads, { at: now, path: subject })
            trimWindow(row.smallFileReads, now, this.windowMs)
          }
        }
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
    // 0.1.20：网络目标记录（用于 spawn + network 关联）
    if (evt.hostname !== '') {
      pushCap(row.netTargets, { at: now, target: evt.hostname })
      trimWindow(row.netTargets, now, this.spawnNetWindowMs)
    }
    const out = this.exfilChecks(row)
    // 0.1.20：spawn + network 关联检测
    out.push(...this.spawnNetChecks(row))
    return out
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
    // 0.3.9（审查修复）：加**时间关联闸**——此前只用「终身累计字节」比值带 [0.4,3.0]，
    // 单调增长的 netWriteBytes 必然某刻扫过比值带（实测：启动读 2KB 凭据 + 17×50B 无关
    // 遥测写就触发 red，盾牌挂 24h）。叠上层下方软黄分支同款 exfilAssocWindowMs：读与写
    // 必须落在关联窗口内才构成「读完立刻同量级外传」的整包外传签名；终身累计但时间解耦的
    // 遥测只落软黄（或完全不报），不再误红。
    if (row.sensitiveReadBytes >= this.exfilMinBytes && row.netWriteBytes >= this.exfilMinBytes) {
      const linked = row.lastSecretReadAt !== 0 && row.lastNetWriteAt !== 0 &&
        row.lastNetWriteAt >= row.lastSecretReadAt &&
        (row.lastNetWriteAt - row.lastSecretReadAt) <= this.exfilAssocWindowMs
      const ratio = row.netWriteBytes / row.sensitiveReadBytes
      if (linked && ratio >= this.exfilRatioMin && ratio <= this.exfilRatioMax) {
        out.push({
          severity: 'red',
          kind: 'n3-exfil-match',
          message: `疑似整包外传：敏感读 ${row.sensitiveReadBytes}B、网络写 ${row.netWriteBytes}B，量级相近且落入读→写关联窗口（N3 台账）`,
        })
        red = true
      }
    }
        // 软黄：读敏感数据后对外发送，但「读→写」间隔已超过序列红窗口——仅在关联窗口内视为可疑，
    // 避免「启动读一次密钥、之后终身每次网写都黄」的误报（窗口外不再触发，n3-exfil 不再常亮）。
    const readNetGap = row.lastNetWriteAt - row.lastSecretReadAt
    if (!red && row.sensitiveReadBytes > 0 && row.netWriteBytes > 0 &&
        row.lastSecretReadAt !== 0 && row.lastNetWriteAt !== 0 &&
        readNetGap > this.seqWindowMs && readNetGap <= this.exfilAssocWindowMs) {
      out.push({
        severity: 'yellow',
        kind: 'n3-exfil',
        message: '近期读取敏感数据后向外发送数据流（读→写关联窗口内，N3 台账）',
      })
    }
    return out
  }

  private destroyChecks(row: LedgerRow, now: number): LedgerAlarm[] {
    // round-5 review（A#1）：deletes/renames/writeEvents 只在「同类新事件」push 时
    // trimWindow——插件在窗口内达成阈值后静默（如 1s 内 20 次 unlink 后停止活动），
    // 陈旧计数永久保留：之后任何一次其他 fs 事件都会以过期计数再次产出
    // n3-mass-delete/rename/write-amplify，status 的 60s 去重窗口一过就 replace 重入
    // → 报警永久复燃、盾牌粘黄。统一在每次检查时对三个窗口修剪，计数反映真实窗口。
    trimWindow(row.deletes, now, this.windowMs)
    trimWindow(row.renames, now, this.windowMs)
    trimWindow(row.writeEvents, now, this.windowMs)
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
    // 0.1.20：高频小文件读取检测（凭据狩猎模式）
    trimWindow(row.smallFileReads, now, this.windowMs)
    if (row.smallFileReads.length >= th.highFreqRead) {
      out.push({
        severity: 'yellow',
        kind: 'n3-high-freq-read',
        message: `高频读取签名：10s 窗口内读取 ${row.smallFileReads.length} 个不同小文件（< 1KB，疑似凭据狩猎，N3 台账）`,
      })
    }
    // 0.1.20：写后删除关联检测（经典勒索模式）
    trimWindow(row.writeThenDeletes, now, this.windowMs)
    if (row.writeThenDeletes.length >= th.writeThenDelete) {
      out.push({
        severity: 'red',
        kind: 'n3-write-then-delete',
        message: `写后删除签名：10s 窗口内 ${row.writeThenDeletes.length} 个文件被写入后删除（疑似加密后删除原文件，N3 台账）`,
      })
      red = true
    }
    // 组合 red 时吞掉单个 yellow（同一次检查内去噪）
    return red ? out.filter(a => a.severity === 'red') : out
  }

  /** 0.1.20：spawn + network 关联检测（spawn 后网络连接同一目标）。
 * round-16 review（S2）：旧实现双层循环 O(spawn×net)（窗口数组各可达 2048 → 最坏 400 万
 * 次比较/每次检查）；两数组都按时间升序，改单指针扫描 O(spawn+net) 摊还。 */
  private spawnNetChecks(row: LedgerRow): LedgerAlarm[] {
    const out: LedgerAlarm[] = []
    const now = Date.now()
    // 检查时先修剪两数组（spawn 侧与 net 侧窗口），避免陈旧条目参与配对
    trimWindow(row.spawnTargets, now, this.spawnNetWindowMs)
    trimWindow(row.netTargets, now, this.spawnNetWindowMs)
    // 目标已由两侧分别规范化为小写主机名（spawn 侧 new URL().hostname；net 侧 extractNetworkTarget）
    let netStart = 0
    for (const spawn of row.spawnTargets) {
      // net 数组按时间升序：跳过所有早于本 spawn 的 net 条目（且随 spawn 后移单调推进）
      while (netStart < row.netTargets.length && row.netTargets[netStart].at < spawn.at) netStart++
      for (let j = netStart; j < row.netTargets.length; j++) {
        const net = row.netTargets[j]
        // 顺序约束：spawn 必须先于网络连接；net 超窗不计（此后条目更晚，可直接跳出）
        if (net.at - spawn.at > this.spawnNetWindowMs) break
        if (spawn.target === net.target) {
          out.push({
            severity: 'red',
            kind: 'n3-spawn-net-match',
            message: `spawn + network 关联：spawn 外联工具后 ${((net.at - spawn.at) / 1000).toFixed(2)}s 内网络连接同一目标 ${spawn.target}（N3 台账）`,
            target: spawn.target,
          })
          return out // 只报一次
        }
      }
    }
    return out
  }

  /** 测试/取证辅助：某插件累积计数快照。 */
  snapshot(plugin: string): { sensitiveReadBytes: number; netWriteBytes: number } | undefined {
    const row = this.ledgers.get(plugin)
    if (row === undefined) return undefined
    return { sensitiveReadBytes: row.sensitiveReadBytes, netWriteBytes: row.netWriteBytes }
  }

  /** 单测辅助（S2 窗口计数上限断言）：某插件各窗口数组总样本数。 */
  stateSize(plugin: string): number | undefined {
    const row = this.ledgers.get(plugin)
    if (row === undefined) return undefined
    return row.deletes.length + row.renames.length + row.writeEvents.length + row.inPlace.length
      + row.smallFileReads.length + row.writeThenDeletes.length + row.spawnTargets.length + row.netTargets.length
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
