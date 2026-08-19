/**
 * T2 进程内钩子（D22）：在宿主进程内包装 fs / child_process 内置模块导出。
 * 危险操作 → 取栈 → 归因插件包名 → 报警；N7（0.1.14 起）确认破坏类操作
 * （fs 族 1/2，confirmBlock 默认 block）在调用原函数前抛错拦截（fail-open：异常→放行）。
 * 已知旁路（PLAN §14.5 / README）：ESM 具名导入快照、worker_threads 独立 realm、
 * 原生插件、process.binding。
 */
export type HookModule = 'fs' | 'child_process'

import type { LedgerFsEvent, LedgerNetEvent } from './exfil-ledger.js'
import { confirmBlock, BLOCK_FS_OPS, isPersistenceWriteTarget, isInstallWriteTarget, type BlockDecision } from './confirm-block.js'

export interface HookConfig {
  /** 命中即报警的系统目录前缀。 */
  sensitiveRoots: string[]
  /** 敏感段名：路径任一段整体等于其中一项（大小写不敏感）即敏感。 */
  sensitiveSegments: string[]
  /** 凭据关键词：路径段中以段首或 . _ - 为边界出现即敏感（不含 token——'js-tokens' 这类库名会误伤）。 */
  sensitiveKeywords: string[]
  /** 密钥文件后缀（路径段以此结尾）。 */
  sensitiveExts: string[]
  /** 子进程命令行报警关键词（shell 解释器 + 下载/外联工具；整词命中才报警）。 */
  shellTokens: string[]
  /** 蜜罐根目录（D27）：命中即按蜜罐报警——触碰任何诱饵路径都是高置信信号。 */
  honeypotRoots: string[]
  /** 完整性金丝雀路径（N4，仅 ~/.dsh 内）：写/删即 red kind=integrity（与凭据蜜罐语义分离）。 */
  integrityRoots: string[]
}

export const DEFAULT_HOOK_CONFIG: HookConfig = {
  sensitiveRoots: ['/etc', '/usr', '/var', '/boot', '/bin', '/sbin'],
  // P2-6：.dsh = DSH 配置根（真实凭据 credentials.yaml、profile 配置、会话存储、蜜罐根都在其下）。
  // 此前 readdirSync('~/.dsh') 这类凭据狩猎第一步完全不可见（M7 只覆盖 .ssh/.aws 等）。
  // 官方包（@deepseek-ai/*）高频读写 ~/.dsh（会话/配置/存储）由 sink 的官方信任降噪吸收；
  // vet 自身对 patch 文件的轮询读取经 withVetSelfIo 直通，不会自报警。
  sensitiveSegments: ['.dsh', '.ssh', '.aws', '.gnupg', '.npmrc', '.env', '.netrc', '.pgpass', '.gitconfig', 'credentials', 'credential', 'secrets', 'secret', 'tokens', 'token', 'passwd', 'shadow', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.git-credentials', '.kube', 'vault'],
  sensitiveKeywords: ['secret', 'secrets', 'credential', 'credentials', 'passwd', 'shadow', 'private', 'auth', 'vault'],
  sensitiveExts: ['.pem', '.key', '.p12', '.pfx', '.keystore', '.jks', '.env'],
  shellTokens: ['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh', 'curl', 'wget', 'nc', 'ncat', 'telnet'],
  honeypotRoots: [],
  integrityRoots: [],
}

/** T2 报警候选（at/source 由调用方补全）。 */
export interface HookAlarm {
  severity: 'yellow' | 'red'
  kind: string
  message: string
  target?: string
  pluginHint?: string
  /** 目标是否为会话日志文件（用于归因分层文案：无归因 + 会话日志 → 轮换提示）。 */
  sessionLog?: boolean
}

export interface HookOp {
  module: HookModule
  op: string
  args: unknown[]
}

/** 破坏性删除类 fs 操作（red）。 */
const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
/** 写入/变更类 fs 操作（yellow）。0.1.16（M5）：补 symlink/link/chmod/chown/mkdir/utimes——
 * 此前 symlink 落点可绕过敏感路径判定（写 /tmp 符号链接指向 ~/.ssh/authorized_keys）、
 * chmod 可放宽凭据文件权限、mkdir 可落位 /etc/cron.d 等提权面。 */
const WRITE_OPS = new Set([
  'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync',
  'truncate', 'truncateSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream',
  'symlink', 'symlinkSync', 'link', 'linkSync', 'chmod', 'chmodSync', 'chown', 'chownSync',
  'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync', 'utimes', 'utimesSync', 'lutimes', 'lutimesSync',
])
/** 读取类 fs 操作（密钥路径 → yellow）。 */
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'])
/** 侦察类 fs 操作（M7：列目录/stat/access 是凭据狩猎的第一步——readdirSync('~/.ssh') 此前完全不可见）。 */
// 0.1.16（M5）：lstat 是符号链接侦察的标准原语（stat 跟随链接），补入侦察面
const PROBE_OPS = new Set(['readdir', 'readdirSync', 'opendir', 'opendirSync', 'stat', 'statSync', 'lstat', 'lstatSync', 'access', 'accessSync', 'existsSync', 'readlink', 'readlinkSync', 'realpath', 'realpathSync'])
/** child_process 全部操作（spawn 面，yellow）。 */
const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])

// ── N3 台账观测通道（optional observe：runtime-guard 接线 exfil-ledger；不接线时零开销）──

/** 需要向台账发事件的 fs/子进程操作（删/写/读/spawn 面；PROBE 侦察不参与破坏窗口）。 */
const FS_LEDGER_OPS = new Set<string>([...DESTROY_OPS, ...WRITE_OPS, ...READ_OPS, ...PROC_OPS])

/** 数据块字节数（Buffer/string/TypedArray/ArrayBuffer；未知返回 0，绝不抛）。 */
export function chunkBytes(chunk: unknown): number {
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, 'utf8')
  if (Buffer.isBuffer(chunk)) return chunk.length
  if (chunk instanceof Uint8Array) return chunk.byteLength
  if (typeof chunk === 'object' && chunk !== null && 'byteLength' in chunk) {
    const n = (chunk as { byteLength?: unknown }).byteLength
    if (typeof n === 'number') return n
  }
  return 0
}

/** 一次 fs 调用的字节量：读 = 结果长度；写 = 数据参数长度（流操作由流计数器按 chunk 上报）。 */
function fsOpBytes(opName: string, args: unknown[], result: unknown): number {
  if (opName === 'readFile' || opName === 'readFileSync') return chunkBytes(result)
  if (opName === 'writeFile' || opName === 'writeFileSync' || opName === 'appendFile' || opName === 'appendFileSync') {
    return chunkBytes(args[1])
  }
  return 0
}

const WRITE_COUNTER_FLAG = Symbol('vet-ledger-write-counter')
const END_COUNTER_FLAG = Symbol('vet-ledger-end-counter')
const CANARY_FLAG = Symbol('vet-canary-monitor')
const READ_COUNTER_FLAG = Symbol('vet-ledger-read-counter')

/** 包装可写对象（http.ClientRequest / net.Socket / fs.WriteStream）的 write/end，按 chunk 计数。 */
export function attachWriteCounter(obj: { write?: unknown; end?: unknown }, onBytes: (n: number) => void): void {
  const flagged = obj as { [k: symbol]: unknown }
  const write = obj.write
  if (typeof write === 'function' && flagged[WRITE_COUNTER_FLAG] !== true) {
    flagged[WRITE_COUNTER_FLAG] = true
    const w = write as (...a: unknown[]) => unknown
    obj.write = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      const n = chunkBytes(chunk)
      if (n > 0) onBytes(n)
      return w.apply(this, [chunk, ...rest])
    }
  }
  const end = obj.end
  if (typeof end === 'function' && flagged[END_COUNTER_FLAG] !== true) {
    flagged[END_COUNTER_FLAG] = true
    const e = end as (...a: unknown[]) => unknown
    obj.end = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      const n = chunkBytes(chunk)
      if (n > 0) onBytes(n)
      return e.apply(this, [chunk, ...rest])
    }
  }
}

/**
 * N4 金丝雀出站监控：包装请求对象 write/end，把 body 文本按 chunk 累计（跨 chunk 拼接、
 * 上限 64KB 截尾——canary 每次必然落在尾部窗口内）并调用 onText 回调。幂等（防二次包装）。
 */
export function attachCanaryScanner(obj: { write?: unknown; end?: unknown }, onText: (text: string) => void): void {
  if ((obj as { [k: symbol]: unknown })[CANARY_FLAG] === true) return
  ;(obj as { [k: symbol]: unknown })[CANARY_FLAG] = true
  let buf = ''
  const push = (chunk: unknown): void => {
    if (typeof chunk === 'string') buf += chunk
    else {
      const n = chunkBytes(chunk)
      if (n === 0) return
      buf += typeof chunk === 'object' && chunk !== null && 'toString' in chunk ? String(chunk) : ''
    }
    if (buf.length > 64 * 1024) buf = buf.slice(buf.length - 64 * 1024)
    onText(buf)
  }
  const write = obj.write
  if (typeof write === 'function') {
    const w = write as (...a: unknown[]) => unknown
    obj.write = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      push(chunk)
      return w.apply(this, [chunk, ...rest])
    }
  }
  const end = obj.end
  if (typeof end === 'function') {
    const e = end as (...a: unknown[]) => unknown
    obj.end = function (this: unknown, chunk: unknown, ...rest: unknown[]): unknown {
      push(chunk)
      return e.apply(this, [chunk, ...rest])
    }
  }
}

/** 包装可读流（createReadStream）的 data 处理器：只包第一个 data 监听器，计数每个 chunk 一次。 */
export function attachReadCounter(stream: { on?: unknown }, onBytes: (n: number) => void): void {
  const on = stream.on
  if (typeof on !== 'function' || (stream as { [k: symbol]: unknown })[READ_COUNTER_FLAG] === true) return
  ;(stream as { [k: symbol]: unknown })[READ_COUNTER_FLAG] = true
  const orig = on as (event: string, ...rest: unknown[]) => unknown
  let wrappedFirst = false
  stream.on = function (this: unknown, event: string, ...rest: unknown[]): unknown {
    if (event === 'data' && !wrappedFirst && typeof rest[0] === 'function') {
      wrappedFirst = true
      const handler = rest[0] as (chunk: unknown) => unknown
      rest[0] = function (this: unknown, chunk: unknown): unknown {
        const n = chunkBytes(chunk)
        if (n > 0) onBytes(n)
        return handler(chunk)
      }
    }
    return orig.apply(this, [event, ...rest])
  }
}
/** P1-8：破坏性命令词——命中且命令里出现敏感路径（参数或重定向目标）才报警，避免 rm -rf /tmp 这类常规清理误报。 */
const DESTRUCTIVE_TOKENS = new Set(['rm', 'mv', 'cp', 'dd', 'mkfs', 'mkfs.ext4', 'mkfs.xfs', 'shred', 'truncate'])

/** 关键词边界匹配：须出现在段首或 . _ - 之后（避免 'js-tokens' 这类库名误伤）。 */
const KEYWORD_REGEX_CACHE = new Map<string, RegExp>()
function segmentHasKeyword(part: string, keyword: string): boolean {
  // 上限防护：关键词来自固定配置（理论上限极小），防键注入/异常增长导致无界缓存
  if (KEYWORD_REGEX_CACHE.size >= 512) KEYWORD_REGEX_CACHE.clear()
  let re = KEYWORD_REGEX_CACHE.get(keyword)
  if (re === undefined) {
    const esc = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    re = new RegExp('(?:^|[._-])' + esc + '(?:[._-]|$)', 'i')
    KEYWORD_REGEX_CACHE.set(keyword, re)
  }
  return re.test(part)
}

/**
 * R31 归因阶段直通标志（模块私有，不挂 globalThis——挂全局等于给恶意插件一把「让 vet 失明」
 * 的钥匙：置位后所有 T2 报警静默）。rootIndex 归因期间置位，包装器直通原始 fs，断开
 * 「敏感包名 alarm → 归因 → fs → alarm」无限递归（实测崩溃：V8 栈溢出误报 OOM）。
 */
let rootIndexing = false
export function setRootIndexing(active: boolean): void {
  rootIndexing = active
}
/** 检查当前是否在归因阶段（用于网络模块包装）。 */
export function isRootIndexing(): boolean {
  return rootIndexing
}

/**
 * vet 自身 IO 直通标志（P2-6）：vet 的已知自操作（读/写自己在 ~/.dsh/profiles 下的
 * cordis.patch.yml）在 .dsh 敏感段加入后会被自己报警（A9 归因排除 vet → 归因落空=无主
 * → 照常报警）——盾牌 5s 轮询读 patch 会永久自报警。模块私有标志，只由 withVetSelfIo
 * 同步设置/恢复；恶意插件无法经全局对象置位（与 R31 同款约束：即使 import 本包，也只能
 * 影响自身调用栈内的同步执行）。
 */
let vetSelfIo = false
/** 检查当前是否在 vet 自身 IO 期间（用于网络模块包装）。 */
export function isVetSelfIo(): boolean {
  return vetSelfIo
}
/** 在 fn 执行期间让 T2 包装器直通 vet 自身 IO（恢复式：嵌套调用安全）。 */
export function withVetSelfIo<T>(fn: () => T): T {
  const prev = vetSelfIo
  vetSelfIo = true
  try {
    return fn()
  } finally {
    vetSelfIo = prev
  }
}

/** 工具链临时产物后缀（tsc/vitest/esbuild 等）：*.tmpdir / *.tmp / *.temp / *.swp / *.bak / vim ~。 */
const TRANSIENT_TEMP_SUFFIX = /\.(?:tmp(?:dir)?|temp|swp|bak|orig)$/i

// ── C4 归因链防篡改（0.1.16 加固）───────────────────────────────────

/**
 * 归因链快照：vet 模块加载先于第三方插件，此刻的 Error.prepareStackTrace 是宿主基线。
 * 恶意插件可在运行时替换它（伪造栈文本 → 归因到官方包 → 触发官方信任降噪），
 * 或把 stackTraceLimit 压到 0/1（new Error().stack 无帧 → hint=undefined → N7 族1/2 拦截条件
 * 不成立、族3/4 报警被抑制）。检测到篡改时归因不可信，操作按"归因污染"处理。
 */
const ORIG_PREPARE_STACK_TRACE = Error.prepareStackTrace

/** 归因时栈文本是否不可信（prepareStackTrace 被替换 / stackTraceLimit < 2）。 */
export function isStackTraceTampered(): boolean {
  return Error.prepareStackTrace !== ORIG_PREPARE_STACK_TRACE || Error.stackTraceLimit < 2
}

/**
 * 锁兄弟文件（<file>.lock，@deepseek-ai/dsh-atomic-write 写协议产物）：DSH 对
 * credentials.yaml 等文件的原子写用「wx 创建 <file>.lock（内容仅 PID）→ 写完 finally
 * rm 删锁」互斥；锁的创建与删除是写协议的一部分，不是凭据破坏（真实攻击删的是
 * .credentials.yaml 本体，不删锁）。盾牌实测：宿主每次保存凭据 → unlink(.lock) →
 * .dsh 敏感段命中 → 无主 fs-destroy red 误报。此处豁免锁文件的单路径写/删；
 * 凭据本体与 cp/rename 双路径语义保持严格。
 */
export function isLockSiblingPath(p: string): boolean {
  const norm = p.replace(/\\/g, '/')
  const last = norm.slice(norm.lastIndexOf('/') + 1)
  return last.endsWith('.lock')
}

/**
 * 末段是否为工具链临时产物（纯名字判定，不碰文件系统）。
 * tsc 增量编译在源文件旁建 `<源名>.<pid>.<uuid>.tmpdir` 并随用随删（实测宿主 PID 即嵌入名中）——
 * 名字里的 'secrets' 只是被编译的源文件名（secrets.ts），不是密钥文件；删除它是清理不是破坏。
 */
export function isTransientTempPath(p: string): boolean {
  const norm = p.replace(/\\/g, '/')
  const last = norm.slice(norm.lastIndexOf('/') + 1)
  return last !== '' && TRANSIENT_TEMP_SUFFIX.test(last)
}

/**
 * 归一化路径并判断是否敏感。
 * mode='mutate'（写/删）额外计入系统根前缀（/etc /usr /var …：写删系统文件=篡改/破坏）；
 * mode='read' 只看密钥特征（段名/后缀/关键词）——读系统目录下的普通文件（库文件、配置）属正常
 * 操作；枚举目标（/etc/passwd、/etc/shadow）已由精确段名覆盖，不需要系统根。
 */
/** DSH 安装树豁免正则（~/.dsh/profiles 下 node_modules 依赖树）——高频路径，提为模块常量。 */
const DASH_PROFILES_NODE_MODULES_RE = /\/\.dsh\/profiles(?:\/[^/]+)?\/node_modules\//
export function isSensitivePath(p: string, cfg: HookConfig, mode: 'read' | 'mutate' = 'mutate'): boolean {
  const norm = p.replace(/\\/g, '/')
  // DSH 安装树豁免：~/.dsh/profiles/**/node_modules/** 是平台自己装的公开依赖树。
  // 插件加载期 require.resolve 触发 realpathSync（electron/install.js、dsh-traffic-light/package.json
  // 等），归因到插件但行为完全合法。凭据从不在 profiles/*/node_modules 下（真实凭据面
  // ~/.dsh/.credentials.yaml、~/.dsh/sessions/** 等不匹配此模式，仍正常报警）。
  // 没有这条：.dsh 段先命中 sensitiveSegments，node_modules 的 break 根本执行不到——
  // A9 设计时只考虑了 ~/.ssh/node_modules/x（该报），没预料到 DSH 安装树是合法常态。
  // (?:/[^/]+)? 可选 profile 名段：per-profile（profiles/web/node_modules）与顶层 hoisted
  // 树（profiles/node_modules，pnpm workspace 根布局）都豁免——旧正则要求中间必须有 profile
  // 名，顶层树不匹配 → 落到 .dsh 敏感段 → DSH 重启重解析插件树时刷出一批 fs-probe 误报。
  if (DASH_PROFILES_NODE_MODULES_RE.test(norm)) return false
  const parts = norm.split('/')
  for (let i = 0; i < parts.length; i++) {
    const low = parts[i].toLowerCase()
    // A9 包目录豁免：node_modules 段之后的路径段不做敏感匹配。包名/包内文件是公开工件——
    // 含 credential/secret 等词的包名是正常生态（实测 @aws-sdk/credential-provider-*、
    // @deepseek-ai/dsh-credentials-local 等 12 个），宿主模块解析（require.resolve 内部
    // realpathSync/stat 包内 package.json）与 vet 扫描读取都会高频触碰 → 既往全部误报成
    // fs-probe 且归因到 vet 自己。真实凭据在用户/系统目录，不在包目录；node_modules 之前的
    // 段照常判定（~/.ssh/node_modules/x 仍命中 .ssh）。
    if (low === 'node_modules') break
    if (low === '.env' || low.startsWith('.env.')) return true
    // 末段是工具链临时产物（.secrets.ts.165387.<uuid>.tmpdir）→ 跳过敏感词判定；父段照常
    // 全量判定（~/.ssh/config.bak 仍命中 .ssh；.env.tmp 已在上方命中）。
    if (i === parts.length - 1 && isTransientTempPath(norm)) continue
    if (cfg.sensitiveSegments.some(s => low === s.toLowerCase())) return true
    if (cfg.sensitiveExts.some(ext => low.endsWith(ext))) return true
    if (cfg.sensitiveKeywords.some(k => segmentHasKeyword(low, k))) return true
  }
  if (mode === 'read') return false
  for (const root of cfg.sensitiveRoots) {
    if (norm === root || norm.startsWith(root + '/')) return true
  }
  return false
}

/**
 * 检测路径是否为 DSH 会话日志文件（~/.dsh/sessions/** 下的 .zst/.zstd/.jsonl 等）。
 * 这类文件的删除通常是宿主自身的日志轮换（压缩/整理），非恶意销毁。
 */
/** DSH 会话目录前缀正则（高频路径，提为模块常量）。 */
const DSH_SESSIONS_DIR_RE = /\/\.dsh\/sessions\//
/** 会话日志扩展名（含分片后缀）正则。 */
const SESSION_LOG_EXT_RE = /\.(zst|zstd|jsonl|log)(?:\.[a-z0-9]+)*(\.tmp)?$/i
export function isSessionLogFile(path: string): boolean {
  const norm = path.replace(/\\/g, '/')
  // 必须在 ~/.dsh/sessions/ 下
  if (!DSH_SESSIONS_DIR_RE.test(norm)) return false
  // 文件名以压缩/日志扩展名结尾；允许分片后缀（如 session.jsonl.zstd.9a3 / .zst.001）
  return SESSION_LOG_EXT_RE.test(norm)
}

/** 取第一个字符串参数作为目标（路径/命令）。 */
function firstString(args: unknown[]): string | undefined {
  for (const a of args) {
    if (typeof a === 'string') return a
    if (typeof a === 'object' && a !== null && 'path' in a) {
      const p = (a as { path?: unknown }).path
      if (typeof p === 'string') return p
    }
  }
  return undefined
}

/** 取全部字符串参数（cp/rename 的 src+dest 都要检查——dest 覆盖系统文件/密钥也应报警）。 */
function allStrings(args: unknown[]): string[] {
  const out: string[] = []
  for (const a of args) {
    if (typeof a === 'string') out.push(a)
    else if (Array.isArray(a)) out.push(...allStrings(a)) // spawn/execFile 的 argv 数组
    else if (typeof a === 'object' && a !== null && 'path' in a && typeof (a as { path?: unknown }).path === 'string') {
      out.push((a as { path: string }).path)
    }
  }
  return out
}

/** 拼接命令行为可读目标（含参数，便于人工判断）。 */
function commandString(args: unknown[]): string {
  const parts: string[] = []
  for (const a of args) {
    if (typeof a === 'string') parts.push(a)
  }
  return parts.join(' ').slice(0, 200)
}

/** 命令行是否命中报警关键词：整词等于命令词或其 basename（'bash' 不误伤 'bashful'，'git' 不报警）。 */
function hitsShellToken(command: string, tokens: string[]): boolean {
  const words = command.split(/[^A-Za-z0-9._/-]+/).filter(Boolean)
  return tokens.some(t => words.some(w => w === t || w.slice(w.lastIndexOf('/') + 1) === t))
}

/**
 * P1-8：命令串里的路径形 token（含 / 或 ~ 开头）——用于「破坏性命令 + 敏感路径」组合判定。
 * exec('rm -rf ~/.ssh') 里 '~/.ssh' 是路径 token；exec('echo x') 没有。
 * ~ 展开为 /home 前缀（保守形态：命中 .ssh 等段名即可判定，不必解析真实 HOME）。
 */
function pathTokens(command: string): string[] {
  return command.split(/\s+/)
    .map(w => w.replace(/^['"]|['"]$/g, ''))
    .filter(w => w.includes('/') || w.startsWith('~'))
    .map(w => w.replace(/^~/, '/home'))
}

/** P1-8：shell 重定向目标（> file / >> file / 2> file），用于 exec('echo x > /etc/passwd') 检测。 */
function redirectTarget(command: string): string | undefined {
  const m = /(?:^|\s)[12]?>>?\s*([^\s&;|]+)/.exec(command)
  return m === null ? undefined : m[1].replace(/^['"]|['"]$/g, '').replace(/^~/, '/home')
}

/** 路径是否为完整性金丝雀文件（精确文件名匹配，N4）。 */
export function isIntegrityPath(p: string, roots: string[]): boolean {
  if (roots.length === 0) return false
  const norm = p.replace(/\\/g, '/')
  return roots.some(r => norm === r.replace(/\\/g, '/'))
}

/** 路径是否落在任一蜜罐根下（D27）。 */
export function isHoneypotPath(p: string, roots: string[]): boolean {
  if (roots.length === 0) return false
  const norm = p.replace(/\\/g, '/')
  return roots.some(r => {
    const root = r.replace(/\\/g, '/')
    return norm === root || norm.startsWith(root + '/')
  })
}

/** 危险操作分类（纯函数）：返回报警候选（pluginHint 由调用方经栈归因补全）。 */
export function classifyOp(op: HookOp, cfg: HookConfig): HookAlarm | null {
  const { module, op: name, args } = op
  const target = firstString(args) ?? ''
  if (module === 'child_process' && PROC_OPS.has(name)) {
    const cmd = commandString(args)
    // 命令全貌（含 spawn argv 数组的元素）：exec('rm -rf ~/.ssh') 与 spawn('rm', ['-rf', '/home/u/.ssh'])
    // 都能被词/路径检测覆盖。注意 cmd 是字符串，不能展开成字符数组（...cmd 会每字符间插空格）。
    const full = [cmd, ...allStrings(args)].join(' ')
    // P1-8：破坏性命令（rm -rf ~/.ssh / dd of=/etc/… / mkfs / cp 覆盖敏感路径）——只对命令里
    // 出现敏感路径（参数或重定向目标）的组合报警；exec('rm -rf /tmp/x') 常规清理不报。
    const destr = hitsShellToken(full, [...DESTRUCTIVE_TOKENS])
    const redirect = redirectTarget(full)
    const redirectSensitive = redirect !== undefined && isSensitivePath(redirect, cfg, 'mutate')
    if (!hitsShellToken(cmd, cfg.shellTokens)) {
      // 触发条件：破坏性命令 + 敏感路径参数，或 shell 重定向到敏感路径（echo x > /etc/passwd）
      if (!destr && !redirectSensitive) return null
      const paths = [...pathTokens(full), redirect].filter((p): p is string => p !== undefined)
      if (!paths.some(p => isSensitivePath(p, cfg, 'mutate'))) return null
    }
    return {
      severity: 'yellow',
      kind: 'spawn',
      message: `子进程 spawn：${name}(${cmd.slice(0, 120)})`,
      target: cmd.slice(0, 120),
    }
  }
  if (module === 'fs' && isHoneypotPath(target, cfg.honeypotRoots)) {
    // D27 蜜罐：触碰诱饵路径（读/写/删）→ 高置信的翻找密钥信号，独立报警类
    if (DESTROY_OPS.has(name) || WRITE_OPS.has(name) || READ_OPS.has(name) || PROBE_OPS.has(name)) {
      const severity = DESTROY_OPS.has(name) ? 'red' : 'yellow'
      return { severity, kind: 'honeypot', message: `蜜罐命中：${name}(${target.slice(0, 120)}) — 诱饵密钥文件被触碰（疑似翻找密钥）`, target }
    }
  }
  if (module === 'fs') {
    // N4 完整性金丝雀（仅 ~/.dsh 内）：写/删即 red kind=integrity——勒索加密 profile 目录
    // （配置/会话/凭据面）的最早触发信号；读不报（内容固定已知，无害）
    if ((DESTROY_OPS.has(name) || WRITE_OPS.has(name)) && isIntegrityPath(target, cfg.integrityRoots) && !isLockSiblingPath(target)) {
      return {
        severity: 'red',
        kind: 'integrity',
        message: `完整性金丝雀被写删：${name}(${target.slice(0, 120)}) — ~/.dsh 关键文件被篡改（疑似勒索/破坏，N4）`,
        target,
      }
    }
    // N7 族 3/4：系统持久化/提权面写入、供应链/安装态篡改 → 报警（写操作判定前，更具体）
    // cp/rename/copyFile 是成对路径：写目标可能是 dst（覆盖系统文件/落位安装态），两侧都查
    if (WRITE_OPS.has(name)) {
      const writeCandidates = (name === 'cp' || name === 'cpSync' || name === 'rename' || name === 'renameSync'
        || name === 'copyFile' || name === 'copyFileSync') ? allStrings(args) : [target]
      const persist = writeCandidates.find(isPersistenceWriteTarget)
      if (persist !== undefined) {
        return { severity: 'yellow', kind: 'persistence-write', message: `系统持久化/提权面写入（N7 族 3）：${name}(${persist.slice(0, 120)}) — 可恢复，建议核实来源`, target: persist.slice(0, 120) }
      }
      const install = writeCandidates.find(isInstallWriteTarget)
      if (install !== undefined) {
        return { severity: 'yellow', kind: 'install-write', message: `供应链/安装态篡改（N7 族 4）：${name}(${install.slice(0, 120)}) — 可重装恢复，建议重哈希比对`, target: install.slice(0, 120) }
      }
    }
    // isLockSiblingPath：atomic-write 协议锁（<file>.lock）随写随删，豁免；凭据本体照删照报
    if (DESTROY_OPS.has(name) && isSensitivePath(target, cfg, 'mutate') && !isLockSiblingPath(target)) {
      const isSessionLog = isSessionLogFile(target)
      return {
        severity: 'red',
        kind: 'fs-destroy',
        message: `敏感路径删除：${name}(${target.slice(0, 120)})`,
        target,
        ...(isSessionLog && { sessionLog: true }),
      }
    }
    // cp/rename 是成对路径：src 敏感（拷贝密钥出局）或 dest 敏感（覆盖系统文件/密钥落位）都要报
    if (name === 'cp' || name === 'cpSync' || name === 'rename' || name === 'renameSync' || name === 'copyFile' || name === 'copyFileSync') {
      const paths = allStrings(args)
      const sensitive = paths.find(p => isSensitivePath(p, cfg, 'mutate'))
      if (sensitive !== undefined) {
        return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入（${name}）：${sensitive.slice(0, 120)}`, target: sensitive.slice(0, 120) }
      }
    }
    // open/openSync 的 flags 参数带 w/a/+/x → 写意图（fs.open('/etc/passwd','w') 不该按读取报）
    // P1-7：跳过首参（路径本身以 r/w/a 开头会误当 flags，如 open('auth.txt','r')）——
    // flags 认 Node 短合法形态：r/w/a/x（x=排他新建）、可带 s（同步）/x/+（rwx/as/ax/wx 等 2-3 字符），
    // 长度 ≤3；wx+/ax+/as+/rs+ 等复合也要进入写意图判定（旧正则 ^[rwax]\+?$ 漏复合 → 按读报，盲点）。只认首参之后。
    if ((name === 'open' || name === 'openSync') && READ_OPS.has(name)) {
      const flags = args.slice(1).find((a): a is string => typeof a === 'string' && /^(?:[rwax]|[rwa][sx]|[rwa][+]|[rwa][sx][+])$/.test(a))
      if (flags !== undefined && /[wax+]/.test(flags) && isSensitivePath(target, cfg, 'mutate')) {
        return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入（open flags=${flags}）：${target.slice(0, 120)}`, target }
      }
    }
    // isLockSiblingPath：写入锁文件（wx 创建带 PID）也是协议操作，不再误报 fs-write
    if (WRITE_OPS.has(name) && isSensitivePath(target, cfg, 'mutate') && !isLockSiblingPath(target)) {
      return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入：${name}(${target.slice(0, 120)})`, target }
    }
    if (READ_OPS.has(name) && isSensitivePath(target, cfg, 'read')) {
      return { severity: 'yellow', kind: 'fs-read', message: `敏感路径读取：${name}(${target.slice(0, 120)})`, target }
    }
    // M7：列目录/stat/access 敏感路径 = 侦察（凭据狩猎第一步）
    if (PROBE_OPS.has(name) && isSensitivePath(target, cfg, 'read')) {
      return { severity: 'yellow', kind: 'fs-probe', message: `敏感路径侦察：${name}(${target.slice(0, 120)})`, target }
    }
  }
  return null
}

/** 从错误栈提取插件包名：栈帧路径 → 已知插件根目录（root→包名映射）最长前缀匹配。 */
export function pluginFromStack(stack: string | undefined, roots: Map<string, string>): string | undefined {
  if (stack === undefined || roots.size === 0) return undefined
  for (const frame of stack.split('\n')) {
    const m = /\((.+?):\d+:\d+\)/.exec(frame) ?? /at (.+?):\d+:\d+/.exec(frame)
    if (m === null) continue
    let path = m[1].replace(/\\/g, '/')
    if (path.startsWith('file://')) path = path.slice('file://'.length).replace(/\\/g, '/')
    let best: { len: number; name: string } | undefined
    for (const [root, name] of roots) {
      const normRoot = root.replace(/\\/g, '/')
      // M4：要求路径边界——/node_modules/foo 不能匹配 /node_modules/foobar/index.js
      if ((path === normRoot || path.startsWith(normRoot + '/'))
        && (best === undefined || normRoot.length > best.len)) {
        best = { len: normRoot.length, name }
      }
    }
    if (best !== undefined) return best.name
  }
  return undefined
}

/**
 * 包装一个模块对象上的操作（可对真实内置模块或测试假模块使用）。
 * 包装器：classify → 报警（栈归因）→ 原函数原样调用（alarm-only，不阻断）。
 * @returns 恢复原函数的 disposer。
 */
export function patchModule(
  mod: Record<string, unknown>,
  moduleName: HookModule,
  cfg: HookConfig,
  sink: (alarm: HookAlarm) => void,
  rootIndex: () => Map<string, string>,
  /** N3 台账观测通道（可选）：每个删/写/读/spawn 事件发一份 LedgerFsEvent；不传则零开销。 */
  observe?: (evt: LedgerFsEvent) => void,
): () => void {
  const original = new Map<string, unknown>()
  const allOps = [...DESTROY_OPS, ...WRITE_OPS, ...READ_OPS, ...PROC_OPS, ...PROBE_OPS]
  for (const opName of allOps) {
    const fn = mod[opName]
    if (typeof fn !== 'function') continue
    original.set(opName, fn)
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
      // R31：rootIndex 归因阶段自身的 fs 探测直通（断开敏感包名 alarm→归因→fs→alarm 无限递归）
      // P2-6：vet 自身已知 IO（patch 配置读写）同样直通，不产生自报警
      if (rootIndexing || vetSelfIo) {
        return (fn as (...a: unknown[]) => unknown).apply(this, args)
      }
      const alarm = classifyOp({ module: moduleName, op: opName, args }, cfg)
      const ledgerRelevant = observe !== undefined && FS_LEDGER_OPS.has(opName)
      const blockRelevant = moduleName === 'fs' && BLOCK_FS_OPS.has(opName) && confirmBlock.mode() === 'block'
      // C4（0.1.16 加固）：归因链被篡改（prepareStackTrace 替换 / stackTraceLimit<2）时栈文本不可信
      const stackTampered = isStackTraceTampered()
      let hint: string | undefined
      if (alarm !== null || ledgerRelevant || blockRelevant) {
        try {
          if (stackTampered) {
            hint = undefined // 归因不可信：不取栈，操作按归因污染处理
          } else {
            // P1-3：归因失败不能反噬原始调用——报警保留无主，操作照常执行
            hint = pluginFromStack(new Error().stack ?? undefined, rootIndex())
          }
        } catch {
          hint = undefined
        }
      }
      // C4：归因被篡改 + 敏感操作 → 独立 red 报警（主动隐藏归因本身就是攻击信号）
      if (stackTampered && (alarm !== null || blockRelevant)) {
        const t = firstString(args) ?? ''
        sink({
          severity: 'red',
          kind: 'attribution-tampered',
          message: '栈归因被篡改（Error.prepareStackTrace/stackTraceLimit 被修改）——敏感操作无法归属，主动隐藏归因疑为攻击（C4）',
          target: t.slice(0, 120),
        })
      }
      // N7 确认拦截：判定（族 1/2）在调用原函数之前执行——拦截 = 抛错（fail-open：异常 → 放行）
      // C4：归因被篡改时用哨兵身份（不匹配任何已知插件）参与族 2 凭据本体判定——
      // 故意隐藏归因的凭据破坏照样拦截；族 1（已确认插件的后续破坏）在归因不可用下降级（记录边界）
      let block: BlockDecision | null = null
      const blockIdentity: string | undefined = stackTampered ? '__vet_attribution_tampered__' : hint
      if (blockRelevant && blockIdentity !== undefined && (stackTampered || !isOfficial(blockIdentity))) {
        try {
          block = confirmBlock.decideBlock(blockIdentity, opName, args)
          // 族 3/4 覆写：用户显式 'block' 才拦（默认 alarm 只报警，零误拦护栏不变——
          // 仅破坏类操作面、仅该插件归因；appendFile 等可逆写即使升级也不拦）
          if (block === null && alarm !== null && (alarm.kind === 'persistence-write' || alarm.kind === 'install-write')) {
            const family = alarm.kind === 'persistence-write' ? 3 : 4
            if (confirmBlock.familyMode(family) === 'block') {
              block = { family, reason: alarm.message }
            }
          }
        } catch {
          block = null
        }
      }
      if (block !== null) {
        const target = firstString(args) ?? ''
        sink({
          severity: 'red',
          kind: 'n7-block',
          message: `vet 拦截（N7 族 ${block.family}）：${block.reason}`,
          target: target.slice(0, 120),
          pluginHint: hint,
        })
        throw new Error('vet 拦截（N7）：' + block.reason + '；如系误判请将 confirmBlock 降为 alarm 后重试')
      }
      const result = (fn as (...a: unknown[]) => unknown).apply(this, args)
      if (observe !== undefined && !rootIndexing && !vetSelfIo && ledgerRelevant) {
        const target = firstString(args) ?? ''
        const evt: LedgerFsEvent = {
          plugin: hint,
          module: moduleName,
          op: opName,
          target,
          paths: allStrings(args),
          sensitive: isSensitivePath(target, cfg, 'read'),
          bytes: fsOpBytes(opName, args, result),
        }
        // 流操作：字节走流计数器（同一流对象上挂 chunk 计数，身份不变）
        if (typeof result === 'object' && result !== null) {
          if (opName === 'createReadStream') {
            attachReadCounter(result as { on?: unknown }, (bytes) => observe({ ...evt, bytes }))
          } else if (opName === 'createWriteStream') {
            attachWriteCounter(result as { write?: unknown; end?: unknown }, (bytes) => observe({ ...evt, bytes }))
          } else {
            observe(evt)
          }
        } else {
          observe(evt)
        }
      }
      if (alarm !== null) sink({ ...alarm, pluginHint: hint })
      return result
    }
    mod[opName] = wrapped
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
}

// ── 网络出口观测（P1 特性）─────────────────────────────────────

/** 官方包信任（能力授权）：网络出口观测对官方归因的报警降噪。
 * P2-5 修复：统一导出，runtime-guard.ts 复用（避免包名变更时一处遗漏）。
 */
export function isOfficial(name: string): boolean {
  return name.startsWith('@deepseek-ai/') || name === '@jieai/dsh-plugin-vet'
}

/**
 * 网络模块的操作名集合。
 * P2-10：必须包含 'get'——http.get/https.get 是独立导出函数，其内部调用的是模块闭包里的
 * request（非 module.exports.request），只包装 request/connect/createConnection 会让
 * https.get('https://webhook.site/...') 这类外泄调用完全绕过出口监控（实测逃逸）。
 * tls/net 没有 get 导出，patchNetworkModule 的 typeof fn==='function' 守卫会跳过，安全。
 */
const NET_OPS = new Set(['request', 'connect', 'createConnection', 'get'])

/** 敏感主机列表（v5 修订：移除 gist.github.com，合法服务）。 */
const SENSITIVE_HOSTS = [
  'webhook.site', 'requestbin.com', 'ngrok.io', 'localtunnel.me',
  'pastebin.com',
  'api.binance.com', 'api.coinbase.com',
]

/** 敏感端口（v5 修订：移除 8888，Jupyter 默认端口）。 */
const SENSITIVE_PORTS = new Set([4444, 5555, 6666, 7777, 1337, 31337])

/** 白名单主机（不报警）。 */
const EGRESS_ALLOWLIST = [
  'registry.npmjs.org',
  'api.github.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
]

/** 网络主机是否参与台账/外泄观测（回环/白名单/unix socket 不算——本地与受信服务不计数）。 */
export function isTrackedNetHost(hostname: string): boolean {
  const h = hostname.toLowerCase()
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === 'unix-socket') return false
  return !EGRESS_ALLOWLIST.includes(h)
}

/**
 * 从网络模块参数中提取目标（hostname, port, path）。
 * 处理多种参数形态：
 * - http.request(urlString, ...)
 * - http.request(urlObject, ...)
 * - http.request(options, ...)
 * - net.connect({ host, port }, ...)
 * - net.connect(port, host?, ...)
 */
export function extractNetworkTarget(args: unknown[]): { hostname: string; port?: number; path: string } | null {
  if (args.length === 0) return null
  
  const first = args[0]
  
  // 字符串 URL
  if (typeof first === 'string') {
    try {
      const url = new URL(first)
      return {
        hostname: url.hostname,
        port: url.port ? parseInt(url.port, 10) : undefined,
        path: url.pathname + url.search,
      }
    } catch {
      return null
    }
  }
  
  // URL 对象
  if (first instanceof URL) {
    return {
      hostname: first.hostname,
      port: first.port ? parseInt(first.port, 10) : undefined,
      path: first.pathname + first.search,
    }
  }

  // Request 实例（fetch(new Request(url, init))）——目标取自 .url。此前漏分支：实例落到下方
  // options 对象判定全 miss → classify/台账/金丝雀全部失明（网络出口盲点）。body 是流不取读
  // （保持字符串 body 才计字节的既有约定），仅目标必须回到观测面。
  if (typeof first === 'object' && first !== null && typeof (first as { url?: unknown }).url === 'string') {
    try {
      const url = new URL((first as { url: string }).url)
      return {
        hostname: url.hostname,
        port: url.port ? parseInt(url.port, 10) : undefined,
        path: url.pathname + url.search,
      }
    } catch {
      return null
    }
  }
  
  // options 对象
  if (typeof first === 'object' && first !== null) {
    const opts = first as Record<string, unknown>
    
    // net.connect({ port, host }) 形态
    if (typeof opts.port === 'number') {
      const rawHost = typeof opts.host === 'string' ? opts.host : (typeof opts.hostname === 'string' ? opts.hostname : 'localhost')
      return {
        // P2-7 修复：hostname 统一小写（防止 {host:'Webhook.Site'} 逃逸敏感主机匹配）
        hostname: rawHost.toLowerCase(),
        port: opts.port,
        path: typeof opts.path === 'string' ? opts.path : '/',
      }
    }
    
    // http.request({ hostname, port, path }) 形态
    if (typeof opts.hostname === 'string' || typeof opts.host === 'string') {
      const rawHost = (typeof opts.hostname === 'string' ? opts.hostname : opts.host) as string
      return {
        // P2-7 修复：hostname 统一小写
        hostname: rawHost.toLowerCase(),
        port: typeof opts.port === 'number' ? opts.port : (typeof opts.port === 'string' ? parseInt(opts.port, 10) : undefined),
        path: typeof opts.path === 'string' ? opts.path : '/',
      }
    }
    
    // net.connect({ path }) Unix socket 形态
    if (typeof opts.path === 'string' && opts.hostname === undefined && opts.host === undefined) {
      return {
        hostname: 'unix-socket',
        path: opts.path,
      }
    }
  }
  
  // net.connect(port, host?) 形态
  if (typeof first === 'number') {
    const rawHost = typeof args[1] === 'string' ? args[1] as string : 'localhost'
    return {
      // P2-7 修复：hostname 统一小写
      hostname: rawHost.toLowerCase(),
      port: first,
      path: '/',
    }
  }
  
  return null
}

/**
 * 网络操作分类函数。
 */
export function classifyNetworkOp(
  moduleName: string,
  opName: string,
  args: unknown[],
  _cfg: HookConfig
): HookAlarm | null {
  const target = extractNetworkTarget(args)
  if (target === null) return null
  
  // 回环地址不报警
  if (target.hostname === 'localhost' || target.hostname === '127.0.0.1' || target.hostname === '::1') return null
  
  // 白名单主机不报警
  if (EGRESS_ALLOWLIST.includes(target.hostname)) return null
  
  // Unix socket 不报警（本地通信）
  if (target.hostname === 'unix-socket') return null
  
  // 敏感端口 → red（反向 shell 特征）
  if (target.port !== undefined && SENSITIVE_PORTS.has(target.port)) {
    return {
      severity: 'red',
      kind: 'net-egress',
      message: `网络出口：${moduleName}.${opName} → ${target.hostname}:${target.port}（敏感端口）`,
      target: `${target.hostname}:${target.port}`,
    }
  }
  
  // 敏感主机 → yellow
  if (SENSITIVE_HOSTS.some(h => target.hostname === h || target.hostname.endsWith('.' + h))) {
    return {
      severity: 'yellow',
      kind: 'net-egress',
      message: `网络出口：${moduleName}.${opName} → ${target.hostname}${target.path}（敏感主机）`,
      target: target.hostname + target.path,
    }
  }
  
  return null
}

/**
 * 包装网络模块（独立于 patchModule，因为网络模块的操作名和参数形态与 fs 完全不同）。
 */
export function patchNetworkModule(
  mod: Record<string, unknown>,
  moduleName: string,
  cfg: HookConfig,
  sink: (alarm: HookAlarm) => void,
  rootIndex: () => Map<string, string>,
  /** N3 台账观测通道（可选）：对非白名单主机包装 write/end 按 chunk 上报字节；不传则零开销。 */
  observe?: (evt: LedgerNetEvent) => void,
  /** N4 金丝雀扫描（可选）：出站 URL（一次/请求）与 body 文本（按 chunk）回调；不传则零开销。 */
  canaryScan?: (hint: string | undefined, text: string, where: 'url' | 'body') => void,
): () => void {
  const original = new Map<string, unknown>()
  for (const opName of NET_OPS) {
    const fn = mod[opName]
    if (typeof fn !== 'function') continue
    original.set(opName, fn)
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
      if (rootIndexing || vetSelfIo) {
        return (fn as (...a: unknown[]) => unknown).apply(this, args)
      }
      const alarm = classifyNetworkOp(moduleName, opName, args, cfg)
      // C4：归因链被篡改 → 网络归因同样不可信（置空归因，操作照报）
      const stackTampered = isStackTraceTampered()
      let hint: string | undefined
      if (alarm !== null || observe !== undefined || canaryScan !== undefined) {
        try { if (!stackTampered) hint = pluginFromStack(new Error().stack ?? undefined, rootIndex()) } catch {}
      }
      if (stackTampered && alarm !== null) {
        sink({
          severity: 'red',
          kind: 'attribution-tampered',
          message: '栈归因被篡改（Error.prepareStackTrace/stackTraceLimit 被修改）——网络操作无法归属，主动隐藏归因疑为攻击（C4）',
          target: (firstString(args) ?? '').slice(0, 120),
        })
      }
      const result = (fn as (...a: unknown[]) => unknown).apply(this, args)
      if (observe !== undefined && !rootIndexing && !vetSelfIo) {
        const target = extractNetworkTarget(args)
        if (target !== null && isTrackedNetHost(target.hostname)) {
          const base: LedgerNetEvent = { plugin: hint, module: moduleName, op: opName, hostname: target.hostname, bytes: 0 }
          const res = result as { write?: unknown } | null | undefined
          if (typeof res === 'object' && res !== null && typeof res.write === 'function') {
            // 请求对象上的 write/end 是全量可见的（TLS 加密前，应用层数据）；按 chunk 上报
            attachWriteCounter(res, (bytes) => observe({ ...base, bytes }))
          } else {
            observe(base)
          }
        }
      }
      if (canaryScan !== undefined && !rootIndexing && !vetSelfIo) {
        const t = extractNetworkTarget(args)
        if (t !== null) {
          const urlText = typeof args[0] === 'string' ? args[0] : t.hostname + t.path
          canaryScan(hint, urlText, 'url')
          if (isTrackedNetHost(t.hostname)) {
            const res = result as { write?: unknown } | null | undefined
            if (typeof res === 'object' && res !== null && typeof res.write === 'function') {
              attachCanaryScanner(res, (text) => canaryScan(hint, text, 'body'))
            }
          }
        }
      }
      if (alarm !== null) {
        if (hint === undefined || !isOfficial(hint)) {
          sink({ ...alarm, pluginHint: hint })
        }
      }
      return result
    }
    mod[opName] = wrapped
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
}