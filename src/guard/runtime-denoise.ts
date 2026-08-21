/**
 * T2 归因降噪原语
 * P0-4 结构债拆分自 runtime-hooks.ts（路径敏感判定 / 锁兄弟豁免 / 会话日志降噪 / 栈归因链防篡改 / vet 自身 IO 直通 / rootIndexing 直通 / 命令串与路径 token 解析）
 */

import type { HookConfig } from './runtime-ops.js'

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

/** DSH web 状态目录正则（覆盖 ~/.dsh/web 与 ~/.dsh/profiles/web 两种布局，高频路径提为常量）。 */
const DSH_WEB_STATE_DIR_RE = /\/\.dsh\/(?:profiles\/)?web\//
/**
 * DSH web 状态临时产物（五轮用户反馈降噪）：宿主 web 层保存 UI 状态（.shortcut-bar.json 等）
 * 走原子写协议——高频创建/清理 `.名.json.<pid>.<uuid>.tmpdir`，lstat+rmdir 成对出现；栈里只有
 * 宿主帧 → 无归因 → 每次保存都刷 red fs-destroy / yellow fs-probe。判定纯名字/目录形状。
 * 刻意收窄到 web/ 目录：凭据面（.credentials.yaml 原子写临时件）、sessions/**、完整性金丝雀、
 * 蜜罐不在此列，其上任何操作照旧报警。是否豁免由调用方结合归因决定（插件碰它=信号，照报）。
 */
export function isDshWebTempArtifact(p: string): boolean {
  const norm = p.replace(/\\/g, '/')
  if (!DSH_WEB_STATE_DIR_RE.test(norm)) return false
  const last = norm.slice(norm.lastIndexOf('/') + 1)
  return last !== '' && TRANSIENT_TEMP_SUFFIX.test(last)
}

/** DSH 状态目录正则（~/.dsh 下任意深度）。 */
const DSH_STATE_DIR_RE = /\/\.dsh\//
/** 宿主原子写暂存目录段：`.<basename>.<pid>.<uuid>.tmpdir`（randomUUID 小写 hex，宽松认大小写）。 */
const ATOMIC_STAGING_SEGMENT_RE = /^\..+\.\d+\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmpdir$/i
/**
 * DSH 宿主原子写暂存路径（六轮用户反馈降噪）：fs-local 的 writeFileAtomic 在目标旁建
 * `.<basename>.<pid>.<uuid>.tmpdir` 暂存目录（0700），写入 `<basename>.tmp` 后 rename 提交、
 * rm -rf 必删（dsh-src packages/fs/fs-local/src/fsio.ts writeFileAtomic 协议，暂存目录是
 * 随用随清的残留）。用户手改配置触发宿主重存、或宿主直接保存设置，都会在 ~/.dsh 根产生
 * `.settings.yaml.<pid>.<uuid>.tmpdir` 的 lstat+rmdir 清理对——此前豁免只覆盖 web/ 子树，
 * 这里补齐 ~/.dsh 任意深度。判定到段级：暂存目录本身与其内 .tmp 文件都命中。
 * 刻意不匹配凭据面协议形态（@deepseek-ai/dsh-atomic-write 的 `<file>.<hex12>.tmp`，无
 * pid/uuid 段）：凭据临时件照旧报警；是否豁免由调用方结合归因决定（插件碰它=信号，照报）。
 */
export function isDshAtomicStagingPath(p: string): boolean {
  const norm = p.replace(/\\/g, '/')
  if (!DSH_STATE_DIR_RE.test(norm)) return false
  return norm.split('/').some(seg => ATOMIC_STAGING_SEGMENT_RE.test(seg))
}
/**
 * 归一化路径并判断是否敏感。
 * mode='mutate'（写/删）额外计入系统根前缀（/etc /usr /var …：写删系统文件=篡改/破坏）；
 * mode='read' 只看密钥特征（段名/后缀/关键词）——读系统目录下的普通文件（库文件、配置）属正常
 * 操作；枚举目标（/etc/passwd、/etc/shadow）已由精确段名覆盖，不需要系统根。
 */
/** DSH 安装树豁免正则（~/.dsh 下任意 profile 目录里的 node_modules 依赖树）——高频路径，提为模块常量。 */
const DASH_PROFILES_NODE_MODULES_RE = /\/\.dsh\/(?:[^/]+\/)*node_modules\//
export function isSensitivePath(p: string, cfg: HookConfig, mode: 'read' | 'mutate' = 'mutate'): boolean {
  const norm = p.replace(/\\/g, '/')
  // DSH 安装树豁免：~/.dsh/**/node_modules/** 是平台自己装的公开依赖树（任意 profile 布局——
  // 本机 profiles/web/node_modules、用户机 .dsh/web/node_modules、顶层 hoisted node_modules）。
  // 插件加载期 require.resolve 触发 realpathSync（electron/install.js、dsh-traffic-light/package.json
  // 等），归因到插件但行为完全合法；DSH 升级安装/重解析依赖树时这些无主访问也高频出现。
  // 凭据从不在任何 profile 的 node_modules 下（真实凭据面 ~/.dsh/.credentials.yaml、
  // ~/.dsh/sessions/** 等不匹配此模式，仍正常报警）。
  // 没有这条：.dsh 段先命中 sensitiveSegments，node_modules 的 break 根本执行不到——
  // A9 设计时只考虑了 ~/.ssh/node_modules/x（该报），没预料到 DSH 安装树是合法常态。
  // 旧正则只豁免 profiles(?:/[^/]+)?——顶层 hoisted 或 .dsh 直接放 profile（无 profiles 层）
  // 都落回 .dsh 敏感段 → DSH 重启/升级重解析插件树时刷出一批 fs-probe/fs-read 误报。
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
export function firstString(args: unknown[]): string | undefined {
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
export function allStrings(args: unknown[]): string[] {
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
export function commandString(args: unknown[]): string {
  const parts: string[] = []
  for (const a of args) {
    if (typeof a === 'string') parts.push(a)
  }
  return parts.join(' ').slice(0, 200)
}

/** 命令行是否命中报警关键词：整词等于命令词或其 basename（'bash' 不误伤 'bashful'，'git' 不报警）。 */
export function hitsShellToken(command: string, tokens: string[]): boolean {
  const words = command.split(/[^A-Za-z0-9._/-]+/).filter(Boolean)
  return tokens.some(t => words.some(w => w === t || w.slice(w.lastIndexOf('/') + 1) === t))
}

/**
 * P1-8：命令串里的路径形 token（含 / 或 ~ 开头）——用于「破坏性命令 + 敏感路径」组合判定。
 * exec('rm -rf ~/.ssh') 里 '~/.ssh' 是路径 token；exec('echo x') 没有。
 * ~ 展开为 /home 前缀（保守形态：命中 .ssh 等段名即可判定，不必解析真实 HOME）。
 */
export function pathTokens(command: string): string[] {
  return command.split(/\s+/)
    .map(w => w.replace(/^['"]|['"]$/g, ''))
    .filter(w => w.includes('/') || w.startsWith('~'))
    .map(w => w.replace(/^~/, '/home'))
}

/** P1-8：shell 重定向目标（> file / >> file / 2> file），用于 exec('echo x > /etc/passwd') 检测。 */
export function redirectTarget(command: string): string | undefined {
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
