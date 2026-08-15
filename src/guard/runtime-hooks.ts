/**
 * T2 进程内钩子（D22）：在宿主进程内包装 fs / child_process 内置模块导出。
 * 危险操作 → 取栈 → 归因插件包名 → 报警（alarm-only，从不阻断调用）。
 * 已知旁路（PLAN §14.5 / README）：ESM 具名导入快照、worker_threads 独立 realm、
 * 原生插件、process.binding。
 */
export type HookModule = 'fs' | 'child_process'

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
}

export const DEFAULT_HOOK_CONFIG: HookConfig = {
  sensitiveRoots: ['/etc', '/usr', '/var', '/boot', '/bin', '/sbin'],
  sensitiveSegments: ['.ssh', '.aws', '.gnupg', '.npmrc', '.env', '.netrc', '.pgpass', '.gitconfig', 'credentials', 'credential', 'secrets', 'secret', 'tokens', 'token', 'passwd', 'shadow', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.git-credentials', '.kube', 'vault'],
  sensitiveKeywords: ['secret', 'secrets', 'credential', 'credentials', 'passwd', 'shadow', 'private', 'auth', 'vault'],
  sensitiveExts: ['.pem', '.key', '.p12', '.pfx', '.keystore', '.jks', '.env'],
  shellTokens: ['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh', 'curl', 'wget', 'nc', 'ncat', 'telnet'],
  honeypotRoots: [],
}

/** T2 报警候选（at/source 由调用方补全）。 */
export interface HookAlarm {
  severity: 'yellow' | 'red'
  kind: string
  message: string
  target?: string
  pluginHint?: string
}

export interface HookOp {
  module: HookModule
  op: string
  args: unknown[]
}

/** 破坏性删除类 fs 操作（red）。 */
const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
/** 写入类 fs 操作（yellow）。 */
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync', 'truncate', 'truncateSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream'])
/** 读取类 fs 操作（密钥路径 → yellow）。 */
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'])
/** 侦察类 fs 操作（M7：列目录/stat/access 是凭据狩猎的第一步——readdirSync('~/.ssh') 此前完全不可见）。 */
const PROBE_OPS = new Set(['readdir', 'readdirSync', 'opendir', 'opendirSync', 'stat', 'statSync', 'access', 'accessSync', 'existsSync', 'readlink', 'readlinkSync', 'realpath', 'realpathSync'])
/** child_process 全部操作（spawn 面，yellow）。 */
const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])
/** P1-8：破坏性命令词——命中且命令里出现敏感路径（参数或重定向目标）才报警，避免 rm -rf /tmp 这类常规清理误报。 */
const DESTRUCTIVE_TOKENS = new Set(['rm', 'mv', 'cp', 'dd', 'mkfs', 'mkfs.ext4', 'mkfs.xfs', 'shred', 'truncate'])

/** 关键词边界匹配：须出现在段首或 . _ - 之后（避免 'js-tokens' 这类库名误伤）。 */
function segmentHasKeyword(part: string, keyword: string): boolean {
  const esc = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp('(?:^|[._-])' + esc + '(?:[._-]|$)', 'i').test(part)
}

/**
 * 归一化路径并判断是否敏感。
 * mode='mutate'（写/删）额外计入系统根前缀（/etc /usr /var …：写删系统文件=篡改/破坏）；
 * mode='read' 只看密钥特征（段名/后缀/关键词）——读系统目录下的普通文件（库文件、配置）属正常
 * 操作；枚举目标（/etc/passwd、/etc/shadow）已由精确段名覆盖，不需要系统根。
 */
export function isSensitivePath(p: string, cfg: HookConfig, mode: 'read' | 'mutate' = 'mutate'): boolean {
  const norm = p.replace(/\\/g, '/')
  for (const part of norm.split('/')) {
    const low = part.toLowerCase()
    if (low === '.env' || low.startsWith('.env.')) return true
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
    if (DESTROY_OPS.has(name) && isSensitivePath(target, cfg, 'mutate')) {
      return { severity: 'red', kind: 'fs-destroy', message: `敏感路径删除：${name}(${target.slice(0, 120)})`, target }
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
    // flags 只认短合法形态（r/w/a/x 可带 +，长度 ≤2），且只在首个参数之后的字符串里找。
    if ((name === 'open' || name === 'openSync') && READ_OPS.has(name)) {
      const flags = args.slice(1).find((a): a is string => typeof a === 'string' && /^[rwax]\+?$/.test(a))
      if (flags !== undefined && /[wax+]/.test(flags) && isSensitivePath(target, cfg, 'mutate')) {
        return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入（open flags=${flags}）：${target.slice(0, 120)}`, target }
      }
    }
    if (WRITE_OPS.has(name) && isSensitivePath(target, cfg, 'mutate')) {
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
    let path = m[1]
    if (path.startsWith('file://')) path = path.slice('file://'.length)
    let best: { len: number; name: string } | undefined
    for (const [root, name] of roots) {
      // M4：要求路径边界——/node_modules/foo 不能匹配 /node_modules/foobar/index.js
      if ((path === root || path.startsWith(root + '/') || path.startsWith(root + '\\'))
        && (best === undefined || root.length > best.len)) {
        best = { len: root.length, name }
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
): () => void {
  const original = new Map<string, unknown>()
  const allOps = [...DESTROY_OPS, ...WRITE_OPS, ...READ_OPS, ...PROC_OPS, ...PROBE_OPS]
  for (const opName of allOps) {
    const fn = mod[opName]
    if (typeof fn !== 'function') continue
    original.set(opName, fn)
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
      const alarm = classifyOp({ module: moduleName, op: opName, args }, cfg)
      if (alarm !== null) {
        const hint = pluginFromStack(new Error().stack ?? undefined, rootIndex())
        sink({ ...alarm, pluginHint: hint })
      }
      return (fn as (...a: unknown[]) => unknown).apply(this, args)
    }
    mod[opName] = wrapped
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
}