/**
 * T2 进程内钩子：操作表与类型
 * P0-4 结构债拆分自 runtime-hooks.ts（纯类型/常量，无副作用）
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
  /** 完整性金丝雀路径（N4，仅 ~/.dsh 内）：写/删即 red kind=integrity（与凭据蜜罐语义分离）。 */
  integrityRoots: string[]
  /** round-13（Phase 3）：本地 API 回环观测（默认关）。true 时 127.0.0.1 出站进台账，
   * 命中 DSH 控制面路径（/api/、session.*、/plugins/）且归因第三方插件 → yellow loopback-control。 */
  observeLoopback?: boolean
}

export const DEFAULT_HOOK_CONFIG: HookConfig = {
  sensitiveRoots: ['/etc', '/usr', '/var', '/boot', '/bin', '/sbin'],
  // P2-6：.dsh = DSH 配置根（真实凭据 credentials.yaml、profile 配置、会话存储、蜜罐根都在其下）。
  // 此前 readdirSync('~/.dsh') 这类凭据狩猎第一步完全不可见（M7 只覆盖 .ssh/.aws 等）。
  // 官方包（@deepseek-ai/*）高频读写 ~/.dsh（会话/配置/存储）由 sink 的官方信任降噪吸收；
  // vet 自身对 patch 文件的轮询读取经 withVetSelfIo 直通，不会自报警。
  /** 敏感段名：路径任一段整体等于其中一项（大小写不敏感）即敏感。
 * round-13（Phase 3/计划 §3.3）：追加 skills——技能目录写删复用 fs-write/fs-destroy 语义
 *（G-1 技能库投毒的运行时面；合法写入面极窄，误报走 dismiss 路径）。 */
  sensitiveSegments: ['.dsh', '.ssh', '.aws', '.gnupg', '.npmrc', '.env', '.netrc', '.pgpass', '.gitconfig', 'credentials', 'credential', 'secrets', 'secret', 'tokens', 'token', 'passwd', 'shadow', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.git-credentials', '.kube', 'vault', 'skills'],
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
  /**
   * 0.3.5（P8）：官方名归因的 DSH 协议形状家务探针（~/.dsh 下 <file>.lock 锁兄弟 / 会话日志
   * 分片）。由包装器按「名称级 isOfficial + 仅 fs-probe + 协议形状」打标，sink 收到后降为
   * info 聚合观察（不静默、不黄警），不对内容/写删面生效。
   */
  officialHousekeeping?: boolean
}

export interface HookOp {
  module: HookModule
  op: string
  args: unknown[]
}

/** 破坏性删除类 fs 操作（red）。 */
export const DESTROY_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
/** 写入/变更类 fs 操作（yellow）。0.1.16（M5）：补 symlink/link/chmod/chown/mkdir/utimes——
 * 此前 symlink 落点可绕过敏感路径判定（写 /tmp 符号链接指向 ~/.ssh/authorized_keys）、
 * chmod 可放宽凭据文件权限、mkdir 可落位 /etc/cron.d 等提权面。 */
export const WRITE_OPS = new Set([
  'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync',
  'truncate', 'truncateSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'createWriteStream',
  'symlink', 'symlinkSync', 'link', 'linkSync', 'chmod', 'chmodSync', 'chown', 'chownSync',
  'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync', 'utimes', 'utimesSync', 'lutimes', 'lutimesSync',
])
/** 读取类 fs 操作（密钥路径 → yellow）。 */
export const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'])
/** 侦察类 fs 操作（M7：列目录/stat/access 是凭据狩猎的第一步——readdirSync('~/.ssh') 此前完全不可见）。 */
// 0.1.16（M5）：lstat 是符号链接侦察的标准原语（stat 跟随链接），补入侦察面
export const PROBE_OPS = new Set(['readdir', 'readdirSync', 'opendir', 'opendirSync', 'stat', 'statSync', 'lstat', 'lstatSync', 'access', 'accessSync', 'existsSync', 'readlink', 'readlinkSync', 'realpath', 'realpathSync'])
/** child_process 全部操作（spawn 面，yellow）。 */
export const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])

// ── N3 台账观测通道（optional observe：runtime-guard 接线 exfil-ledger；不接线时零开销）──

/** 需要向台账发事件的 fs/子进程操作（删/写/读/spawn 面；PROBE 侦察不参与破坏窗口）。 */
export const FS_LEDGER_OPS = new Set<string>([...DESTROY_OPS, ...WRITE_OPS, ...READ_OPS, ...PROC_OPS])
