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
  /** 任一路径段命中即敏感的密钥/凭据特征。 */
  sensitiveSegments: string[]
  /** 子进程命令行报警关键词。 */
  shellTokens: string[]
}

export const DEFAULT_HOOK_CONFIG: HookConfig = {
  sensitiveRoots: ['/etc', '/usr', '/var', '/boot', '/bin', '/sbin'],
  sensitiveSegments: ['.ssh', '.aws', '.gnupg', '.npmrc', '.env', 'credentials', 'secrets', 'tokens'],
  shellTokens: ['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh'],
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
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'rename', 'renameSync', 'truncate', 'truncateSync', 'copyFile', 'copyFileSync'])
/** 读取类 fs 操作（密钥路径 → yellow）。 */
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream'])
/** child_process 全部操作（spawn 面，yellow）。 */
const PROC_OPS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'])

/** 归一化路径并判断是否敏感：命中敏感根前缀或任一敏感段。 */
export function isSensitivePath(p: string, cfg: HookConfig): boolean {
  const norm = p.replace(/\\/g, '/')
  for (const seg of cfg.sensitiveSegments) {
    if (norm.split('/').some(part => part.includes(seg))) return true
  }
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

/** 危险操作分类（纯函数）：返回报警候选（pluginHint 由调用方经栈归因补全）。 */
export function classifyOp(op: HookOp, cfg: HookConfig): HookAlarm | null {
  const { module, op: name, args } = op
  const target = firstString(args) ?? ''
  if (module === 'child_process' && PROC_OPS.has(name)) {
    return {
      severity: 'yellow',
      kind: 'spawn',
      message: `子进程 spawn：${name}(${target.slice(0, 120)})`,
      target,
    }
  }
  if (module === 'fs') {
    if (DESTROY_OPS.has(name) && isSensitivePath(target, cfg)) {
      return { severity: 'red', kind: 'fs-destroy', message: `敏感路径删除：${name}(${target.slice(0, 120)})`, target }
    }
    if (WRITE_OPS.has(name) && isSensitivePath(target, cfg)) {
      return { severity: 'yellow', kind: 'fs-write', message: `敏感路径写入：${name}(${target.slice(0, 120)})`, target }
    }
    if (READ_OPS.has(name) && isSensitivePath(target, cfg)) {
      return { severity: 'yellow', kind: 'fs-read', message: `敏感路径读取：${name}(${target.slice(0, 120)})`, target }
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
      if (path.startsWith(root) && (best === undefined || root.length > best.len)) {
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
  const allOps = [...DESTROY_OPS, ...WRITE_OPS, ...READ_OPS, ...PROC_OPS]
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
