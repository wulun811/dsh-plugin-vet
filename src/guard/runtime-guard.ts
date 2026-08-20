/**
 * 运行时守卫装配（D22）：runtimeGuard: 'watch' 时启用 T1 哨兵（子进程 /proc 监视）
 * + T2 钩子（进程内包装 fs/child_process）。
 * 默认 alarm：所有报警进 VetStatus，不拦截；N7（0.1.14 起）对确认破坏类操作
 * （fs 族 1/2，confirmBlock 默认 block）在钩子侧抛错拦截（PLAN §2.1 D21 修订：
 * 高置信破坏 ≠ 纯观测；族 3/4 默认仍只报警）。
 */
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolveVetFile } from '../pkg-root.js'
import fs from 'node:fs'
import cp from 'node:child_process'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import http2 from 'node:http2'
import tls from 'node:tls'
import dgram from 'node:dgram'
import type { Context } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { VetStatus, type VetAlarm } from './status.js'
import type { WatchAlarm } from './runtime-watch.js'
import { DEFAULT_HOOK_CONFIG, patchModule, patchNetworkModule, setRootIndexing, classifyNetworkOp, extractNetworkTarget, isVetSelfIo, isRootIndexing, pluginFromStack, isOfficial, chunkBytes, isTrackedNetHost, type HookAlarm } from './runtime-hooks.js'
import { resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'
import { ensureHoneypot, ensureIntegrityCanaries } from './honeypot.js'
import { capabilityDiff, diffKindOf } from './capability-diff.js'
import { exfilLedger, detectKeyLeaks, type LedgerAlarm, type LedgerFsEvent, type LedgerNetEvent } from './exfil-ledger.js'
import { canaryStore } from './canary.js'
import { confirmBlock } from './confirm-block.js'
import { incrementAlarmsRecorded } from './stats.js'
import { existsSync } from 'node:fs'

/** T1 哨兵是否已启动（invariant 断言用）。 */
export let sidecarSpawned = false

/**
 * D30 修漏：哨兵 pid 注册表（process.env，跨模块热重载保留）。
 * dsh 配置热重载会重新 apply vet 插件 → module 级变量（child/sidecarAlive）全部重置，
 * 但 process.env 保留。用 env 记当前哨兵 pid：
 * - watch 分支 spawn 前查 env：已有存活哨兵 → 复用不重复 spawn（根治重复 apply 叠加）；
 * - off 分支查 env：kill 遗留哨兵（关闭守卫必须真正停掉监控）。
 * sidecar 崩溃退出后 env 里的 pid 存活检查失败 → 下次 apply 重新 spawn。
 */
const SIDECAR_PID_ENV = 'DSH_VET_SIDECAR_PID'

/**
 * P0-2：哨兵意外退出后是否重拉（纯函数，可测）。
 * 条件：env 注册表仍指向本哨兵（mine）+ 非 stopping + 未达上限。
 * 旧实现先删 env 再比较 → 恒 false，respawn 死代码；这里由调用方传入注册表 pid，判定与清理解耦。
 */
export function decideRespawn(
  registeredPid: number | undefined,
  childPid: number | undefined,
  stopping: boolean,
  respawnCount: number,
  maxRespawn: number,
): boolean {
  // 两边都要有值才判 mine——undefined === undefined 是「spawn 失败/无注册」不是「本哨兵」
  return registeredPid !== undefined && registeredPid === childPid && !stopping && respawnCount < maxRespawn
}

/** P1-6：T2 报警去重 id——拼 pluginHint，避免不同插件同路径互吞报警。 */
export function t2AlarmId(kind: string, target: string | undefined, pluginHint: string | undefined): string {
  return `t2:${kind}:${target ?? ''}:${pluginHint ?? ''}`
}

/** 0.1.20 内容短 hash（密钥外泄报警去重 id 用；FNV-1a 32 位，确定性，不落原文）。 */
export function hashShort(s: string): string {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 16777619)
  }
  return (h >>> 0).toString(36)
}

/**
 * 0.1.16 修正：未归因的会话日志删除（~/.dsh/sessions 下分片文件轮换）从 red 降到 yellow。
 * 0.1.19 起：无主会话日志删除完全静默（见 isSuppressUnattributedSessionLog）——DSH 宿主压缩
 * 会话日志（zstd 删分片）是无归因高频运维，每次降级 yellow 仍刷屏；归因到插件的会话日志
 * 删除仍保持 red（可能是插件在销毁证据、规避审计）。其余报警严重度原样透传。
 */
export function t2Severity(alarm: HookAlarm, pluginHint: string | undefined): HookAlarm['severity'] {
  if (alarm.kind === 'fs-destroy' && alarm.sessionLog === true && pluginHint === undefined) {
    return 'yellow'
  }
  return alarm.severity
}

/**
 * 无主会话日志删除是否静默（0.1.19）：DSH 宿主压缩/轮转 ~/.dsh/sessions 会话日志
 * （zstd 产生 session.jsonl.zstd.xxx 分片后删除）是无归因高频运维——每次压缩都报 yellow
 * 会刷屏淹没真报警。仅当 kind=fs-destroy + sessionLog=true + 无插件归因时静默；
 * 归因到插件的会话日志删除仍是 red（插件销毁证据），无归因的非会话日志敏感删除照报。
 */
export function isSuppressUnattributedSessionLog(kind: string | undefined, sessionLog: boolean | undefined, pluginHint: string | undefined): boolean {
  return kind === 'fs-destroy' && sessionLog === true && pluginHint === undefined
}

function envSidecarPid(): number | undefined {
  const raw = process.env[SIDECAR_PID_ENV]
  if (raw === undefined || raw === '') return undefined
  const pid = Number(raw)
  if (!Number.isInteger(pid) || pid <= 0) return undefined
  return pid
}

/** pid 是否存活（kill(0) 探测；EPERM 也视为存活——存在但不是我们的子进程）。 */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    return code === 'EPERM'
  }
}

/** M9（0.1.16 加固）：/proc/<pid>/cmdline 是否含 vet 侧车标记（Linux）。 */
export function pidCmdlineIsVetSidecar(pid: number): boolean {
  try {
    return readFileSync('/proc/' + pid + '/cmdline').includes(Buffer.from('vet-sidecar'))
  } catch {
    return false
  }
}

/**
 * M9（0.1.16 加固）：安全终止侧车——先核对 cmdline 再 SIGTERM，防 OS PID 复用误杀无辜进程
 * （旧实现只看 kill(pid,0) 存活即杀：侧车已退出 + 5s 窗口内 PID 被复用时会把别的进程干掉）。
 * 非 Linux（无 /proc）回退存活探测；被杀对象身份存疑时不动手并返回 false。
 */
export function safeKillSidecar(pid: number, signal: NodeJS.Signals = 'SIGTERM'): boolean {
  if (!pidAlive(pid)) return false
  if (process.platform === 'linux' && !pidCmdlineIsVetSidecar(pid)) return false
  try {
    process.kill(pid, signal)
    return true
  } catch {
    return false
  }
}

/** 按 env 注册表 kill 遗留哨兵（关闭守卫时调用）。 */
function killSidecarFromEnv(logger: { warn: (m: string) => void }): void {
  const pid = envSidecarPid()
  if (pid === undefined) return
  const killed = safeKillSidecar(pid)
  if (!killed && pidAlive(pid)) {
    // M9：存活但身份存疑（PID 复用/找不到 cmdline）——不再误杀，仅告警
    logger.warn(`vet: 哨兵 pid=${pid} 存活但身份存疑（可能被 PID 复用），未终止——请人工确认`)
  }
  delete process.env[SIDECAR_PID_ENV]
  if (killed) logger.warn(`vet: 运行时守卫关闭，终止哨兵 (pid=${pid})`)
}

// P2-5 修复：isOfficial 统一从 runtime-hooks.ts 导入（避免包名变更时一处遗漏）

/**
 * A9 归因排除：vet 自身不参与 T2 栈归因。包装器帧（runtime-hooks.js）永远是报警栈的栈顶，
 * 若 vet 根在归因映射里，一切宿主/无主报警都会归到 vet 头上（"vet 把自己算成警报"）。
 * 纯函数便于测试；排除后 vet 自己的敏感操作仍会报警（归因落空显示无主），不隐藏行为。
 */
export function isAttributableEntry(name: string): boolean {
  return name !== PACKAGE_NAME
}

/**
 * 构建 T2 栈归因映射（root→包名），结果缓存（报警风暴不重复 require.resolve）。
 * P1-3：整个构建体（含 loader.entries() 与 ctx.baseUrl 访问）都在 try/finally 内——
 * 任一环节抛错都必须复位 rootIndexing 标志，否则所有 T2 报警被静默 bypass（R31 的
 * 反向失败：护栏防了递归，却可能把 vet 永久搞失明）。归因失败时返回空映射（缓存），
 * 包装器侧另有 try/catch，fs 调用永不因归因失败而中断。
 */
export function createRootIndex(ctx: Context): () => Map<string, string> {
  let rootsCache: Map<string, string> | undefined
  return () => {
    if (rootsCache !== undefined) return rootsCache
    const map = new Map<string, string>()
    // R31：归因阶段自身的 fs 探测（resolvePackageRoot 的 realpathSync）会再次进入
    // T2 包装器；敏感包名（如 dsh-credentials）会再次 alarm → 归因 → 无限递归，
    // 栈深后任意正则编译触发 V8 栈溢出误报 OOM。置标志让包装器直通，断开递归。
    setRootIndexing(true)
    try {
      let loader: LoaderLike | undefined
      try {
        loader = (ctx as Context & { loader?: LoaderLike }).loader
      } catch {
        // cordis proxy 对未注入属性直接抛错而非返回 undefined（与 invariants 同款）
        loader = undefined
      }
      const names: string[] = []
      if (loader !== undefined) {
        for (const entry of loader.entries()) names.push(entry.options.name)
      }
      // vet 被符号链接安装时 realpath 解析不到 profile node_modules → 用 loader 基准（ctx.baseUrl）
      const profileDir = (ctx as { baseUrl?: string }).baseUrl
      for (const name of names) {
        // A9 归因排除 vet 自身（见 isAttributableEntry 注释）
        if (!isAttributableEntry(name)) continue
        const root = resolvePackageRoot(name, profileDir)
        if (root !== undefined) map.set(root, name)
      }
    } finally {
      setRootIndexing(false)
    }
    rootsCache = map
    return map
  }
}

interface LoaderLike {
  entries(): { options: { name: string } }[]
}

/**
 * 安装运行时守卫（T1 + T2）。
 * @returns disposer：恢复钩子并终止哨兵（HMR/卸载安全）。
 */
/** 全局 guard 实例注册表（D30 修漏 H1）：dsh 配置热重载会重复 apply，
 * 若前一个实例的 T2 钩子没被卸载就叠加包装。用模块级变量记住上一个 disposer，
 * 每次 install 前先 dispose 旧实例（恢复 fs/child_process 原始函数 + 终止旧哨兵），再装新的。
 * 与 ctx.on('dispose') 双保险：disposer 幂等（disposed 标志），先到者生效。 */
let prevGuardDisposer: (() => void) | undefined

/** H2：守卫已关闭（off/dispose）——pending 的 respawn 定时器检查此标志，禁止复活孤儿哨兵。 */
let guardDisabled = false

/** 守卫当前是否禁用（供 respawn 定时器/外部查询）。 */
export function isGuardDisabled(): boolean {
  return guardDisabled
}

export function installRuntimeGuard(ctx: Context, config: VetConfig, status: VetStatus): () => void {
  // 先卸载上一个实例（热重载/重复 apply 场景：旧钩子/旧哨兵必须清理，否则叠加）
  if (prevGuardDisposer !== undefined) {
    try {
      prevGuardDisposer()
    } catch {
      // 旧实例清理失败不阻断新实例
    }
    prevGuardDisposer = undefined
  }
  if (config.runtimeGuard !== 'watch') {
    // H2：置位 disabled，pending respawn 定时器将检查并放弃复活
    guardDisabled = true
    // 关闭守卫必须真正停掉监控：kill 遗留哨兵（env 注册表，跨重载有效）
    killSidecarFromEnv(ctx.logger)
    // 蜜罐依赖 T2 钩子：guard 未开时蜜罐静默不生效——显式告警，避免用户以为开了其实没开
    if (config.honeypot?.enabled === true) {
      ctx.logger.warn('vet: honeypot.enabled=true 但 runtimeGuard 非 watch——蜜罐未生效（需先开启运行时守卫）')
    }
    return () => {}
  }
  // P1-1：off→watch 转换（同一模块实例内重复 apply，如配置热重载先关后开）必须复位——
  // spawnSidecar 的 fresh-spawn 分支检查 guardDisabled，不复位则哨兵永不启动且无任何日志/报警
  guardDisabled = false
  const disposers: (() => void)[] = []

  // ── T1 哨兵 ─────────────────────────────────────────────
  const watchArgs = [
    String(config.runtimeIntervalMs),
    String(config.runtimeMemLimitMb),
    String(config.runtimeForkBurstN),
    String(config.runtimeFdLimit),
    String(config.runtimeGrowthMb),
    String(config.runtimeGrowthWindowMs),
  ]
  const sidecarPath = resolveVetFile('guard/runtime-watch.js')
  // 0.1.20：启动时文件存在性校验——sidecar 文件缺失时直接报 red vet-self-broken，
  // 不静默降级（prepublish 检查防打包漏，这里防安装损坏/用户误删）
  if (!existsSync(sidecarPath)) {
    status.record({
      id: 'vet-self-broken:sidecar-missing',
      severity: 'red',
      source: 't1',
      kind: 'vet-self-broken',
      message: 'vet 哨兵文件缺失：' + sidecarPath + '——T1 运行时监控无法启动。可能原因：安装损坏/文件被误删。建议重装 vet 插件',
      at: Date.now(),
    })
    ctx.logger.error('vet: 哨兵文件缺失，T1 监控无法启动：' + sidecarPath)
    // 不 return——继续尝试 T2 钩子（进程内防线仍可用）
  }
  let child: ReturnType<typeof spawn> | undefined
  let sidecarAlive = false
  let stopping = false
  /** 意外退出重拉：上限 5 次 + 5s 退避（监控器自身失活必须可见，不能静默）。 */
  const MAX_RESPAWN = 5
  const RESPAWN_DELAY_MS = 5000
  let respawnCount = 0
  const spawnSidecar = (): void => {
    if (stopping) return
    // H2：守卫已关（off/dispose）→ 不复活哨兵（pending respawn 定时器触发时走到这里）
    if (guardDisabled) return
    // env 注册表：已有存活哨兵（热重载前的实例/重复安装的旧副本）
    // P1-2：不能复用——旧哨兵的 stdout 管道属于旧模块实例的 child 句柄，新实例没有它的
    // 监听器；复用 = 哨兵继续跑但 T1 报警全部写进已废弃的旧 VetStatus（热重载后静默丢失）。
    // 旧管道无法接管，只能清 env（防旧实例 exit 处理器按 decideRespawn 复活）+ 终止旧哨兵，
    // 再走下方全新 spawn（新管道 + 新监听器）。旧实例的 exit 处理器会记一条 sentinel-down
    // 到它自己的（已废弃）status，无害。
    const existing = envSidecarPid()
    if (existing !== undefined && pidAlive(existing)) {
      ctx.logger.warn(`vet: 检测到既有哨兵 (pid=${existing})——终止并以新实例接管（旧报警通道不可复用）`)
      delete process.env[SIDECAR_PID_ENV]
      // M9：先核对身份再终止（PID 复用保护）
      if (!safeKillSidecar(existing)) {
        ctx.logger.warn(`vet: 既有哨兵 pid=${existing} 存活但身份存疑，未终止——按接管流程继续（新实例将接管监控）`)
      }
      sidecarSpawned = false
      sidecarAlive = false
    }
    child = spawn(process.execPath, [sidecarPath, '--vet-sidecar', ...watchArgs], {
      stdio: ['ignore', 'pipe', 'inherit'],
    })
    process.env[SIDECAR_PID_ENV] = String(child.pid ?? '')
    sidecarSpawned = true
    sidecarAlive = true
    child.stdout?.setEncoding('utf8')
    // L2：JSON 行可能跨 chunk 截断——累积行缓冲，只在遇到完整换行时解析
    let lineBuf = ''
    child.stdout?.on('data', (chunk: string) => {
      lineBuf += chunk
      let nl: number
      while ((nl = lineBuf.indexOf('\n')) !== -1) {
        const line = lineBuf.slice(0, nl).trim()
        lineBuf = lineBuf.slice(nl + 1)
        if (line === '') continue
        try {
          const a = JSON.parse(line) as WatchAlarm
          status.record({ ...a, source: 't1' })
        } catch {
          ctx.logger.warn(`vet: 哨兵输出无法解析: ${line.slice(0, 120)}`)
        }
      }
    })
    child.on('error', (err) => {
      // P2-3：spawn 失败（EACCES/无效路径等）不能无监听——未捕获 'error' 事件会崩宿主。
      // 置为未存活并清掉残留 env（从未活过的 pid），不抛不 respawn（下次 apply 重新尝试）。
      sidecarAlive = false
      sidecarSpawned = false
      if (envSidecarPid() === child?.pid) delete process.env[SIDECAR_PID_ENV]
      ctx.logger.error(`vet: T1 哨兵启动失败：${String(err)}`)
      status.record({
        id: 't1:spawn-fail',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵启动失败，运行时内存/子进程/fd 监控未生效',
        at: Date.now(),
      })
    })
    child.on('exit', (code) => {
      sidecarAlive = false
      // P0-2：不再先删 env 再判定——那样 respawn 判定恒 false（env 刚被删），respawn 变死代码，
      // 哨兵意外退出后监控静默中断到下次 apply。这里直接用 exit 时读到的 registered 判定：
      // env 指向已死 pid 无害（spawnSidecar 的 pidAlive 探测失败会重新 spawn 并覆盖 env；
      // off/接管场景 env 已被清/改指，decideRespawn 为 false 不复活）。
      const registered = envSidecarPid()
      const respawn = decideRespawn(registered, child?.pid, stopping, respawnCount, MAX_RESPAWN)
      ctx.logger.warn(`vet: T1 哨兵退出（code=${code ?? 'null'}，respawn=${respawn}）`)
      if (stopping) return
      // 监控器失活本身是黄灯报警（vet 自己的进程挂了，用户该知道守护断了）
      status.record({
        id: 't1:sentinel-down',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵意外退出，运行时内存/子进程/fd 监控中断',
        at: Date.now(),
      })
      // 仅当 env 注册表仍指向本哨兵时才 respawn（off/接管场景不复活）
      if (respawn) {
        respawnCount++
        ctx.logger.warn(`vet: 5s 后重拉哨兵（第 ${respawnCount}/${MAX_RESPAWN} 次）`)
        setTimeout(spawnSidecar, RESPAWN_DELAY_MS).unref?.()
      }
      // P2-3：env 不再指向本实例且指向存活 pid → 哨兵已被其他实例接管/替换（跨模块重复安装
      // + 5s respawn 窗口竞态：旧副本可能 kill 新哨兵并复活自己的）。本实例不 respawn（判定
      // 正确），但接管是否成功不可见——这里记一条 warn + 黄灯，让「监控被换手」可观测而非静默。
      if (!respawn && registered !== undefined && registered !== child?.pid && pidAlive(registered)) {
        ctx.logger.warn(`vet: 哨兵已被其他实例接管（env 注册表指向存活 pid=${registered}，本实例 child=${child?.pid ?? 'none'}）——旧报警通道废弃，接管方负责监控`)
        status.record({
          id: 't1:sentinel-taken-over',
          severity: 'yellow',
          source: 't1',
          kind: 'sentinel',
          message: 'T1 哨兵被其他实例接管，本实例监控通道失效（如重复安装 vet，建议只保留一份）',
          at: Date.now(),
        })
      }
    })
  }
  spawnSidecar()
  disposers.push(() => {
    stopping = true
    const pid = envSidecarPid()
    if (pid !== undefined && pidAlive(pid)) {
      // 复用模式 child=undefined：走 env 注册表 kill（热重载后旧模块的 child 引用已不可靠）
      // M9：先核对 cmdline 再终止（PID 复用保护）
      if (!safeKillSidecar(pid)) {
        ctx.logger.warn(`vet: 卸载时哨兵 pid=${pid} 身份存疑，未终止`)
      }
      delete process.env[SIDECAR_PID_ENV]
    } else if (sidecarAlive && child !== undefined) {
      child.kill()
    }
  })

  // ── T2 钩子 ─────────────────────────────────────────────
  // A9 归因映射（root→包名）只建一次并缓存：每个被分类的 fs 调用都会走归因，重建=每条
  // 报警 N×require.resolve 的 CPU 空转（报警风暴时放大）；热重载会重新 apply 生成新闭包，
  // 天然重建，无需失效机制。
  const rootIndex = createRootIndex(ctx)
  const sink = (alarm: HookAlarm): void => {
    // 官方包信任（能力授权，P2-6）：官方归因的报警全部降噪——官方包是平台本体，
    // dsh 自身高频读写 ~/.dsh（会话持久化/配置/存储），.dsh 敏感段加入后若只降噪 spawn
    // 会刷屏成永久黄灯。报警面 = 第三方插件与无主操作；第三方无法伪造归因（按真实栈路径判定）。
    if (alarm.pluginHint !== undefined && isOfficial(alarm.pluginHint)) return
    // N7 族 3/4 报警只对第三方归因有效（宿主/用户自己写 bashrc、npm install 等无主操作不报）
    if ((alarm.kind === 'persistence-write' || alarm.kind === 'install-write') && alarm.pluginHint === undefined) return
    // 无主会话日志删除静默（isSuppressUnattributedSessionLog）：DSH 宿主压缩/轮转会话日志
    // （zstd 会产生 session.jsonl.zstd.xxx 分片后删除）是无归因高频运维——每次压缩都报 yellow
    // 会刷屏淹没真报警。归因到插件的会话日志删除仍是 red（插件销毁证据）；无归因的非会话日志
    // 敏感删除（如删 .credentials.yaml 本体）照报。
    if (isSuppressUnattributedSessionLog(alarm.kind, alarm.sessionLog, alarm.pluginHint)) return
    // N7 族 1 触发：完整性金丝雀被写删（归因插件）→ 进入拦截名单（后续破坏类操作抛错）
    if (alarm.kind === 'integrity' && alarm.pluginHint !== undefined) confirmBlock.markFamily1(alarm.pluginHint)
    const entry: VetAlarm = {
      // P1-6：id 拼 pluginHint——两个插件碰同一敏感路径不再同 id 互吞（后到者报警被去重吞掉）
      id: t2AlarmId(alarm.kind, alarm.target, alarm.pluginHint),
      severity: t2Severity(alarm, alarm.pluginHint),
      source: 't2',
      kind: alarm.kind,
      message: alarm.message,
      target: alarm.target,
      pluginHint: alarm.pluginHint,
      sessionLog: alarm.sessionLog,
      // 关联签名类（n3-）按 (kind,plugin) 合并去重：跨主机/跨密钥的同类报警折叠为一条、累计次数。
      // T2 hook 报警（fs-destroy/net 等）不带 mergeKey，保留按精确 id 的原有去重语义。
      mergeKey: alarm.kind.startsWith('n3-') ? `t2:${alarm.kind}:${alarm.pluginHint}` : undefined,
      at: Date.now(),
    }
    status.record(entry)
    // 0.1.20：防御统计——每次警报记录时自增
    incrementAlarmsRecorded()
    // N1 差分：敏感操作观测 → 静态能力清单对账（隐藏能力 red/certain；只差分已扫描插件）
    const kind = diffKindOf(alarm.kind)
    if (kind !== null && alarm.pluginHint !== undefined && alarm.target !== undefined) {
      const hidden = capabilityDiff.observeAndCheck({
        plugin: alarm.pluginHint,
        kind,
        value: alarm.target,
      })
      if (hidden !== null) {
        status.record({
          id: `n1-hidden:${hidden.plugin}:${hidden.kind}`,
          severity: 'red',
          source: 't2',
          kind: 'n1-hidden',
          message: hidden.message,
          target: hidden.value,
          pluginHint: hidden.plugin,
          at: Date.now(),
        })
      }
    }
  }
  // N3 台账接线：T2 观测 → 字节台账 + 破坏签名（官方归因不建桶；报警经同一 sink 去重/归因）
  const emitLedger = (plugin: string | undefined, alarms: LedgerAlarm[]): void => {
    for (const a of alarms) {
      // N7 族 1 触发：N3 破坏签名组合（勒索实锤）→ 拦截名单
      if (a.kind === 'n3-ransom' && plugin !== undefined) confirmBlock.markFamily1(plugin)
      sink({ severity: a.severity, kind: a.kind, message: a.message, target: a.target, pluginHint: plugin })
    }
  }
  // N4 金丝雀确认外泄：出站 URL/body/spawn 参数中发现活跃金丝雀 → 100% 外泄确认（red）。
  // 官方归因降噪；命中同时把该插件台账标记为疑似（阈值降最低，N3）。
  const recordCanary = (where: 'url' | 'body' | 'spawn', hit: string, plugin: string | undefined): void => {
    if (plugin !== undefined && isOfficial(plugin)) return
    if (plugin !== undefined) exfilLedger.markSuspected(plugin)
    // N7 族 1 触发：canary 泄漏 = 100% 破坏确认 → 拦截名单
    if (plugin !== undefined) confirmBlock.markFamily1(plugin)
    status.record({
      id: `n4-canary:${hit}:${plugin ?? ''}`,
      severity: 'red',
      source: 't2',
      kind: 'canary-leak',
      message: `蜜罐金丝雀外泄确认：出站${where === 'url' ? 'URL' : where === 'spawn' ? '命令参数' : '数据体'}中发现金丝雀 ${hit.slice(0, 16)}…（${hit.length} 位）——100% 确认外泄（N4；${plugin ?? '无主'}）`,
      target: hit,
      pluginHint: plugin,
      mergeKey: `t2:canary-leak:${plugin ?? ''}`,
      at: Date.now(),
    })
  }
  // 0.1.20：密钥外泄内容匹配（PEM/AWS key 格式；纯函数 detectKeyLeaks 于 exfil-ledger）
  const recordKeyLeak = (where: 'url' | 'body', text: string, plugin: string | undefined): void => {
    if (plugin !== undefined && isOfficial(plugin)) return
    const leaks = detectKeyLeaks(text)
    if (leaks.length === 0) return
    
    for (const hit of leaks) {
      const tag = hit.kind === 'pem' ? 'pem' : 'aws'
      // Issue W 修复：PEM key 按上下文 hash（同类型不同 key 各自报警）
      // AWS key 按 match hash（key id 唯一，天然去重）
      let hashInput: string
      if (hit.kind === 'pem') {
        // 取匹配前后各 100 字符作为上下文
        const contextStart = Math.max(0, hit.index - 100)
        const contextEnd = Math.min(text.length, hit.index + hit.match.length + 100)
        hashInput = text.slice(contextStart, contextEnd)
      } else {
        hashInput = hit.match
      }
      
      status.record({
        id: `n3-key-leak-${tag}:${plugin ?? ''}:${hashShort(hashInput)}`,
        severity: 'red',
        source: 't2',
        kind: 'n3-key-leak',
        message: `密钥外泄确认：出站${where === 'url' ? 'URL' : '数据体'}中检测到${hit.kind === 'pem' ? 'PEM 私钥格式' : 'AWS Access Key'}（${hit.match.slice(0, 30)}…）——100% 确认密钥外泄（N3；${plugin ?? '无主'}）`,
        target: hit.match,
        pluginHint: plugin,
        mergeKey: `t2:n3-key-leak:${plugin ?? ''}`,
        at: Date.now(),
      })
    }
  }
  const ledgerFsObserver = (evt: LedgerFsEvent): void => {
    if (evt.plugin !== undefined && isOfficial(evt.plugin)) return
    // N4：spawn 参数匹配金丝雀（命令含 curl/wget/nc 场景；网络体走 netCanaryScan）
    if (evt.module === 'child_process' && canaryStore.count() > 0) {
      const hit = canaryStore.match(evt.paths.join(' '))
      if (hit !== undefined) recordCanary('spawn', hit, evt.plugin)
    }
    emitLedger(evt.plugin, exfilLedger.observeFs(evt))
  }
  const ledgerNetObserver = (evt: LedgerNetEvent): void => {
    if (evt.plugin !== undefined && isOfficial(evt.plugin)) return
    emitLedger(evt.plugin, exfilLedger.observeNet(evt))
  }
  const netCanaryScan = (hint: string | undefined, text: string, where: 'url' | 'body'): void => {
    // 0.1.20：密钥外泄内容匹配
    recordKeyLeak(where, text, hint)
    if (canaryStore.count() === 0) return
    const hit = canaryStore.match(text)
    if (hit === undefined) return
    recordCanary(where, hit, hint)
  }
  const hookCfg = { ...DEFAULT_HOOK_CONFIG }
  // D27 蜜罐：guard watch 时按配置播种诱饵并登记蜜罐根（alarm-only；失败只告警）
  if (config.honeypot.enabled) {
    const hpRoot = ensureHoneypot(config.honeypot.dir, ctx.logger)
    if (hpRoot !== undefined) hookCfg.honeypotRoots = [hpRoot]
  }
  // N4 完整性金丝雀（仅 ~/.dsh 内，watch 恒开）：写/删 → red kind=integrity；失败只告警
  hookCfg.integrityRoots = ensureIntegrityCanaries('', ctx.logger)
  // N7 确认拦截模式（进程内存；DSH 重启/配置变更重新生效）
  confirmBlock.setMode(config.confirmBlock)
  confirmBlock.setFamilyModes(config.confirmBlockFamily3, config.confirmBlockFamily4)
  disposers.push(patchModule(fs as unknown as Record<string, unknown>, 'fs', hookCfg, sink, rootIndex, ledgerFsObserver))
  // fs.promises 是独立对象（require('fs').promises / node:fs/promises 同一对象），同步包装不覆盖 → 必须单独包装（D26 审核补漏）
  const promisesMod = (fs as unknown as { promises?: Record<string, unknown> }).promises
  if (promisesMod !== undefined) {
    disposers.push(patchModule(promisesMod, 'fs', hookCfg, sink, rootIndex, ledgerFsObserver))
  }
  disposers.push(patchModule(cp as unknown as Record<string, unknown>, 'child_process', hookCfg, sink, rootIndex, ledgerFsObserver))

  // ── 网络出口观测（P1 特性）─────────────────────────────────────
  if (config.networkEgress !== false) {
    disposers.push(patchNetworkModule(http as unknown as Record<string, unknown>, 'http', hookCfg, sink, rootIndex, ledgerNetObserver, netCanaryScan))
    disposers.push(patchNetworkModule(https as unknown as Record<string, unknown>, 'https', hookCfg, sink, rootIndex, ledgerNetObserver, netCanaryScan))
    disposers.push(patchNetworkModule(net as unknown as Record<string, unknown>, 'net', hookCfg, sink, rootIndex, ledgerNetObserver, netCanaryScan))
    disposers.push(patchNetworkModule(http2 as unknown as Record<string, unknown>, 'http2', hookCfg, sink, rootIndex, ledgerNetObserver, netCanaryScan))
    disposers.push(patchNetworkModule(tls as unknown as Record<string, unknown>, 'tls', hookCfg, sink, rootIndex, ledgerNetObserver, netCanaryScan))
    
    // dgram 需要特殊处理：createSocket() 返回实例，send 是实例方法
    const originalCreateSocket = dgram.createSocket
    dgram.createSocket = function(...args: unknown[]) {
      const socket = (originalCreateSocket as Function).apply(this, args)
      const originalSend = socket.send
      socket.send = function(...sendArgs: unknown[]) {
        // dgram.send 有两种形态：
        // 形态1: socket.send(msg, offset, length, port, address, callback)
        // 形态2: socket.send(msg, port, address, callback)
        let port: number | undefined
        let address: string | undefined
        // 实际发送字节（形态1 = length 切片，不能计整个 buffer）
        let sentBytes = 0
        
        if (sendArgs.length >= 5 && typeof sendArgs[1] === 'number' && typeof sendArgs[2] === 'number' && typeof sendArgs[3] === 'number' && typeof sendArgs[4] === 'string') {
          // 形态1: msg, offset, length, port, address —— 发送的是 msg[offset..offset+length)，字节=length
          port = sendArgs[3] as number
          address = sendArgs[4] as string
          sentBytes = Math.max(0, sendArgs[2] as number)
        } else if (sendArgs.length >= 3 && typeof sendArgs[1] === 'number' && typeof sendArgs[2] === 'string') {
          // 形态2: msg, port, address —— 整块 msg
          port = sendArgs[1] as number
          address = sendArgs[2] as string
          sentBytes = chunkBytes(sendArgs[0])
        }
        
        if (port !== undefined && address !== undefined) {
          const alarm = classifyNetworkOp('dgram', 'send', [{ host: address, port }], hookCfg)
          if (!(isRootIndexing() || isVetSelfIo())) {
            let hint: string | undefined
            try { hint = pluginFromStack(new Error().stack ?? undefined, rootIndex()) } catch {}
            if (alarm !== null && (hint === undefined || !isOfficial(hint))) {
              sink({ ...alarm, pluginHint: hint })
            }
            // N3 台账：dgram 写出字节 + NET_WRITE token
            const host = address.toLowerCase()
            if (isTrackedNetHost(host) && (hint === undefined || !isOfficial(hint))) {
              emitLedger(hint, exfilLedger.observeNet({
                plugin: hint,
                module: 'dgram',
                op: 'send',
                hostname: host,
                bytes: sentBytes,
              }))
            }
            // N3/N4：dgram 报文体 = 密钥外泄内容匹配 + 金丝雀匹配
            const msgText = typeof sendArgs[0] === 'string' ? sendArgs[0] : ''
            recordKeyLeak('body', msgText, hint)
            if (canaryStore.count() > 0 && (hint === undefined || !isOfficial(hint))) {
              const chit = canaryStore.match(msgText)
              if (chit !== undefined) recordCanary('body', chit, hint)
            }
          }
        }
        return (originalSend as Function).apply(this, sendArgs)
      }
      return socket
    }
    disposers.push(() => { dgram.createSocket = originalCreateSocket })
    
    // fetch 是 globalThis 上的，需要单独处理
    const originalFetch = globalThis.fetch
    if (typeof originalFetch === 'function') {
      globalThis.fetch = function vetFetchWrapper(...args: unknown[]) {
        const alarm = classifyNetworkOp('http', 'fetch', args, hookCfg)
        if (!(isRootIndexing() || isVetSelfIo())) {
          let hint: string | undefined
          try { hint = pluginFromStack(new Error().stack ?? undefined, rootIndex()) } catch {}
          if (alarm !== null && (hint === undefined || !isOfficial(hint))) {
            sink({ ...alarm, pluginHint: hint })
          }
          // N3 台账：fetch 出站（body 字节仅字符串形态可计，其余 0）
          const target = extractNetworkTarget(args)
          if (target !== null && isTrackedNetHost(target.hostname) && (hint === undefined || !isOfficial(hint))) {
            const body = (args[1] as { body?: unknown } | undefined)?.body
            const bytes = typeof body === 'string' ? Buffer.byteLength(body, 'utf8') : 0
            emitLedger(hint, exfilLedger.observeNet({
              plugin: hint,
              module: 'fetch',
              op: 'fetch',
              hostname: target.hostname,
              bytes,
            }))
          }
          // N3/N4：fetch URL 与字符串 body 走统一 netCanaryScan（密钥外泄内容匹配 + 金丝雀）
          const urlText = typeof args[0] === 'string' ? args[0] : (target !== null ? target.hostname + target.path : '')
          netCanaryScan(hint, urlText, 'url')
          const body = (args[1] as { body?: unknown } | undefined)?.body
          const bodyText = typeof body === 'string' ? body : ''
          netCanaryScan(hint, bodyText, 'body')
        }
        return (originalFetch as Function).apply(this, args)
      }
      disposers.push(() => { globalThis.fetch = originalFetch })
    }
  }

  // 幂等：ctx.on('dispose') 与 prevGuardDisposer 都可能触发同一 disposer（重载时旧 ctx
  // 先 dispose、新 apply 再调 prevGuardDisposer）——先到者生效，重复执行是 no-op。
  let disposed = false
  const disposer = (): void => {
    if (disposed) return
    disposed = true
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // 恢复/终止失败不阻断卸载
      }
    }
  }
  prevGuardDisposer = disposer
  return disposer
}