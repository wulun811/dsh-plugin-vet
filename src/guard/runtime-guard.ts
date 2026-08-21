/**
 * 运行时守卫装配（D22）：runtimeGuard: 'watch' 时启用 T1 哨兵（子进程 /proc 监视）
 * + T2 钩子（进程内包装 fs/child_process）。
 * 默认 alarm：所有报警进 VetStatus，不拦截；N7（0.1.14 起）对确认破坏类操作
 * （fs 族 1/2，confirmBlock 默认 block）在钩子侧抛错拦截（PLAN §2.1 D21 修订：
 * 高置信破坏 ≠ 纯观测；族 3/4 默认仍只报警）。
 *
 * P0-4 结构债拆分：T1 哨兵生命周期 → runtime-sidecar.ts；T2 报警/台账/金丝雀/密钥/
 * 取证管道 → runtime-sink.ts。本文件保留 installRuntimeGuard 装配、栈归因映射构建、
 * 归因排除，并对拆出模块的公共符号做再导出（外部 import 路径与符号不变）。
 */

// re-export：T1 哨兵公共 API（外部直连 runtime-guard.js 的测试/宿主仍可 import）
export { sidecarSpawned, decideRespawn, sidecarSupportedOn, pidCmdlineIsVetSidecar, safeKillSidecar } from './runtime-sidecar.js'
// re-export：T2 报警/降级公共 API
export { t2AlarmId, t2Severity, isSuppressUnattributedSessionLog, hashShort } from './runtime-sink.js'

import { spawn } from 'node:child_process'
import { resolveVetFile } from '../pkg-root.js'
import fs from 'node:fs'
import cp from 'node:child_process'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import http2 from 'node:http2'
import tls from 'node:tls'
import dgram from 'node:dgram'
import { existsSync, readFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { VetStatus } from './status.js'
import type { WatchAlarm } from './runtime-watch.js'
import { DEFAULT_HOOK_CONFIG, patchModule, patchNetworkModule, setRootIndexing, classifyNetworkOp, extractNetworkTarget, isVetSelfIo, isRootIndexing, pluginFromStack, isOfficial, chunkBytes, isTrackedNetHost, hookHeartbeat, registerHookTarget, brandVetHook } from './runtime-hooks.js'
import { isStackTraceTampered } from './runtime-denoise.js'
import { resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'
import { ensureHoneypot, ensureIntegrityCanaries } from './honeypot.js'
import { exfilLedger } from './exfil-ledger.js'
import { canaryStore } from './canary.js'
import { confirmBlock } from './confirm-block.js'
import { createT2Sink, type ContractResolver } from './runtime-sink.js'
import { loadContract } from './contract.js'
import { SIDECAR_PID_ENV, envSidecarPid, pidAlive, safeKillSidecar, killSidecarFromEnv, sidecarSkippedWarned, setSidecarSpawned, setSidecarSkippedWarned, decideRespawn, sidecarSupportedOn } from './runtime-sidecar.js'

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
  // T1 哨兵：子进程 /proc 监视（stdout JSON 行 → status.record；重拉起 + 卸载清理）
  disposers.push(installSidecar(ctx, config, status))
  // T2 钩子 + 网络出口观测：fs/child_process/http*/dgram/fetch 进程内包装
  installT2(ctx, config, status, disposers)
  // 钩子完整性心跳：周期复查 T2 包装品牌，被剥离即 yellow（alarm-only）
  installHookHeartbeat(ctx, config, status, disposers)
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

/** T1 哨兵装配：spawn sidecar 子进程 + stdout JSON 行解析 + respawn 管理与卸载清理。 */
function installSidecar(ctx: Context, config: VetConfig, status: VetStatus): () => void {
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
    // P0-6：T1 依赖 /proc（Linux 专有）。非 Linux 显式跳过——不拉哨兵、不进 respawn 循环、
    // 清 env 注册表；避免"首轮 exit(0) → 意外退出 → 重拉×5"的空转与 sentinel-down 噪音。
    // T2 钩子不受影响（进程内防线照常装配）。
    if (!sidecarSupportedOn(process.platform)) {
      setSidecarSpawned(false)
      sidecarAlive = false
      delete process.env[SIDECAR_PID_ENV]
      if (!sidecarSkippedWarned) {
        setSidecarSkippedWarned(true)
        ctx.logger.info('vet: T1 哨兵依赖 /proc（仅 Linux），当前平台跳过——内存/子进程/fd 监控不生效；T2 钩子与静态扫描不受影响')
      }
      return
    }
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
      setSidecarSpawned(false)
      sidecarAlive = false
    }
    child = spawn(process.execPath, [sidecarPath, '--vet-sidecar', ...watchArgs], {
      stdio: ['ignore', 'pipe', 'inherit'],
    })
    process.env[SIDECAR_PID_ENV] = String(child.pid ?? '')
    setSidecarSpawned(true)
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
      setSidecarSpawned(false)
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
  return () => {
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
  }
}

/** T2 钩子 + 网络出口观测装配：fs/child_process patch + http/https/net/http2/tls/dgram/fetch 包装。 */
function installT2(ctx: Context, config: VetConfig, status: VetStatus, disposers: (() => void)[]): void {
// ── T2 钩子 ─────────────────────────────────────────────
  // A9 归因映射（root→包名）只建一次并缓存：每个被分类的 fs 调用都会走归因，重建=每条
  // 报警 N×require.resolve 的 CPU 空转（报警风暴时放大）；热重载会重新 apply 生成新闭包，
  // 天然重建，无需失效机制。
  const rootIndex = createRootIndex(ctx)
  // T2 报警/台账/金丝雀/密钥/取证管道（P0-4：自 runtime-sink.ts 装配；行为与内联版完全一致）
  // M1 契约解析器（record 档）：仅当 config.contract.enabled 且目录可读时启用；无契约文件 = 每插件零开销
  const contractResolver: ContractResolver | undefined = config.contract?.enabled !== false
    ? (plugin) => loadContract(plugin, (path) => {
        try { return readFileSync(path, 'utf8') } catch { return undefined }
      }, config.contract?.dir || undefined)
    : undefined
  const { sink, emitLedger, recordCanary, recordKeyLeak, ledgerFsObserver, ledgerNetObserver, netCanaryScan } = createT2Sink(status, contractResolver)
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
    // #9（0.2.2 注释）：disposer 只恢复 createSocket 导出——已创建的 socket 实例上的 send
    // 包装无法被统一恢复（vet 无法枚举所有已创建的实例）。这是设计限制：vet 卸载后，
    // 早先创建的 socket 仍走包装（观测写入已拆卸的 sink，写盘/报警均失败静默，无害）；
    // 新创建 socket 走原始路径。与 patchModule 恢复模块导出同理，实例级恢复不支持。
    // P0-2 #2：dgram 包装参与钩子完整性心跳（patchModule/patchNetworkModule 之外的手工包装单独登记 + 打品牌）
    registerHookTarget('dgram', dgram as unknown as Record<string, unknown>, ['createSocket'])
    brandVetHook(dgram.createSocket as unknown as (...a: unknown[]) => unknown)
    
    // fetch 是 globalThis 上的，需要单独处理
    const originalFetch = globalThis.fetch
    if (typeof originalFetch === 'function') {
      globalThis.fetch = function vetFetchWrapper(...args: unknown[]) {
        const alarm = classifyNetworkOp('http', 'fetch', args, hookCfg)
        if (!(isRootIndexing() || isVetSelfIo())) {
          // C4（0.1.16 加固，fetch 分支补齐，与 patchNetworkModule 行为一致）：归因链被篡改
          // （prepareStackTrace 替换 / stackTraceLimit<2）时栈文本不可信 → 取不到 hint，
          // 但敏感出口必须显式报警（主动隐藏归因疑为攻击），不能静默降级为无主。
          const stackTampered = isStackTraceTampered()
          let hint: string | undefined
          try {
            if (!stackTampered) hint = pluginFromStack(new Error().stack ?? undefined, rootIndex())
          } catch {}
          if (stackTampered && alarm !== null) {
            const t = typeof args[0] === 'string' ? args[0] : extractNetworkTarget(args)?.hostname ?? ''
            sink({
              severity: 'red',
              kind: 'attribution-tampered',
              message: '栈归因被篡改（Error.prepareStackTrace/stackTraceLimit 被修改）——fetch 网络出口无法归属，主动隐藏归因疑为攻击（C4）',
              target: t.slice(0, 120),
            })
          }
          if (alarm !== null && (hint === undefined || !isOfficial(hint))) {
            sink({ ...alarm, pluginHint: hint })
          }
          const target = extractNetworkTarget(args)
          // #1/#6 修复：fetch body 提取归一（一次计算，两处复用）。
          // 形态 1：fetch(url, init) —— body 在 init.body（字符串直接可读）。
          // 形态 2：fetch(new Request(url, { body })) —— body 在 Request 内部：
          //   - Node 的 Request.body 是 ReadableStream，同步不可读；
          //   - 但 clone() 不消费原流：同步 clone 后异步 .text()，观测不阻塞原调用。
          //   拿到文本后补跑金丝雀/密钥扫描（异步观测 = 出站后确认，同网络模块 chunk 语义）。
          const initBody = (args[1] as { body?: unknown } | undefined)?.body
          const stringBody = typeof initBody === 'string' ? initBody : undefined
          let requestBodyPromise: Promise<string> | undefined
          const first = args[0]
          if (stringBody === undefined && typeof first === 'object' && first !== null &&
              typeof (first as { bodyUsed?: unknown }).bodyUsed === 'boolean') {
            try {
              const req = first as Request
              if (!req.bodyUsed && typeof req.clone === 'function') {
                requestBodyPromise = req.clone().text()
              }
            } catch {
              requestBodyPromise = undefined
            }
          }
          const tracked = target !== null && isTrackedNetHost(target.hostname) && (hint === undefined || !isOfficial(hint))
          if (tracked) {
            const bytes = stringBody !== undefined ? Buffer.byteLength(stringBody, 'utf8') : 0
            emitLedger(hint, exfilLedger.observeNet({
              plugin: hint,
              module: 'fetch',
              op: 'fetch',
              hostname: target.hostname,
              bytes,
            }))
          }
          // N3/N4：fetch URL 与 body 走统一 netCanaryScan（密钥外泄内容匹配 + 金丝雀）
          const urlText = typeof args[0] === 'string' ? args[0] : (target !== null ? target.hostname + target.path : '')
          netCanaryScan(hint, urlText, 'url')
          if (stringBody !== undefined) {
            netCanaryScan(hint, stringBody, 'body')
          } else if (requestBodyPromise !== undefined) {
            // Request 形态：body 异步补观测（clone 已隔离，不消费原流；失败静默——观测是增强不是防线）
            requestBodyPromise.then((text) => {
              if (text === '') return
              netCanaryScan(hint, text, 'body')
              if (tracked) {
                emitLedger(hint, exfilLedger.observeNet({
                  plugin: hint,
                  module: 'fetch',
                  op: 'fetch',
                  hostname: target?.hostname ?? '',
                  bytes: Buffer.byteLength(text, 'utf8'),
                }))
              }
            }).catch(() => {})
          }
        }
        return (originalFetch as Function).apply(this, args)
      }
      disposers.push(() => { globalThis.fetch = originalFetch })
      // P0-2 #2：fetch 包装参与钩子完整性心跳
      registerHookTarget('fetch', globalThis as unknown as Record<string, unknown>, ['fetch'])
      brandVetHook(globalThis.fetch as unknown as (...a: unknown[]) => unknown)
    }
  }
}

/** 钩子完整性心跳：周期复查 T2 包装品牌标记，被剥离即 yellow（alarm-only）。 */
function installHookHeartbeat(ctx: Context, config: VetConfig, status: VetStatus, disposers: (() => void)[]): void {
// ── P0-2 #2：钩子完整性心跳 ─────────────────────────────────────
  // T2 包装被剥离/替换（插件改 require.cache 后覆盖导出，或直接写回原始函数）是绕过进程内防线唯一
  // 的 in-process 向量；周期复查品牌标记 → 失守即 yellow（alarm-only）。零配置、零出站、确定性。
  const HOOK_HEARTBEAT_FACTOR = 4 // 比 T1 轮询稀疏：默认 runtimeIntervalMs×4 = 8s 一次
  const heartbeatMs = Math.max(5000, config.runtimeIntervalMs * HOOK_HEARTBEAT_FACTOR)
  const runHookHeartbeat = (): void => {
    if (guardDisabled) return
    let result
    try {
      result = hookHeartbeat()
    } catch {
      return
    }
    if (result.ok) return
    const stripped = result.checks.filter(c => !c.intact).map(c => c.module + '.' + c.op).join('，')
    ctx.logger.warn('vet: 钩子完整性心跳失败——T2 挂钩被剥离/替换：' + stripped + '；运行时观测已降级（alarm-only 提示，请检查是否有插件篡改内置模块）')
    status.record({
      id: 't2:hook-heartbeat',
      severity: 'yellow',
      source: 't2',
      kind: 'hook-heartbeat',
      message: '钩子完整性心跳失败：T2 包装被剥离/替换（' + stripped + '）——运行时观测降级，疑似插件篡改内置模块',
      target: stripped.slice(0, 120),
      at: Date.now(),
    })
  }
  const heartbeatTimer = setInterval(runHookHeartbeat, heartbeatMs)
  heartbeatTimer.unref?.()
  disposers.push(() => clearInterval(heartbeatTimer))
  // 安装时立即基线一次（此刻钩子全新，理应完好；后续周期复查才是报警面）
  runHookHeartbeat()
}
