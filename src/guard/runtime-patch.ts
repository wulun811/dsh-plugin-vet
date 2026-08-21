/**
 * T2 进程内钩子包装器
 * P0-4 结构债拆分自 runtime-hooks.ts（patchModule：fs/child_process；patchNetworkModule：http/https/net/http2/tls。包装器：classify → 报警（栈归因）→ 原函数原样调用（alarm-only）；N7 确认破坏类操作在调用前抛错拦截，fail-open）
 */
import { DESTROY_OPS, WRITE_OPS, READ_OPS, PROBE_OPS, PROC_OPS, FS_LEDGER_OPS } from './runtime-ops.js'
import type { HookModule, HookConfig, HookAlarm } from './runtime-ops.js'
import type { LedgerFsEvent, LedgerNetEvent } from './exfil-ledger.js'
import { confirmBlock, BLOCK_FS_OPS, type BlockDecision } from './confirm-block.js'
import { isRootIndexing, isVetSelfIo, isStackTraceTampered, firstString, allStrings, isSensitivePath } from './runtime-denoise.js'
import { classifyOp } from './runtime-classify.js'
import { classifyNetworkOp, extractNetworkTarget, isTrackedNetHost, NET_OPS } from './runtime-net.js'
import { fsOpBytes, attachWriteCounter, attachCanaryScanner, attachReadCounter } from './runtime-count.js'
import { isOfficial, pluginFromStack } from './runtime-attrib.js'
import { brandVetHook, registerHookTarget } from './runtime-heartbeat.js'

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
      if (isRootIndexing() || isVetSelfIo()) {
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
      if (observe !== undefined && !isRootIndexing() && !isVetSelfIo() && ledgerRelevant) {
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
    brandVetHook(wrapped)
    registerHookTarget(moduleName, mod, [opName])
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
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
      if (isRootIndexing() || isVetSelfIo()) {
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
      if (observe !== undefined && !isRootIndexing() && !isVetSelfIo()) {
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
      if (canaryScan !== undefined && !isRootIndexing() && !isVetSelfIo()) {
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
    brandVetHook(wrapped)
    registerHookTarget(moduleName, mod, [opName])
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
}
