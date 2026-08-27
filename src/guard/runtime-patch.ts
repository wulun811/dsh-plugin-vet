/**
 * T2 进程内钩子包装器
 * P0-4 结构债拆分自 runtime-hooks.ts（patchModule：fs/child_process；patchNetworkModule：http/https/net/http2/tls。包装器：classify → 报警（栈归因）→ 原函数原样调用（alarm-only）；N7 确认破坏类操作在调用前抛错拦截，fail-open）
 */
import { DESTROY_OPS, WRITE_OPS, READ_OPS, PROBE_OPS, PROC_OPS, FS_LEDGER_OPS } from './runtime-ops.js'
import type { HookModule, HookConfig, HookAlarm } from './runtime-ops.js'
import type { LedgerFsEvent, LedgerNetEvent } from './exfil-ledger.js'
import { confirmBlock, BLOCK_FS_OPS, type BlockDecision } from './confirm-block.js'
import { incrementBlocked } from './stats.js'
import { isRootIndexing, isVetSelfIo, isStackTraceTampered, firstString, allStrings, isSensitivePath, isDshWebTempArtifact, isDshAtomicStagingPath, isDshRuntimeTempPath } from './runtime-denoise.js'
import { classifyOp } from './runtime-classify.js'
import { classifyNetworkOp, extractNetworkTarget, isTrackedNetHost, isLoopbackHost, isControlPlanePath, NET_OPS } from './runtime-net.js'
import { fsOpBytes, attachWriteCounter, attachCanaryScanner, attachReadCounter } from './runtime-count.js'
import { isOfficial, isOfficialTrusted, pluginFromStack } from './runtime-attrib.js'
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
  try {
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
      let alarm = classifyOp({ module: moduleName, op: opName, args }, cfg)
      const ledgerRelevant = observe !== undefined && FS_LEDGER_OPS.has(opName)
      // round-22：open/openSync 必须进入判定面——decideBlock 内按写标志判断是否破坏
      // （read 不拦）；此前不含 open → 族 2 SA2-5 分支（fd 面凭据破坏拦截）生产不可达。
      const blockRelevant = moduleName === 'fs'
        && (BLOCK_FS_OPS.has(opName) || opName === 'open' || opName === 'openSync')
        && confirmBlock.mode() === 'block'
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
        // round-16 review（S5）：拦截降级必须显式记录——stackTampered 时族 1（已确认插件
        // 的后续破坏）无法按插件身份判定（哨兵身份不匹配任何 f1Blocked 条目）→ 拦截静默
        // 降级。家族 2（凭据本体破坏）与 3/4 路径不受影响（凭据精确匹配不依赖归因）；
        // 在既有 C4 红警文案里点明降级面，用户不会误以为拦截仍全覆盖。
        sink({
          severity: 'red',
          kind: 'attribution-tampered',
          message: '栈归因被篡改（Error.prepareStackTrace/stackTraceLimit 被修改）——敏感操作无法归属，主动隐藏归因疑为攻击（C4）'
            + (blockRelevant && confirmBlock.mode() === 'block' ? '；N7 族 1 拦截（已确认插件的后续破坏）因归因不可用而降级（族 2 凭据本体破坏仍拦截）' : ''),
          target: t.slice(0, 120),
        })
      }
      // 五轮用户反馈降噪：DSH web 状态临时产物（UI 原子写 `.x.json.<pid>.<uuid>.tmpdir` 的
      // lstat/rmdir 清理）——宿主自身高频家务操作，栈里只有宿主帧 → 无归因 → 每次保存刷
      // red fs-destroy / yellow fs-probe。六轮扩展：fs-local writeFileAtomic 暂存目录
      // (`.<name>.<pid>.<uuid>.tmpdir`，~/.dsh 任意深度，settings.yaml 保存实测路径)同判。
      // 仅在「无归因 + 归因链未被篡改」时按宿主自身豁免；插件归因的同类操作照报
      // （碰宿主状态=信号），蜜罐/完整性金丝雀类不受此豁免。
      // 0.3.3（P7）：~/.dsh/sessions/** 下宿主会话存储的临时产物（*.tmp 随用随清）——
      // 只对侦察类（fs-probe）降噪：lstat/stat 探针无害；写/删同类路径（会话日志轮换
      // 等）不走此豁免，维持既有 fs-write/fs-destroy 语义（isSessionLogFile 已独立
      // 处理无主会话日志删除）。
      const opTarget = firstString(args) ?? '';
      if (
        alarm !== null && hint === undefined && !stackTampered &&
        alarm.kind !== 'honeypot' && alarm.kind !== 'integrity' &&
        (isDshWebTempArtifact(opTarget) || isDshAtomicStagingPath(opTarget)
          || (alarm.kind === 'fs-probe' && isDshRuntimeTempPath(opTarget)))
      ) {
        alarm = null
      }
      // N7 确认拦截：判定（族 1/2）在调用原函数之前执行——拦截 = 抛错（fail-open：异常 → 放行）
      // C4：归因被篡改时用哨兵身份（不匹配任何已知插件）参与族 2 凭据本体判定——
      // 故意隐藏归因的凭据破坏照样拦截；族 1（已确认插件的后续破坏）在归因不可用下降级（记录边界）
      // round-16（SEC-1）：官方豁免改内容信任锚——名称级 isOfficial 会让伪名 tarball
      // 的破坏类操作整个跳过 N7 拦截（身份判定被名字欺骗）。
      let block: BlockDecision | null = null
      const blockIdentity: string | undefined = stackTampered ? '__vet_attribution_tampered__' : hint
      if (blockRelevant && blockIdentity !== undefined && (stackTampered || !isOfficialTrusted(blockIdentity))) {
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
        // round-15 review：N7 钩子侧拦截此前不计入 stats.blockedCount（只由静态 deny 门禁
        // 的 internal-plugin 路径递增）——面板「拦截次数」对运行时拦截长期显示 0。
        incrementBlocked()
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
  } catch (error) {
    // round-16 review（S3）：mid-loop 抛错（冻结模块/只读属性/Proxy 拒绝等）→ 已包装的
    // 操作必须回滚再抛——否则部分包装残留且调用方拿不到 disposer（installT2 装配失败
    // 路径无法清理，热重载后旧包装永久叠加）。
    for (const [opName, fn] of original) {
      try {
        mod[opName] = fn
      } catch {
        // 回滚失败（原属性本身不可写）——无害：该属性从未被改成功
      }
    }
    throw error
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
  try {
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
      if (alarm !== null || observe !== undefined || canaryScan !== undefined || cfg.observeLoopback === true) {
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
        if (target !== null && isTrackedNetHost(target.hostname, cfg)) {
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
          if (isTrackedNetHost(t.hostname, cfg)) {
            const res = result as { write?: unknown } | null | undefined
            if (typeof res === 'object' && res !== null && typeof res.write === 'function') {
              attachCanaryScanner(res, (text) => canaryScan(hint, text, 'body'))
            }
          }
        }
      }
      if (alarm !== null) {
        // round-16（SEC-1）：内容信任锚（同 fs 面抑制判据）；回环观测走廊（下方 247）
        // 保留名称级 isOfficial——纯展示观测，不构成防线盲区。
        if (hint === undefined || !isOfficialTrusted(hint)) {
          sink({ ...alarm, pluginHint: hint })
        }
      }
      // round-13（Phase 3）：本地 API 回环观测——observeLoopback=true、命中 DSH 控制面路径、
      // 归因第三方插件（非官方/非无主）→ yellow 观测（alarm-only；观测不是修复，RPC 认证需 dsh 侧）
      // round-16（SEC-1）：本条保留名称级 isOfficial（纯展示走廊，不构成防线盲区）。
      if (cfg.observeLoopback === true && hint !== undefined && !isOfficial(hint)) {
        const lp = extractNetworkTarget(args)
        if (lp !== null && isLoopbackHost(lp.hostname) && isControlPlanePath(lp.path)) {
          const lpTarget = lp.hostname + (lp.port !== undefined ? ':' + lp.port : '') + lp.path
          sink({
            severity: 'yellow',
            kind: 'loopback-control',
            message: '插件访问本地 DSH 控制面：' + lpTarget + '（回环观测，observeLoopback——无认证 RPC 面，P15/P17 形态）',
            target: lpTarget.slice(0, 120),
            pluginHint: hint,
          })
        }
      }
      return result
    }
    mod[opName] = wrapped
    brandVetHook(wrapped)
    registerHookTarget(moduleName, mod, [opName])
  }
  } catch (error) {
    // round-16 review（S3）：mid-loop 抛错（冻结模块等）→ 已包装操作回滚再抛
    // （与 patchModule 同纪律：装配失败不允许残留半包装状态）。
    for (const [opName, fn] of original) {
      try {
        mod[opName] = fn
      } catch {
        // 回滚失败（原属性本身不可写）——无害：该属性从未被改成功
      }
    }
    throw error
  }
  return () => {
    for (const [opName, fn] of original) mod[opName] = fn
  }
}
