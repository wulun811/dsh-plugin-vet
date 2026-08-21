/**
 * T2 报警/台账/金丝雀/密钥/取证管道（P0-4 结构债拆分自 runtime-guard.ts）。
 * createT2Sink(status)：装配 T2 观测接线所需的全部闭包（sink 去重/归因/降噪、
 * N3 台账、N4 金丝雀确认、密钥外泄内容匹配、P0-2 取证、N1 差分对账、N7 族 1 名单）。
 * 本模块只依赖上游模块（status/stats/capability-diff/exfil-ledger/canary/confirm-block/
 * forensics/runtime-hooks），不反向依赖 runtime-guard（无环）。
 */

import type { VetStatus, VetAlarm } from './status.js'
import { incrementAlarmsRecorded } from './stats.js'
import { isPersistentlyDismissed } from './dismissed-alerts.js'
import { capabilityDiff, diffKindOf } from './capability-diff.js'
import { exfilLedger, detectKeyLeaks, type LedgerAlarm, type LedgerFsEvent, type LedgerNetEvent } from './exfil-ledger.js'
import { canaryStore } from './canary.js'
import { confirmBlock } from './confirm-block.js'
import { arm as armForensics, record as recordForensics, isArmed as forensicsArmed } from './forensics.js'
import { isOfficial } from './runtime-hooks.js'
import type { HookAlarm } from './runtime-hooks.js'
import { checkAlarmInContract } from './contract.js'
import type { Contract } from './contract.js'

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

/** M1：插件 → 契约解析（由 runtime-guard 注入；测试可注入假解析器）。缺省 undefined = 不接 M1（零变化）。 */
export type ContractResolver = (plugin: string) =>
  | { kind: 'loaded'; contract: Contract }
  | { kind: 'rejected' }
  | { kind: 'no-contract' }

export interface T2SinkResult {
  sink: (alarm: HookAlarm) => void
  emitLedger: (plugin: string | undefined, alarms: LedgerAlarm[]) => void
  recordCanary: (where: 'url' | 'body' | 'spawn', hit: string, plugin: string | undefined) => void
  recordKeyLeak: (where: 'url' | 'body', text: string, plugin: string | undefined) => void
  ledgerFsObserver: (evt: LedgerFsEvent) => void
  ledgerNetObserver: (evt: LedgerNetEvent) => void
  netCanaryScan: (hint: string | undefined, text: string, where: 'url' | 'body') => void
}

/** 装配 T2 报警管道（sink + 台账/金丝雀/密钥/取证接线）。 */
export function createT2Sink(status: VetStatus, contractResolver?: ContractResolver): T2SinkResult {
  // M1 契约（record 档）一次性记档去重：拒载/证伪各只记一次，越界按 (插件,字段) 合并。
  const rejectedNoted = new Set<string>()
  const distrustedNoted = new Set<string>()
  const m1Contract = (plugin: string): Contract | undefined => {
    if (contractResolver === undefined) return undefined
    const r = contractResolver(plugin)
    if (r.kind === 'loaded') return r.contract
    if (r.kind === 'rejected' && !rejectedNoted.has(plugin)) {
      rejectedNoted.add(plugin)
      status.record({
        id: 'm1:contract-rejected:' + plugin,
        severity: 'yellow',
        source: 't2',
        kind: 'm1-contract-rejected',
        message: '契约被拒载（M1）：插件 ' + plugin + ' 的契约未通过宽松度校验，已按无契约处理——当前行为仍由静态/运行时观测判定',
        pluginHint: plugin,
        at: Date.now(),
      })
    }
    return undefined
  }
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
    // M1 契约对账（record 档：越界小声记 info，绝不动既有报警/拦截；无契约 = 零开销）
    if (alarm.pluginHint !== undefined) {
      const contract = m1Contract(alarm.pluginHint)
      if (contract !== undefined) {
        const chk = checkAlarmInContract(alarm.kind, alarm.target, contract)
        if (chk !== null && !chk.within) {
          status.record({
            id: 'm1:contract-violation:' + alarm.pluginHint + ':' + chk.field + ':' + (alarm.target ?? '').slice(0, 120),
            severity: 'info',
            source: 't2',
            kind: 'm1-contract-violation',
            message: '契约越界（M1）：插件 ' + alarm.pluginHint + ' 宣称不对「' + chk.field + '」面执行该操作，但观测到 ' + alarm.message,
            target: alarm.target,
            pluginHint: alarm.pluginHint,
            mergeKey: 't2:m1-contract-violation:' + alarm.pluginHint + ':' + chk.field,
            at: Date.now(),
          })
        }
      }
    }
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
        // M1：代码事实（N1 隐藏能力）证伪契约 → 契约不可信 yellow（只记一次；契约压不过代码事实）
        if (hidden.plugin !== undefined && !distrustedNoted.has(hidden.plugin)) {
          const contract = m1Contract(hidden.plugin)
          if (contract !== undefined) {
            distrustedNoted.add(hidden.plugin)
            status.record({
              id: 'm1:contract-distrusted:' + hidden.plugin,
              severity: 'yellow',
              source: 't2',
              kind: 'm1-contract-distrusted',
              message: '契约与代码事实相悖（M1）：插件 ' + hidden.plugin + ' 的承诺书宣称该能力在范围内，但代码事实（N1 隐藏能力）证伪——按代码事实为准，契约不可信',
              pluginHint: hidden.plugin,
              at: Date.now(),
            })
          }
        }
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
    // P0-2 取证：金丝雀外泄 = 100% 确认恶意 → 启动详细取证模式（后续微小活动全量落盘）
    if (plugin !== undefined) armForensics(plugin)
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
      
      // 0.1.21 归因分级：格式形状命中 ≠ 外泄实锤。归因到第三方插件 → red 按外泄处置；
      // 无主（宿主自身流量——会话体/文档天然含密钥样文本）→ yellow 待人工研判，
      // 不再宣称“100% 确认”。金丝雀命中（recordCanary）不受此影响：预埋值出现即近乎实锤。
      const attributed = plugin !== undefined
      // 0.2.1 修复：无主警报（宿主自身流量）不报警——宿主对话包含 PEM 格式是正常行为
      // （安全讨论、文档示例等），不是外泄。真正的外泄是第三方插件发送的流量。
      if (!attributed) return
      const alertId = `n3-key-leak-${tag}:${plugin ?? ''}:${hashShort(hashInput)}`
      // 0.2.1：用户已忽略的警报不再重新记录（持久化忽略）
      if (isPersistentlyDismissed(alertId)) return
      status.record({
        id: alertId,
        severity: 'red',
        source: 't2',
        kind: 'n3-key-leak',
        message: `密钥外泄确认：出站${where === 'url' ? 'URL' : '数据体'}中检测到${hit.kind === 'pem' ? 'PEM 私钥格式' : 'AWS Access Key'}（${hit.match.slice(0, 30)}…）——已归因插件 ${plugin}，按外泄处置（N3）`,
        target: hit.match,
        pluginHint: plugin,
        mergeKey: `t2:n3-key-leak:${plugin ?? ''}`,
        at: Date.now(),
      })
    }
  }
  const ledgerFsObserver = (evt: LedgerFsEvent): void => {
    if (evt.plugin !== undefined && isOfficial(evt.plugin)) return
    // P0-2 取证：已武装插件的每次 fs/子进程操作全量落盘（操作形状 + 目标，不落会话内容）
    if (forensicsArmed(evt.plugin)) {
      recordForensics(evt.plugin, { module: evt.module, op: evt.op, target: evt.target, paths: evt.paths, sensitive: evt.sensitive })
    }
    // N4：spawn 参数匹配金丝雀（命令含 curl/wget/nc 场景；网络体走 netCanaryScan）
    if (evt.module === 'child_process' && canaryStore.count() > 0) {
      const hit = canaryStore.match(evt.paths.join(' '))
      if (hit !== undefined) recordCanary('spawn', hit, evt.plugin)
    }
    emitLedger(evt.plugin, exfilLedger.observeFs(evt))
  }
  const ledgerNetObserver = (evt: LedgerNetEvent): void => {
    if (evt.plugin !== undefined && isOfficial(evt.plugin)) return
    // P0-2 取证：已武装插件的网络出口全量落盘
    if (forensicsArmed(evt.plugin)) {
      recordForensics(evt.plugin, { module: evt.module, op: evt.op, target: evt.hostname })
    }
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
  return { sink, emitLedger, recordCanary, recordKeyLeak, ledgerFsObserver, ledgerNetObserver, netCanaryScan }
}