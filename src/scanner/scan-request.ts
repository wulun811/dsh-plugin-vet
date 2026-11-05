/**
 * 扫描请求的唯一构造点（0.5.10，不变式 9「三入口等价」）。
 *
 * 背景：`scan_plugin`（工具面）与「加载前自动扫描」（守卫面）各自手拼一个 `ScanRequest`——
 * 文件枚举、指令文件开关、`osv`、`targetKind` 各写一遍。`vet-gate` 复用工具面的
 * `buildRequest`，所以真正的分叉只有两处，但两处都会让**同一份字节得到两种判定**：
 *
 * - 部署者把 `scanSurface.instructionFiles` 关掉后，加载前扫描不再看 `AGENTS.md`，工具面
 *   照看不误（R18 面在一边生效、在另一边不生效）；
 * - `targetKind` 在守卫面从来没显式给过，靠协议默认 `'plugin'`；工具面按包形态算，没有
 *   插件标记的包会被判 `'generic'`（R3 逃逸判定降级为能力触达面）。
 *
 * 这里把「同一个包根 → 同一份请求」收成一处：调用方只能给**策略输入**（开哪些面、要不要
 * OSV、身份是什么），不能自己拼字段。策略输入之间的差仍然存在，并且是有意的——
 * 但从此它必须**显式**写在调用点上，而不是散落在两段相似的代码里。
 *
 * 归一化约定：**身份（`targetKind`）由调用方显式声明，构造点不改写它**——把调用方说过的
 * 话说成"省略"，会让"这个包是什么"在请求对象里变得不可见。省略与显式 `'plugin'` 在引擎里
 * 完全等价（规则侧一律判 `=== 'generic'`），差别只在缓存键（`scanner-bin/cache.ts` 用
 * `tk:${targetKind ?? ''}`）——所以缓存键那边把 `'plugin'` 归到与省略同一个槽位：
 * 加载前扫描的键因此不因这次收口而漂移（升级不会让几百个官方包重扫一遍），工具面也终于
 * 和它共用同一份缓存。
 * - `surface` 仍按「全开即省略」写：引擎把 undefined 当全开，缓存键里 `cf:1|if:1` 与省略
 *   等价，两边都不产生漂移。
 */
import { resolve } from 'node:path'
import { listSourceFiles, listInstructionFiles } from './package-sources.js'
import { detectDshVersion } from '../guard/update-check.js'
import type { ScanRequest } from './protocol.js'

/** 一次文件面扫描的策略输入。所有字段都是「要不要」，没有形状。 */
export interface FileScanPolicy {
  /** 指令/技能文件（R18 面）。undefined/true = 收；false = 不列文件、也不让引擎跑该面。 */
  instructionFiles?: boolean
  /** 包根配置文件（R17 面）。undefined/true = 收；false = 让引擎跳过该面。 */
  configFiles?: boolean
  /** OSV 已知漏洞核对（网络，严格 opt-in）。 */
  osv?: boolean
  /** 传递依赖雷达（网络，严格 opt-in）。 */
  transitiveDeps?: boolean
  /** 目标身份。'plugin' 走协议默认（省略），'generic' 显式写入。 */
  targetKind?: 'plugin' | 'generic'
  /**
   * 规则开关（0.5.15）。**这是 `config.rules` 到达扫描器的唯一通道**——0.5.14 及以前
   * `config.rules` 是死的：README 承诺 `{"R17": false}` 能关掉一个面，但没有任何一条路径
   * 把它写进 `ScanRequest`，引擎侧的开关因此永远是缺省（全开）。用户照文档关掉的规则一条
   * 都没关，而面板还把它标成 `active`——`docs/FAILURES.md` F12 是同一类错的上一例。
   * 空对象与省略等价（引擎把 undefined 当全开），缓存键里 `{}` 与省略也是同一槽位。
   */
  rules?: Record<string, boolean>
  /** 官方目录成员且字节可信 → 产物降噪（改变 severity，进缓存键）。 */
  officialFamily?: boolean
  /** 扫描基础：'git' 源码仓回扫（R12 入口缺失降 info）| 'npm' 发布物（默认）。 */
  scanBasis?: 'git' | 'npm'
  /**
   * 本机 DSH 版本（0.5.24）：R12 需求闸门的版本对照输入。省略 = 自动探测（进程内一次）；
   * 显式给 '' = 不判版本（只做形态检查）。测试用它把「本机跑的是哪版」变成可注入输入。
   */
  dshVersion?: string
  /**
   * 显式文件集：给了就不再枚举。vet 本体自扫用它换成「发布物范围」（与钉扎/门禁同集），
   * 其余入口不传。
   */
  files?: string[]
}

/**
 * 扫描面的文件枚举。指令文件按 `instructionFiles` 决定要不要追加——**枚举与开关必须一起
 * 生效**：只把开关塞给引擎、文件照列，等于引擎关掉了一条规则却仍在为它读盘散列。
 */
export function listScanFiles(root: string, policy: FileScanPolicy = {}): string[] {
  if (policy.files !== undefined) return policy.files
  const base = listSourceFiles(root)
  return policy.instructionFiles === false ? base : [...base, ...listInstructionFiles(root)]
}

/** 本机 DSH 版本（进程内只探一次）。探不到 → ''（= 不判版本，绝不因此报警）。 */
let cachedHostDshVersion: string | undefined
export function hostDshVersion(): string {
  if (cachedHostDshVersion === undefined) cachedHostDshVersion = detectDshVersion()
  return cachedHostDshVersion
}

/** 由策略输入构造文件面 `ScanRequest`。这是全仓唯一一处拼这个形状的地方。 */
export function buildFileScanRequest(root: string, policy: FileScanPolicy = {}): ScanRequest {
  // 0.5.26：根目录先归一为绝对路径再枚举。engine 的入口集合是 `resolve(pkgRoot, …)` 算出的
  // 绝对路径；而 `vet-gate --package ./x` 这类调用会传相对路径——两边一比就永远不相等，
  // 「声明入口优先于测试路径」（0.5.24）在相对路径下会静默退回旧行为：同一份字节、两种判定。
  const files = listScanFiles(resolve(root), policy)
  const surface = policy.configFiles === false || policy.instructionFiles === false
    ? { configFiles: policy.configFiles !== false, instructionFiles: policy.instructionFiles !== false }
    : undefined
  // 0.5.15：规则开关只在**真的写了**才进请求——`{}` 与省略等价（引擎把 undefined 当全开），
  // 写空对象进请求会让缓存键多一个 `{}` 与省略不同的槽位，白白让存量缓存失效一次。
  const rules = policy.rules !== undefined && Object.keys(policy.rules).length > 0 ? policy.rules : undefined
  // 0.5.24：需求闸门的版本对照输入。空串（探不到）不写进请求——与省略等价，缓存键也不漂移。
  const dshVersion = policy.dshVersion ?? hostDshVersion()
  return {
    kind: 'files',
    files,
    ...(policy.targetKind !== undefined ? { targetKind: policy.targetKind } : {}),
    ...(policy.officialFamily === true ? { officialFamily: true } : {}),
    ...(surface !== undefined ? { surface } : {}),
    ...(rules !== undefined ? { rules } : {}),
    osv: policy.osv === true,
    ...(policy.transitiveDeps === true ? { transitiveDeps: true } : {}),
    ...(policy.scanBasis !== undefined ? { scanBasis: policy.scanBasis } : {}),
    ...(dshVersion !== '' ? { dshVersion } : {}),
  }
}
