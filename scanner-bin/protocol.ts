/**
 * Scanner wire protocol (shared by client and scanner-bin).
 * @module dsh-plugin-vet/scanner-protocol
 */

export type Language = 'js' | 'ts'
export type Runtime = 'host' | 'sandbox'
export type Severity = 'critical' | 'high' | 'medium' | 'info'
export type Confidence = 'certain' | 'likely' | 'heuristic'
export type Verdict = 'critical' | 'suspicious' | 'clean'

export interface ScanRequest {
  kind: 'code' | 'files'
  language?: Language
  runtime?: Runtime
  code?: string
  files?: string[]
  rules?: Record<string, boolean>
  /** 扫描目标身份：'plugin'（DSH 插件包，严格逃逸判定，默认）| 'generic'（通用代码审计，R3 降级为能力触达面 info）。 */
  targetKind?: 'plugin' | 'generic'
  /** 扫描基础（接入 dsh.so 静态注册站）：'npm' = registry tarball 真实发布物（入口/patch 声明对照发布物有效）；
   * 'git' = 仅源码仓（通常不提交 lib/ 等构建产物），此时 R12 入口/patch 缺失降 info 不误报。缺省按 npm 语义。 */
  scanBasis?: 'git' | 'npm'
  /** OSV 已知漏洞核对（npm 生态）：仅 files 模式且存在 package.json 时生效；严格 opt-in（=== true）。 */
  osv?: boolean
  /** 宿主侧计划超时（P2-1 对齐）：engine 以此收敛扫描预算（budget=min(files×2s, timeout-余量)），
   * 保证 R8-skip 先于宿主 kill 触发（否则 15+/31+ 文件包被 kill 报 scan-fail，优雅降级不可达）。 */
  timeoutMs?: number
  /** P1：传递依赖 OSV 核对（opt-in，默认 false）：调用 upstream-radar CLI 扫描传递依赖树。 */
  transitiveDeps?: boolean
  /** C3（0.1.16 加固）：缓存目录由宿主 vet 决定并注入（宿主侧模块加载时快照 env，进程内插件改 env 无效）；
   * 缺省走 scanner-bin 本地回退（测试直调引擎场景）。 */
  cacheDir?: string
  /** C3（0.1.16 加固）：缓存 key 混淆随机数——宿主进程内生成、仅经 stdin 传给 scanner 子进程，
   * 同进程插件无法预写伪造缓存条目（deny 门禁反缓存投毒）。 */
  cacheNonce?: string
}

export interface Finding {
  rule: string
  severity: Severity
  message: string
  evidence: string
  file?: string
  line?: number
  confidence: Confidence
  /** N2（round-9.1）：经解码还原的命中——原表达式在 AST 的位置保留在 message/evidence，此字段记解码方式。 */
  decodedFrom?: 'base64' | 'hex' | 'charCode' | 'concat' | 'template'
}

/** N2：静态可求值的解码字面量（解码结果喂回 R13/R7/R11 匹配语料）。 */
export interface DecodedLiteral {
  text: string
  method: 'base64' | 'hex' | 'charCode' | 'concat' | 'template'
  /** 原表达式所在行（审计溯源）。 */
  line: number
  file?: string
}

/** N1 静态能力清单（声明侧）：不是判定，只是"代码引用了什么"的结构化事实；
 * scanner-bin 产出 findings 的同时产出能力清单；T2 运行时观测与它做差分——
 * "观测到但清单没声明"即隐藏能力。提取策略：宁可多列（宽松），不误报。 */
export interface CapabilityManifest {
  /** 代码中出现的网络主机（字符串字面量里解析出的 http/https/ws 目标）。 */
  hosts: string[]
  /** 代码中出现的文件路径/敏感段（fs 调用实参 + 形似路径的字面量）。 */
  fsPaths: string[]
  /** 代码中出现的子进程命令名（child_process 实参 + shell/下载命令词）。 */
  spawnCmds: string[]
  /** 第三方 require/import 的包名（能力未知 → 保守声明：imports 非空即视为可能具备任何能力）。 */
  imports: string[]
  /** 是否引用 http/https/net/fetch/dgram 等网络能力。 */
  hasNetwork: boolean
  /** 是否引用 eval/Function/child_process 等动态执行能力。 */
  hasExec: boolean
  /** C2（0.1.16 加固）：是否含内建危险模块的 ESM 具名/命名空间导入（Node 互操作快照，T2 钩子盲区）。 */
  esmNamedBuiltins?: boolean
  /** P0-2（round-11，0.1.21）：代码引用但 package.json 未声明的"幽灵依赖"（靠传递依赖提升侥幸可解析，
   * 升级即可能断供/换源）。仅 files 模式 + 存在可读 package.json 时产出（R16 门控）；
   * @deepseek-ai/* 宿主信任边界不列。 */
  ghostDeps?: string[]
  /** P0-2（round-11，0.1.21）：package.json 声明但 node_modules 缺失的"僵尸依赖"（陈旧/伪造声明）；
   * 仅本地能定位到 node_modules 时才能判定（无 node_modules 则不设此字段）。 */
  zombieDeps?: string[]
}

export interface ScanReport {
  engine: 'static-v13'
  sourceCount: number
  findings: Finding[]
  staticScore: number
  verdict: Verdict
  /** N1：文件模式扫描的静态能力清单（code 模式无插件身份，不产出）。 */
  capabilities?: CapabilityManifest
}

export interface ScanResponse {
  ok: boolean
  error?: string
  report?: ScanReport
}

/** 规则/引擎实现变更必须递增此版本——cache key 与缓存有效性校验都依赖它（round-6：R1 new 形态、R9 ReDoS 判定变更后未递增导致旧缓存中毒；round-7：R2 括号形态/R4 原型污染/R6 组合证据/R9 判定/R3 形态降级；round-7.1：R3 只读成员分类/R4 generic 不再降 info；round-7.2：R2 new X.constructor 复用 isConstructorCapture base 校验/R9 带标签 break 出口语义；round-8：新增 R13 网络外泄端点/R14 非 JS 脚本下载即执行；round-8.1：R14 大小写不敏感（PowerShell/cmd 命令不分大小写）、curl -o 落盘降 medium、flags 传播修复；round-9（0.1.15）：新增 R15 动态网络目标（N5，信息级观测）；round-10（0.1.16 加固批次）：R2 间接/前缀 eval·Function（globalThis.eval/(0,eval)）与 require 拼接折叠、R3 global.*process* 前缀形态（此前漏检为 info）、R4 Reflect.defineProperty、R9 sync 子进程变体与转义括号深度计数、R10 prepare 钩子、R14 python/ruby/perl 下载即执行模式、R15 undici sink。
 * round-11（0.1.21，P0-2 #9）：新增 R16 幽灵/僵尸依赖健康审计（声明 vs 代码引用 vs 实际安装的确定性观测；
 * info 级不扣分不改 verdict；capabilities 增 ghostDeps/zombieDeps）。 */
export const ENGINE_VERSION = 'static-v13' as const

/** The rules of static-v13. R8 is a meta finding emitted by the engine (scan timeout skip); R16 is a
 * project-scope dep-consistency audit (emitted by the engine, not a per-file AST rule). */
export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'R16'] as const

/** Shared context handed to every rule. */
export interface RuleContext {
  request: ScanRequest
  runtime: Runtime
  /** 包内 bin 入口文件的 basename 集合（engine 从 package.json bin 字段解析，round-7）——
   * bin 脚本永远独立运行（CLI），按通用代码判定：R2/R3 降级能力触达面、R9 死循环降 medium。 */
  cliFiles?: Set<string>
  /** 应用型包（package.json 声明非空 bin，round-7）：process 访问是产品功能（CLI/TUI/server），
   * R3 降级能力触达面 info——与 generic 降级同构的「应用型」降级（外部实测：dsh-tui/dsh-bridges）。 */
  appShape?: boolean
  /** 触发规则的文件完整路径（engine 从 files 列表注入，round-10.x 接入 dsh.so）：供规则做目录级上下文判定
   * （如 test/ scripts/ 目录识别，将 process 访问降为能力触达面 info）。code 模式为 undefined。 */
  filePath?: string
  /** N2：本文件静态可求值的解码字面量（base64/hex/charCode/常量拼接/模板串），
   * 引擎在规则执行前产出，R13/R7/R11 并入匹配语料（规则判定逻辑不变，只是"看得更清楚"）。 */
  decodedLiterals?: DecodedLiteral[]
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'info']
export const CONFIDENCES: readonly Confidence[] = ['certain', 'likely', 'heuristic']
