/**
 * 客户端侧协议类型。⚠ 与 scanner-bin/protocol.ts 保持同步（实现决策：跨构建根目录无法单源共享，
 * 协议测试以 scanner-bin 为准做往返校验）。
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
  /** 官方目录成员包（0.3.13/static-v26，与 scanner-bin 同步）：非授权源码产物（构建输出路径、
   * 压缩/打包文件、.d.ts 声明）里的 critical/high 折为 info；第三方（缺省 false）只加标注。 */
  officialFamily?: boolean
  /** 扫描基础（与 scanner-bin 同步）：'git' = 仅源码仓（R12 入口/patch 缺失降 info 不误报）；'npm' = registry tarball 真实发布物（默认）。 */
  scanBasis?: 'git' | 'npm'
  /** 宿主正在运行的 DSH 版本（0.5.24，与 scanner-bin 同步）：R12 需求闸门的版本对照输入；
   * 缺省 = 不判版本（只做形态检查）。 */
  dshVersion?: string
  /** 扫描面扩展（与 scanner-bin 同步）：configFiles → R17 !!js 配置检测；instructionFiles → R18 指令/技能注入检测。undefined = 全开。 */
  surface?: { configFiles?: boolean; instructionFiles?: boolean }
  /** OSV 已知漏洞核对（npm 生态）：仅 files 模式且存在 package.json 时生效；严格 opt-in（=== true）。 */
  osv?: boolean
  /** 宿主侧计划超时（与 scanner-bin/protocol.ts 同步）：engine 据此对齐扫描预算（P2-1）。 */
  timeoutMs?: number
  /** P1：传递依赖 OSV 核对（opt-in，默认 false）：调用 upstream-radar CLI 扫描传递依赖树。 */
  transitiveDeps?: boolean
  /** C3（0.1.16 加固）：缓存目录与 key 混淆 nonce——宿主注入，进程内插件不可重定向/预写缓存（与 scanner-bin 协议同步）。 */
  cacheDir?: string
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
  /** N2：经解码还原的命中。 */
  decodedFrom?: 'base64' | 'hex' | 'charCode' | 'concat' | 'template'
}

/** N2：静态可求值的解码字面量。 */
export interface DecodedLiteral {
  text: string
  method: 'base64' | 'hex' | 'charCode' | 'concat' | 'template'
  line: number
  file?: string
}

/** N1 静态能力清单（与 scanner-bin/protocol.ts 同步）：声明侧事实，非判定。 */
export interface CapabilityManifest {
  hosts: string[]
  fsPaths: string[]
  spawnCmds: string[]
  imports: string[]
  hasNetwork: boolean
  hasExec: boolean
  /** C2（0.1.16 加固）：ESM 具名/命名空间导入内建危险模块（与 scanner-bin 同步）。 */
  esmNamedBuiltins?: boolean
  /** 0.5.3（static-v27）：上面那个布尔命中的具体内建模块（与 scanner-bin 同步）。
   * 缺席 = 旧扫描器/旧缓存，消费方必须按「有盲区但不知是哪个面」降级，不能当没有。 */
  esmNamedBuiltinModules?: string[]
  /** P0-2（0.1.21，R16）：代码引用但 package.json 未声明的"幽灵依赖"（与 scanner-bin 同步）。 */
  ghostDeps?: string[]
  /** P0-2（0.1.21，R16）：package.json 声明但 node_modules 缺失的"僵尸依赖"（与 scanner-bin 同步）。 */
  zombieDeps?: string[]
  /** C4（0.3.8）：包内含预编译原生/二进制模块（.node/.so/.dll/.dylib/.exe/.wasm 等；
   * 文件面证据，见 scanner-bin/protocol.ts 注记）。宿主侧可选——0.3.8 前的存量记录无此字段。 */
  hasNativeBinary?: boolean
  /** C4（0.3.8）：命中的原生二进制文件名（basename，去重，上限 10）。 */
  nativeBinaries?: string[]
}

/**
 * 本构建期望的静态引擎标识。
 *
 * 为什么 `src/` 需要自己的一份：`src` 与 `scanner-bin` 是两个 tsconfig（各自的 rootDir），
 * 跨边界 import 会让编译产物落到 rootDir 之外，所以只能各存一份。两份的一致性由
 * `test/engine-version-sync.test.ts` 钉住——它同时 import 两侧的常量，不一致就红。
 *
 * 0.5.20 起用于资格判定：审计档案会写下产出判读的引擎，加载时拿它和这里比，只有
 * 「规则集变了**且**新规则集会得出更差的结论」才要求重审（见 `audit/archive.ts`）。
 * 0.5.24 起 static-v28：R12 增 DSH 需求闸门；测试/CI 路径降级让位给包声明的入口。
 * 0.5.25 起 static-v29：需求闸门支持部分版本范围（>=0.2 / <0.3）。
 * 0.5.26 起 static-v30：发布前自查修正——`^1.2` caret 边界、engines.dsh 与 peer 的判定顺序、
 * 非法范围形态（非对象 / 空 / dist-tag / 逗号）补报。
 * 0.5.27 起 static-v31：x-range（`0.2.x`）与 `~>` 进入求值；任一 OR 组确证非法 → 整段不满足。
 */
export const CURRENT_ENGINE = 'static-v31' as const

export interface ScanReport {
  /** 与 scanner-bin/protocol.ts 同步；0.3.3 起 static-v19，round-22 起 static-v20，0.3.8（C4 原生二进制感知）起 static-v21，0.3.9（审查修复批次）起 static-v22，0.3.10（R13 误报治理）起 static-v23，0.3.11（R3 dev/ops 脚本中间态）起 static-v24，0.3.12（R3 根级判定审查修正：相对包根平铺）起 static-v25，0.3.13（DSH 0.1.7-rc.1 同步：R12 数组 patch + 官方包产物降噪）起 static-v26；0.5.3（C2 盲区精确化：capabilities 增 esmNamedBuiltinModules，规则判定未改）起 static-v27；0.5.24（DSH 0.2.2 适配：R12 需求闸门 + 测试/CI 路径降级让位给声明入口）起 static-v28；0.5.25（需求闸门支持部分版本范围 >=0.2 / <0.3）起 static-v29；0.5.26（发布前自查：^1.2 caret 边界、engines.dsh 存在时不看 peer、非法范围形态补报）起 static-v30；0.5.27（x-range/`~>` 求值；OR 组整体失效）起 static-v31。 */
  engine: typeof CURRENT_ENGINE
  sourceCount: number
  findings: Finding[]
  staticScore: number
  verdict: Verdict
  /** N1：文件模式扫描的静态能力清单（code 模式不产出）。 */
  capabilities?: CapabilityManifest
  /** 0.5.4：OSV 相位的自述统计（与 scanner-bin 同步）：仅异步 scanWithOsv 路径产出，不进缓存。
   * 缺席 = 旧扫描器 / 同步路径（deny 模式）——宿主覆盖面必须按「没回报」处置，不能当成「问到了」。 */
  osv?: OsvOutcome
}

/**
 * 0.5.4：OSV 相位的自述统计（与 scanner-bin/protocol.ts 同步）。
 * 只记事实：发出去几条、回来几条、停在哪一步。可推导的不重复存——
 * 失败条数 = attempted - answered，未发出条数 = targets - attempted。
 */
export interface OsvOutcome {
  /** ran：查完了；overran：相位被总预算掐断（计数是断点前的事实）；skipped：余量不足整段没跑（计数无意义）。 */
  phase: 'ran' | 'overran' | 'skipped'
  targets: number
  attempted: number
  answered: number
}

export interface ScanResponse {
  ok: boolean
  error?: string
  report?: ScanReport
}
