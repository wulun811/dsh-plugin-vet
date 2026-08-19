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
}

export interface ScanReport {
  /** 与 scanner-bin/protocol.ts 同步；0.1.16（加固批次）起为 static-v12（R2/R3/R4/R9/R10/R14/R15 补丁）。 */
  engine: 'static-v12'
  sourceCount: number
  findings: Finding[]
  staticScore: number
  verdict: Verdict
  /** N1：文件模式扫描的静态能力清单（code 模式不产出）。 */
  capabilities?: CapabilityManifest
}

export interface ScanResponse {
  ok: boolean
  error?: string
  report?: ScanReport
}
