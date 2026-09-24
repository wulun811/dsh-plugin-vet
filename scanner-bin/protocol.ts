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
  /** 官方目录成员包（宿主按官方全集判定，0.3.13/static-v26）：非授权源码产物（构建输出路径、
   * 压缩/打包文件、.d.ts 声明）里的 critical/high 折为 info（加「…（官方包降噪）」前缀）；
   * 缺省 false = 第三方语义（只加产物标注，不动 severity/verdict）。身份核验仍由哈希基线 +
   * registry 对账负责——本字段只做规则面降噪，不参与信任判定。 */
  officialFamily?: boolean
  /** 扫描基础（接入 dsh.so 静态注册站）：'npm' = registry tarball 真实发布物（入口/patch 声明对照发布物有效）；
   * 'git' = 仅源码仓（通常不提交 lib/ 等构建产物），此时 R12 入口/patch 缺失降 info 不误报。缺省按 npm 语义。 */
  scanBasis?: 'git' | 'npm'
  /** 扫描面扩展（undefined = 全开；dsh.so 等消费方可按需关闭）：
   * configFiles: 包根 cordis.yml、cordis.patch.yml、*.patch.yml 纳入扫描面 → R17 !!js 配置检测；
   * instructionFiles: AGENTS.md/CLAUDE.md 与 skills 目录、*.skill 目录下的 SKILL.md 纳入扫描面 → R18 指令/技能注入检测。
   * 两档默认开启但产出以 info 观测为主（见 R17/R18 severity 设计），要绝对静默可用 rules 开关逐规则关。 */
  surface?: { configFiles?: boolean; instructionFiles?: boolean }
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
  /** C4（0.3.8，DSH 0.1.5 同步——官方首发平台二进制包 node-addon-system）：包内含预编译原生/
   * 二进制模块（.node/.dll/.dylib/.so/.exe/.wasm/.ocx 扩展名，或已入面文件的 ELF/PE/Mach-O 魔数）。
   * 判定纪律：纯**文件面证据**（扩展名 + 头部魔数），不静态可审——第三方插件夹带预编译二进制
   * 是经典恶意手法（native 代码绕过一切 JS 规则面），故进能力清单/营养标签/升级差分。 */
  hasNativeBinary: boolean
  /** C4：命中的原生二进制文件名（basename，去重，上限 10）——标签/差分展示用。 */
  nativeBinaries?: string[]
}

export interface ScanReport {
  /** 随 ENGINE_VERSION 递增（round-15，0.3.2 起 static-v17——R20 新增 + capability 提取行为变化；
   * round-16，0.3.3 起 static-v18——R20/R11/R9 绑定与语料门控、N2 解码扩容、大小写/扩展名面；
   * round-17 起 static-v19——R16 幽灵依赖改子路径前缀解析（父包已声明的子路径导入不再误报）；
   * round-22 起 static-v20——R1/R2 逃逸正则扩形态（括号/前缀元素访问）+ R1 别名遮蔽修复（误判
   * critical 面收窄）、R3 前缀元素访问与解构成员形态补漏（critical 面扩大）、R7 sk-proj-/github_pat_
   * 补漏、R2 顶级 require 判定收紧到真·模块顶层、capability require() 空参崩溃修复 + node: 前缀
   * 能力归一（hasNetwork/hasExec 不再漏记）；
   * 0.3.8 起 static-v21——C4 原生二进制感知：能力清单新增 hasNativeBinary/nativeBinaries
   * （.node/.dll/.dylib/.so/.exe/.wasm/.ocx/.sys 扩展名 + ELF/PE/Mach-O/wasm 魔数复核；
   * 计数不解析不入 sourceCount）——输出形状变化，引擎版本递增使旧缓存失效。
   * 0.3.9 起 static-v22（审查修复批次）——① 预算耗尽的部分结果不再写缓存（此前 deadline
   * 跳过的尾部文件会把假 clean 永久固化）；② 单文件异常不再丢整包（元 finding R8-rule-error）；
   * ③ stringyValue/numberyValue 环检测 + 深度帽（自引用初始化器此前 RangeError → 整包 ok:false）；
   * ④ isExtensionlessJs 补 stat 守卫（无扩展名 FIFO 永久挂起）与 extOf 基名化（带点目录段下
   * 无扩展名入口判定的死代码）；⑤ R9 isRedosPattern 改线性配对 + 工作预算；⑥ 循环外
   * package.json 读取改限量（大 manifest 不再绕开 8MB 预检）。规则行为与扫描面均变化。
   * 0.3.10 起 static-v23（R13 误报治理，OSS 注册表 64 例反馈）——① 端点形状：整字面量
   * 必须整体形如 host/IP/URL，散文/标签/说明串不再命中；② Tor 只认合法 label（v2 16 /
   * v3 56 base32），action.onion 类垃圾不再命中；③ 守卫/拒绝名单语境（=== 比较操作数、
   * new Set().has 消费、Object.freeze 表、容器绑定名守卫语义）与测试/CI 文件降 info；
   * 0.3.11 起 static-v24（R3 dev/ops 脚本中间态，OSS 注册站 329 样本反馈）——根级
   * dev/ops 脚本（check-*、dev-*、docker-*、*-install 等明确动词名）里的 process.exit/reallyExit
   * 从 critical 降为 high（仍在 verdict/评分内，不再推最高档）+ message 前缀标记 dev-script；
   * getBuiltinModule/mainModule/module 与运行时文件名（transport/cli/desktop/start-*）、
   * scripts/ 目录（0.3.9 立场）均不参与。R3 判定语义变化，旧缓存作废。
   * 0.3.12 起 static-v25（审查修正）：根级判定改为**相对包根**（package.json 所在目录平铺、
   * 深度 1）——首发版深度无关 basename 匹配会把 scripts/、lib/ 等嵌套运行时文件一并降档，
   * 与「scripts/ 是产品代码、运行时文件名不参与」的立场矛盾；现仅包根平铺的明确 dev/ops
   * 动词脚本降档，无 package.json 上下文保守不降。R3 判定语义变化，旧缓存作废。
   * 0.3.13 起 static-v26（DSH 0.1.7-rc.1 同步）：① R12 支持 dsh.bundle.patch 的有序数组形态
   * （rc.2 只支持字符串）并对非法形态报 high；② 新增 request.officialFamily——官方目录成员包
   * 的**非授权源码产物**（构建输出 lib/dist/build/out 等路径、压缩/打包文件、.d.ts 声明）里的
   * critical/high 折为 info 并加「构建产物/压缩产物/类型声明」前缀，第三方包只标注不降档
   * （身份核验仍由哈希基线 + registry 对账负责，本降噪不改判定权属）。输出形状变化，旧缓存作废。 */
  engine: 'static-v26'
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
 * info 级不扣分不改 verdict；capabilities 增 ghostDeps/zombieDeps）。
 * round-12（R17/R18 扫描面扩展）：新增 R17 !!js 配置注入检测（cordis.yml/cordis.patch.yml 等根级配置文件
 * 中的 !!js 表达式文本，仅提取不执行，单动词 info、动词+外联/凭据组合 high）与 R18 指令/技能注入观测
 * （AGENTS.md/CLAUDE.md 与 skills、*.skill 目录下 SKILL.md 的组合式文本特征，首版全 info）。
 * 均受 request.surface 门控；surface 并入缓存 key。
 * round-13（R19）：新增 R19 typosquat 观测（包名/依赖 vs 官方核心名编辑距离 ≤1 或同形，info 永不进 verdict）。
 * round-14（异常流对抗回归）：R18 匹配前剥离不可见字符（ZWSP 等打断规避）、R19 比较前 NFKC 归一
 * （全角同形规避）——规则行为变化，引擎版本递增使旧缓存失效。
 * round-15（0.3.2）：新增 R20 exec/spawn 族实参下载即执行（JS 内嵌 curl|sh 等形态，组合证据
 * high/medium，N2 解码并入；generic/测试文件降 info）——新增规则 + capability 提取行为变化，
 * 引擎版本递增使旧缓存失效。
 * round-16（0.3.3）：R20 绑定口径升级（解构别名/promisify/对象内嵌/属性链）+ N2 增 Array.join
 * 与 Buffer.from 拼接递归 + curl/wget/|sh 大小写不敏感 + 动态片段占位；R11 补 require('fs')
 * 直调与解构绑定 + N2 语料加 fs 足迹门控；R9 fork-bomb 加 child_process/worker_threads 绑定
 * 门控；stringyValue/numberyValue 补词法遮蔽防护；AST 面新增无扩展名/大写扩展名入口
 * （extOf 统一小写 + package.json bin/scripts 引用 + node shebang）——规则行为大改，
 * 引擎版本递增使旧缓存失效。
 * round-17（0.3.3）：R16 幽灵依赖改子路径前缀解析（declared.some(d => i === d || i.startsWith(d + '/'))）
 * ——父包已声明的 react/jsx-runtime 类子路径导入不再误报；父包未声明的子路径（ghost-pkg/sub）
 * 照旧判幽灵。规则行为变化，引擎版本递增使旧缓存失效。
 * round-22（0.3.4）：① capability require() 无实参崩溃修复（整扫描 ok:false）+ node: 前缀
 * 能力归一（hasNetwork/hasExec 此前漏记 → N1 误报隐藏能力）；② R1/R2 逃逸正则扩形态
 * （return (process) 括号包裹、globalThis['process'] 前缀元素访问——此前零命中）且 R1/R2
 * 从双副本改为单源导入；③ R1 别名解析补遮蔽（形参遮蔽 const c = x.constructor 的 critical
 * 误判）；④ R3 补 globalThis['process'].exit 元素访问形态（此前零命中）与解构成员形态
 * （const { exit } = process; exit(1) 此前只报 info）；⑤ R7 补 sk-proj- 与 github_pat_
 * 现行密钥格式（'-' 打散旧字符类整族漏报）；⑥ R2 顶级 require 判定收紧到真·模块顶层
 * （函数体 const require 此前被误当顶级降噪漏报）。规则行为变化，引擎版本递增使旧缓存失效。
 * 0.3.8（C4）：原生二进制感知——能力清单新增 hasNativeBinary/nativeBinaries（文件面证据：
 * 原生扩展名命中或 ELF/PE/Mach-O/wasm 魔数命中；命中文件不解析、不入 sourceCount）。
 * 输出形状变化（且扫描面自 0.3.8 起含原生扩展文件，cacheKey 随之漂移），引擎版本递增失效旧缓存。
 * 0.3.9（审查修复）：缓存写入门控（预算耗尽不缓存）、单文件容错元 finding、ast 环检测/深度帽、
 * FIFO 守卫与 extOf 基名化、R9 线性化、循环外 package.json 限量读——规则行为与形状均有变化。
 * 0.3.10（R13 误报治理）：R13 判定收紧——端点形状（① 散文/标签不再命中）、Tor label 校验
 * （② action.onion 不再命中）、守卫/拒绝名单与测试/CI 语境降 info（③⑤）、脱敏占位降 info
 * （④）——规则行为变化，旧缓存作废。
 * 0.3.11（R3 dev/ops 中间态）：根级明确开发/运维动词脚本（check-pr-title.mjs /
 * dev-install.mjs / uninstall.mjs / docker-init.mjs 等）内的 process.exit/reallyExit 从
 * critical 降为 high + message 标记 dev-script；getBuiltinModule/mainModule/module、
 * 运行时文件名（transport/cli/desktop/start-*）与 scripts/ 目录保持 critical——规则行为
 * 变化，旧缓存作废。
 * 0.3.12（审查修正）：上述「根级」改按 package.json 所在目录界定（仅深度 1 平铺）——
 * 首发版按 basename 深度无关匹配把 scripts/、lib/ 等嵌套文件也降档，与「scripts/ 是产品
 * 代码、运行时文件名不参与」立场矛盾；修正后嵌套文件一律不降，无 package.json 保守不降——
 * 规则行为变化，旧缓存作废。 */
export const ENGINE_VERSION = 'static-v26' as const

/** The rules of static-v26（规则集相对 v25 变化：0.3.13 新增 request.officialFamily——官方目录成员包的
 * 非授权源码产物（构建输出路径/压缩内容/.d.ts）里 critical/high 折 info 并加类别前缀（第三方只加
 * 前缀）；R12 支持 dsh.bundle.patch 有序数组并对非法形态报 high。前序 v25（相对 v24）变化：R3 dev/ops 中间态改**相对包根**的根级判定——
 * 0.3.11 首发的深度无关 basename 匹配会把 scripts/、lib/ 等嵌套的运行时文件一并降档（与
 * 「scripts/ 是产品代码、运行时文件名不参与」的立场矛盾），审查修正为：仅包根平铺
 * （相对 package.json 所在目录深度 1）的明确 dev/ops 动词脚本才降 critical→high+dev-script
 * 标记，无 package.json 上下文保守不降；getBuiltinModule/mainModule/module 与运行时文件名
 * 仍保持 critical）。 R8 is a meta finding emitted by the engine (scan timeout skip / per-file error skip);
 * R17/R18/R19 are surface-gated text/config rules (emitted by the engine, not per-file AST rules);
 * R20 is a per-file AST rule (exec/spawn-family argument download-and-exec, registry-driven);
 * OSV / OSV-T are engine-emitted data-source findings (OSV advisory board / transitive upstream-radar)
 * — 列入 RULE_IDS 供白名单式消费方完整枚举（round-16：此前只枚举 AST 规则，OSV 两码会静默丢失；
 * 0.3.9 review：R8 元 finding 同样由 engine 产出却漏列，白名单消费方会静默丢跳过提示）。 */
export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'R16', 'R17', 'R18', 'R19', 'R20', 'OSV', 'OSV-T'] as const

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
   * 引擎在规则执行前产出，R13/R7/R11/R20 并入匹配语料（规则判定逻辑不变，只是"看得更清楚"）。 */
  decodedLiterals?: DecodedLiteral[]
  /** 包根目录（files 模式：文件列表中 package.json 所在目录，round-24/0.3.11 审查修正）——
   * 供规则做**相对包根**的位置判定（如 R3 dev/ops 中间态只认根级平铺的 dev 脚本）。
   * 无 package.json（code 模式 / 消费方未传清单）为 undefined → 规则保守不降。 */
  pkgRoot?: string
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'info']
export const CONFIDENCES: readonly Confidence[] = ['certain', 'likely', 'heuristic']
