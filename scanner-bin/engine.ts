/**
 * Scan orchestration: code-string mode, files mode with per-file budget and
 * content-hash cache. Pure logic — the stdio wrapper is index.ts.
 * @module dsh-plugin-vet/scanner-engine
 */
import { readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path'
import { createRequire, builtinModules } from 'node:module'
import { parseSource } from './ast.js'
import { extractCapabilities, aggregateCapabilities } from './capability.js'
import { collectDecodedLiterals } from './decode.js'
import { executeRules } from './rules/index.js'
import { runPackageJson } from './rules/supply-chain.js'
import { runContract } from './rules/contract.js'
import { runTyposquat } from './rules/typosquat.js'
import { runConfigScan, isRootConfigName, CONFIG_EXT } from './rules/config-scan.js'
import { runInstructionScan, isInstructionFile } from './rules/instruction-scan.js'
import { NON_JS_SCRIPT_EXT, runNonJsScript } from './rules/non-js-scripts.js'
import { computeScore, computeVerdict } from './score.js'
import { cacheKey, readCached, writeCached, cacheDirFor } from './cache.js'
import { ENGINE_VERSION } from './protocol.js'
import { queryOsv, type OsvVuln } from './osv.js'
import type { CapabilityManifest, Finding, ScanReport, ScanRequest, ScanResponse } from './protocol.js'

const SCANNABLE_EXT = new Set(['js', 'ts', 'mjs', 'cjs'])

/** Node 内建模块集合（R16 幽灵依赖排除用）：代码里 import 'fs'/'path' 等裸内建
 * 是 CJS 惯用写法，不是「引用了未声明的第三方包」——require('fs') 从不依赖
 * package.json 的 dependencies（capability.ts packageName 已排除 node: 前缀，
 * 裸内建名如 fs/path 会漏进来 → 每个传统 CJS 插件都误报 R16 幽灵依赖 info）。 */
export const NODE_BUILTINS = new Set(builtinModules.map(m => m.split('/')[0]))

/** 大文件预检上限（技术债偿还）：超过该大小的源码文件不做整文件 readFileSync——
 * 直接产出 R8-scan-skipped info（规则扫不到≠干净，但绝不让大文件把引擎内存打爆）。 */
const PRE_FILE_SIZE_LIMIT = 8 * 1024 * 1024

/** Extension of a path (without dot, lowercased), or undefined when none.
 * round-16：统一小写——`.SH`/`.CMD`/`.MD` 等大小写变体此前绕过 R14/R18 与源码面
 * （大小写不敏感文件系统/显式 `bash Setup.SH` 是真实形态；isInstructionFile 等内部
 * 判定早已按大小写不敏感写）。
 * 0.3.9（审查修复）：只看 **basename**——此前对整条路径 lastIndexOf('.')，路径里带点的
 * 目录段（DSH 安装树 ~/.dsh/… 必带）会把无扩展名文件算成伪扩展名（`dsh/profiles/…/cli`），
 * 481 行据此提前 continue → round-16 的无扩展名 bin 入口判定在真实安装路径下等于死代码。 */
function extOf(file: string): string | undefined {
  const base = basename(file)
  const dot = base.lastIndexOf('.')
  if (dot <= 0) return undefined
  return base.slice(dot + 1).toLowerCase()
}

/** 无扩展名文件是否按 JS 解析（round-16）：package.json bin/scripts 引用的入口，或
 * 内容首行是 node shebang（`#!/usr/bin/env node`）；二进制/无特征文件跳过（防误解析）。 */
function isExtensionlessJs(file: string, referenced: Set<string> | undefined): boolean {
  if (referenced !== undefined && referenced.has(basename(file))) return true
  try {
    // 0.3.9（审查修复）：stat 前置守卫——与 sniffNativeBinary 同款纪律。此前直接
    // openSync('r')，无扩展名 FIFO 会让同步循环永久阻塞（deadline/宿主 timeoutMs 都
    // 无法抢占，只能 SIGKILL）；D3 回归测试只覆盖了 x.sh 这类走 R14（有守卫）的形态。
    if (!statSync(file).isFile()) return false
    const fd = openSync(file, 'r')
    try {
      const buf = Buffer.alloc(512)
      const n = readSync(fd, buf, 0, 512, 0)
      const head = buf.subarray(0, Math.max(0, n))
      if (n <= 0) return false
      if (head.includes(0)) return false // 二进制文件
      const first = head.toString('utf8').split('\n', 1)[0] ?? ''
      return first.startsWith('#!') && /\bnode(?:js)?\b/i.test(first)
    } finally {
      closeSync(fd)
    }
  } catch {
    return false
  }
}

/** Read a file as UTF-8, returning '' when unreadable. */
function readOrDefault(file: string): string {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

/** 限量整读（0.3.9 审查修复）：超限/非常规文件一律返回 ''。
 * 循环**外**的 package.json 读取（packageShape/buildDepsInfo/checkOsv）此前走 readOrDefault
 * ——多 GB 假 manifest 会被整个读进内存（实测 120MB → +147MB RSS），绕开 round-15 在扫描
 * 循环内加的 8MB 预检（那份注释正是为「超大 package.json」写的）。 */
function readCapped(file: string, limit = PRE_FILE_SIZE_LIMIT): string {
  try {
    const st = statSync(file)
    if (!st.isFile() || st.size > limit) return ''
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

// ── C4（0.3.8，DSH 0.1.5 同步）：原生二进制感知 ──────────────────────────────
// 官方首发平台二进制包（@deepseek-ai/node-addon-system-linux-x64 携带 .node）；预编译二进制
// 对 JS 规则面完全不可见（AST/文本规则都扫不到 native 代码），第三方插件夹带 .node 是经典
// 恶意载荷手法。判定纪律：纯文件面证据——扩展名命中或 ELF/PE/Mach-O/wasm 魔数命中（后者顺带
// 覆盖把编译产物伪装成 .js/.yml 等入面名的形态）；命中文件只计数不读取解析（防二进制内容
// 进语料/OOM），不入 sourceCount。与宿主侧 package-sources.ts 的 NATIVE_BINARY_EXT 同步——
// 跨构建根目录无法单源共享，改动需两边同改（SOURCE_EXT/CONFIG_EXT 同款纪律）。
const NATIVE_BINARY_EXT = new Set(['node', 'dll', 'dylib', 'so', 'exe', 'wasm', 'ocx', 'sys'])

/** 魔数复核：只读头部（64B + PE 头一跳）。必须先 stat 挡非常规文件——
 * 对 FIFO 调 openSync('r') 会无界阻塞（scanner-fixes D3 场景：包目录里有 mkfifo），
 * 设备/socket 同理；读失败按非原生处理。 */
function sniffNativeBinary(file: string): boolean {
  let fd: number | undefined
  try {
    if (!statSync(file).isFile()) return false
    fd = openSync(file, 'r')
    const head = Buffer.alloc(64)
    const n = readSync(fd, head, 0, 64, 0)
    if (n < 4) return false
    // ELF：7f 'ELF'
    if (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) return true
    // wasm：00 'asm'
    if (head[0] === 0x00 && head[1] === 0x61 && head[2] === 0x73 && head[3] === 0x6d) return true
    // Mach-O thin/fat（含字节序反相；0xcafebabe 兼收 Java class——npm 语境同为编译二进制）
    const u32 = head.readUInt32BE(0)
    if (u32 === 0xfeedface || u32 === 0xfeedfacf || u32 === 0xcefaedfe || u32 === 0xcffaedfe
      || u32 === 0xcafebabe || u32 === 0xbebafeca) return true
    // PE：'MZ' + e_lfanew(0x3c) 指向 'PE\0\0'（文本文件恰好以 MZ 开头的形态被偏移复核排除）
    if (head[0] === 0x4d && head[1] === 0x5a && n >= 64) {
      const peOff = head.readUInt32LE(0x3c)
      if (peOff > 0 && peOff < 4096) {
        const sig = Buffer.alloc(4)
        const m = readSync(fd, sig, 0, 4, peOff)
        if (m === 4 && sig[0] === 0x50 && sig[1] === 0x45 && sig[2] === 0 && sig[3] === 0) return true
      }
    }
    return false
  } catch {
    return false
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* 已失效 */ }
    }
  }
}

/** R8-skip 触发后仍需时间写出报告并退出——必须早于宿主 kill 的余量。 */
const ENGINE_KILL_MARGIN_MS = 1500

/**
 * OSV 硬护栏余量（0.3.14 用户实测回归）。
 * P2-10 的预算算术**默认 fetch 会响应 AbortSignal**——DNS 卡在 threadpool、代理吞连接、
 * 半开 socket 时 await 永不 settle，AbortController 只是发信号，预算约束整体失效：
 * 实测把 fetch 换成永不 settle 的实现，引擎 25s+ 不返回 → 宿主 15s SIGKILL → 整个扫描丢失
 * （report 报 scan-fail 黄牌；deny 模式 fail-closed 误拦）。真实案例：
 * @deepseek-ai/dsh-mcp-client 重启首扫时 OSV 相位挂死 → 「scanner timeout after 15000ms」。
 * 故每次网络等待都加一层竞速硬超时：无论底层是否响应 abort，引擎都在预算内返回。
 */
const OSV_RACE_SLACK_MS = 250

/**
 * OSV 最小可用预算（0.3.14）：宿主余量低于此值就整段跳过——OSV 是增强项（README 口径：
 * 网络失败静默降级），不值得贴着宿主 kill 线赌。旧行为把预算地板设成 1000ms，最坏情形
 * 只剩 0.5s 余量（静态扫描已吃掉大半），正是 scan-fail 的高发区。
 */
const OSV_MIN_BUDGET_MS = 2000

/**
 * 竞速硬超时：resolve 值或 null（超时/异常）。返回 null = 该次网络等待按失败静默降级。
 * 注意不 unref 定时器——挂起的等待若只剩未引用的句柄，进程可能在写出报告前就退出。
 */
function withHardTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return new Promise<T | null>(resolve => {
    const timer = setTimeout(() => resolve(null), ms)
    const settle = (value: T | null): void => { clearTimeout(timer); resolve(value) }
    promise.then(v => settle(v), () => settle(null))
  })
}

// ── P0-2 #9（R16）：幽灵/僵尸依赖健康审计 ──────────────────────────────────
// 依赖声明（package.json）↔ 代码引用（capabilities.imports）↔ 实际安装（node_modules）三方对账：
// - 幽灵依赖（ghost）：代码引用但 package.json 未声明——靠传递依赖提升侥幸可解析，升级即可能断供/换源；
// - 僵尸依赖（zombie）：package.json 声明但 node_modules 找不到——陈旧/伪造声明，运行到即崩溃。
// 纪律（产品红线）：info 级观测（WEIGHTS.info=0 不扣分）、heuristic 置信（不改 verdict）、零出站；
// @deepseek-ai/* 宿主信任边界两端都不列（与 OSV 直接依赖核对的跳过规则一致，避免 DSH 插件宿主 SDK 误报）。
const R16_DEP_CAP = 20
/** 从包根向上的 node_modules 查找层数上限（npm hoisting/工作区常见 2-4 层；8 层已超出常规 monorepo）。 */
const R16_ROOT_WALK = 8

export interface DepsInfo {
  /** 声明侧直接依赖（dependencies/devDependencies/peerDependencies/optionalDependencies；去 @deepseek-ai/*、排序去重）。 */
  declared: string[]
  /** declared 中实际安装的子集；null = 本地无 node_modules，僵尸判定不可用。 */
  installed: string[] | null
  /** 参与缓存 key 的指纹（声明/node_modules 变化 → 缓存失效重扫，保证幽灵/僵尸结果不陈旧）。 */
  fingerprint: string
}

function declaredDepsOf(pkg: Record<string, unknown>): string[] {
  const out = new Set<string>()
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const) {
    const deps = pkg[key]
    if (typeof deps !== 'object' || deps === null) continue
    for (const name of Object.keys(deps as Record<string, unknown>)) {
      if (name.startsWith('@deepseek-ai/')) continue
      out.add(name)
    }
  }
  return [...out].sort()
}

/** 从包根向上（含本层）收集现有 node_modules 目录（hoisting 到工作区根的情况也能找到）。 */
function nodeModulesRoots(pkgRoot: string): string[] {
  const roots: string[] = []
  let dir = pkgRoot
  for (let i = 0; i <= R16_ROOT_WALK; i++) {
    try {
      if (statSync(join(dir, 'node_modules')).isDirectory()) roots.push(join(dir, 'node_modules'))
    } catch {
      // 无此目录/不可读：跳过该层
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return roots
}

/** 某依赖是否在任一 node_modules 根下实际安装（scoped 包拆两段路径）。 */
function isInstalledDep(name: string, roots: string[]): boolean {
  const parts = name.split('/')
  for (const root of roots) {
    const p = parts.length === 2 ? join(root, parts[0], parts[1]) : join(root, name)
    try {
      if (statSync(p).isDirectory()) return true
    } catch {
      // 缺失：继续找下一个根
    }
  }
  return false
}

/** 构建依赖健康审计上下文（无 package.json / 坏 package.json → null，静默跳过）。 */
export function buildDepsInfo(files: string[] | undefined): DepsInfo | null {
  if (files === undefined) return null
  const pkgFile = files.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return null
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(readCapped(pkgFile)) as Record<string, unknown>
  } catch {
    return null
  }
  const declared = declaredDepsOf(pkg)
  const roots = nodeModulesRoots(dirname(pkgFile))
  if (roots.length === 0) {
    return { declared, installed: null, fingerprint: JSON.stringify({ declared }) }
  }
  const installed = declared.filter(d => isInstalledDep(d, roots))
  return { declared, installed, fingerprint: JSON.stringify({ declared, installed }) }
}

/** R16 info 观测（不给分、不改 verdict——WEIGHTS.info=0 & heuristic 恒 0.5 但 info 权重为 0）。 */
function depsFindings(ghost: string[], zombie: string[]): Finding[] {
  const out: Finding[] = []
  for (const d of ghost) {
    out.push({
      rule: 'R16', severity: 'info', confidence: 'heuristic',
      message: '幽灵依赖：代码引用 ' + d + ' 但 package.json 未声明（靠传递依赖提升侥幸可解析，升级可能断供/换源）',
      evidence: d, file: 'package.json',
    })
  }
  for (const d of zombie) {
    out.push({
      rule: 'R16', severity: 'info', confidence: 'heuristic',
      message: '僵尸依赖：package.json 声明了 ' + d + ' 但 node_modules 中不存在（陈旧/伪造声明，运行到即失败）',
      evidence: d, file: 'package.json',
    })
  }
  return out
}

/**
 * 从 package.json 内容解析包形态（round-7，P4）：bin 声明（字符串或对象）→ 应用型包
 * （appShape，R3 按能力触达面降级）；bin 值对应文件 → CLI 入口（cliFiles，R2/R3/R9 按
 * 通用代码判定）。round-16：scripts 命令里出现的路径 token 也入 cliFiles（postinstall
 * `node scripts/install` 等——无扩展名入口的常见宿主，engine 按 basename 匹配它们）。
 * engine 只见文件 basename，bin/scripts 路径统一归一为 basename 匹配。
 */
function packageShape(content: string): { cliFiles: Set<string>; appShape: boolean } {
  const cliFiles = new Set<string>()
  let appShape = false
  try {
    const pkg = JSON.parse(content) as Record<string, unknown>
    const bin = pkg.bin
    const entries: string[] = []
    if (typeof bin === 'string' && bin !== '') entries.push(bin)
    else if (typeof bin === 'object' && bin !== null) {
      for (const v of Object.values(bin)) {
        if (typeof v === 'string' && v !== '') entries.push(v)
      }
    }
    appShape = entries.length > 0
    for (const e of entries) {
      const name = basename(e.replace(/^\.\//, ''))
      if (name !== '' && name !== '.') cliFiles.add(name)
    }
    const scripts = pkg.scripts
    if (typeof scripts === 'object' && scripts !== null) {
      for (const v of Object.values(scripts)) {
        if (typeof v !== 'string' || v === '') continue
        // 取命令中首个"像路径"的 token（node scripts/install、node --no-warnings bin/start …）
        const tok = v.trim().split(/\s+/).find(t => t.includes('/') || t.includes('\\'))
        if (tok !== undefined) {
          const name = basename(tok.replace(/^\.\//, '').replace(/\\/g, '/'))
          if (name !== '' && name !== '.') cliFiles.add(name)
        }
      }
    }
  } catch {
    // 坏 package.json：无形态证据（保守不降级）
  }
  return { cliFiles, appShape }
}

/**
 * Total scan budget: min(files × 2s, host-timeout − margin), floor 1s.
 * P2-1：宿主 kill 超时（report min(…,60s) / deny min(…,30s) / 工具 60s）比 files×2s 先到的话，
 * 子进程在 R8-skip 触发前被杀 → ok:false（deny fail-closed 误拦合法大包、report 误报 scan-fail）。
 * 引入宿主计划超时（request.timeoutMs，client 写入）后：budget = min(files×2s, timeout−ENGINE_KILL_MARGIN_MS)，
 * R8-skip 恒先于 kill 触发——优雅降级结构上可达。timeoutMs 缺省（直调 engine 的测试）维持旧行为。
 * round-4：移除 DSH_PLUGIN_VET_SCAN_BUDGET_MS env 覆盖——设大值会绕过宿主对齐再次让
 * R8-skip 不可达（子进程被杀 → deny fail-closed 误拦）；测试用 timeoutMs 参数控制预算。
 */
function budgetMs(fileCount: number, timeoutMs?: number): number {
  const byFiles = fileCount * 2000
  const byHost = timeoutMs !== undefined && Number.isFinite(timeoutMs)
    ? timeoutMs - ENGINE_KILL_MARGIN_MS
    : byFiles
  return Math.max(1000, Math.min(byFiles, byHost))
}

/** Meta finding emitted when a file exceeds the scan budget (R8-scan-skipped). */
function skipFinding(file: string): Finding {
  return {
    rule: 'R8',
    severity: 'info',
    confidence: 'heuristic',
    message: '扫描超时/文件过大跳过（R8-scan-skipped）',
    evidence: '',
    file: basename(file),
  }
}

/** 0.3.9（审查修复）：单文件处理异常（解析/规则/能力提取抛错）的 info 元 finding。
 * 关键差别在**不丢整包**：此前这种异常让 scan() 返回 ok:false，同包其它文件的 critical
 * 命中一并丢失；现在只标记该文件“未完成静态审”，其余文件照常出结论。 */
function ruleErrorFinding(file: string): Finding {
  return {
    rule: 'R8',
    severity: 'info',
    confidence: 'heuristic',
    message: '文件处理异常跳过（R8-rule-error）——该文件未完成静态审，其余文件不受影响',
    evidence: '',
    file: basename(file),
  }
}

/** 大文件预检（round-12 供 R17/R18 分支复用）：整读前先 stat，超限即 R8-skip（不整读、不 OOM）。
 * round-16 review（D3）：非常规文件（fifo/设备/socket）一律视为超限跳过——/dev/zero 等
 * 无限流 readFileSync 无 EOF 会打爆扫描子进程内存、fifo 会挂死到宿主超时（size 恒 0 骗过
 * 旧的大小预检）。 */
function sizeWithinBudget(file: string): boolean {
  try {
    const st = statSync(file)
    return st.isFile() && st.size <= PRE_FILE_SIZE_LIMIT
  } catch {
    return true // stat 失败（消失/不可读）→ 交给 readOrDefault 的空串兜底
  }
}

/**
 * 非授权源码产物分类（0.3.13，DSH 0.1.7-rc.1 同步；官方包降噪的判据）。
 *
 * 背景：官方包发布物里绝大部分是**机器产物**——`lib/**`（tsc/tsdown 编译输出）、
 * `dist/**` 打包产物、压缩单行 bundle、`.d.ts` 类型声明。规则面（R1/R2/R3/R7…）是为
 * **人写的源码**设计的：压缩产物里 `new Function`、`process.kill`、`process.exit` 是
 * 库/工具链的常规形态，逐条判决定性档只会在每次 DSH 升级（官方家族整体换版本 → 首见
 * 严格扫描）时把盾牌压成黄色（实测 0.1.7-rc.1：277 个官方包 27 个 non-clean，live 自动
 * 扫描已记 5 个 suspicious）。
 *
 * 判据（确定性、纯文件面，不看包名/不看网络）：
 *  1. `.d.ts` —— 类型声明，永不参与运行时；
 *  2. **包根相对路径**的目录段含构建输出目录（lib/dist/build/out/esm/cjs/umd）——DSH 官方包
 *     约定源码在 src/、发布物在 lib/。⚠ 必须相对包根：绝对路径里 npm 全局前缀本身含
 *     `lib`（~/.npm-global/lib/node_modules/…），按绝对路径判会把整包误判成产物；
 *  3. 压缩/打包内容特征——单行 ≥1000 字符，或 ≥3 行超 500 字符（超长行 + 无源码结构）。
 * 其余（src/**、scripts/**、根级 *.mjs/*.js、package.json、assets/**）都算授权源码，不降噪。
 *
 * 边界（诚实记录）：本分类只决定**规则面档位**，不参与信任判定——官方身份仍由内容哈希
 * 基线 + registry 对账 + official-not-in-catalog 黄牌负责；第三方包只加标注、severity 不变。
 * @param filePath 文件路径（files 模式为绝对路径）。
 * @param content 文件内容（调用方已读取）。
 * @param pkgRoot 包根目录（files 模式含 package.json 时由调用方给出）。
 * @returns 产物类别标签；授权源码返回 undefined。
 */
export function artifactKind(filePath: string, content: string, pkgRoot?: string): '构建产物' | '压缩产物' | '类型声明' | undefined {
  const base = basename(filePath)
  // .d.ts 声明（纯类型面，永不参与运行时）。⚠ 只有 .d.ts 可达：SCANNABLE_EXT 是
  // {js,ts,mjs,cjs}，.d.mts/.d.cts 的 extOf='mts'/'cts' 压根不进扫描面（既有覆盖缺口，
  // 不在本次降噪范围内——写在这里免得读者以为它们已被处理）。
  if (base.endsWith('.d.ts')) return '类型声明'
  const rel = packageRelative(filePath, pkgRoot)
  if (rel !== undefined && rel.split(/[\\/]/).slice(0, -1).some(s => BUILD_OUTPUT_SEGMENTS.has(s.toLowerCase()))) {
    return '构建产物'
  }
  if (isMinifiedContent(content)) return '压缩产物'
  return undefined
}

/**
 * 包根相对路径：pkgRoot 已知且文件在其内 → 直接相对化；否则退化为最后一个 `node_modules`
 * 之后的部分（单文件扫描/无 package.json 场景）；都不适用 → undefined（路径判据不参与，
 * 只剩内容判据——保守方向：不降噪）。
 */
function packageRelative(filePath: string, pkgRoot?: string): string | undefined {
  if (pkgRoot !== undefined && pkgRoot !== '') {
    const rel = relative(pkgRoot, filePath)
    if (rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)) return rel
  }
  const parts = filePath.split(/[\\/]/)
  const idx = parts.lastIndexOf('node_modules')
  if (idx >= 0 && idx < parts.length - 1) return parts.slice(idx + 1).join('/')
  return undefined
}

/** 构建输出目录段（官方包发布物约定：src 授权源码 → lib/dist 产物）。 */
const BUILD_OUTPUT_SEGMENTS = new Set(['lib', 'dist', 'build', 'out', 'esm', 'cjs', 'umd'])

/** 压缩/打包内容特征：超长行（单行 ≥1000）或长行密集（≥3 行超 500 字符）。 */
function isMinifiedContent(content: string): boolean {
  let long = 0
  let start = 0
  for (let i = 0; i <= content.length; i++) {
    if (i === content.length || content.charCodeAt(i) === 10) {
      const len = i - start
      if (len >= 1000) return true
      if (len > 500 && ++long >= 3) return true
      start = i + 1
    }
  }
  return false
}

/**
 * 非授权源码产物的 finding 后处理（0.3.13）：命中落在构建输出/压缩产物/类型声明里时，
 * 加类别前缀；官方目录成员包（request.officialFamily）额外把 critical/high 折为 info
 * （message 带「（官方包降噪）」），第三方包只标注、severity/verdict 全量保留。
 * 只处理 decisive 档（critical/high/medium）——info 观测不加前缀，避免噪音。
 *
 * 归因键：规则落 finding.file 时可能给**完整路径**也可能给 **basename**（AST 路径统一补
 * basename）。完整路径键总是精确；basename 键仅在本次扫描里该 basename **唯一**时才启用
 * ——否则同包 `index.js`（授权源码）与 `lib/index.js`（构建产物）会互相串味，把授权源码
 * 的命中误折（实测自审发现的窄口径误判窗口）。
 * 原地修改 findings，必须在 computeScore/computeVerdict 之前调用。
 */
function applyArtifactGrading(findings: Finding[], artifacts: ArtifactScan, officialFamily: boolean): void {
  if (artifacts.files.length === 0) return
  const keys = new Map<string, string>()
  for (const { path, base, kind } of artifacts.files) {
    keys.set(path, kind)
    // basename 键：仅当该 basename 在本次扫描里**类别唯一**（同 basename 的文件全是产物且同类，
    // 或只有它一个）时启用——只要掺进一个授权源码文件（'' 档），归因就有歧义，退回路径键。
    if (artifacts.basenameKinds.get(base)?.size === 1) keys.set(base, kind)
  }
  for (const f of findings) {
    if (f.file === undefined) continue
    const kind = keys.get(f.file)
    if (kind === undefined) continue
    if (f.severity === 'info') continue
    if (officialFamily && (f.severity === 'critical' || f.severity === 'high')) {
      f.severity = 'info'
      f.message = kind + '（官方包降噪）：' + f.message
    } else {
      f.message = kind + '：' + f.message
    }
  }
}

/** 产物扫描台账：每个已判类文件的（路径、basename、类别）+ basename → 类别集合（歧义闸门；'' = 授权源码）。 */
interface ArtifactScan {
  files: { path: string; base: string; kind: string }[]
  basenameKinds: Map<string, Set<string>>
}

/** Assemble the final report (score + verdict) for a request. */
function buildReport(
  request: ScanRequest,
  findings: Finding[],
  sourceCount: number,
  capabilities?: CapabilityManifest,
): ScanReport {
  const report: ScanReport = {
    engine: ENGINE_VERSION,
    sourceCount,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
  // N1：能力清单仅 files 模式产出（code 模式无插件身份）
  if (capabilities !== undefined) report.capabilities = capabilities
  return report
}

/** Scan one in-memory code string. */
function scanCode(request: ScanRequest): ScanResponse {
  if (request.code === undefined || request.language === undefined) {
    return { ok: false, error: 'code 模式需要 language 与 code' }
  }
  const sf = parseSource(request.code, `input.${request.language}`, request.language)
  // N2：解码预处理（code 模式同样受益：scan_plugin dynamic-code 对混淆片段输出解码命中）
  const decodedLiterals = collectDecodedLiterals(sf, `input.${request.language}`)
  const findings = executeRules(sf, { request, runtime: request.runtime ?? 'host', decodedLiterals })
  return { ok: true, report: buildReport(request, findings, 1) }
}

/** Scan a file list with a total budget and content-hash cache (files mode). */
function scanFiles(request: ScanRequest): ScanResponse {
  if (request.files === undefined || request.files.length === 0) {
    return { ok: false, error: 'files 模式需要非空 files 列表' }
  }
  const runtime = request.runtime ?? 'host'
  // round-7：package.json 内容参与缓存 hash（bin 形态变化 → 缓存自然失效），无需额外 context
  const pkgJson = request.files.find(f => basename(f) === 'package.json')
  const shape = pkgJson === undefined ? undefined : packageShape(readCapped(pkgJson))
  // P0-2 #9（R16）：依赖健康上下文（幽灵/僵尸对账 + 缓存指纹）
  const depsInfo = buildDepsInfo(request.files)
  // R8-skip 先于缓存散列：超过 PRE_FILE_SIZE_LIMIT 的文件不会进入扫描循环（stat 先行跳过），
  // 缓存 key 不再整读它们——旧实现 key 阶段对全部文件 readOrDefault，大文件被全量读入 → 内存峰值。
  // 超限文件用 stat 尺寸做 key 占位（超大文件内容从不参与判定，尺寸即"未扫描"的充分表示）。
  const key = cacheKey(
    request.files.map(file => {
      try {
        const st = statSync(file)
        // round-16 review（D3）：非常规文件（fifo/设备）在 cacheKey 阶段就跳读——
        // 否则 readOrDefault 在缓存散列前就会 readFileSync 挂死/吸入无限流（size 恒 0
        // 骗过大小预检；此阶段发生在 sizeWithinBudget 护栏之前）。
        if (!st.isFile() || st.size > PRE_FILE_SIZE_LIMIT) return { path: file, content: 'vet-skipped:size=' + (st.isFile() ? st.size : 0) }
      } catch {
        // stat 失败 → 走 readOrDefault 的空串兜底
      }
      return { path: file, content: readOrDefault(file) }
    }),
    request.rules,
    {
      targetKind: request.targetKind,
      runtime,
      scanBasis: request.scanBasis,
      // P0-2 #9（R16）：声明/node_modules 变化 → key 变化 → 缓存失效重扫；规则关掉则不参与 key
      deps: request.rules?.['R16'] === false ? undefined : depsInfo?.fingerprint,
      // round-12（R17/R18）：surface 改变输出形状 → 入 key，开关切换不命中旧形状缓存
      surface: request.surface,
      // 0.3.13：officialFamily 改变 severity（产物降噪）→ 入 key，否则官方扫描的降噪报告
      // 会被同字节的第三方扫描命中（反向亦然）
      officialFamily: request.officialFamily,
    },
  )
  // C3（0.1.16 加固）：目录与 nonce 均来自宿主注入（cacheDirFor 缺省回退 env/tmpdir）
  const cacheDir = cacheDirFor(request.cacheDir)
  const cached = readCached(key, cacheDir, request.cacheNonce ?? '')
  if (cached !== undefined) return { ok: true, report: cached }

  const findings: Finding[] = []
  const manifests: CapabilityManifest[] = []
  /** C4（0.3.8）：命中的原生二进制文件（basename，去重）。 */
  const nativeBinaries: string[] = []
  /** 0.3.13：非授权源码产物台账（路径键精确；basename 键仅在无同名歧义时启用）。 */
  const artifacts: ArtifactScan = { files: [], basenameKinds: new Map() }
  let sourceCount = 0
  /** 0.3.9（审查修复）：本轮是否因预算耗尽提前 break——决定能不能写缓存（见下方 writeCached）。 */
  let budgetExceeded = false
  const deadline = Date.now() + budgetMs(request.files.length, request.timeoutMs)
  for (let i = 0; i < request.files.length; i++) {
    const file = request.files[i]
    if (i > 0 && Date.now() > deadline) {
      findings.push(skipFinding(file))
      budgetExceeded = true
      break
    }
    // R10/R12: package.json manifests are JSON, not source; scan them directly.
    if (basename(file) === 'package.json') {
      // round-15 review：package.json 同样可能被恶意构造为超大文件（多 GB 假清单）——
      // 与 AST/R17/R18 同款 8MB 预检，避免 R10/R12/R19 分支全量读入打爆扫描子进程
      if (!sizeWithinBudget(file)) {
        findings.push(skipFinding(file))
        continue
      }
      const json = readOrDefault(file)
      if (json === '') continue
      if (request.rules?.['R10'] !== false) {
        // 0.3.13：官方目录成员按 generic 语义做清单观测——R10 的 install 钩子对官方包是
        // native 编译等合法安装步骤（规则自带 generic 文案 + info 档），而 auto-scan 不传
        // targetKind（缺省严格）→ 官方包此前常驻 suspicious。只影响清单观测，不动 R12/R19。
        const manifestKind = request.officialFamily === true ? 'generic' : request.targetKind
        findings.push(...runPackageJson(json, 'package.json', manifestKind))
      }
      // R12: Cordis/DSH bundle 契约（P-2 计划项）——入口/patch 声明等确定性检查
      if (request.rules?.['R12'] !== false) {
        findings.push(...runContract(json, file, request.targetKind, request.scanBasis))
      }
      // R19: typosquat 观测（round-13）——包名/依赖 vs 官方核心名编辑距离 ≤1/同形
      if (request.rules?.['R19'] !== false) {
        findings.push(...runTyposquat(json, 'package.json'))
      }
      continue
    }
    const ext = extOf(file)
    // C4（0.3.8）：原生二进制取证——扩展名命中（.node/.so/.dll/.dylib/.exe/.wasm/.ocx/.sys）
    // 或魔数命中（编译产物伪装成 .js/.yml 等入面名的形态）。只记名不读取解析（二进制内容进
    // AST/语料无意义且有 OOM 面），不入 sourceCount、不产 finding（纯能力面，见 protocol 注记）。
    if ((ext !== undefined && NATIVE_BINARY_EXT.has(ext)) || sniffNativeBinary(file)) {
      const nb = basename(file)
      if (!nativeBinaries.includes(nb)) nativeBinaries.push(nb)
      continue
    }
    // R14: non-JS script files (shell/PowerShell/batch) get a deterministic
    // text scan for download-and-exec primitives — the AST rules do not see them.
    // （round-16：extOf 已统一小写，Setup.SH/evil.CMD 同样命中）
    if (ext !== undefined && NON_JS_SCRIPT_EXT.has(ext)) {
      if (request.rules?.['R14'] !== false) {
        // round-15 review：R14 分支此前无 8MB 预检（AST/R17/R18 都有）——多 GB 的
        // .sh/.ps1 恶意脚本会被整读进内存，正是 PRE_FILE_SIZE_LIMIT 要防的 OOM。
        if (!sizeWithinBudget(file)) {
          findings.push(skipFinding(file))
        } else {
          const script = readOrDefault(file)
          if (script !== '') {
            findings.push(...runNonJsScript(script, basename(file), request.targetKind))
          }
        }
      }
      continue
    }
    // R17: 根级配置面（round-12）——cordis.yml/cordis.patch.yml 等的 !!js 表达式文本检测。
    // 只提取不执行（红线 N1）；surface.configFiles 关闭或 rules.R17=false 时不参与。
    if (ext !== undefined && CONFIG_EXT.has(ext) && isRootConfigName(basename(file)) && request.surface?.configFiles !== false) {
      if (request.rules?.['R17'] !== false) {
        // N2 纪律：大文件不整读（与 AST 路径同款预检；超限 R8-skip）
        if (!sizeWithinBudget(file)) {
          findings.push(skipFinding(file))
        } else {
          const configText = readOrDefault(file)
          if (configText !== '') {
            findings.push(...runConfigScan(configText, basename(file), file, request.targetKind))
          }
        }
      }
      continue
    }
    // R18: 指令/技能文件面（round-12）——AGENTS.md/skills/**/SKILL.md 的组合式注入观测。
    if (ext === 'md' && isInstructionFile(file) && request.surface?.instructionFiles !== false) {
      if (request.rules?.['R18'] !== false) {
        if (!sizeWithinBudget(file)) {
          findings.push(skipFinding(file))
        } else {
          const mdText = readOrDefault(file)
          if (mdText !== '') {
            findings.push(...runInstructionScan(mdText, basename(file), file))
          }
        }
      }
      continue
    }
    if (ext === undefined || !SCANNABLE_EXT.has(ext)) {
      // round-16：无扩展名文件——npm 标准形态（bin 入口、postinstall 脚本）此前整段隐形
      // （连 R8 提示都没有）。按 JS 解析需形态证据：package.json bin/scripts 引用或 node
      // shebang；其余无扩展名文件（二进制、无特征文本）照旧跳过（不误解析）。
      if (ext !== undefined || !isExtensionlessJs(file, shape?.cliFiles)) continue
    }
    // 大文件预检（技术债偿还）：readFileSync 前先 stat，超限即 R8-skip（不整读、不 OOM）
    // round-16 review（D3）：非常规文件同判跳过（见 sizeWithinBudget 注释——/dev/zero 等
    // 无限流/fifo 不能进 readOrDefault）
    try {
      const st = statSync(file)
      if (!st.isFile() || st.size > PRE_FILE_SIZE_LIMIT) {
        findings.push(skipFinding(file))
        continue
      }
    } catch {
      // stat 失败（文件消失/不可读）：走 readOrDefault 的空串兜底
    }
    // 0.3.9（审查修复）：单文件处理全程容错——解析/解码/规则/能力提取任一抛错（环状初始化器
    // 的 RangeError、超深嵌套把 TS parser 栈打爆等）此前一路冒到 scan() 顶层 → 整包 ok:false，
    // 同包其它文件的 critical 命中一并丢失（deny 模式 fail-closed 误拦 / report 模式 scan-fail）。
    // 与 R8-skip 同族：当前文件记一条 info 元 finding，继续扫下一个。
    try {
      const code = readOrDefault(file)
      if (code === '') continue
      // 0.3.13：产物分类（构建输出路径/压缩内容/类型声明）——供报告前统一加标注与官方降噪
      const artifact = artifactKind(file, code, pkgJson === undefined ? undefined : dirname(pkgJson))
      const base = basename(file)
      const kinds = artifacts.basenameKinds.get(base) ?? new Set<string>()
      kinds.add(artifact ?? '')
      artifacts.basenameKinds.set(base, kinds)
      if (artifact !== undefined) artifacts.files.push({ path: file, base, kind: artifact })
      const language = ext === 'ts' ? 'ts' : 'js'
      const sf = parseSource(code, basename(file), language)
      // N2：解码预处理（每文件独立采集，结果并入 R13/R7/R11 语料）
      const decodedLiterals = collectDecodedLiterals(sf, basename(file))
      const fileFindings = executeRules(sf, {
        request,
        runtime,
        cliFiles: shape?.cliFiles,
        appShape: shape?.appShape,
        filePath: file,
        pkgRoot: pkgJson === undefined ? undefined : dirname(pkgJson),
        decodedLiterals,
      })
      for (const f of fileFindings) {
        if (f.file === undefined) f.file = basename(file)
        findings.push(f)
      }
      // N1：每文件能力提取 → 聚合（files 模式才有插件身份；code 模式不产出）
      manifests.push(extractCapabilities(sf))
      sourceCount++
    } catch {
      findings.push(ruleErrorFinding(file))
    }
  }
  // C4（0.3.8）：原生二进制证据以合成 manifest 并入同一聚合路（唯一出口，不另开形状分支）。
  if (nativeBinaries.length > 0) {
    manifests.push({
      hosts: [], fsPaths: [], spawnCmds: [], imports: [],
      hasNetwork: false, hasExec: false, hasNativeBinary: true, nativeBinaries,
    })
  }
  const capabilities = aggregateCapabilities(manifests)
  // P0-2 #9（R16）：幽灵/僵尸依赖三方对账——写入能力清单 + info 观测（files 模式 + 有 package.json 才生效；
  // info/heuristic 不计分不改 verdict，纯数据面与提示面）
  if (depsInfo !== null && request.rules?.['R16'] !== false) {
    const declaredSet = depsInfo.declared
    const ghost = capabilities.imports
      // 内建排除按首段：import { x } from 'fs/promises' → 首段 'fs' 在内建集合内
      // round-17（子路径前缀解析）：react/jsx-runtime 这类子路径导入，父包 react 已声明即视为已声明
      // （此前只做精确匹配 → 对所有 React 客户端插件误报幽灵依赖）；父包未声明的子路径
      // （ghost-pkg/sub）照旧判幽灵。规则行为变化 ⇒ ENGINE_VERSION 递增使旧缓存失效。
      .filter(i => !i.startsWith('@deepseek-ai/') && !NODE_BUILTINS.has(i.split('/')[0])
        && !declaredSet.some(d => i === d || i.startsWith(d + '/')))
      .slice(0, R16_DEP_CAP)
    const installed = depsInfo.installed
    const zombie = installed === null
      ? []
      : declaredSet.filter(d => !installed.includes(d)).slice(0, R16_DEP_CAP)
    if (ghost.length > 0) capabilities.ghostDeps = ghost
    if (zombie.length > 0) capabilities.zombieDeps = zombie
    findings.push(...depsFindings(ghost, zombie))
  }
  // 0.3.13：产物标注 + 官方包降噪——必须在 buildReport（评分/verdict）之前生效
  applyArtifactGrading(findings, artifacts, request.officialFamily === true)
  const report = buildReport(request, findings, sourceCount, capabilities)
  // 0.3.9（审查修复）：预算耗尽的部分结果**不写缓存**——此前无条件 writeCached，首轮在
  // deadline 下跳过的尾部文件（payload 常被故意放到枚举末尾）会把假 clean 永久固化：
  // 缓存键不含预算/超时维度，之后预算充裕的重扫也命中该条目（实测：首轮 clean+R8，
  // 无限预算复扫 14ms 返回同一份 clean，新缓存目录才现形 suspicious）——静默漏判通道。
  if (!budgetExceeded) writeCached(key, report, cacheDir, request.cacheNonce ?? '')
  return { ok: true, report }
}

/**
 * Run one scan request (pure logic; the stdio wrapper lives in index.ts).
 * kind='code': scan one source string. kind='files': scan a path list with
 * per-file 2s budget and total budget files×2s (R8-scan-skipped on timeout),
 * cached by content hash.
 */
export function scan(request: ScanRequest): ScanResponse {
  try {
    return request.kind === 'code' ? scanCode(request) : scanFiles(request)
  } catch (error) {
    return { ok: false, error: String(error) }
  }
}

export interface OsvCheckOptions {
  /** 跨源去重（OSV ↔ upstream-radar 共享）：同漏洞 id 只报一次（曾各自 seenVuln → 重复 finding）。 */
  seenVuln?: Set<string>
  /** upstream-radar 实现注入（测试用）：默认走本地 execFile CLI；返回 null 视为未安装/失败降级。 */
  radarImpl?: (packageRoot: string, timeoutMs: number) => Promise<UpstreamRadarResult | null>
  osvTimeoutMs?: number
  /** P2-10：OSV 总预算（宿主超时余量）。提供时逐查询超时按剩余预算动态收窄且 OSV 总耗时不超过预算，
   * 避免超出宿主 kill 超时 → 子进程被 SIGKILL → 扫描失败（deny 模式 fail-closed 误拦合法包）。
   * 直调引擎（无 timeoutMs）时不提供，沿用旧的每查询固定超时、无总预算行为。 */
  osvBudgetMs?: number
  fetchImpl?: typeof fetch
}

/**
 * 取 package.json 的直接依赖（dependencies + peerDependencies），用于 OSV 依赖核对。
 * P3-10：跳过 @deepseek-ai/*（官方包与 vet 同一信任边界，查询是噪声）；上限 8 个（有界网络面）。
 */
const OSV_MAX_DIRECT_DEPS = 8

/**
 * P3-1/P3-3：OSV 只做精确版本查询。*、>=1.0.0、^1 等 range 原样传给 OSV 会被当精确版本
 * 匹配——误返回或报错被吞。非精确（含 undefined）一律跳过该目标查询；主包无 version
 * 也不查全量历史（陈旧漏洞全是误报）。判定：以数字开头、含至少一个点、无 range 符号。
 */
function isExactVersion(v: unknown): v is string {
  if (typeof v !== 'string' || v.length === 0) return false
  const first = v.charCodeAt(0)
  if (first < 48 || first > 57) return false
  const dot = v.indexOf('.')
  if (dot <= 0 || dot === v.length - 1) return false
  for (let i = 0; i < v.length; i++) {
    const code = v.charCodeAt(i)
    const ok = (code >= 48 && code <= 57) || (code >= 97 && code <= 122) || (code >= 65 && code <= 90)
      || v[i] === '-' || v[i] === '+' || v[i] === '_' || v[i] === '.'
    if (!ok) return false
  }
  return true
}

function directDepsOf(pkg: Record<string, unknown>): { name: string; version?: string }[] {
  const out: { name: string; version?: string }[] = []
  const seen = new Set<string>()
  for (const key of ['dependencies', 'peerDependencies'] as const) {
    const deps = pkg[key]
    if (typeof deps !== 'object' || deps === null) continue
    for (const [name, ver] of Object.entries(deps as Record<string, unknown>)) {
      if (name.startsWith('@deepseek-ai/')) continue
      if (seen.has(name)) continue
      seen.add(name)
      // round-7（P2）：range（^/~/*/>= 等）原样保留，不再剥前缀——isExactVersion 只放行
      // 精确版本，range 一律跳过查询（README 宣称行为）。此前 ^2.4.2 被剥成下界 "2.4.2"
      // 发给 OSV：下界在受影响区间而上界已修复（实际装到 2.8.x）时会误报已知漏洞。
      out.push({ name, version: typeof ver === 'string' ? ver : undefined })
    }
    if (out.length >= OSV_MAX_DIRECT_DEPS) break
  }
  return out.slice(0, OSV_MAX_DIRECT_DEPS)
}

/**
 * OSV 已知漏洞核对（R10 补漏）：仅 files 模式 + package.json 有 name 时执行。
 * P3-10：核对面从插件自身扩展到直接依赖（上限 8 个）——插件生态的主要风险在依赖树；
 * 每项独立查询、独立超时，网络失败只跳过该项（静默降级，不影响静态判定）。
 * 间接传递树超出 OSV v1 范围与扫描预算，README 已记录边界。
 */
async function checkOsv(request: ScanRequest, opts: OsvCheckOptions = {}): Promise<Finding[]> {
  if (request.osv !== true) return []
  const pkgFile = request.files?.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return []
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(readCapped(pkgFile)) as Record<string, unknown>
  } catch {
    return []
  }
  if (typeof pkg.name !== 'string' || pkg.name === '') return []
  const targets: { name: string; version?: string }[] = [
    { name: pkg.name, version: typeof pkg.version === 'string' ? pkg.version : undefined },
    ...directDepsOf(pkg),
  ].filter(t => isExactVersion(t.version)) // filter: only exact versions take part in OSV checks
  const vulns: OsvVuln[] = []
  // 透传的外部集合（checkSupplyChain 跨源共享）或孤立集合——dedup 按 id 生效
  const seenVuln = opts.seenVuln ?? new Set<string>()
  // P2-10：OSV 总预算（宿主超时余量）——逐查询超时按「剩余预算 / 剩余目标数」动态收窄（下限
  // 500ms、上限 4000ms），并保证 OSV 总耗时不超过预算，提前 break 避免超出宿主 kill 超时
  // 导致子进程被 SIGKILL → 扫描失败（deny 模式 fail-closed 误拦合法包 / report 误报 scan-fail）。
  const budgetEnd = opts.osvBudgetMs !== undefined ? Date.now() + opts.osvBudgetMs : undefined
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i]
    if (budgetEnd !== undefined && Date.now() >= budgetEnd) break
    const remaining = budgetEnd !== undefined ? budgetEnd - Date.now() : undefined
    const perQuery = remaining !== undefined
      ? Math.max(500, Math.min(4000, Math.floor(remaining / (targets.length - i))))
      : (opts.osvTimeoutMs ?? 4000)
    let found: OsvVuln[]
    try {
      // F15：带 version 查询——OSV 服务端按 affected ranges 过滤，已修复版本不再误报
      // 0.3.14：外层竞速硬超时兜底（abort 不生效时也不会挂死，见 withHardTimeout）
      const raced = await withHardTimeout(queryOsv(target.name, {
        timeoutMs: perQuery,
        fetchImpl: opts.fetchImpl,
        version: target.version,
      }), perQuery + OSV_RACE_SLACK_MS)
      if (raced === null) continue // 硬超时：按网络失败静默降级
      found = raced
    } catch {
      continue // 网络失败/超时：静默降级，不影响静态判定
    }
    for (const v of found) {
      if (seenVuln.has(v.id)) continue
      seenVuln.add(v.id)
      vulns.push(v)
    }
    if (vulns.length >= 10) break
  }
  return vulns.slice(0, 10).map(v => ({
    rule: 'OSV',
    severity: 'high',
    confidence: 'certain', // 漏洞库命中是事实（非启发式），verdict 可据此抬升
    message: '已知漏洞 ' + v.id + (v.aliases.length > 0 ? '（' + v.aliases[0] + '）' : '') + '：' + (v.summary ?? 'npm 生态已知漏洞').slice(0, 110),
    evidence: '',
    file: 'package.json',
  }))
}

/**
 * scan + OSV 核对（异步，含网络调用）：静态判定（含缓存）与 OSV 结果分离——
 * 缓存只存静态报告，OSV 每次扫描实时查询（保持数据新鲜）。OSV 命中追加 high
 * findings 并重算 score/verdict；网络失败静默降级为纯静态结果。
 */
export async function scanWithOsv(request: ScanRequest, opts: OsvCheckOptions = {}): Promise<ScanResponse> {
  const start = Date.now()
  const base = scan(request)
  if (!base.ok || base.report === undefined) return base
  // P2-10：从宿主超时推导 OSV 总预算，确保 OSV 网络相位不超出宿主 kill 超时（见 checkOsv）。
  // 预算 = 宿主超时 - 静态扫描耗时 - 引擎余量 - 输出余量；缺省（直调引擎、无 timeoutMs）不改行为。
  // 0.3.14：余量低于 OSV_MIN_BUDGET_MS → 整段跳过（旧行为用地板 1000ms 硬撑，最坏只剩 0.5s 余量）。
  let osvBudgetMs = opts.osvBudgetMs
  if (osvBudgetMs === undefined && typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)) {
    const remaining = request.timeoutMs - (Date.now() - start) - ENGINE_KILL_MARGIN_MS - 500
    if (remaining < OSV_MIN_BUDGET_MS) return base
    osvBudgetMs = remaining
  }
  // 0.3.14：相位级竞速兜底——逐查询护栏之外再保一层，供应链相位整体（含 upstream-radar 与
  // 多次查询的累计误差）不得越过预算；超时即返回纯静态报告（OSV 是增强项，静默降级）。
  const supplyChainFindings = osvBudgetMs === undefined
    ? await checkSupplyChain(request, { ...opts, osvBudgetMs })
    : (await withHardTimeout(checkSupplyChain(request, { ...opts, osvBudgetMs }), osvBudgetMs + OSV_RACE_SLACK_MS)) ?? []
  if (supplyChainFindings.length === 0) return base
  const findings = [...base.report.findings, ...supplyChainFindings]
  const report: ScanReport = {
    ...base.report,
    findings,
    staticScore: computeScore(findings),
    verdict: computeVerdict(findings),
  }
  return { ok: true, report }
}

// ── 传递依赖扫描（P1 特性）─────────────────────────────────────

import { execFile } from 'node:child_process'

export interface UpstreamRadarResult {
  vulnerabilities: { id: string; package: string; severity: string; source: string }[]
}

// 创建 require 函数（ESM 模块中需要 createRequire）
const require = createRequire(import.meta.url)

// v5 修订（专家1 #5）：不使用 npx 自动安装，先探测本地安装路径。
// 导出仅供测试（三轮审查 R18 加固回归）：生产路径经 checkSupplyChain 调用。
export async function queryUpstreamRadar(
  packageRoot: string,
  timeoutMs: number = 15_000
): Promise<UpstreamRadarResult | null> {
  // 三轮审查加固：只在 vet 自身模块树内解析（不带 paths 参数，起点=本编译文件所在目录向上）。
  // 此前 { paths: [packageRoot] } 会优先命中被扫描包自带/伪造的 node_modules/upstream-radar——
  // 恶意包塞同名假包即可让 execFile 在 scanner 子进程里执行不可信代码，破坏“静态分析、
  // 不执行被扫代码”的核心隔离承诺。未安装 → 静默降级（与原行为一致）。
  let radarPath: string | null = null
  try {
    radarPath = require.resolve('upstream-radar/bin/upstream-radar.js')
  } catch {
    return null
  }
  // 纵深防御：解析结果即使落在被扫包目录内也拒绝执行
  if (radarPath.startsWith(packageRoot + sep)) return null
  
  return new Promise((resolve) => {
    execFile(radarPath!, ['scan', packageRoot, '--json'], {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,  // v5 修订（专家2 #10）：增加到 10MB
    }, (err, stdout) => {
      if (err !== null || stdout === '') {
        resolve(null)  // 超时/失败：静默降级
        return
      }
      try {
        resolve(JSON.parse(stdout) as UpstreamRadarResult)
      } catch {
        resolve(null)
      }
    })
  })
}

let upstreamRadarWarned = false

/** 单测辅助：重置模块级 warn 标志（进程内测试隔离；生产每次扫描为独立子进程，天然每次只警告一次）。 */
export function resetUpstreamRadarWarned(): void {
  upstreamRadarWarned = false
}

/**
 * 供应链检查：直接依赖 OSV + 传递依赖 upstream-radar。
 */
async function checkSupplyChain(
  request: ScanRequest,
  opts: OsvCheckOptions & { transitiveDeps?: boolean }
): Promise<Finding[]> {
  // 1. 现有逻辑：插件自身 + 直接依赖 OSV 查询（osvBudgetMs 随 opts 透传，约束 OSV 总预算）
  //    跨源去重：与 upstream-radar 共享同一 seenVuln，同 id CVE 不重复报告（#8 修复）
  const crossSourceSeen = new Set<string>()
  const directFindings = await checkOsv(request, { ...opts, seenVuln: crossSourceSeen })

  // 2. 新增：传递依赖扫描（调用 upstream-radar CLI）
  if (request.transitiveDeps !== true) return directFindings
  const pkgFile = request.files?.find(f => basename(f) === 'package.json')
  if (pkgFile === undefined) return directFindings
  const pkgRoot = dirname(pkgFile)

  // P2-10：传递依赖 CLI 超时同样受 OSV 总预算约束（缺省 15s），避免拖垮宿主 kill 超时
  const radarTimeout = opts.osvBudgetMs !== undefined
    ? Math.min(opts.osvBudgetMs, opts.osvTimeoutMs ?? 15_000)
    : (opts.osvTimeoutMs ?? 15_000)
  const radarResult = opts.radarImpl !== undefined
    ? await opts.radarImpl(pkgRoot, radarTimeout)
    : await queryUpstreamRadar(pkgRoot, radarTimeout)
  if (radarResult === null) {
    // v5 修订（专家2 #9）：首次调用时给出友好提示
    if (!upstreamRadarWarned) {
      console.warn('[vet] transitiveDeps enabled but upstream-radar not installed or failed, skipping transitive dependency scan')
      upstreamRadarWarned = true
    }
    return directFindings  // 未安装/超时：静默降级
  }

  // 形状校验：确保 vulnerabilities 字段存在且为数组
  if (!Array.isArray(radarResult.vulnerabilities)) {
    return directFindings  // 输出格式不符合预期，静默降级
  }

  const transitiveFindings: Finding[] = []

  // 与 OSV 共享去重集合：同一漏洞在 OSV 与 upstream-radar 间只报一条（曾各用各的
  // seenVuln → 同一 CVE 出 rule=OSV 与 rule=OSV-T 两条 finding）。
  for (const vuln of radarResult.vulnerabilities.slice(0, 20)) {
    if (crossSourceSeen.has(vuln.id)) continue
    crossSourceSeen.add(vuln.id)
    transitiveFindings.push({
      rule: 'OSV-T',  // 新规则名：传递依赖已知漏洞
      severity: 'medium',  // v5 修订（专家1 #7 + 专家2 #11）：传递依赖利用面小于直接依赖，权重降为 medium
      confidence: 'certain',
      message: `传递依赖已知漏洞 ${vuln.id}（${vuln.package}，来源 ${vuln.source}）`,
      evidence: '',
      file: 'package.json',
    })
  }

  return [...directFindings, ...transitiveFindings]
}