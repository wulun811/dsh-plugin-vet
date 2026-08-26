import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { basename, dirname, isAbsolute, join } from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { scan, scanBudget } from '../scanner/client.js'
import { listSourceFiles, listInstructionFiles } from '../scanner/package-sources.js'
import type { ScanRequest } from '../scanner/protocol.js'
import type { PluginScorecard } from '../report/types.js'
import { renderScorecard } from '../report/render.js'
import { PACKAGE_NAME } from '../package-meta.js'
import { isVetSelfPath } from '../pkg-root.js'
import { withVetSelfIo } from '../guard/runtime-hooks.js'
import { computePackageHash, checkBaseline, recordBaseline, saveBaseline, getBaseline } from '../guards/content-baseline.js'
import { annotateSelfScan, type SelfScanInfo } from '../report/self-scan.js'
import { hashScanFiles, pinStateFor, loadSelfPins } from '../report/self-pin.js'
import { listShippedFiles } from '../report/self-scope.js'

export interface ScanPluginArgs {
  target: 'dynamic-code' | 'package' | 'file'
  source?: string
  packagePath?: string
  reason?: string
  /** 扫描基础（协议已支持，P0-3 接线到工具面）：'git' = 仅源码仓（通常不提交构建产物，R12 入口/patch 缺失降 info）；'npm' = registry tarball 真实发布物（默认）。 */
  scanBasis?: 'git' | 'npm'
}

/** 扫描目标是否是当前运行的 vet 实例本身（realpath 比对，round-7.1 P-3；
 * round-5 review B-A1：身份校验收编到 pkg-root 共享实现）。 */
function isSelfPackage(packagePath: string): boolean {
  return isVetSelfPath(packagePath)
}

/**
 * 目标身份判定（PLAN §14.3 边界落地）：DSH 插件包（依赖 @deepseek-ai/* 或声明
 * dsh/cordis bundle）→ 'plugin' 严格逃逸判定；否则 'generic'——process 访问降级为
 * 能力触达面（info），避免把普通 npm 工具包/信任锚的合法宿主进程使用误报为逃逸。
 * P2-2：读用户指定路径属 vet 审计操作——withVetSelfIo 直通（.dsh 下不产生无主自报警）。
 * round-7.1（P-3）：vet 自豁免必须 realpath 验证，不只比 name——本地 file: 安装无
 * registry 校验，恶意 tarball 可把 package.json 的 name 写成 @jieai/dsh-plugin-vet
 * 骗过 generic 降级（R3/R4 全降级、deny 放行）；同名冒名包按最严格 plugin 判定。
 */
export function detectTargetKind(packagePath: string): 'plugin' | 'generic' {
  return withVetSelfIo(() => {
    let pkg: Record<string, unknown>
    try {
      pkg = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8')) as Record<string, unknown>
    } catch {
      return 'generic' // 无 package.json：无插件形态证据，保守走通用审计
    }
    if (pkg.name === PACKAGE_NAME) {
      // vet 自身（信任锚工具包，process 为子进程实现）→ generic；同名冒名包 → 最严格 plugin
      return isSelfPackage(packagePath) ? 'generic' : 'plugin'
    }
    // 官方包：P-5 内容哈希校验（v5 修订：信任内容而非名字；预算参数取默认，B-A4）
    if (typeof pkg.name === 'string' && pkg.name.startsWith('@deepseek-ai/')) {
      const hashResult = computePackageHash(packagePath)
      if (hashResult === null) return 'plugin'  // 超限/超时：严格判定
      const hash = hashResult.hash
      const version = typeof pkg.version === 'string' ? pkg.version : 'unknown'
      const store = getBaseline()
      const result = checkBaseline(pkg.name, version, hash, store)
      if (result === 'first-seen') {
        // round-16 review（决策 1）：首见不得降级——自生哈希基线挡得住「改完再装」，
        // 挡不住伪造包名的首见即信（恶意 tarball 首装即记录自身字节为基线）。
        // 首见按最严格 plugin 判定全扫（结果如实呈现给 agent/用户），内容入基线；
        // 后续同内容（match）才降级 generic 轻量判定。
        recordBaseline(pkg.name, version, hash, store)
        if (!saveBaseline(store)) {
          // S10：基线落盘失败要可见（disk full/权限）——扫描照常，但记录失败
          // （基线不落盘 = 每次加载都按首见严格扫，安全方向，只是性能退化）
          console.error(`vet: baseline 保存失败（${pkg.name}@${version}）——后续加载将重复全量扫描`)
        }
        return 'plugin'
      }
      if (result === 'match') return 'generic'  // 内容一致，信任
      // mismatch：同名但内容变了 → 严格判定
      return 'plugin'
    }
    const deps: Record<string, unknown> = {
      ...(pkg.dependencies as Record<string, unknown> | undefined),
      ...(pkg.peerDependencies as Record<string, unknown> | undefined),
    }
    const hasDshDep = Object.keys(deps).some(k => k.startsWith('@deepseek-ai/'))
    const hasBundleDecl = pkg.dsh !== undefined || pkg.cordis !== undefined
    return hasDshDep || hasBundleDecl ? 'plugin' : 'generic'
  })
}

/**
 * round-16 review（决策 3）：file 目标定界——LLM 可控路径不得指向任意设备/管道。
 * 只接受：绝对路径 + 已存在的常规文件；拒绝相对路径/~/展开、目录、非常规文件
 * （fifo/设备/socket——/dev/zero 等无限流会让 readFileSync 无 EOF 直接打爆扫描子进程
 * 内存；fifo 会挂死子进程到超时）、符号链接（与 package-sources 的 walk 纪律一致，
 * 防面越出包根）。vetSelfIo 直通（审计读操作，不自报警）。 */
function validateFileTarget(source: string): void {
  if (!isAbsolute(source)) throw new Error('vet: file target 需要绝对路径（拒绝相对路径 / ~ 展开）')
  let st
  try {
    st = withVetSelfIo(() => lstatSync(source))
  } catch {
    throw new Error('vet: file 不存在或不可访问：' + source)
  }
  if (!st.isFile()) {
    throw new Error('vet: file target 只接受常规文件（拒绝目录/设备/FIFO/符号链接）：' + source)
  }
}

/** 从文件所在目录向上找最近的 package.json 所在目录（上限 4 层；P3-4）。
 * round-4：existsSync 探测也属 vet 审计读操作——不包 vetSelfIo 时，扫描 ~/.dsh 下
 * 非 node_modules 文件会产生无主 fs-probe 自报警（P2-2 修复缺口）。 */
function nearestPackageRoot(file: string): string | undefined {
  return withVetSelfIo(() => {
    let dir = dirname(file)
    for (let i = 0; i < 4; i++) {
      try {
        if (existsSync(join(dir, 'package.json'))) return dir
      } catch {
        return undefined
      }
      const parent = dirname(dir)
      if (parent === dir) return undefined
      dir = parent
    }
    return undefined
  })
}

/** 读包根 package.json 的 version（P-2 计划：scan_plugin 输出带版本，供档案/版本核对）。 */
function readPackageVersion(root: string): string | undefined {
  return withVetSelfIo(() => {
    try {
      const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: unknown }
      return typeof pkg.version === 'string' && pkg.version !== '' ? pkg.version : undefined
    } catch {
      return undefined
    }
  })
}

export function buildRequest(args: ScanPluginArgs): { request: ScanRequest; pluginName: string; pluginVersion?: string } {
  if (args.target === 'dynamic-code') {
    if (typeof args.source !== 'string') throw new Error('vet: dynamic-code 需要 source')
    return {
      pluginName: 'dynamic-code',
      request: { kind: 'code', language: 'js', runtime: 'host', code: args.source },
    }
  }
  if (args.target === 'file') {
    if (typeof args.source !== 'string') throw new Error('vet: file 需要 source')
    // round-16 review（决策 3）：路径定界（绝对路径 + 常规文件），见 validateFileTarget
    validateFileTarget(args.source)
    // P3-4：file 目标也尝试识别插件形态——从文件所在目录向上找最近的 package.json（上限
    // 4 层，覆盖包内嵌套子目录），找到则按包判定（插件文件的逃逸判定不再恒降级 generic）；
    // 找不到则 generic。detectTargetKind 内部已 vetSelfIo 直通。
    let targetKind: 'plugin' | 'generic' = 'generic'
    const pkgRoot = nearestPackageRoot(args.source)
    try {
      if (pkgRoot !== undefined) targetKind = detectTargetKind(pkgRoot)
    } catch {
      targetKind = 'generic'
    }
    return {
      pluginName: basename(args.source),
      pluginVersion: targetKind === 'plugin' && pkgRoot !== undefined ? readPackageVersion(pkgRoot) : undefined,
      request: { kind: 'files', files: [args.source], targetKind },
    }
  }
  if (args.target === 'package') {
    if (typeof args.packagePath !== 'string') throw new Error('vet: package 需要 packagePath')
    const packagePath = args.packagePath // 闭包内 TS 不保留属性 narrowing（同 status-route 修法）
    // P2-2：列目录/读 package.json 属 vet 审计操作——vetSelfIo 直通，.dsh 下不自报警
    // vet 本体自扫：用权威自扫范围（排除 lib/dsh-src/plugin-scan-tmp 等非本体目录，且已含
    // 经 self-scope 过滤的指令/技能文件——R18 面），与钉扎/门禁同集——否则 pin 算不一致、
    // 豁免失效（普通插件仍全量扫安装产物 + 追加指令文件）。
    // round-16 review（决策 2）：vet 本体自扫用发布物范围（self-scope.listShippedFiles）
    // ——与钉扎/门禁同集：生产安装（tarball 只含 lib/）与开发树字节一致时可 pinned-match，
    // Trusted 可达；旧范围（src 源码树）生产永远 dev-tree（升级后自己不认自己）。
    const files = withVetSelfIo(() => isSelfPackage(packagePath)
      ? listShippedFiles(packagePath)
      : [...listSourceFiles(packagePath), ...listInstructionFiles(packagePath)])
    if (files.length === 0) throw new Error('vet: ' + packagePath + ' 下没有可扫描的源码')
    return {
      pluginName: basename(packagePath),
      pluginVersion: readPackageVersion(packagePath),
      request: { kind: 'files', files, targetKind: detectTargetKind(packagePath) },
    }
  }
  throw new Error('vet: 未知 target ' + String(args.target))
}

/** scan_plugin：确定性静态扫描工具（verdict 只来自静态层，LLM 不参与）。 */
export function createScanPluginTool(config: { osvCheck?: boolean; scannerTimeoutMs?: number; transitiveDeps?: boolean } = {}): ReturnType<typeof defineTool> {
  return defineTool({
    name: 'scan_plugin',
    description: 'Static-scan plugin code or an installed package for escape patterns (constructor-chain, direct process access), dynamic execution, hardcoded secrets, and Cordis/DSH bundle contract. Deterministic rule engine in an isolated process; returns a scorecard with verdict (critical/suspicious/clean) and staticScore. 静态层为确定性判定，LLM 不参与。',
    parameters: {
      target: {
        // 实现决策：dsh-tools 类型不支持 enum（ValueSchemaSpec 无 enum 字段），选项写入 description
        type: 'string', required: true,
        description: '扫描目标类型：dynamic-code（源码字符串）| package（插件包目录）| file（单文件路径）',
      },
      source: { type: 'string', description: 'dynamic-code 的源码字符串 / file 的文件路径（绝对路径 + 常规文件；拒绝相对路径/目录/设备/FIFO/符号链接）' },
      packagePath: { type: 'string', description: 'package 的插件包目录（绝对路径）' },
      reason: { type: 'string', description: '扫描原因（审计留痕）' },
      scanBasis: { type: 'string', description: '扫描基础：git（仅源码仓——通常不提交 lib/ 构建产物，R12 入口/patch 缺失降 info 不误报）| npm（registry tarball 真实发布物，默认，R12 按发布物校验）' },
    },
    output: {
      // schema 内联以保留字面量推断（repo 约定，tool-skill 同款）
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          pluginName: { type: 'string', required: true },
          pluginVersion: { type: 'string' },
          scannedAt: { type: 'string', required: true },
          static: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              verdict: { type: 'string', required: true },
              staticScore: { type: 'number', required: true },
              findings: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
              capabilities: {
                type: 'object',
                additionalProperties: false,
                description: '插件静态能力清单（N1 能力差分基础）',
                properties: {
                  hosts: { type: 'array', items: { type: 'string' } },
                  fsPaths: { type: 'array', items: { type: 'string' } },
                  spawnCmds: { type: 'array', items: { type: 'string' } },
                  imports: { type: 'array', items: { type: 'string' } },
                  hasNetwork: { type: 'boolean' },
                  hasExec: { type: 'boolean' },
                  esmNamedBuiltins: { type: 'boolean' },
                  ghostDeps: { type: 'array', items: { type: 'string' } },
                  zombieDeps: { type: 'array', items: { type: 'string' } },
                },
              },
            },
          },
          selfScan: {
            type: 'object',
            additionalProperties: false,
            description: 'vet 本体自扫注解（仅被扫目标 realpath 确认为 vet 自身时输出）',
            properties: {
              isTrustLayer: { type: 'boolean', required: true },
              version: { type: 'string' },
              pin: { type: 'string', required: true },
              declared: { type: 'object', additionalProperties: true },
              annotation: { type: 'object', additionalProperties: true },
              verdict: { type: 'string', required: true },
              staticScore: { type: 'number', required: true },
            },
          },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderScorecard(value as unknown as PluginScorecard) }],
    },
    async execute(args) {
      const { request, pluginName, pluginVersion } = buildRequest(args as unknown as ScanPluginArgs)
      request.osv = config.osvCheck === true
      request.transitiveDeps = config.transitiveDeps === true
      // P0-3：scanBasis 接线（协议已支持——git 源码仓回扫不误报 R12 入口缺失）
      if (args.scanBasis === 'git' || args.scanBasis === 'npm') request.scanBasis = args.scanBasis
      // P2-1 系列：工具超时与 internal/plugin 同公式（scanBudget：按文件数放大、60s 封顶），
      // 配合 engine 预算对齐（budget=min(files×2s, timeout-1.5s)），大包走 R8-skip 而不是被 kill 报错
      const fileCount = request.files?.length ?? 0
      const timeoutMs = scanBudget(fileCount, config.scannerTimeoutMs)
      const response = await scan(request, { timeoutMs })
      if (!response.ok || response.report === undefined) {
        throw new Error('vet: 扫描失败 ' + (response.error ?? 'unknown'))
      }
      // vet 本体自扫（①+②）：realpath 身份判定 → 版本钉扎 → 声明能力注解（有界豁免）。
      // 非本体一律不产 selfScan——普通插件走原静态判定路径，行为零变化。
      let selfScan: SelfScanInfo | undefined
      if (args.target === 'package' && typeof args.packagePath === 'string' && isSelfPackage(args.packagePath) && request.files !== undefined) {
        const pin = pinStateFor(loadSelfPins(), pluginVersion, hashScanFiles(request.files, args.packagePath))
        selfScan = annotateSelfScan(response.report.findings, { pin, ...(pluginVersion !== undefined ? { version: pluginVersion } : {}) })
      }
      return {
        pluginName,
        ...(selfScan !== undefined ? { selfScan } : {}),
        ...(pluginVersion !== undefined ? { pluginVersion } : {}),
        scannedAt: new Date().toISOString(),
        static: {
          verdict: response.report.verdict,
          staticScore: response.report.staticScore,
          // 输出 schema 推断的 findings 项为开放对象，静态 Finding[] 断言为 JSON 值形状
          findings: response.report.findings as unknown as Record<string, JsonValue>[],
          // N1 能力清单：插件静态触达面（hosts/fsPaths/spawnCmds/imports/hasNetwork/hasExec）
          // 供门户/审计工具入库作能力索引；capabilities 缺失时不输出（code 模式无文件上下文）
          ...(response.report.capabilities !== undefined ? { capabilities: response.report.capabilities } : {}),
        },
      }
    },
    presentCall: (args) => ({ card: 'generic', title: 'Scan plugin: ' + args.target, kind: 'read', rawInput: args.target }),
  })
}
