import { existsSync, readFileSync, realpathSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { scan } from '../scanner/client.js'
import { listSourceFiles } from '../scanner/package-sources.js'
import type { ScanRequest } from '../scanner/protocol.js'
import type { PluginScorecard } from '../report/types.js'
import { renderScorecard } from '../report/render.js'
import { PACKAGE_NAME } from '../invariant.js'
import { withVetSelfIo } from '../guard/runtime-hooks.js'

export interface ScanPluginArgs {
  target: 'dynamic-code' | 'package' | 'file'
  source?: string
  packagePath?: string
  reason?: string
}

/** vet 自身包根（lib/tools/scan-plugin.js 上溯两级；realpath 防符号链接绕过）。 */
const SELF_ROOT = (() => {
  try {
    return realpathSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..'))
  } catch {
    return ''
  }
})()

/** 扫描目标是否是当前运行的 vet 实例本身（realpath 比对，round-7.1 P-3）。 */
function isSelfPackage(packagePath: string): boolean {
  if (SELF_ROOT === '') return false
  try {
    return realpathSync(packagePath) === SELF_ROOT
  } catch {
    return false
  }
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
    // 官方包：宿主合法代码（与 internal/plugin 守卫 isExempt 的 @deepseek-ai/* 豁免一致），process 为能力触达面
    if (typeof pkg.name === 'string' && pkg.name.startsWith('@deepseek-ai/')) return 'generic'
    const deps: Record<string, unknown> = {
      ...(pkg.dependencies as Record<string, unknown> | undefined),
      ...(pkg.peerDependencies as Record<string, unknown> | undefined),
    }
    const hasDshDep = Object.keys(deps).some(k => k.startsWith('@deepseek-ai/'))
    const hasBundleDecl = pkg.dsh !== undefined || pkg.cordis !== undefined
    return hasDshDep || hasBundleDecl ? 'plugin' : 'generic'
  })
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
    const files = withVetSelfIo(() => listSourceFiles(packagePath))
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
export function createScanPluginTool(config: { osvCheck?: boolean; scannerTimeoutMs?: number } = {}): ReturnType<typeof defineTool> {
  return defineTool({
    name: 'scan_plugin',
    description: 'Static-scan plugin code or an installed package for escape patterns (constructor-chain, direct process access), dynamic execution, hardcoded secrets, and Cordis/DSH bundle contract. Deterministic rule engine in an isolated process; returns a scorecard with verdict (critical/suspicious/clean) and staticScore. 静态层为确定性判定，LLM 不参与。',
    parameters: {
      target: {
        // 实现决策：dsh-tools 类型不支持 enum（ValueSchemaSpec 无 enum 字段），选项写入 description
        type: 'string', required: true,
        description: '扫描目标类型：dynamic-code（源码字符串）| package（插件包目录）| file（单文件路径）',
      },
      source: { type: 'string', description: 'dynamic-code 的源码字符串 / file 的文件路径' },
      packagePath: { type: 'string', description: 'package 的插件包目录（绝对路径）' },
      reason: { type: 'string', description: '扫描原因（审计留痕）' },
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
            },
          },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderScorecard(value as unknown as PluginScorecard) }],
    },
    async execute(args) {
      const { request, pluginName, pluginVersion } = buildRequest(args as unknown as ScanPluginArgs)
      request.osv = config.osvCheck === true
      // P2-1 系列：工具超时与 internal/plugin 同公式（按文件数放大、60s 封顶），配合 engine
      // 预算对齐（budget=min(files×2s, timeout-1.5s)），大包走 R8-skip 而不是被 kill 报错
      const fileCount = request.files?.length ?? 0
      const timeoutMs = Math.min(Math.max(config.scannerTimeoutMs ?? 15_000, fileCount * 2000), 60_000)
      const response = await scan(request, { timeoutMs })
      if (!response.ok || response.report === undefined) {
        throw new Error('vet: 扫描失败 ' + (response.error ?? 'unknown'))
      }
      return {
        pluginName,
        ...(pluginVersion !== undefined ? { pluginVersion } : {}),
        scannedAt: new Date().toISOString(),
        static: {
          verdict: response.report.verdict,
          staticScore: response.report.staticScore,
          // 输出 schema 推断的 findings 项为开放对象，静态 Finding[] 断言为 JSON 值形状
          findings: response.report.findings as unknown as Record<string, JsonValue>[],
        },
      }
    },
    presentCall: (args) => ({ card: 'generic', title: 'Scan plugin: ' + args.target, kind: 'read', rawInput: args.target }),
  })
}
