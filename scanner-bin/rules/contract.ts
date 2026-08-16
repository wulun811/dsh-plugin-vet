import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import type { Finding } from '../protocol.js'

/**
 * R12 Cordis/DSH bundle 契约（P-2 计划项，三审后落地）：
 * 对「插件意图」包（依赖 @deepseek-ai/* 或声明 dsh/cordis 字段）做确定性清单检查——
 * 这些是 DSH 加载器会硬校验/真实失败的项，让 scan_plugin 在安装前就能回答
 * 「这插件装上去能不能跑」，而不是等启动时崩溃。
 *
 * 确定性边界（低误报）：只查 manifest 里声明的路径存在性 + 必备字段，不做源码级推断。
 * - dsh.bundle.patch 声明的文件缺失 → high（插件声明自己是 DSH bundle，挂载必失败）
 * - 无任何可用入口（无 main、无 exports[.]、根也无 index.js 兜底）→ medium
 * - 声明的入口文件缺失 → high（加载抛 ERR_MODULE_NOT_FOUND）
 * - 插件意图包缺 name → medium（审计门槛/OSV 按名归档失效）
 * - engines.node 明确低于 DSH 要求（major < 22）→ info
 * 非插件意图包不判（避免误伤通用 npm 工具包）。generic 官方包同样适用本规则。
 */
export function runContract(content: string, file: string, targetKind?: 'plugin' | 'generic'): Finding[] {
  const found: Finding[] = []
  void targetKind
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(content) as Record<string, unknown>
  } catch {
    return found
  }
  const deps: Record<string, unknown> = {
    ...(pkg.dependencies as Record<string, unknown> | undefined),
    ...(pkg.peerDependencies as Record<string, unknown> | undefined),
  }
  const hasDshDep = Object.keys(deps).some(k => k.startsWith('@deepseek-ai/'))
  const dshField = pkg.dsh
  const hasBundleDecl = dshField !== undefined || pkg.cordis !== undefined
  if (!hasDshDep && !hasBundleDecl) return found // 非插件意图：不做契约判定

  const pkgRoot = dirname(file)

  // 1) dsh.bundle.patch 声明 vs 实际文件
  const patch = pickBundlePatch(dshField)
  if (patch !== undefined) {
    if (!existsSync(resolve(pkgRoot, patch))) {
      found.push({
        rule: 'R12',
        severity: 'high',
        confidence: 'certain',
        message: 'DSH bundle 声明的 patch 文件缺失（dsh.bundle.patch=' + patch + '）——插件将无法挂载',
        evidence: patch,
        file,
      })
    }
  }

  // 2) 包入口：main / exports["."] / 根 index.js 兜底
  const entry = pickEntry(pkg)
  if (entry === undefined && !existsSync(join(pkgRoot, 'index.js'))) {
    found.push({
      rule: 'R12',
      severity: 'medium',
      confidence: 'likely',
      message: '无包入口（无 main、无 exports["."]，根目录也无 index.js）——cordis 无法解析插件模块',
      evidence: '',
      file,
    })
  } else if (entry !== undefined && !existsSync(resolve(pkgRoot, entry))) {
    found.push({
      rule: 'R12',
      severity: 'high',
      confidence: 'certain',
      message: '入口文件缺失：' + entry,
      evidence: entry,
      file,
    })
  }

  // 3) 插件意图包缺 name：审计归档/OSV 核对按名失效
  if (typeof pkg.name !== 'string' || pkg.name === '') {
    found.push({
      rule: 'R12',
      severity: 'medium',
      confidence: 'likely',
      message: '插件包缺 name——审计门槛与 OSV 依赖核对按包名归档会失效',
      evidence: '',
      file,
    })
  }

  // 4) engines.node 明确低于 DSH（>=22.19）→ info 提示
  const engines = pkg.engines
  const nodeRange = engines !== undefined && typeof engines === 'object' && engines !== null
    ? (engines as Record<string, unknown>).node
    : undefined
  if (typeof nodeRange === 'string' && nodeMajorBelow22(nodeRange)) {
    found.push({
      rule: 'R12',
      severity: 'info',
      confidence: 'heuristic',
      message: 'engines.node=' + nodeRange + ' 低于 DSH 运行要求（>=22.19），可能不兼容',
      evidence: nodeRange,
      file,
    })
  }
  return found
}

/** dsh.bundle.patch（字符串相对路径）或 undefined。 */
function pickBundlePatch(dshField: unknown): string | undefined {
  if (dshField === undefined || typeof dshField !== 'object' || dshField === null) return undefined
  const bundle = (dshField as Record<string, unknown>).bundle
  if (bundle === undefined || typeof bundle !== 'object' || bundle === null) return undefined
  const patch = (bundle as Record<string, unknown>).patch
  return typeof patch === 'string' && patch !== '' ? patch : undefined
}

/** 包入口：exports["."]（字符串/flat/条件对象）优先，其次 main；无则 undefined。 */
function pickEntry(pkg: Record<string, unknown>): string | undefined {
  const exp = pkg.exports
  if (typeof exp === 'string' && exp !== '') return exp // round-4：Node 合法形态 "exports": "./index.js"
  if (exp !== undefined && typeof exp === 'object' && exp !== null) {
    const dot = (exp as Record<string, unknown>)['.']
    if (typeof dot === 'string' && dot !== '') return dot
    if (dot !== undefined && typeof dot === 'object' && dot !== null) {
      // round-4：条件对象含 'node'（DSH 运行在 Node，node 条件最常见）——旧列表漏 node
      for (const key of ['node', 'import', 'require', 'default', 'types']) {
        const v = (dot as Record<string, unknown>)[key]
        if (typeof v === 'string' && v !== '') return v
      }
    }
  }
  const main = pkg.main
  return typeof main === 'string' && main !== '' ? main : undefined
}

/** engines.node 主版本是否低于 22（启发式 info 用；解析数字前缀主版本比较，不做完整语义解析）。 */
function nodeMajorBelow22(range: string): boolean {
  let s = range.trim()
  while (s.length > 0 && '><=~^v '.includes(s[0])) s = s.slice(1)
  // round-4：主版本必须按数字前缀解析——旧实现假定两位数（two=s[0]+s[1]），
  // "4.0.0"/"8.17.0"/"2.0.0" 等单数字主版本全部漏检（返回 false 不提示）
  const m = /^\d+/.exec(s)
  if (m === null) return false // 无数字（'*'、''、纯符号）→ 无法判定，不提示
  return Number(m[0]) < 22
}