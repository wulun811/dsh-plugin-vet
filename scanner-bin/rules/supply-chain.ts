import type { Finding } from '../protocol.js'

/**
 * R10 supply chain (PLAN.md §14.2 R10): package.json manifest scan.
 * install hooks (preinstall/install/postinstall/uninstall) are real
 * arbitrary-code execution at install time -> high. The dependency manifest
 * is advisory info for the LLM audit round (known-vulnerability matching is
 * deferred: data source selection pending, D15).
 */
const HOOKS = ['preinstall', 'install', 'postinstall', 'uninstall', 'preuninstall']
const DEP_KEYS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

/** Parse a package.json manifest; returns R10 findings (invalid JSON -> none). */
export function runPackageJson(content: string, file: string): Finding[] {
  const found: Finding[] = []
  let pkg: Record<string, unknown>
  try {
    pkg = JSON.parse(content) as Record<string, unknown>
  } catch {
    return found
  }
  const scripts = pkg.scripts
  if (scripts !== undefined && typeof scripts === 'object' && scripts !== null) {
    for (const hook of HOOKS) {
      const cmd = (scripts as Record<string, unknown>)[hook]
      if (typeof cmd === 'string' && cmd !== '') {
        found.push({
          rule: 'R10',
          severity: 'high',
          confidence: 'likely',
          message: 'install 钩子：package.json scripts.' + hook + '（安装期任意代码执行面）',
          evidence: cmd.slice(0, 200),
          file,
        })
      }
    }
  }
  const names: string[] = []
  for (const key of DEP_KEYS) {
    const deps = pkg[key]
    if (deps !== undefined && typeof deps === 'object' && deps !== null) {
      names.push(...Object.keys(deps as Record<string, unknown>))
    }
  }
  if (names.length > 0) {
    found.push({
      rule: 'R10',
      severity: 'info',
      confidence: 'heuristic',
      message: '依赖清单：' + names.length + ' 项（' + names.slice(0, 30).join(', ') + (names.length > 30 ? '…' : '') + '，供 LLM 审计供应链；已知漏洞匹配待数据源选型）',
      evidence: names.slice(0, 30).join(', ').slice(0, 200),
      file,
    })
  }
  return found
}
