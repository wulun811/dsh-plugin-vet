import type { Finding } from '../protocol.js'

/**
 * R10 supply chain : package.json manifest scan.
 * install hooks (preinstall/install/postinstall/uninstall) are real
 * arbitrary-code execution at install time -> high. The dependency manifest
 * is advisory info for the LLM audit round (known-vulnerability matching is
 * deferred: data source selection pending, D15).
 */
// round-9（0.1.16 加固）：prepare 在本地 npm install（无参）/publish/git 依赖时执行——真实任意代码执行面
const HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'uninstall', 'preuninstall']
const DEP_KEYS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

/** Parse a package.json manifest; returns R10 findings (invalid JSON -> none). */
export function runPackageJson(content: string, file: string, targetKind?: 'plugin' | 'generic'): Finding[] {
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
        // generic（官方包/信任包）：postinstall 常为 native 编译等合法步骤 → 降级 info 提示
        const generic = targetKind === 'generic'
        found.push({
          rule: 'R10',
          severity: generic ? 'info' : 'high',
          confidence: 'likely',
          message: 'install 钩子：package.json scripts.' + hook + (generic ? '（能力触达面：官方包合法安装步骤）' : '（安装期任意代码执行面）'),
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
      message: '依赖清单：' + names.length + ' 项（' + names.slice(0, 30).join(', ') + (names.length > 30 ? '…' : '') + '，供 LLM 审计供应链；已知漏洞核对见后续 OSV 精确版本查询（网络失败静默降级））',
      evidence: names.slice(0, 30).join(', ').slice(0, 200),
      file,
    })
  }
  return found
}
