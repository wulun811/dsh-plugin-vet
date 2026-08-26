/**
 * vet 本体自扫的权威扫描范围（③ 工具 / ② 钉扎 / ④ 门禁共用，避免各写各的导致 pin 不一致）。
 *
 * round-16 review（决策 2：升级体验优先）：旧范围是 src 源码树（SELF_SCOPE_SKIP_RE 排除
 * lib/ 等构建产物）——但发布 tarball 只含 lib/（package.json files 白名单），生产安装
 * （非 dev symlink）自扫 = 源码缺失 = hash 永远 ≠ 钉扎 = Trusted 不可达；升级后更是
 * 「两个 vet 互不认」。现把范围改为「随包发布的产物白名单」：
 *   lib/**（实际执行的代码）+ 包根清单文件 + docs/**（随包发布的文档）。
 * 开发树与生产安装同一范围：dev 需先 build 出 lib/（未构建的裸源码树 → 缺失项 content=''
 * 与 pin 不符 → dev-tree amber，诚实标注）；字节一致（开发树已构建 / 生产安装）→
 * pinned-match。listSourceFiles 全量（普通插件审计）不受影响。
 */
import { lstatSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'

/** 发布物白名单：相对路径前缀命中即入自扫面（与 package.json files 字段保持一致）。 */
const SHIPPED_PREFIXES = ['lib/', 'docs/']

/** 包根清单文件（files 字段白名单；vet-self-pins.json 例外——钉扎表自引用，不可哈希自身）。 */
const SHIPPED_ROOT_FILES = new Set([
  'package.json',
  'cordis.patch.yml',
  'README.md',
  'README.zh.md',
  'AUDIT_PROTOCOL.md',
  'CHANGELOG.md',
])

/** vet 本体自扫范围：发布物白名单（lib/** + 根级清单 + docs/**）。绝对路径。
 * 与 listSourceFiles 同款 walk 纪律：跳过 node_modules/.git/隐藏目录，深度 ≤ 6，
 * 不跟随符号链接（防扫描面越出包根与链接环）。 */
export function listShippedFiles(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number): void => {
    if (depth > 6) return
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const name of entries) {
      if (name === 'node_modules' || name === '.git' || name.startsWith('.')) continue
      const full = join(dir, name)
      let stat
      try {
        stat = lstatSync(full)
      } catch {
        continue
      }
      if (stat.isSymbolicLink()) continue
      const rel = relative(root, full).split('\\').join('/')
      if (rel === 'vet-self-pins.json') continue
      const inScope = SHIPPED_PREFIXES.some(p => rel.startsWith(p)) || SHIPPED_ROOT_FILES.has(rel)
      // 前缀树判定：目录本身或其祖先是发布前缀（'lib' / 'lib/scanner' / 'docs'）才继续下钻——
      // 根级清单文件都在包根，包根其他目录不进面
      const inPrefixTree = SHIPPED_PREFIXES.some(p => rel === p.slice(0, -1) || rel.startsWith(p))
      if (stat.isDirectory()) {
        if (inPrefixTree) walk(full, depth + 1)
      } else if (stat.isFile() && inScope) {
        out.push(full)
      }
    }
  }
  walk(root, 0)
  return out
}