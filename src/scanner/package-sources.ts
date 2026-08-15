import { createRequire } from 'node:module'
import { readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'

const require = createRequire(import.meta.url)
const SOURCE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs'])

/** 解析已安装 npm 包的根目录（经 package.json 定位，兼容 pnpm 软链）。 */
export function resolvePackageRoot(packageName: string): string | undefined {
  try {
    return dirname(require.resolve(`${packageName}/package.json`))
  } catch {
    return undefined
  }
}

/** 递归收集包内可扫描源码（跳过 node_modules/.git/隐藏目录，深度 ≤ 6）。 */
export function listSourceFiles(root: string): string[] {
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
        stat = statSync(full)
      } catch {
        continue
      }
      if (stat.isDirectory()) {
        walk(full, depth + 1)
      } else if (stat.isFile() && (SOURCE_EXT.has(extOf(full)) || (name === 'package.json' && dir === root))) {
        out.push(full)
      }
    }
  }
  walk(root, 0)
  return out
}

function extOf(file: string): string {
  const dot = file.lastIndexOf('.')
  return dot === -1 ? '' : file.slice(dot)
}
