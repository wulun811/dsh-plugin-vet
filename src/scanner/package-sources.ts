import { createRequire } from 'node:module'
import { readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SOURCE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs'])

/**
 * 解析已安装 npm 包的根目录（经 package.json 定位，兼容 pnpm 软链）。
 * @param baseDir 解析基准目录（可选）：vet 被符号链接进 dsh 后，import.meta.url 解析为 vet
 * 的 realpath，createRequire 按它向上找 node_modules 找不到 DSH 实际安装目录（profile 的
 * node_modules）里的第三方插件 → 自动扫描/T2 归因对第三方插件会静默失效。dsh loader 用
 * ctx.baseUrl（profile 目录）解析模块，这里同样优先用 profile 目录作基准，回退 vet 自身。
 */
export function resolvePackageRoot(packageName: string, baseDir?: string): string | undefined {
  const bases: string[] = []
  if (baseDir !== undefined && baseDir !== '') {
    bases.push(baseDir.startsWith('file:') ? fileURLToPath(baseDir) : baseDir)
  }
  // vet 自身位置（测试/本地依赖解析基准，与历史行为一致）
  bases.push(dirname(fileURLToPath(import.meta.url)))
  for (const base of bases) {
    try {
      // createRequire 的父路径只用于确定解析起点，文件本身无需存在
      const rq = createRequire(join(base, '__vet_resolve_probe__.js'))
      return dirname(rq.resolve(`${packageName}/package.json`))
    } catch {
      continue
    }
  }
  return undefined
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
