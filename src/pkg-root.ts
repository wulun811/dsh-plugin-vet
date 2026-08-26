import { existsSync, realpathSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * 解析 vet 包根目录（含 package.json 的最近祖先）。
 *
 * 兼容两种产物形态：
 * - 逐文件形态：lib/skills/audit-protocol.js → 上溯两级到包根
 * - host bundle 形态：lib/index.bundle.js → 上溯一级到包根
 *
 * 固定 `..` 级数在 main 切到 bundle 后失效（lib/ 上两级会越出包），
 * 改为向上搜索 package.json 定位，形态无关。realpath 防符号链接绕过。
 *
 * `base` 可注入解析起点（回归测试用，模拟任意产物形态的模块位置）：
 * 默认取当前模块文件（import.meta.url）所在目录。
 */
export function resolvePkgRoot(base?: string): string {
  let dir = base ?? dirname(fileURLToPath(import.meta.url))
  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(join(dir, 'package.json'))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return dir
}

/**
 * 解析包内资源文件（scanner-bin / sidecar 等），按候选目录存在性取第一个：
 * 1. 包根/lib/<rel>（bundle 与逐文件产物均落位 lib/ 的固定布局）
 * 2. 包根/<rel>（个别产物直接落包根的场景）
 * 3. 包根/src/<rel>（源码形态，本地测试直跑 src）
 * `base` 可注入解析起点（回归测试用）：透传给 resolvePkgRoot。
 */
export function resolveVetFile(rel: string, base?: string): string {
  const root = resolvePkgRoot(base)
  for (const prefix of ['lib', '', 'src']) {
    const candidate = join(root, prefix, rel)
    if (existsSync(candidate)) return candidate
  }
  return join(root, 'lib', rel)
}

/**
 * vet 本体真实根（realpath，模块加载后惰性缓存一次；解析失败 = ''）。
 * round-5 review（B-A1）：与「按包名自豁免」配套的身份校验基元——恶意 tarball 可把
 * package.json 的 name 写成 @jieai/dsh-plugin-vet 冒名，名字比对无法区分；realpath
 * 比对根目录才是本体。scan-plugin / internal-plugin / runtime-guard 归因映射共用。
 */
let selfRootCache: string | undefined
export function vetSelfRoot(): string {
  if (selfRootCache === undefined) {
    try {
      selfRootCache = realpathSync(resolvePkgRoot())
    } catch {
      selfRootCache = ''
    }
  }
  return selfRootCache
}

/** 路径是否为 vet 本体根（realpath 比对；解析失败或本体根不可得 → false）。 */
export function isVetSelfPath(p: string): boolean {
  const self = vetSelfRoot()
  if (self === '' || p === '') return false
  try {
    return realpathSync(p) === self
  } catch {
    return false
  }
}