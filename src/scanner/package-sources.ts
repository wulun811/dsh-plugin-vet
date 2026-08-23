import { createRequire } from 'node:module'
import { lstatSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** 常规源码扩展（R17 配置面不在此列——cordis.yml 等由下方根级配置名条件单独收口，面更窄）。 */
const SOURCE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs', '.sh', '.bash', '.ps1', '.cmd', '.bat', '.psm1', '.zsh'])

/** 根级配置文件白名单（R17 面；与 scanner-bin/rules/config-scan.ts isRootConfigName 保持同步——
 * 跨构建根目录无法单源共享，改动需两边同改）。 .md 不进 SOURCE_EXT：指令/技能文件由
 * listInstructionFiles 单独收口，避免任意 README 进扫描面。 */
const ROOT_CONFIG_RE = /^(cordis|plugin)\.ya?ml$/i
const PATCH_CONFIG_RE = /\.patch\.ya?ml$/i

export function isRootConfigFile(name: string): boolean {
  return ROOT_CONFIG_RE.test(name) || PATCH_CONFIG_RE.test(name)
}

/** 指令/技能文件白名单（R18 面；与 scanner-bin/rules/instruction-scan.ts isInstructionFile 保持同步）。
 * AGENTS/CLAUDE/CODEGOV 仅限包根（relPath 无分隔符）——深度嵌套的说明文件不属于指令面（窄面防误报）； */
const INSTRUCTION_BASE_RE = /^(AGENTS|CLAUDE|CODEGOV)\.md$/i
export function isInstructionFile(name: string, relPath?: string): boolean {
  if (INSTRUCTION_BASE_RE.test(name)) return relPath !== undefined && !relPath.includes('/') && !relPath.includes('\\')
  if (!/\.md$/i.test(name)) return false
  if (relPath === undefined) return false
  const segs = relPath.split(/[\\/]/)
  return segs.includes('skills') || segs.some(s => /\.skill$/i.test(s))
}

/** R18 指令文件收集上限（防扫描体积失控；超限静默截断，注释记录边界）。 */
const INSTRUCTION_MAX_FILES = 64

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
        stat = lstatSync(full)
      } catch {
        continue
      }
      // 符号链接（目录/文件）不进扫描面：不跟随——防扫描面越出包根（链接到 /home/… 等宿主目录）与链接环。
      if (stat.isSymbolicLink()) continue
      if (stat.isDirectory()) {
        walk(full, depth + 1)
      } else if (stat.isFile() && (SOURCE_EXT.has(extOf(full)) ||
        // 根级配置文件（R17 面）：cordis.yml/cordis.patch.yml/plugin.yml 仅限包根
        (dir === root && isRootConfigFile(name)) ||
        (name === 'package.json' && dir === root))) {
        out.push(full)
      }
    }
  }
  walk(root, 0)
  return out
}

/**
 * 递归收集指令/技能文件（R18 面，与 listSourceFiles 同款 walk 纪律）：
 * 跳过 node_modules/.git/隐藏目录，深度 ≤ 6，上限 64 个。只认 AGENTS.md/CLAUDE.md/CODEGOV.md
 * 与 skills 目录、*.skill 目录下的 SKILL.md（.md）——README/docs 不进面（防误报设计 N6）。
 */
export function listInstructionFiles(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number): void => {
    if (depth > 6 || out.length >= INSTRUCTION_MAX_FILES) return
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
      // 符号链接（目录/文件）不进扫描面：不跟随——防扫描面越出包根（链接到 /home/… 等宿主目录）与链接环。
      if (stat.isSymbolicLink()) continue
      if (stat.isDirectory()) {
        walk(full, depth + 1)
      } else if (stat.isFile() && isInstructionFile(name, full.slice(root.length + 1))) {
        out.push(full)
        if (out.length >= INSTRUCTION_MAX_FILES) return
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
