import { createRequire } from 'node:module'
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

/** 常规源码扩展（R17 配置面不在此列——cordis.yml 等由下方根级配置名条件单独收口，面更窄）。 */
const SOURCE_EXT = new Set(['.js', '.ts', '.mjs', '.cjs', '.sh', '.bash', '.ps1', '.cmd', '.bat', '.psm1', '.zsh'])

/** C4（0.3.8，DSH 0.1.5 同步）：原生二进制扩展——官方首发平台二进制包（node-addon-system-*
 * 携带 .node），第三方插件夹带预编译二进制是经典恶意手法（native 代码不可 JS 静态审）。
 * 与 scanner-bin/engine.ts 的 NATIVE_BINARY_EXT 保持同步（跨构建根无法单源共享，改动需两边
 * 同改——SOURCE_EXT/CONFIG_EXT 同款纪律）。仅以「存在性证据」进扫描面：engine 命中即记名，
 * 不读取、不解析、不入 sourceCount（见 engine C4 注记）。 */
const NATIVE_BINARY_EXT = new Set(['.node', '.dll', '.dylib', '.so', '.exe', '.wasm', '.ocx', '.sys'])

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

/** 递归收集包内可扫描源码（跳过 node_modules/.git/隐藏目录，深度 ≤ 6）。
 * 0.3.9（审查修复）：额外收集 package.json 声明的 bin/scripts 入口文件——npm 标准形态的
 * bin 入口普遍无扩展名，此前整段隐形（实证：bin/cli 里放 curl|sh 不出现在枚举结果里），
 * engine 侧的 isExtensionlessJs/cliFiles 判定在自动扫描链上永远收不到这些文件 = 死代码。 */
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
      } else if (stat.isFile() && (
        // 0.3.8：扩展名统一小写再比对（engine 侧 round-16 已小写；宿主枚举侧此前大小写敏感——
        // `.NODE`/`.SH` 从宿主面漏出，engine 的大小写处理形同虚设。两侧口径就此对齐）
        SOURCE_EXT.has(extOf(full).toLowerCase()) ||
        // C4（0.3.8）：原生二进制存在性证据（engine 只记名不解析）
        NATIVE_BINARY_EXT.has(extOf(full).toLowerCase()) ||
        // 根级配置文件（R17 面）：cordis.yml/cordis.patch.yml/plugin.yml 仅限包根
        (dir === root && isRootConfigFile(name)) ||
        (name === 'package.json' && dir === root))) {
        out.push(full)
      }
    }
  }
  walk(root, 0)
  const declared = listDeclaredEntries(root)
  if (declared.length === 0) return out
  const have = new Set(out)
  for (const d of declared) if (!have.has(d)) out.push(d)
  return out
}

/** package.json 声明的入口/脚本目标文件（bin 值 + scripts 里的路径 token，0.3.9）。
 * 与 engine 侧 packageShape 的 cliFiles 收集同口径（宽松：含 '/' 或带源码扩展名的 token），
 * 但这里额外要求**真实存在的常规文件且落在包根内**（防 `../` 逃逸与远程 URL token 进面）。 */
function listDeclaredEntries(root: string): string[] {
  const out: string[] = []
  let pkg: Record<string, unknown>
  try {
    const raw = readFileSync(join(root, 'package.json'), 'utf8')
    if (raw.length > 4 * 1024 * 1024) return out
    pkg = JSON.parse(raw) as Record<string, unknown>
  } catch {
    return out
  }
  const tokens = new Set<string>()
  const bin = pkg.bin
  if (typeof bin === 'string') tokens.add(bin)
  else if (typeof bin === 'object' && bin !== null) {
    for (const v of Object.values(bin as Record<string, unknown>)) if (typeof v === 'string') tokens.add(v)
  }
  const scripts = pkg.scripts
  if (typeof scripts === 'object' && scripts !== null) {
    for (const v of Object.values(scripts as Record<string, unknown>)) {
      if (typeof v !== 'string') continue
      for (const tok of v.split(/\s+/)) {
        if (tok === '' || tok.startsWith('-')) continue
        if (tok.includes('/') || SOURCE_EXT.has(extOf(tok))) tokens.add(tok)
      }
    }
  }
  const seen = new Set<string>()
  for (const t of tokens) {
    const rel = t.replace(/^\.\//, '')
    const abs = rel.startsWith('/') ? rel : resolve(root, rel)
    if (abs !== root && !abs.startsWith(root + sep)) continue
    if (seen.has(abs)) continue
    seen.add(abs)
    try {
      if (!lstatSync(abs).isFile()) continue
    } catch {
      continue
    }
    out.push(abs)
  }
  return out
}

/**
 * 递归收集指令/技能文件（R18 面，与 listSourceFiles 同款 walk 纪律）：
 * 跳过 node_modules/.git/隐藏目录，深度 ≤ 6，上限 64 个。只认 AGENTS.md/CLAUDE.md/CODEGOV.md
 * 与 skills 目录、*.skill 目录下的 SKILL.md（.md）——README/docs 不进面（防误报设计 N6）。
 */
export function listInstructionFiles(root: string): string[] {
  const out: string[] = []
  // round-22：root 带尾斜杠（shell/LLM 常传 /path/pkg/）时，`full.slice(root.length + 1)`
  // 会多裁掉相对路径首字符（'skills/SKILL.md' → 'kills/SKILL.md'）——skills/*.skill 段
  // 判定全落空，嵌套指令文件静默掉出 R18/G-1 扫描面（根级 AGENTS.md 因无分隔符反而
  // 碰巧通过，掩盖了问题）。入口统一归一；Windows 尾反斜杠（C:\pkg\）同病同修。
  const base = root.length > 0 && (root.endsWith('/') || root.endsWith('\\')) ? root.slice(0, -1) : root
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
      } else if (stat.isFile() && isInstructionFile(name, full.slice(base.length + 1))) {
        out.push(full)
        if (out.length >= INSTRUCTION_MAX_FILES) return
      }
    }
  }
  walk(base, 0)
  return out
}

function extOf(file: string): string {
  // 0.3.9（审查修复）：只看 basename——此前对整条路径 lastIndexOf('.')，路径里带点的目录段
  // （DSH 安装树 ~/.dsh/… 必带）会给无扩展名文件造出伪扩展名，bin 入口判定恒不命中。
  const base = basename(file)
  const dot = base.lastIndexOf('.')
  if (dot <= 0) return ''
  return base.slice(dot)
}
