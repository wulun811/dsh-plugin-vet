#!/usr/bin/env node
/**
 * prepublish 完整性检查：验证发布物（npm tarball 应包含的内容）自洽。
 *
 * 检查项：
 * 1. resolveVetFile('xxx') 引用的文件在 package.json files 覆盖内
 * 2. resolvePkgRoot() 读取的文件在 files 覆盖内
 * 3. [0.2.2 新增] lib/** 全部相对 import/export/require 在发布集内闭合——
 *    防 files 白名单漏目录（0.2.2 曾漏 lib/tools、lib/audit、lib/guards、
 *    lib/pkg-root.js、lib/invariant.js，散件入口一装就 ERR_MODULE_NOT_FOUND）
 * 4. [0.2.2 新增] bin 与 exports 声明的入口文件全部可达
 * 5. [0.2.2 新增] 发布物内不得混入源码/开发脚本（src/、scanner-bin/*.ts、scripts/、test/）
 */

import { execSync } from 'node:child_process'
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'

const ROOT = process.cwd()

// ── 发布集推导（按 files 字段语义：目录=递归全收，文件=单收）──
function expandFilesField(filesField) {
  const out = new Set()
  const walk = (dir, base) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name)
      if (e.isDirectory()) walk(p, base)
      else out.add(relative(base, p).split('\\').join('/'))
    }
  }
  for (const pattern of filesField) {
    if (pattern.includes('*')) {
      console.warn('  ⚠ files 含 glob 模式（' + pattern + '），此模式未展开校验——建议改用目录/文件条目')
      continue
    }
    const abs = join(ROOT, pattern)
    if (!existsSync(abs)) {
      console.error('  ✗ files 条目在磁盘上不存在：' + pattern)
      process.exitCode = 1
      continue
    }
    if (statSync(abs).isDirectory()) walk(abs, ROOT)
    else out.add(pattern)
  }
  return out
}

// ── 相对引用提取（import/export from + 裸 import + require）──
const REL_REF_RE =
  /(?:import|export)\s+(?:[^'"]*?\s+from\s*)?['"](\\.{1,2}\/[^'"]+)['"]|require\(\s*['"](\\.{1,2}\/[^'"]+)['"]\s*\)/g

function relativeRefs(file) {
  const src = readFileSync(join(ROOT, file), 'utf8')
  const refs = []
  for (const m of src.matchAll(REL_REF_RE)) {
    const spec = m[1] ?? m[2]
    if (spec) refs.push(spec)
  }
  return refs
}

// 引用解析：ESM 下显式扩展名；目录 → index；省略扩展名 → 尝试 .js/.json/.mjs/.cjs
function resolveRef(spec, fromFile, shipSet, missing) {
  const candidates = [spec, spec + '.js', spec + '.json', spec + '.mjs', spec + '.cjs']
  for (const c of candidates) {
    const normalized = join(dirname(fromFile), c).split('\\').join('/')
    if (shipSet.has(normalized)) return true
    if (existsSync(join(ROOT, normalized))) {
      const target = join(ROOT, normalized)
      if (statSync(target).isDirectory() && shipSet.has(normalized + '/index.js')) return true
    }
  }
  missing.push({ from: fromFile, spec })
  return false
}

// ── 主逻辑 ──
console.log('🔍 检查运行时依赖完整性...\n')

const filesField = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).files || []
const shipSet = expandFilesField(filesField)
let hasError = (process.exitCode || 0) === 1

// 1) resolveVetFile 调用
console.log('📦 resolveVetFile 调用（需要 lib/<path>）：')
try {
  const src = execSync('grep -r "resolveVetFile(" src/ --include="*.ts"', { cwd: ROOT, encoding: 'utf8' })
  const calls = [...new Set([...src.matchAll(/resolveVetFile\(['"]([^'"]+)['"]\)/g)].map(m => m[1]))]
  for (const file of calls) {
    const full = 'lib/' + file
    const ok = shipSet.has(full)
    console.log('  ' + (ok ? '✓' : '✗') + ' ' + full)
    if (!ok) hasError = true
  }
} catch {
  console.log('  （src/ 无 resolveVetFile 引用或 grep 失败）')
}

// 2) resolvePkgRoot 读取
console.log('\n📦 resolvePkgRoot 读取（需要根目录文件）：')
try {
  const src = execSync('grep -r "resolvePkgRoot()" src/ --include="*.ts" -A 1', { cwd: ROOT, encoding: 'utf8' })
  const files = [...new Set(
    [...src.matchAll(/join\(resolvePkgRoot\(\),\s*['"]([^'"]+)['"]\)/g)].map(m => m[1])
      .concat([...src.matchAll(/resolvePkgRoot\(\)\s*\+\s*['"]\/([^'"]+)['"]/g)].map(m => m[1])),
  )]
  for (const file of files) {
    const ok = shipSet.has(file)
    console.log('  ' + (ok ? '✓' : '✗') + ' ' + file)
    if (!ok) hasError = true
  }
} catch {
  console.log('  （src/ 无 resolvePkgRoot 读取或 grep 失败）')
}

// 3) lib/** 相对引用闭合
console.log('\n📦 lib/** 相对 import/export/require 闭合（0.2.2 新增）：')
const libFiles = [...shipSet].filter(f => f.startsWith('lib/') && f.endsWith('.js'))
const broken = []
for (const file of libFiles) {
  for (const spec of relativeRefs(file)) resolveRef(spec, file, shipSet, broken)
}
if (broken.length === 0) {
  console.log('  ✓ ' + libFiles.length + ' 个编译 JS 相对引用全部闭合（0 缺失）')
} else {
  console.error('  ✗ ' + broken.length + ' 处相对引用在发布集内缺失：')
  for (const b of broken.slice(0, 20)) {
    console.error('    ' + b.from + ' -> ' + b.spec)
  }
  hasError = true
}

// 4) bin / exports 入口可达
console.log('\n📦 bin / exports 入口可达（0.2.2 新增）：')
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const entries = []
if (pkg.bin) for (const [name, p] of Object.entries(pkg.bin)) entries.push('bin.' + name + ': ' + p)
if (pkg.exports) {
  for (const [sub, target] of Object.entries(pkg.exports)) {
    if (typeof target === 'string') entries.push('exports["' + sub + '"]: ' + target)
    else for (const v of Object.values(target)) if (typeof v === 'string') entries.push('exports["' + sub + '"]: ' + v)
  }
}
// npm 强制随包发布的文件（files 之外始终包含，无需列入 files）
const ALWAYS_SHIP = new Set(['package.json', 'README.md', 'README', 'LICENSE', 'LICENSE.md', 'CHANGELOG.md'])
for (const e of entries) {
  const path = e.split(': ')[1]
  const relPath = path.replace(/^\.\//, '')
  const ok = shipSet.has(relPath) || ALWAYS_SHIP.has(relPath)
  console.log('  ' + (ok ? '✓' : '✗') + ' ' + e)
  if (!ok) hasError = true
}

// 5) 发布集边界
console.log('\n📦 发布集边界（0.2.2 新增，禁止源码/开发脚本入包）：')
const forbidden = [...shipSet].filter(f =>
  f.startsWith('src/') || f.startsWith('scripts/') || f.startsWith('test/') ||
  (f.startsWith('scanner-bin/') && f.endsWith('.ts')) ||
  f.startsWith('dsh-src/') || f.startsWith('plugin-scan-tmp/'),
)
if (forbidden.length === 0) {
  console.log('  ✓ 发布集不含 src/ scripts/ test/ scanner-bin/*.ts 等非发布物')
} else {
  console.error('  ✗ 发布集混入 ' + forbidden.length + ' 个非发布文件：')
  for (const f of forbidden.slice(0, 10)) console.error('    ' + f)
  hasError = true
}

if (hasError) {
  console.error('\n❌ 完整性检查失败——请修复 package.json files 字段或构建产物后重跑')
  process.exit(1)
} else {
  console.log('\n✅ 完整性检查通过')
}
