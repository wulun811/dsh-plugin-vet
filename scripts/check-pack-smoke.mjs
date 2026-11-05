#!/usr/bin/env node
/**
 * 发布物冒烟（0.5.13，专家复审 A）：真的打包、真的解包、真的 import。
 *
 * 为什么单开一个脚本：`check-pack-integrity.mjs` 校验的是「files 白名单够不够」——
 * 它按发布集推导逐条比对相对 import 是否闭合，全程读的是工作区源码树。它能证明
 * "清单没漏文件"，不能证明"装下来的那个东西能跑"。两者之间隔着几件工作区里看不到的事：
 * tarball 里的路径前缀、`exports` 映射、`type: module` 与入口扩展名、以及
 * 「发布物里混进了一个只有开发态才存在的相对路径」。
 *
 * 所以这里做的是最短的那条真实链路：
 *   npm pack → 解包 → 读包内 package.json → import 包内入口 → 断言导出的形状。
 *
 * 刻意不做的：不跑扫描器（要宿主/网络，且 `npm test` 已覆盖）；不 import 浏览器半区
 * （`lib/client.js` 是 module-loader 包装的 IIFE，Node 里 import 会立刻炸——这里只断言
 * 它确实是那个包装形态，防止把源码/jest 产物错发出去）。
 *
 * 解包目录放在仓库内 `tmp/`（.gitignore 已忽略）：这样包内入口的相对 import 能向上找到
 * 工作区的 `node_modules`，与「装到一个已装好依赖的 profile 里」等价；解到系统临时目录
 * 反而会因为找不到宿主依赖而假红。
 */

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const ROOT = process.cwd()
const problems = []
const fail = (msg) => { problems.push(msg); console.error('  ✗ ' + msg) }
const ok = (msg) => console.log('  ✓ ' + msg)

/**
 * Windows 兼容：`npm` 在 win32 是 npm.cmd，Node 22 起 spawn .cmd 必须经 shell（否则 EINVAL）；
 * 从 npm script 启动时优先用 npm_execpath（`node <npm-cli.js>`），避免依赖 PATH 里的 shim。
 */
function runNpm(args, opts) {
  if (process.env.npm_execpath !== undefined) {
    return execFileSync(process.execPath, [process.env.npm_execpath, ...args], opts)
  }
  return execFileSync('npm', args, { ...opts, shell: process.platform === 'win32' })
}

// mkdtemp 的前缀目录必须已存在；仓库通常已有 tmp/（.gitignore 忽略），缺了就建。
mkdirSync(join(ROOT, 'tmp'), { recursive: true })
const scratch = mkdtempSync(join(ROOT, 'tmp', 'pack-smoke-'))

let work
try {
  // `npm pack` 不触发 prepublishOnly（那只在 publish 时跑），所以不会递归。
  const raw = runNpm(['pack', '--json', '--pack-destination', scratch], {
    cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
  })
  const info = JSON.parse(raw)[0]
  const tarball = join(scratch, info.filename)
  if (!existsSync(tarball)) fail('npm pack 没有产出 tarball')
  ok(`打包：${info.filename}（${info.files.length} 个文件，${(info.size / 1024).toFixed(0)} KB）`)

  work = mkdtempSync(join(ROOT, 'tmp', 'unpack-'))
  // Windows 兼容：不给 tar 传盘符绝对路径（Git Bash 的 GNU tar 会把 `C:\…` 当远程主机，
  // `-C C:\…` 也会被 MSYS 转义）——切到解包目录用相对路径，GNU tar 与 bsdtar 同语义。
  const relArchive = relative(work, tarball).split(sep).join('/')
  execFileSync('tar', ['-xzf', relArchive], { cwd: work })
  const pkgDir = join(work, 'package')
  const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'))

  // 1) 发布物里不得有安装期脚本（SECURITY.md 的原话是"vet ships no install-time scripts"）
  const hooks = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack']
  const found = hooks.filter((h) => pkg.scripts?.[h] !== undefined)
  if (found.length > 0) fail(`发布物含安装期脚本：${found.join(', ')}`)
  else ok('无安装期脚本（preinstall/install/postinstall/prepare/prepack 全空）')

  // 2) 版本与工作区一致（防止忘 bump 就发出去）
  const rootPkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  if (pkg.version !== rootPkg.version) fail(`版本不一致：tarball=${pkg.version} 工作区=${rootPkg.version}`)
  else ok(`版本一致：${pkg.version}`)

  // 3) 清单里声明过的入口，解包后必须真的在
  for (const rel of ['lib/index.bundle.js', 'lib/client.js', 'cordis.patch.yml', 'vet-self-pins.json', 'docs/ARCHITECTURE.md']) {
    if (!existsSync(join(pkgDir, rel))) fail(`发布物缺少 ${rel}`)
  }
  ok('关键文件在位（宿主 bundle / 浏览器 bundle / patch / 自钉扎 / 架构文档）')

  // 4) 浏览器半区必须是 module-loader 包装形态（不是源码、不是空文件）
  const client = readFileSync(join(pkgDir, 'lib/client.js'), 'utf8')
  if (!client.includes('__ModuleLoader__')) fail('lib/client.js 不是 module-loader 包装形态')
  else ok(`浏览器半区形态正确（${(client.length / 1024).toFixed(0)} KB）`)

  // 5) 真的 import 宿主入口，断言导出的形状
  const entry = pkg.main ?? pkg.exports?.['.']?.import
  if (entry === undefined) fail('package.json 没有可解析的宿主入口（main / exports["."].import）')
  const mod = await import(pathToFileURL(join(pkgDir, entry)).href)
  for (const [key, type] of [['apply', 'function'], ['name', 'string'], ['Config', 'function']]) {
    if (typeof mod[key] !== type) fail(`入口 ${entry} 导出 ${key} 不是 ${type}（实际 ${typeof mod[key]}）`)
  }
  if (mod.name !== 'plugin-vet') fail(`入口 name 应为 plugin-vet，实际 ${String(mod.name)}`)
  ok(`宿主入口可 import：${entry}（apply/name/Config 形状正确）`)
} catch (error) {
  fail(`冒烟中断：${error instanceof Error ? error.message : String(error)}`)
} finally {
  for (const dir of [work, scratch]) {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
  }
}

if (problems.length > 0) {
  console.error(`\n✗ 发布物冒烟失败（${problems.length} 项）`)
  process.exit(1)
}
console.log('\n✓ 发布物冒烟通过：打出来的包能装、能 import、没有安装期脚本')
