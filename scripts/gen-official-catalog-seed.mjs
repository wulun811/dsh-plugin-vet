#!/usr/bin/env node
/**
 * 生成官方包目录种子（M1，0.3.5；0.3.6 扩展收集范围）：输出 src/guards/official-catalog-seed.ts。
 *
 * 为什么是种子而非唯一真值：registry scope 枚举才是在线权威（refreshOfficialCatalogFromRegistry
 * 兜底）；种子保证纯离线/首启时目录非空——「官方所有的包咱们都有」在代码仓库侧的具体形态
 * 就是 dsh-src 这份官方源码目录树。dsh-src 更新后重跑本脚本即可（见 gen-self-pin 同款纪律）。
 *
 * 0.3.6（DSH npm-public 模块化家族同步）收集范围四合一，与现网发行物对齐：
 *   1. dsh-src/packages         —— 官方运行时包（主体，历史来源）；
 *   2. dsh-src/apps             —— CLI 与前端 shell（@deepseek-ai/dsh、dsh-web-frontend）；
 *   3. dsh-src/vendor           —— cordis fork 家族（@deepseek-ai/cordis、cordis-plugin-*、
 *                                   cosmokit 等）。npm search 的 scope 枚举不索引这批包
 *                                   （实测定 @deepseek-ai 搜索 2500 槽内不出现 cordis 家族），
 *                                   此前漏种导致 DSH 升级后 cordis-plugin-hmr 等误报
 *                                   official-not-in-catalog 黄牌——必须随源码树内置；
 *   4. 本机已安装的 DSH 家族目录 —— 正在运行的 DSH（global 安装的 @deepseek-ai/dsh 的
 *                                   node_modules/@deepseek-ai/*）视为「当前发行物事实」：
 *                                  已装即官方（随官方包分发）。运行 DSH 升级后重跑即可同步
 *                                  新拆分的官方包名。
 *
 * 用法：node scripts/gen-official-catalog-seed.mjs [dsh-src 路径] [本机 DSH 家族路径]
 * 位置参数可省略：dsh-src 默认仓库内 ./dsh-src；家族目录默认探测 npm global 根（OS 平台
 * 的全局 node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai），探测不到则静默跳过
 * （离线开发者机器只有源码树三个来源照样可生成）。
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const here = fileURLToPath(new URL('.', import.meta.url))
const root = join(here, '..')
const dshSrc = process.argv[2] ?? join(root, 'dsh-src')
const outFile = join(root, 'src', 'guards', 'official-catalog-seed.ts')

const names = new Set()

/** 收集一个目录（及其一层嵌套）下所有 @deepseek-ai/* package.json 名。 */
const collect = (dir) => {
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const e of entries) {
    if (!e.isDirectory()) continue
    if (e.name === 'node_modules') continue
    const pkgPath = join(dir, e.name, 'package.json')
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
      if (typeof pkg.name === 'string' && pkg.name.startsWith('@deepseek-ai/')) names.add(pkg.name)
    } catch {
      // 无 package.json 或非法 JSON——跳过（非包目录）
    }
    // 嵌套一层（packages/<scope>/<pkg> 布局），避免深挖 dsh-src 全部源码
    const inner = join(dir, e.name)
    let innerEntries
    try {
      innerEntries = readdirSync(inner, { withFileTypes: true })
    } catch {
      continue
    }
    for (const ie of innerEntries) {
      if (!ie.isDirectory() || ie.name === 'node_modules') continue
      const ip = join(inner, ie.name, 'package.json')
      try {
        const pkg = JSON.parse(readFileSync(ip, 'utf8'))
        if (typeof pkg.name === 'string' && pkg.name.startsWith('@deepseek-ai/')) names.add(pkg.name)
      } catch {
        // 同上
      }
    }
  }
}

const sources = []
const srcs = ['packages', 'apps', 'vendor']
for (const s of srcs) {
  if (existsSync(join(dshSrc, s))) {
    collect(join(dshSrc, s))
    sources.push(`dsh-src/${s}`)
  }
}

/** 本机已装 DSH 家族：global 根/@deepseek-ai/dsh/node_modules/@deepseek-ai。
 * 探测多个候选 global 根：npm root -g（默认 prefix）、~/.npm-global（常见手工 prefix）、
 * ~/.local（pnpm global）、NPM_GLOBAL_ROOT 环境变量。命中即用，全部落空返回 null。 */
const familyDefault = (() => {
  const candidates = [process.env.NPM_GLOBAL_ROOT]
  try {
    candidates.push(execFileSync('npm', ['root', '-g'], { encoding: 'utf8', timeout: 10000 }).trim())
  } catch {
    // npm 不可用——继续其他候选
  }
  candidates.push(join(homedir(), '.npm-global', 'lib', 'node_modules'))
  candidates.push(join(homedir(), '.local', 'lib', 'node_modules'))
  for (const g of candidates) {
    if (g === undefined || g === '') continue
    const p = join(g, '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai')
    if (existsSync(p)) return p
  }
  return null
})()
const liveFamily = process.argv[3] ?? familyDefault
if (liveFamily !== undefined && liveFamily !== null && existsSync(liveFamily)) {
  collect(liveFamily)
  sources.push(`live:${liveFamily}`)
}

const sorted = [...names].sort()
const lines = sorted.map(n => `  '${n}',`).join('\n')
const header = `/**
 * 官方包目录种子（M1，0.3.6）：dsh-src（packages+apps+vendor）+ 本机已装 DSH 家族收集的
 * @deepseek-ai/* 全量包名。
 * 生成方式：node scripts/gen-official-catalog-seed.mjs
 *        （dsh-src 更新或本机 DSH 升级后重跑；收集源：${sources.join('、')}）。
 * 语义：目录内 = 可信官方名候选（仍要求与官方哈希一致才入内容信任锚）；
 *       目录外多出来的 @deepseek-ai/* = 冒充或官方新包（黄牌观察，不拦）。
 * 运行时在线刷新（registry scope 枚举）结果与种子合并后落盘覆盖层，见 official-catalog.ts。
 */
export const OFFICIAL_CATALOG_SEED: readonly string[] = [
${lines}
]
`
writeFileSync(outFile, header)
console.log(`official-catalog-seed.ts: ${sorted.length} names (sources: ${sources.join(', ')}) → ${outFile}`)