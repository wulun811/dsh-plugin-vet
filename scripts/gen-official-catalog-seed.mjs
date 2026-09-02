#!/usr/bin/env node
/**
 * 生成官方包目录种子（M1，0.3.4）：从 dsh-src/packages 的 package.json 收集
 * @deepseek-ai/* 包名，输出 src/guards/official-catalog-seed.ts。
 *
 * 为什么是种子而非唯一真值：registry scope 枚举才是在线权威（refreshOfficialCatalogFromRegistry
 * 兜底）；种子保证纯离线/首启时目录非空——「官方所有的包咱们都有」在代码仓库侧的具体形态
 * 就是 dsh-src/packages 这份官方源码目录树。dsh-src 更新后重跑本脚本即可（见 gen-self-pin 同款纪律）。
 *
 * 用法：node scripts/gen-official-catalog-seed.mjs
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(new URL('.', import.meta.url))
const root = join(here, '..')
const packagesRoot = join(root, 'dsh-src', 'packages')
const outFile = join(root, 'src', 'guards', 'official-catalog-seed.ts')

const names = new Set()
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
collect(packagesRoot)

const sorted = [...names].sort()
const lines = sorted.map(n => `  '${n}',`).join('\n')
const header = `/**
 * 官方包目录种子（M1，0.3.4）：从 dsh-src/packages 收集的 @deepseek-ai/* 全量包名。
 * 生成方式：node scripts/gen-official-catalog-seed.mjs（dsh-src 更新后重跑）。
 * 语义：目录内 = 可信官方名候选（仍要求与官方哈希一致才入内容信任锚）；
 *       目录外多出来的 @deepseek-ai/* = 冒充或官方新包（黄牌观察，不拦）。
 * 运行时在线刷新（registry scope 枚举）结果与种子合并后落盘覆盖层，见 official-catalog.ts。
 */
export const OFFICIAL_CATALOG_SEED: readonly string[] = [
${lines}
]
`
writeFileSync(outFile, header)
console.log(`official-catalog-seed.ts: ${sorted.length} names → ${outFile}`)