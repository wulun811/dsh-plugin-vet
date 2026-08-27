#!/usr/bin/env node
/**
 * 断言计数（round-18 起入库）：对 test/**​/*.test.ts 做词法扫描，统计断言调用。
 * 口径固定在此文件，使 README/文档中的断言数字可复现、可追溯：
 *   - standalone：独立断言调用 `expect(`（参数域内的 expect 不重复计入）；
 *   - helper：链式匹配器助手 `expect.xxx(`（如 expect.any / expect.objectContaining /
 *     expect.stringContaining / expect.arrayContaining）——它们嵌在别的断言里作参数，
 *     不算独立断言；实测消除非断言用法，其余用法若出现也如实计入；
 *   - 注释、字符串/模板字面量内的 `expect(` 一律不计数。
 * 已知边界（dev 普查工具，如实记录）：不识别正则字面量——`/["']/` 这类含引号的正则会让
 * 字符串态失步；test/ 现无此形态，且计数与 `\bexpect\(` 纯 grep 双通道交叉一致（2660/2660）。
 *
 * 用法：
 *   node scripts/count-assertions.mjs
 * 输出：JSON { total (=standalone), helper, byFile } 到 stdout。
 */
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const TEST_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'test')

const isIdent = c => /[A-Za-z0-9_$]/.test(c)
const isWs = c => /\s/.test(c)

/**
 * 词法扫描单个文件：跳过注释与字符串字面量，识别标识符 `expect` 后跟 `(`（独立）
 * 或 `.xxx(`（链式助手）。返回 { standalone, helper }。
 */
function scan(src) {
  let standalone = 0
  let helper = 0
  let i = 0
  const n = src.length

  const skipString = quote => {
    i++ // 开引号
    while (i < n) {
      if (src[i] === '\\') { i += 2; continue }
      if (src[i] === quote) { i++; break }
      i++
    }
  }

  while (i < n) {
    const c = src[i]
    if (c === '/' && src[i + 1] === '/') {           // 行注释
      while (i < n && src[i] !== '\n') i++
      continue
    }
    if (c === '/' && src[i + 1] === '*') {           // 块注释
      i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++
      i = Math.min(i + 2, n)
      continue
    }
    if (c === "'" || c === '"' || c === '`') {       // 字符串/模板
      skipString(c)
      continue
    }
    if (isIdent(c)) {                                // 标识符
      let j = i
      while (j < n && isIdent(src[j])) j++
      if (src.slice(i, j) === 'expect') {
        let k = j
        while (k < n && isWs(src[k])) k++
        if (src[k] === '(') {                        // expect( → 独立断言
          standalone++
          i = k + 1
          continue
        }
        if (src[k] === '.') {                        // expect.xxx(
          let m = k + 1
          while (m < n && isWs(src[m])) m++
          let t = m
          while (t < n && isIdent(src[t])) t++
          let u = t
          while (u < n && isWs(src[u])) u++
          if (t > m && src[u] === '(') {
            helper++
            i = u + 1
            continue
          }
        }
      }
      i = j
      continue
    }
    i++
  }
  return { standalone, helper }
}

const files = readdirSync(TEST_DIR).filter(f => f.endsWith('.test.ts')).sort()
const byFile = {}
let total = 0
let helperTotal = 0
for (const f of files) {
  const src = readFileSync(join(TEST_DIR, f), 'utf8')
  const r = scan(src)
  byFile[f] = r
  total += r.standalone
  helperTotal += r.helper
}
console.log(JSON.stringify({ total, helper: helperTotal, byFile }, null, 1))