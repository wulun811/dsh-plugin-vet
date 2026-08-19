#!/usr/bin/env node
/**
 * prepublish 完整性检查：验证所有运行时依赖都在 package.json files 里
 * 
 * 检查项：
 * 1. resolveVetFile('xxx') 引用的文件
 * 2. resolvePkgRoot() 读取的文件（如 AUDIT_PROTOCOL.md）
 * 3. 对比 package.json files 字段
 */

import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = process.cwd()

// 1. 扫描源码中的 resolveVetFile 调用
function findResolveVetFileCalls() {
  try {
    const src = execSync('grep -r "resolveVetFile(" src/ --include="*.ts"', { cwd: ROOT, encoding: 'utf8' })
    const calls = []
    for (const line of src.split('\n')) {
      const match = /resolveVetFile\(['"]([^'"]+)['"]\)/.exec(line)
      if (match) calls.push(match[1])
    }
    return [...new Set(calls)]
  } catch {
    return []
  }
}

// 2. 扫描 resolvePkgRoot 读取的文件
function findResolvePkgRootReads() {
  try {
    const src = execSync('grep -r "resolvePkgRoot()" src/ --include="*.ts" -A 1', { cwd: ROOT, encoding: 'utf8' })
    const files = []
    const patterns = [
      /join\(resolvePkgRoot\(\),\s*['"]([^'"]+)['"]\)/g,
      /resolvePkgRoot\(\)\s*\+\s*['"]\/([^'"]+)['"]/g
    ]
    for (const pattern of patterns) {
      let match
      while ((match = pattern.exec(src)) !== null) {
        files.push(match[1])
      }
    }
    return [...new Set(files)]
  } catch {
    return []
  }
}

// 3. 读取 package.json files 字段
function getFilesField() {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  return pkg.files || []
}

// 4. 检查文件是否被 files 字段覆盖
// file: resolveVetFile 的参数，如 'scanner-bin/index.js'
// 实际路径是 'lib/scanner-bin/index.js'
function isFileCovered(relPath, filesField) {
  const fullPath = 'lib/' + relPath
  for (const pattern of filesField) {
    // 精确匹配
    if (pattern === fullPath) return true
    // 目录前缀匹配：pattern 是 'lib/guard'，fullPath 是 'lib/guard/xxx.js'
    if (fullPath.startsWith(pattern + '/')) return true
    // 目录前缀匹配：pattern 是 'lib/scanner-bin'，fullPath 是 'lib/scanner-bin/index.js'
    if (fullPath.startsWith(pattern + '/')) return true
  }
  return false
}

// 主逻辑
console.log('🔍 检查运行时依赖完整性...\n')

const vetFiles = findResolveVetFileCalls()
const rootFiles = findResolvePkgRootReads()
const filesField = getFilesField()

let hasError = false

console.log('📦 resolveVetFile 调用（需要 lib/<path>）：')
for (const file of vetFiles) {
  const covered = isFileCovered(file, filesField)
  console.log(`  ${covered ? '✓' : '✗'} lib/${file}`)
  if (!covered) hasError = true
}

console.log('\n📦 resolvePkgRoot 读取（需要根目录文件）：')
for (const file of rootFiles) {
  const covered = filesField.includes(file)
  console.log(`  ${covered ? '✓' : '✗'} ${file}`)
  if (!covered) hasError = true
}

if (hasError) {
  console.error('\n❌ 完整性检查失败：部分运行时文件未在 package.json files 中')
  console.error('请检查 package.json 的 files 字段')
  process.exit(1)
} else {
  console.log('\n✅ 完整性检查通过')
}
