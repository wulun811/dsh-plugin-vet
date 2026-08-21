#!/usr/bin/env node
// 生成/刷新 vet-self-pins.json：当前版本 → 扫描集 sha256。发布前运行（prepublish 前本地构建过 lib）。
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const { hashScanFiles } = await import('../lib/report/self-pin.js')

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const version = pkg.version
if (typeof version !== 'string' || version === '') {
  console.error('vet: package.json 缺少 version，无法钉扎')
  process.exit(1)
}
// 钉扎范围 = vet 本体自扫权威范围（src/report/self-scope.ts），与工具/门禁一致。
import { listSelfSourceFiles } from '../lib/report/self-scope.js'
const files = listSelfSourceFiles(ROOT)
const hash = hashScanFiles(files, ROOT)
const pinPath = join(ROOT, 'vet-self-pins.json')
const existing = existsSync(pinPath) ? JSON.parse(readFileSync(pinPath, 'utf8')) : { pins: {} }
existing.pins = existing.pins ?? {}
existing.pins[version] = hash
writeFileSync(pinPath, JSON.stringify(existing, null, 2) + '\n')
console.log(`vet: pinned v${version} -> ${hash} (${files.length} 个源文件进入扫描集)`)
