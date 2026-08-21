#!/usr/bin/env node
// 发布自扫门禁（④）：① 当前版本已钉扎且本地字节匹配；② 已使用但未声明的 decisive 能力
// （critical/high retained）→ 拒绝发布——保证"能发出去的版本，声明一定完整"。
// 直跑前提：已 npm run build （lib/ 就绪）。
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const { scan } = await import('../lib/scanner/client.js')
const { annotateSelfScan } = await import('../lib/report/self-scan.js')
const { hashScanFiles, pinStateFor, loadSelfPins } = await import('../lib/report/self-pin.js')

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const version = pkg.version
// 扫描集 = vet 本体自扫权威范围（src/report/self-scope.ts），与工具/钉扎一致。
import { listSelfSourceFiles } from '../lib/report/self-scope.js'
const files = listSelfSourceFiles(ROOT)
const resp = await scan({ kind: 'files', files, targetKind: 'generic', runtime: 'host' }, { timeoutMs: 60000 })
if (!resp.ok || resp.report === undefined) {
  console.error('vet: 本体自扫失败：', resp.error ?? 'unknown')
  process.exit(2)
}
const pins = loadSelfPins()
const computed = hashScanFiles(files, ROOT)
const pin = pinStateFor(pins, version, computed)
const self = annotateSelfScan(resp.report.findings, { pin, version })

let fail = false
if (pin === 'unpinned') {
  fail = true
  console.error(`✗ 版本 ${version} 未钉扎：先 npm run gen:self-pin 并提交 vet-self-pins.json`)
}
if (pin === 'dev-tree') {
  fail = true
  console.error('✗ 本地扫描集与发布钉扎不符（改码后未重新 gen:self-pin / 未提交构建产物）')
}
const retainedDecisive = self.annotation.retained.filter(f => f.severity === 'critical' || f.severity === 'high')
if (retainedDecisive.length > 0) {
  fail = true
  console.error(`✗ 已使用但未声明的 decisive 能力 ${retainedDecisive.length} 条（发布后本体自扫 retain 红色）：`)
  for (const f of retainedDecisive.slice(0, 10)) {
    const loc = f.file !== undefined ? ` (${f.file}${f.line !== undefined ? ':' + f.line : ''})` : ''
    console.error(`   [${f.rule}] ${f.severity} ${f.message}${loc}`)
  }
}
if (fail) {
  console.error('vet: 自扫门禁 FAILED——修复后重跑')
  process.exit(1)
}
console.log(`vet: 自扫门禁 OK — v${version} pin=${pin} | findings=${resp.report.findings.length} declared=${self.annotation.declared} datasetRef=${self.annotation.datasetSelfRef} devFixtures=${self.annotation.devFixtures} retained(非 decisive)=${self.annotation.retained.filter(f => f.severity !== 'critical' && f.severity !== 'high').length}`)
