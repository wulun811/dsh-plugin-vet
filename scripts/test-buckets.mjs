#!/usr/bin/env node
/**
 * 套件分桶统计（round-17 起入库）：从 vitest JSON 产物（--reporter=json --outputFile）按
 * 文件名→区域显式映射算出五个套件桶（scanner / runtime / plugins / self / qa），供
 * site/index.html 的 testsChart 使用。映射规则固定在此文件——站点数字可复现、可追溯。
 *
 * 用法：
 *   npx vitest run --reporter=json --outputFile=/tmp/vj.json
 *   node scripts/test-buckets.mjs /tmp/vj.json
 * 输出：JSON { total, buckets: { scanner, runtime, plugins, self, qa }, byFile }
 */
import { readFileSync } from 'node:fs'

const VJ = process.argv[2]
if (VJ === undefined) {
  console.error('用法: node scripts/test-buckets.mjs <vitest-json>')
  process.exit(2)
}
const j = JSON.parse(readFileSync(VJ, 'utf8'))
const files = j.testResults.map(r => ({ name: r.name.split('/').pop(), n: r.assertionResults.length }))

/** 区域映射（顺序即优先级；文件名唯一，规则互斥）。 */
function bucketOf(name) {
  // self：vet 自身存储/自钉扎/契约/门禁基础设施
  if (/^(self-scan|self-pin|pkg-root|pack-integrity|contract|content-baseline|baseline-reconcile|scan-summaries|archive-compat|metrics-history|config-diff|config-profile|status-merge|dismiss-restore-cross-session|gate)\.test/.test(name)) return 'self'
  // qa：语料/变异/复审轮/审计档案
  if (/^(mutant-score|review-round\d|review-fixes|audit-summary|v2-ghost-zombie|bundle|integration-dsh-so)\.test/.test(name)) return 'qa'
  // plugins：插件级流程（矩阵/内部插件/版本差异/功能面）
  if (/^(plugin|plugins-matrix|n1-capability|n6-version-diff|v020-[a-z-]+|v2-forensics|v2-label|v2-m1-wiring|rc8-subpath|vet-tools-render|third-party-baseline|radar-resolve-hardening|registry-verify-hardening)\.test/.test(name)) return 'plugins'
  // scanner：静态引擎/规则/解码/供应链面
  if (/^(scanner[a-z-]*|hardening-rules|r\d+[-a-z0-9]*|n2-decode|n5-dynamic-provenance|osv-budget|transitive-deps|capability-[a-z-]+|round16-regressions|abnormal-flow)\.test/.test(name)) return 'scanner'
  // runtime：T1/T2 守卫/归因/蜜罐/网络观测
  return 'runtime'
}

const buckets = { scanner: 0, runtime: 0, plugins: 0, self: 0, qa: 0 }
const byFile = {}
for (const f of files) {
  const b = bucketOf(f.name)
  buckets[b] += f.n
  byFile[f.name] = { bucket: b, tests: f.n }
}
const total = files.reduce((a, x) => a + x.n, 0)
console.log(JSON.stringify({
  total,
  passed: j.numPassedTests ?? undefined,
  failed: j.numFailedTests ?? undefined,
  pending: j.numPendingTests ?? undefined,
  todo: j.numTodoTests ?? undefined,
  buckets,
  byFile,
}, null, 1))