#!/usr/bin/env node
/**
 * 变异语料击杀率评测（muteval 方法论 → 安全扫描器 QA 面）。
 *
 * 评测面：静态引擎（lib/scanner-bin/engine.js 的 scan，与 test/plugins-matrix.test.ts 同一入口）
 * 被测系统：语料 mutants（test/mutants.manifest.json 为唯一权威基线）
 * 击杀判据（恶意 mutants）：任一 expect.rules 命中 = 击杀（规则命中而非 verdict——
 *   多规则 severity 不升级 verdict，如 R19 恒 info、间接 require medium）
 * 良性 controls：实际 verdict 必须 clean，否则计 retained（precision 反项）
 *
 * 用法：
 *   node scripts/mutant-score.mjs            # 报告模式：输出 score card，exit 0
 *   node scripts/mutant-score.mjs --gate     # 门禁模式：任一存活/任一误杀/任一评测失败 → exit 1
 *   node scripts/mutant-score.mjs --json out.json   # 产物路径（默认 reports/mutant-score.json）
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join, dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const { scan } = await import('../lib/scanner-bin/engine.js')

const args = process.argv.slice(2)
const GATE = args.includes('--gate')
const jsonArg = args.indexOf('--json')
const JSON_PATH = jsonArg >= 0 && args[jsonArg + 1] !== undefined
  ? join(ROOT, args[jsonArg + 1])
  : join(ROOT, 'reports', 'mutant-score.json')

// round-6 review：manifest 路径可被环境变量覆盖（相对 ROOT；绝对路径原样使用——测试友好）
const MANIFEST_PATH = process.env.VET_MUTANT_MANIFEST !== undefined
  ? (isAbsolute(process.env.VET_MUTANT_MANIFEST)
      ? process.env.VET_MUTANT_MANIFEST
      : join(ROOT, process.env.VET_MUTANT_MANIFEST))
  : join(ROOT, 'test', 'mutants.manifest.json')
const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'))
// 最小结构校验：坏 manifest 直接报错退出（exit 2），而不是带着畸形数据产出误导性报告
const badShape = (msg) => { console.error('✗ manifest 结构非法: ' + msg); process.exit(2) }
if (manifest === null || typeof manifest !== 'object') badShape('根必须是对象')
for (const key of ['mutants', 'controls']) {
  if (!Array.isArray(manifest[key])) badShape(key + ' 必须是数组')
}
for (const m of manifest.mutants) {
  if (typeof m.id !== 'string' || m.id === '') badShape('mutant 缺 id')
  if (!Array.isArray(m.refs) || m.refs.length === 0) badShape(m.id + ': refs 必须是非空数组')
  if (!Array.isArray(m.expect?.rules) || m.expect.rules.length === 0) badShape(m.id + ': expect.rules 必须是非空数组')
}
const abs = (p) => join(ROOT, p)

/** 评测一条语料（kind files | code），返回 { ok, verdict, findings }。
 * round-6 review：files 语料缺失时显式抛错进 errors 清单——engine 对不存在文件静默返回
 * 空 clean 报告，若不拦截，manifest 路径笔误会伪装成「存活者」（检测缺口）而非「数据错误」。 */
function evaluate(entry) {
  for (const ref of entry.refs ?? []) {
    if (!existsSync(abs(ref))) throw new Error('语料文件不存在: ' + ref)
  }
  if (entry.kind === 'code') {
    const code = readFileSync(abs(entry.refs[0]), 'utf8')
    return scan({ kind: 'code', language: entry.language ?? 'js', runtime: entry.runtime ?? 'host', code })
  }
  return scan({ kind: 'files', files: entry.refs.map(abs) })
}

/** 击杀判定：恶意 mutant 任一 expect.rules 命中 */
function killedBy(rules, findings) {
  const hit = new Set()
  for (const f of findings) if (rules.includes(f.rule)) hit.add(f.rule)
  return hit
}

// —— 评测 ——
const results = { mutants: [], controls: [], errors: [], skipped: [] }
for (const m of manifest.mutants ?? []) {
  if (m.layer === 'runtime') {
    results.skipped.push({ id: m.id, layer: 'runtime' })
    continue
  }
  // round-6 review：单条评测失败（语料缺失/读失败/scan 异常）进 errors 而不是崩脚本——
  // gate 下 fail-closed exit 1，报告模式也给出完整 survivor/错误清单
  try {
    const res = evaluate(m)
    if (!res.ok || res.report === undefined) {
      results.errors.push({ id: m.id, error: res.error ?? 'scan failed' })
      continue
    }
    const hit = killedBy(m.expect.rules, res.report.findings)
    results.mutants.push({
      id: m.id, name: m.name ?? '', evasion: m.evasion ?? '',
      rules: m.expect.rules, hit: [...hit],
      killed: hit.size > 0,
      verdict: res.report.verdict,
    })
  } catch (error) {
    results.errors.push({ id: m.id, error: error instanceof Error ? error.message : String(error) })
  }
}
for (const c of manifest.controls ?? []) {
  try {
    const res = evaluate(c)
    if (!res.ok || res.report === undefined) {
      results.errors.push({ id: c.id, error: res.error ?? 'scan failed' })
      continue
    }
    results.controls.push({
      id: c.id, name: c.name ?? '',
      clean: res.report.verdict === 'clean',
      verdict: res.report.verdict,
    })
  } catch (error) {
    results.errors.push({ id: c.id, error: error instanceof Error ? error.message : String(error) })
  }
}

// —— score card ——
const mutants = results.mutants
const survivors = mutants.filter(m => !m.killed)
const retained = results.controls.filter(c => !c.clean)
const killedCount = mutants.length - survivors.length

// 按规则聚合击杀矩阵（防刷分：矩阵按 manifest 的应杀集合算，非全局均值可注水）
const ruleMatrix = new Map()
for (const m of mutants) {
  for (const r of m.rules) {
    const row = ruleMatrix.get(r) ?? { rule: r, required: 0, killed: 0 }
    row.required += 1
    if (m.hit.includes(r)) row.killed += 1
    ruleMatrix.set(r, row)
  }
}

const lines = []
lines.push('=== vet mutant-score ===')
lines.push(`评测面: 静态引擎 (engine.scan) | 恶意 mutants ${mutants.length} / 良性 controls ${results.controls.length}`)
lines.push(`击杀率: ${killedCount}/${mutants.length}${mutants.length > 0 ? ` (${(killedCount / mutants.length * 100).toFixed(0)}%)` : ''}`)
if (ruleMatrix.size > 0) {
  lines.push('按规则击杀矩阵 (required/killed):')
  for (const row of [...ruleMatrix.values()].sort((a, b) => a.rule.localeCompare(b.rule))) {
    const ok = row.killed >= row.required ? '✓' : '✗'
    lines.push(`  ${ok} ${row.rule.padEnd(4)} ${row.killed}/${row.required}`)
  }
}
lines.push(`良性对照组 retained: ${retained.length}/${results.controls.length}`)
if (results.skipped.length > 0) lines.push(`runtime 面未评测（静态 gate 跳过）: ${results.skipped.map(s => s.id).join(', ')}`)

for (const m of mutants) {
  lines.push(`${m.killed ? '✓击杀' : '◯存活'} ${m.id} ${m.name}  verdict=${m.verdict}  命中=${m.hit.join(',') || '-'}`)
}
for (const s of survivors) {
  lines.push(`  └ 存活者 ${s.id}: 预期 ${s.rules.join('/')}，未命中`)
}
for (const c of results.controls) {
  lines.push(`${c.clean ? '✓干净' : '✗误杀'} ${c.id} ${c.name}  verdict=${c.verdict}`)
}
for (const e of results.errors) lines.push(`✗评测失败 ${e.id}: ${e.error}`)

const out = { gate: GATE, mutants, controls: results.controls, survivors, retained, ruleMatrix: [...ruleMatrix.values()], errors: results.errors, skipped: results.skipped }
try {
  mkdirSync(dirname(JSON_PATH), { recursive: true })
  writeFileSync(JSON_PATH, JSON.stringify(out, null, 2) + '\n')
  lines.push(`产物: ${JSON_PATH}`)
} catch (err) {
  lines.push(`✗ 无法写产物 ${JSON_PATH}: ${err.message}`)
}

console.log(lines.join('\n'))

// —— 门禁判定（fail-closed：评测失败也算失败）——
if (GATE) {
  // round-16（QA-3）：规则击杀矩阵也进门禁——任一规则行 killed < required（存在应杀
  // mutant 未被该规则实际击杀，可能靠同 mutant 的其他规则命中注水）→ fail。矩阵按
  // manifest 应杀集合聚合（非全局均值），保证每条规则的面都有独立击杀证据。
  const weakRows = [...ruleMatrix.values()].filter(row => row.killed < row.required)
  const fail = survivors.length > 0 || retained.length > 0 || results.errors.length > 0 || weakRows.length > 0
  if (fail) {
    console.error('\n✗ mutant gate FAILED')
    for (const row of weakRows) console.error(`  ✗ 规则行未满: ${row.rule} ${row.killed}/${row.required}`)
    process.exit(1)
  }
  console.log('\n✓ mutant gate OK')
}