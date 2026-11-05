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
import { readFileSync, writeFileSync, mkdirSync, existsSync, mkdtempSync, readdirSync, copyFileSync, statSync, rmSync } from 'node:fs'
import { join, dirname, isAbsolute } from 'node:path'
import { tmpdir } from 'node:os'
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

/**
 * 语料镜像（0.5.15）：把 `test/fixtures/**` 复制到临时目录下的中性路径再评测。
 *
 * 为什么必须这么做：引擎按**路径段**判定测试/CI 文件（`rules/process-direct.ts`
 * `isTestOrCiFile`：`test`/`tests`/`spec`/`specs`/`__tests__`/`.github`），命中即把
 * R3/R13/R20 一类整条降成 info。语料原本都在 `test/fixtures/` 下，于是门禁一直在测
 * **一个真实恶意包永远拿不到的降级路径**：
 *
 *   test/fixtures/exfil-discord-webhook.fixture.js → R13:info, verdict=clean
 *   （同样字节复制到中性路径）                     → R13:high, verdict=suspicious
 *
 * 后果不是"分数难看"，是**判据测错了对象**：34 条 mutants 里 10 条命中时 verdict 仍是
 * clean，而记分卡照印 100%。镜像之后，门禁测的是"这个逃逸形态放到一个真实包里会不会被
 * 抓住"，那才是它宣称测的东西。
 *
 * 结构保留：整个 `test/fixtures` 树按原相对结构复制，多文件语料（包根 package.json +
 * 源码）之间的目录关系不变——R12/R16 依赖包根推导，打散就测不出来了。
 */
function mirrorCorpus() {
  const srcRoot = join(ROOT, 'test', 'fixtures')
  const dstRoot = mkdtempSync(join(tmpdir(), 'vet-mutant-corpus-'))
  // Windows 兼容：本机 Node 22.19.0 的 fs.cpSync({recursive:true}) 直接 fail-fast
  // （0xC0000409，连空目录也复现），改用 readdir+copyFile 的等价实现（不保留 mtime/权限，
  // 语料评测不依赖这两者）。
  const copyTree = (src, dst) => {
    if (statSync(src).isDirectory()) {
      mkdirSync(dst, { recursive: true })
      for (const name of readdirSync(src)) copyTree(join(src, name), join(dst, name))
    } else {
      copyFileSync(src, dst)
    }
  }
  copyTree(srcRoot, dstRoot)
  corpusDirs.push(dstRoot)
  return (ref) => {
    const rel = ref.startsWith('test/fixtures/') ? ref.slice('test/fixtures/'.length) : undefined
    if (rel === undefined) {
      // 语料必须全部在 test/fixtures 下——否则镜像不覆盖它，评测会回落到降级路径且**静默**
      throw new Error('语料必须位于 test/fixtures/ 下（镜像只覆盖这棵树）: ' + ref)
    }
    return join(dstRoot, rel)
  }
}

/** 镜像出来的临时根（退出时清理）。 */
const corpusDirs = []
let mirrorRef
/** 断言：送进引擎的每条路径都不得含测试/CI 段——否则本条门禁又退回到测降级路径。 */
function assertNeutral(p) {
  const segs = p.replace(/\\/g, '/').split('/')
  const bad = segs.find(s => ['test', 'tests', 'spec', 'specs', '__tests__', '.github'].includes(s))
  if (bad !== undefined) throw new Error('语料路径含测试/CI 段 "' + bad + '"，会触发降级、门禁测不到真实判定: ' + p)
}

/** 评测一条语料（kind files | code），返回 { ok, verdict, findings }。
 * round-6 review：files 语料缺失时显式抛错进 errors 清单——engine 对不存在文件静默返回
 * 空 clean 报告，若不拦截，manifest 路径笔误会伪装成「存活者」（检测缺口）而非「数据错误」。 */
function evaluate(entry) {
  for (const ref of entry.refs ?? []) {
    if (!existsSync(abs(ref))) throw new Error('语料文件不存在: ' + ref)
  }
  const mirrored = (entry.refs ?? []).map(ref => mirrorRef(ref))
  for (const p of mirrored) assertNeutral(p)
  if (entry.kind === 'code') {
    return scan({ kind: 'code', language: entry.language ?? 'js', runtime: entry.runtime ?? 'host', code: readFileSync(mirrored[0], 'utf8') })
  }
  return scan({ kind: 'files', files: mirrored })
}

/** 击杀判定：恶意 mutant 任一 expect.rules 命中 */
function killedBy(rules, findings) {
  const hit = new Set()
  for (const f of findings) if (rules.includes(f.rule)) hit.add(f.rule)
  return hit
}

// —— 评测 ——
// 0.5.15：先把语料镜像到中性路径，再开始评测——语料原本住 `test/fixtures/` 下，
// 引擎按路径段把测试/CI 文件整条降级，门禁因此一直在测真实恶意包拿不到的降级路径。
mirrorRef = mirrorCorpus()
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
    // 0.5.15：**「规则响过」不等于「用户会被告警」**。
    // 多数 R 规则只降分不升级 verdict（R15/R16/R17 单动词/R18/R19 恒 info，R5/R9-ReDoS
    // medium），所以命中但 verdict=clean 是合法形态。但它必须**在 manifest 里显式声明**
    // （`expect.advisory`），否则就是一条「记分卡 100% 而用户什么也看不到」的击杀——
    // 0.5.14 及以前有 10 条属于这一类，全部静默进了 100%。现在未声明的一律进 gate 失败。
    results.mutants.push({
      id: m.id, name: m.name ?? '', evasion: m.evasion ?? '',
      rules: m.expect.rules, hit: [...hit],
      killed: hit.size > 0,
      verdict: res.report.verdict,
      advisory: m.expect.advisory,
      // 命中却不升级、又没声明理由 = 记账缺口（gate 会拦）
      unexplainedClean: hit.size > 0 && res.report.verdict === 'clean' && m.expect.advisory === undefined,
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
// 0.5.15：把「击杀」拆成两栏——真会告警的，与只降分的。合起来印 100% 会让人以为
// 34 条全都会在用户面前亮红。分开印，两个数字各自可被追问。
const decisive = mutants.filter(m => m.killed && m.verdict !== 'clean').length
const advisory = mutants.filter(m => m.killed && m.verdict === 'clean').length
lines.push(`击杀构成: 判定级 ${decisive} 条（verdict 会升级） / 提示级 ${advisory} 条（规则命中但不升级，manifest 已声明 advisory）`)
if (results.skipped.length > 0) lines.push(`runtime 面未评测（静态 gate 跳过）: ${results.skipped.map(s => s.id).join(', ')}`)

for (const m of mutants) {
  const tier = m.verdict === 'clean' ? '提示级' : '判定级'
  lines.push(`${m.killed ? '✓击杀' : '◯存活'} ${m.id} ${m.name}  verdict=${m.verdict} ${tier}  命中=${m.hit.join(',') || '-'}`)
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
  // 0.5.15：命中却不升级 verdict、manifest 又没写 `expect.advisory` 的条目 = 记账缺口。
  // 它们正是 0.5.14 里"记分卡 100%、用户什么也没看到"的那一批。要过门禁，必须在
  // manifest 里写明"这条规则按设计只降分"，让人能一眼看见两栏各有多少条。
  const unexplained = results.mutants.filter(m => m.unexplainedClean)
  const fail = survivors.length > 0 || retained.length > 0 || results.errors.length > 0
    || weakRows.length > 0 || unexplained.length > 0
  if (fail) {
    console.error('\n✗ mutant gate FAILED')
    for (const row of weakRows) console.error(`  ✗ 规则行未满: ${row.rule} ${row.killed}/${row.required}`)
    for (const m of unexplained) {
      console.error(`  ✗ 未声明的"干净击杀": ${m.id} ${m.name}（命中 ${m.hit.join('/')} 但 verdict=clean，expect.advisory 缺失）`)
    }
    process.exit(1)
  }
  console.log(`\n✓ mutant gate OK — 判定级 ${decisive} · 提示级 ${advisory}（均已声明 advisory）`)
}