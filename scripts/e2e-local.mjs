#!/usr/bin/env node
/**
 * dsh-plugin-vet 本地 e2e（手动脚本）。
 * 用法：node scripts/e2e-local.mjs [--profile <name>]
 * 无 DEEPSEEK_API_KEY 时自动跳过 LLM 相关断言（同 DSH test:e2e 惯例）。
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

const ROOT = resolve(import.meta.dirname, '..')
const FIX = join(ROOT, 'test', 'fixtures')
const SCANNER = join(ROOT, 'lib', 'scanner-bin', 'index.js')
const HAS_KEY = Boolean(process.env.DEEPSEEK_API_KEY)

const args = process.argv.slice(2)
const profile = args.includes('--profile') ? args[args.indexOf('--profile') + 1] : process.env.VET_E2E_PROFILE ?? 'vet-test'

let failed = 0
const check = (name, ok, detail = '') => {
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? ' — ' + detail : ''}`)
  if (!ok) failed++
}

const scan = (request) => {
  const r = spawnSync(process.execPath, [SCANNER], { input: JSON.stringify(request), encoding: 'utf8' })
  return JSON.parse(r.stdout.trim())
}

console.log(`e2e: profile=${profile} DEEPSEEK_API_KEY=${HAS_KEY ? 'present' : 'absent'}`)

// ---- 1) scanner 对 3 个正例 fixture 返回 critical（无 key 也可跑） ----
// 正例按各自 runtime 语义扫描：workflow/动态插件 → sandbox；run_code → host（R3 分级）
for (const [fixture, lang, runtime] of [
  ['escape-workflow.js', 'js', 'sandbox'],
  ['escape-dynamic-plugin.js', 'js', 'sandbox'],
  ['escape-run-code.ts', 'ts', 'host'],
]) {
  const code = readFileSync(join(FIX, fixture), 'utf8')
  const res = scan({ kind: 'code', language: lang, runtime, code })
  check(`scan_plugin 语义：${fixture} → critical`, res.ok && res.report?.verdict === 'critical', res.report?.verdict)
}

// ---- 2) 安装链路状态（无 key 也可跑） ----
const profileDir = join(homedir(), '.dsh', 'profiles', profile)
if (existsSync(join(profileDir, 'package.json'))) {
  const manifest = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8'))
  check('profile bundles 含 @jieai/dsh-plugin-vet', (manifest.dsh?.profile?.bundles ?? []).includes('@jieai/dsh-plugin-vet'))
  check('profile 依赖已装', Boolean(manifest.dependencies?.['@jieai/dsh-plugin-vet']))
} else {
  check(`profile ${profile} 存在`, false, '未找到 profile 目录')
}

// ---- 3) report/deny 拦截语义（通过 tools/execute 守卫单测覆盖；此处冒烟 scanner 侧） ----
{
  const evil = readFileSync(join(FIX, 'escape-run-code.ts'), 'utf8')
  const res = scan({ kind: 'code', language: 'ts', runtime: 'host', code: evil })
  check('run_code 场景（host）→ critical（deny 会拦截）', res.report?.verdict === 'critical', res.report?.verdict)
}

// ---- 4) LLM 相关断言（需 DEEPSEEK_API_KEY + 真实 profile） ----
if (HAS_KEY) {
  console.log('\n— LLM 相关（需真实 harness 会话，按 profile 结构执行）—')
  const boot = spawnSync('dsh', ['--profile', profile, '用 scan_plugin 扫描一段含 TextEncoder.constructor("return process") 的代码并报告 verdict'], {
    encoding: 'utf8', timeout: 300_000, shell: process.platform === 'win32',
  })
  const out = (boot.stdout ?? '') + (boot.stderr ?? '')
  check('会话可启动', boot.status === 0, `exit=${boot.status}`)
  check('输出含 scan_plugin 评分卡', /verdict: critical/.test(out))
  const run = spawnSync('dsh', ['--profile', profile, '用 cordis_run 定义并运行一个动态插件：TextEncoder.constructor("return process")().cwd()'], {
    encoding: 'utf8', timeout: 300_000, shell: process.platform === 'win32',
  })
  const rout = (run.stdout ?? '') + (run.stderr ?? '')
  check('cordis_run 被 VET 前缀标记', /VET cordis_run: critical|VET BLOCKED/.test(rout))
} else {
  console.log('\n— 无 DEEPSEEK_API_KEY，跳过 LLM 与会话相关断言（4 场景中的会话级部分）—')
}

console.log(`\ne2e ${failed === 0 ? 'PASS' : 'FAIL'}（${failed} 项失败）`)
process.exit(failed === 0 ? 0 : 1)
