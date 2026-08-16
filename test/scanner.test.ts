import { describe, expect, it } from 'vitest'
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan, scanWithOsv } from '../lib/scanner-bin/engine.js'
import { queryOsv } from '../lib/scanner-bin/osv.js'
import { computeScore, computeVerdict } from '../lib/scanner-bin/score.js'
import { ENGINE_VERSION } from '../lib/scanner-bin/protocol.js'
import { cacheKey, readCached, writeCached } from '../lib/scanner-bin/cache.js'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

const FIX = join(import.meta.dirname, 'fixtures')
const fixture = (name: string): string => readFileSync(join(FIX, name), 'utf8')

function codeRequest(overrides: Partial<ScanRequest>): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string, severity?: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule && (severity === undefined || f.severity === severity))
}

// ---------------------------------------------------------------------------
// fixture matrix
// ---------------------------------------------------------------------------

describe('fixture matrix', () => {
  it('escape-workflow.js → R1 critical, no R3 (no process identifier), verdict critical', () => {
    const res = scan(codeRequest({ code: fixture('escape-workflow.js'), runtime: 'sandbox' }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.verdict).toBe('critical')
    expect(findingOf(r, 'R1', 'critical')).toBeDefined()
    expect(findingOf(r, 'R3')).toBeUndefined()
    expect(findingOf(r, 'R6')).toBeDefined() // 字符串特征 info
  })

  it('escape-dynamic-plugin.js → R1 + R4 critical, verdict critical', () => {
    const res = scan(codeRequest({ code: fixture('escape-dynamic-plugin.js'), runtime: 'sandbox' }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.verdict).toBe('critical')
    expect(findingOf(r, 'R1', 'critical')).toBeDefined()
    expect(findingOf(r, 'R4', 'critical')).toBeDefined()
  })

  it('escape-run-code.ts (host) → R3 critical; (sandbox) → R3 capped at high', () => {
    const code = fixture('escape-run-code.ts')
    const host = scan(codeRequest({ code, language: 'ts', runtime: 'host' }))
    expect(host.ok).toBe(true)
    expect(host.report!.verdict).toBe('critical')
    expect(findingOf(host.report!, 'R3', 'critical')).toBeDefined()

    const sandbox = scan(codeRequest({ code, language: 'ts', runtime: 'sandbox' }))
    expect(sandbox.ok).toBe(true)
    const r = sandbox.report!
    expect(r.verdict).toBe('suspicious') // R3 high 只到 suspicious
    expect(findingOf(r, 'R3', 'high')).toBeDefined()
    expect(findingOf(r, 'R3', 'critical')).toBeUndefined()
  })

  it('clean-plugin.ts → zero findings, verdict clean, staticScore ≥ 90', () => {
    const code = fixture('clean-plugin.ts')
    const res = scan(codeRequest({ code, language: 'ts', runtime: 'host' }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.findings).toHaveLength(0)
    expect(r.verdict).toBe('clean')
    expect(r.staticScore).toBeGreaterThanOrEqual(90)
  })

  it('obfuscated-concat.js → R1 likely (static concat resolution), verdict critical', () => {
    const res = scan(codeRequest({ code: fixture('obfuscated-concat.js') }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(r.verdict).toBe('critical')
    const r1 = findingOf(r, 'R1', 'critical')
    expect(r1).toBeDefined()
    expect(r1!.confidence).toBe('likely')
    expect(findingOf(r, 'R6')).toBeDefined()
  })

  it('shadowed-process.js → R3 not hit (parameter shadowing), verdict clean', () => {
    const res = scan(codeRequest({ code: fixture('shadowed-process.js') }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(findingOf(r, 'R3')).toBeUndefined()
    expect(r.verdict).toBe('clean')
  })

  it('secret-in-plugin.js → R7 high, verdict suspicious', () => {
    const res = scan(codeRequest({ code: fixture('secret-in-plugin.js') }))
    expect(res.ok).toBe(true)
    const r = res.report!
    expect(findingOf(r, 'R7', 'high')).toBeDefined()
    expect(r.verdict).toBe('suspicious')
  })
})

// ---------------------------------------------------------------------------
// scoring & verdict boundaries
// ---------------------------------------------------------------------------

describe('score & verdict', () => {
  const finding = (rule: string, severity: Finding['severity'], confidence: Finding['confidence']): Finding =>
    ({ rule, severity, confidence, message: '', evidence: '' })

  it('critical gate: one critical certain → verdict critical regardless of score', () => {
    expect(computeVerdict([finding('R1', 'critical', 'certain')])).toBe('critical')
    expect(computeScore([finding('R1', 'critical', 'certain')])).toBe(55)
  })

  it('high ≥ 1 without critical → suspicious', () => {
    expect(computeVerdict([finding('R7', 'high', 'likely')])).toBe('suspicious')
  })

  it('heuristic confidence never upgrades verdict', () => {
    // 只有 heuristic info（R6）→ clean；即使很多条也不升级
    const infos = [1, 2, 3, 4, 5].map(i => finding('R6', 'info', 'heuristic'))
    expect(computeVerdict(infos)).toBe('clean')
    expect(computeScore(infos)).toBe(100) // info 级不扣分（评分模型修正：score 只反映 decisive）
  })

  it('score floor at 0 and mixed contributions', () => {
    const many = Array.from({ length: 10 }, () => finding('R1', 'critical', 'certain'))
    expect(computeScore(many)).toBe(0)
    const mixed = [finding('R1', 'critical', 'certain'), finding('R7', 'high', 'likely'), finding('R5', 'medium', 'likely')]
    // 45 + 16 + 6.4 = 67.4 → round(32.6) = 33
    expect(computeScore(mixed)).toBe(33)
  })
})

// ---------------------------------------------------------------------------
// protocol: request validation + stdio round-trip
// ---------------------------------------------------------------------------

describe('protocol', () => {
  it('code mode without language fails loud', () => {
    const res = scan({ kind: 'code', code: 'x' })
    expect(res.ok).toBe(false)
    expect(res.error).toContain('language')
  })

  it('files mode without files fails loud', () => {
    const res = scan({ kind: 'files' })
    expect(res.ok).toBe(false)
  })

  it('invalid JSON over stdin → error response', () => {
    const bin = join(baseDir(), 'lib/scanner-bin/index.js')
    const out = spawnSync(process.execPath, [bin], { input: 'not json', encoding: 'utf8' })
    expect(out.status).toBe(0)
    const parsed = JSON.parse(out.stdout.trim())
    expect(parsed.ok).toBe(false)
  })

  it('stdio round-trip: files mode over real fixture → critical', () => {
    const bin = join(baseDir(), 'lib/scanner-bin/index.js')
    const req: ScanRequest = { kind: 'files', files: [join(FIX, 'escape-workflow.js'), join(FIX, 'clean-plugin.ts')] }
    const out = spawnSync(process.execPath, [bin], { input: JSON.stringify(req), encoding: 'utf8' })
    expect(out.status).toBe(0)
    const parsed = JSON.parse(out.stdout.trim())
    expect(parsed.ok).toBe(true)
    expect(parsed.report.verdict).toBe('critical')
    expect(parsed.report.sourceCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// cache
// ---------------------------------------------------------------------------

describe('cache', () => {
  it('round-trips a report keyed by content hash', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-cache-'))
    process.env.DSH_PLUGIN_VET_CACHE_DIR = dir
    try {
      const files = [{ path: '/a.js', content: 'const x = 1' }]
      const key = cacheKey(files, undefined)
      const report = { engine: ENGINE_VERSION, sourceCount: 1, findings: [], staticScore: 100, verdict: 'clean' as const }
      writeCached(key, report)
      expect(readCached(key)).toEqual(report)
      // round-6：旧版本引擎的缓存必须失效（规则变更未递增 ENGINE_VERSION 会缓存中毒——实测发现）
      writeCached(key, { ...report, engine: 'static-v0' as const })
      expect(readCached(key)).toBeUndefined()
      expect(readCached(cacheKey([{ path: '/a.js', content: 'const x = 2' }], undefined))).toBeUndefined()
    } finally {
      delete process.env.DSH_PLUGIN_VET_CACHE_DIR
    }
  })

  it('files scan served from cache returns the same report', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-cache2-'))
    process.env.DSH_PLUGIN_VET_CACHE_DIR = dir
    try {
      const req: ScanRequest = { kind: 'files', files: [join(FIX, 'secret-in-plugin.js')] }
      const a = scan(req)
      const b = scan(req)
      expect(a.ok).toBe(true)
      expect(b.ok).toBe(true)
      expect(b.report).toEqual(a.report)
      expect(b.report!.verdict).toBe('suspicious')
    } finally {
      delete process.env.DSH_PLUGIN_VET_CACHE_DIR
    }
  })
})

// ---------------------------------------------------------------------------
// OSV 已知漏洞核对
// ---------------------------------------------------------------------------

describe('OSV', () => {
  const fakeFetch = (vulns: unknown): typeof fetch =>
    (async () => ({ ok: true, status: 200, json: async () => ({ vulns }) })) as unknown as typeof fetch

  it('queryOsv: 解析漏洞列表（id/aliases/summary）', async () => {
    const v = await queryOsv('lodash', {
      fetchImpl: fakeFetch([{ id: 'GHSA-29mw-wpgm-hmr9', aliases: ['CVE-2020-28500'], summary: 'prototype pollution' }]),
    })
    expect(v).toHaveLength(1)
    expect(v[0]!.id).toBe('GHSA-29mw-wpgm-hmr9')
    expect(v[0]!.aliases).toContain('CVE-2020-28500')
  })

  it('queryOsv: 网络失败 → reject（由 scanWithOsv 静默降级）', async () => {
    const fail = (async () => { throw new Error('net down') }) as unknown as typeof fetch
    await expect(queryOsv('x', { fetchImpl: fail, timeoutMs: 100 })).rejects.toThrow('net down')
  })

  it('scanWithOsv: 命中已知漏洞 → 追加 OSV high finding，verdict 抬升为 suspicious', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'vuln-pkg', version: '1.0.0' }))
      const res = await scanWithOsv(
        { kind: 'files', files: [join(dir, 'package.json')], osv: true },
        { fetchImpl: fakeFetch([{ id: 'GHSA-1', aliases: ['CVE-2024-1234'], summary: 'rce' }]) },
      )
      expect(res.ok).toBe(true)
      const f = res.report!.findings.find(x => x.rule === 'OSV')
      expect(f).toBeDefined()
      expect(f!.severity).toBe('high')
      expect(f!.confidence).toBe('certain')
      expect(res.report!.verdict).toBe('suspicious')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('scanWithOsv: osv 未启用 → 纯静态结果，无 OSV finding', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-off-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'vuln-pkg', version: '1.0.0' }))
      const res = await scanWithOsv({ kind: 'files', files: [join(dir, 'package.json')] }, { fetchImpl: fakeFetch([{ id: 'GHSA-1' }]) })
      expect(res.ok).toBe(true)
      expect(res.report!.findings.some(x => x.rule === 'OSV')).toBe(false)
      expect(res.report!.verdict).toBe('clean')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('scanWithOsv: 网络失败 → 静默降级为纯静态结果', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-fail-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'vuln-pkg', version: '1.0.0' }))
      const fail = (async () => { throw new Error('net down') }) as unknown as typeof fetch
      const res = await scanWithOsv({ kind: 'files', files: [join(dir, 'package.json')], osv: true }, { fetchImpl: fail })
      expect(res.ok).toBe(true)
      expect(res.report!.findings.some(x => x.rule === 'OSV')).toBe(false)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('P3-10：直接依赖也核对——精确版本依赖命中漏洞 → OSV high；range 跳过、官方包跳过、去重', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-dep-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'host-app', version: '1.0.0',
        // dep-a 在 dependencies 与 peerDependencies 重复出现（应去重只查一次）；
        // dep-range 是 range（round-7/P2：README 宣称只查精确版本，range 一律跳过——
        // 此前 ^ 被剥成下界精确版，下界受影响但已装版本已修复时会误报）；
        // @deepseek-ai/skip 是官方包（P3-10 明确跳过，查询是噪声）
        dependencies: { 'dep-a': '1.2.0', 'dep-range': '^2.4.2', '@deepseek-ai/skip': '^2.0.0' },
        peerDependencies: { 'dep-a': '^1.0.0' },
      }))
      const queried: string[] = []
      const fake = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body ?? '{}'))
        const name = body?.package?.name as string
        queried.push(name)
        // 带 version 查询（F15）：dep-a 只报受影响版本的漏洞
        expect(body?.package?.ecosystem).toBe('npm')
        if (name === 'dep-a') {
          expect(body?.version).toBe('1.2.0') // 精确版本原样查询
          return { ok: true, status: 200, json: async () => ({ vulns: [{ id: 'GHSA-DEP-1', aliases: ['CVE-2025-1'], summary: 'dep rce' }] }) } as Response
        }
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) } as Response
      }) as unknown as typeof fetch
      const res = await scanWithOsv({ kind: 'files', files: [join(dir, 'package.json')], osv: true }, { fetchImpl: fake })
      expect(res.ok).toBe(true)
      const f = res.report!.findings.find(x => x.rule === 'OSV')
      expect(f).toBeDefined()
      expect(f!.severity).toBe('high')
      expect(f!.message).toContain('GHSA-DEP-1')
      // 查询面：host-app 自身 + dep-a 一次（去重）；dep-range（^2.4.2）与 @deepseek-ai/skip 永不查询
      expect(queried.sort()).toEqual(['dep-a', 'host-app'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('P3-1/P3-3：非精确版本不查询——range 依赖与无 version 主包跳过', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-v-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'no-version-app', // 主包无 version → 不查全量历史（陈旧误报）
        dependencies: { 'dep-star': '*', 'dep-gte': '>=1.0.0', 'dep-tilde': '~1.2.0', 'dep-caret': '^2.4.2', 'dep-ok': '1.0.0' },
      }))
      const queried: string[] = []
      const fake = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body ?? '{}'))
        queried.push(body?.package?.name as string)
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) } as Response
      }) as unknown as typeof fetch
      const res = await scanWithOsv({ kind: 'files', files: [join(dir, 'package.json')], osv: true }, { fetchImpl: fake })
      expect(res.ok).toBe(true)
      expect(res.report!.findings.some(x => x.rule === 'OSV')).toBe(false)
      // 只查精确版本目标：main（无 version 跳过）；*、>=、~1.2.0、^2.4.2 全部跳过
      // （round-7/P2：range 不再剥前缀当精确版本——README 宣称行为；此前 ^/~ 剥成下界
      // 精确版会误报「下界受影响但已装版本已修复」）；dep-ok 1.0.0 照常查询
      expect(queried.sort()).toEqual(['dep-ok'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('R12：Cordis/DSH bundle 契约（P-2 计划项）', () => {
  const scanPkg = (files: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r12-'))
    try {
      for (const [name, content] of Object.entries(files)) {
        const p = join(dir, name)
        mkdirSync(dirname(p), { recursive: true })
        writeFileSync(p, content)
      }
      return scan({ kind: 'files', files: [join(dir, 'package.json')].filter(() => true), targetKind: 'plugin' })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  it('dsh.bundle.patch 声明缺失 → high（挂载必失败）', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'x', main: 'index.js', dsh: { bundle: { patch: './cordis.patch.yml' } } }),
      'index.js': 'export {}',
    })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('suspicious')
    const r12 = res.report!.findings.find(f => f.rule === 'R12')
    expect(r12).toBeDefined()
    expect(r12!.severity).toBe('high')
  })
  it('入口文件缺失 → high；patch 存在 + 入口完整 + name 齐 → 无 R12 high', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'ok-pkg', main: './lib/index.js' }),
      'cordis.patch.yml': '- id: ok-pkg',
      'lib/index.js': 'export const name = "ok-pkg"',
    })
    expect(res.ok).toBe(true)
    const r12 = res.report!.findings.filter(f => f.rule === 'R12')
    // dsh 声明（patch）未声明 → 无 patch finding；main 存在 → 无入口 high
    expect(r12).toHaveLength(0)
  })
  it('无任何入口（无 main/exports/index.js）→ medium 不进 verdict', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'x', dependencies: { '@deepseek-ai/dsh-tools': '^1' } }),
      'a.ts': 'export {}',
    })
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    const r12 = res.report!.findings.find(f => f.rule === 'R12')
    expect(r12).toBeDefined()
    expect(r12!.severity).toBe('medium')
  })
  it('非插件意图包（无 dsh 依赖/声明）→ R12 不判', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'tool', main: 'index.js' }),
      'index.js': 'module.exports = {}',
    })
    expect(res.report!.findings.some(f => f.rule === 'R12')).toBe(false)
  })
  it('engines.node 低于 22 → info；>=22 不报', () => {
    // 包需有插件意图（@deepseek-ai 依赖）R12 才判
    const mk = (engines: unknown) => JSON.stringify({ name: 'x', main: 'index.js', dependencies: { '@deepseek-ai/cordis': '^4' }, engines: { node: engines } })
    const low = scanPkg({ 'package.json': mk('>=21.0.0'), 'index.js': 'export {}' })
    const ok = scanPkg({ 'package.json': mk('>=22.19'), 'index.js': 'export {}' })
    const lowF = low.report!.findings.find(f => f.rule === 'R12' && f.severity === 'info')
    expect(lowF).toBeDefined()
    expect(ok.report!.findings.find(f => f.rule === 'R12' && f.severity === 'info')).toBeUndefined()
  })
  it('engines.node 单数字主版本（2-9）→ 也提示 info（round-4 回归）', () => {
    const mk = (engines: unknown) => JSON.stringify({ name: 'x', main: 'index.js', dependencies: { '@deepseek-ai/cordis': '^4' }, engines: { node: engines } })
    for (const old of ['4.0.0', '8.17.0', '2.0.0', '6.0.0', '9.0.0', '3.x', '5.5.0', 'v18.0.0', '>=16.0.0']) {
      const res = scanPkg({ 'package.json': mk(old), 'index.js': 'export {}' })
      const f = res.report!.findings.find(f => f.rule === 'R12' && f.severity === 'info')
      expect(f, 'engines.node=' + old + ' 应提示 info').toBeDefined()
    }
    for (const ok of ['>=22.19', '22', '23.0.0', '*']) {
      const res = scanPkg({ 'package.json': mk(ok), 'index.js': 'export {}' })
      const f = res.report!.findings.find(f => f.rule === 'R12' && f.severity === 'info')
      expect(f, 'engines.node=' + ok + ' 不应提示 info').toBeUndefined()
    }
  })
  it('exports 字符串形态（"exports": "./index.js"）→ 识别为入口（round-4 回归）', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'x', exports: './lib/index.js', dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'lib/index.js': 'export {}',
    })
    expect(res.ok).toBe(true)
    expect(res.report!.findings.find(f => f.rule === 'R12' && f.severity === 'medium')).toBeUndefined()
  })
  it('exports["."] 仅含 node 条件 → 识别为入口（round-4 回归）', () => {
    const res = scanPkg({
      'package.json': JSON.stringify({ name: 'x', exports: { '.': { node: './lib/index.js' } }, dependencies: { '@deepseek-ai/cordis': '^4' } }),
      'lib/index.js': 'export {}',
    })
    expect(res.ok).toBe(true)
    expect(res.report!.findings.find(f => f.rule === 'R12' && f.severity === 'medium')).toBeUndefined()
  })
})

describe('round-5（实测评估）回归：R1 元素访问、R3 信号处理、R9 ReDoS 误报', () => {
  it('R1: x["constructor"] 元素访问形态（拼接参数）→ critical（此前完全漏检）', () => {
    const res = scan(codeRequest({ code: 'const x = {}; x["constructor"]("return " + "process")' }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('critical')
    expect(findingOf(res.report!, 'R1', 'critical')).toBeDefined()
  })
  it('R1: x["constructor"] 元素访问 + 字面量参数 → critical', () => {
    const res = scan(codeRequest({ code: 'const x = {}; x["constructor"]("return process")' }))
    expect(res.report!.verdict).toBe('critical')
    expect(findingOf(res.report!, 'R1', 'critical')).toBeDefined()
  })
  it('R3: 信号处理器回调内的 process.exit（优雅退出）→ info 不进 verdict', () => {
    const res = scan(codeRequest({ code: 'process.on("SIGTERM", () => { server.close(); process.exit(0) })' }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('clean')
    expect(findingOf(res.report!, 'R3', 'critical')).toBeUndefined()
  })
  it('R3: 裸 process.exit（错误路径）→ 仍 critical', () => {
    const res = scan(codeRequest({ code: 'if (err) { process.exit(1) }' }))
    expect(res.report!.verdict).toBe('critical')
    expect(findingOf(res.report!, 'R3', 'critical')).toBeDefined()
  })
  it('R5: ctx.logger（cordis 官方服务）→ 不报', () => {
    const res = scan(codeRequest({ code: 'export function apply(ctx) { ctx.logger.info("hi") }' }))
    expect(res.ok).toBe(true)
    expect(res.report!.findings.some(f => f.rule === 'R5')).toBe(false)
  })
  it('R9: 良性单可选组 (?:x)? → 不报 ReDoS（此前误报 medium）', () => {
    const res = scan(codeRequest({ code: 'const re = /\\.(?:tmp(?:dir)?|temp|swp|bak|orig)$/i' }))
    expect(res.ok).toBe(true)
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('ReDoS'))).toBe(false)
  })
  it('R9: 真 ReDoS (a+)+ → 仍报 medium', () => {
    const res = scan(codeRequest({ code: 'const re = /(a+)+$/' }))
    expect(res.ok).toBe(true)
    expect(res.report!.findings.some(f => f.rule === 'R9' && (f.message || '').includes('ReDoS'))).toBe(true)
  })
})

describe('开源自检（dogfood）：vet 扫描自己的蜜罐源码不该 R7 自命中', () => {
  it('src/guard/honeypot.ts 无 hardcoded secrets（前缀常量化的诱饵）', () => {
    // 回归：诱饵值若把 sk- 或 AKIA 写进模板串，R7 会把拼接文本判成 high，
    // 发布物自扫 verdict=suspicious、deny 模式重装 vet 会自锁（开源前实测发现）
    const src = readFileSync(join(baseDir(), 'src', 'guard', 'honeypot.ts'), 'utf8')
    const res = scan(codeRequest({ language: 'ts', code: src }))
    expect(res.ok).toBe(true)
    const high = res.report!.findings.find(f => f.rule === 'R7' && f.severity === 'high')
    expect(high).toBeUndefined()
  })
})

function baseDir(): string {
  return join(import.meta.dirname, '..')
}
