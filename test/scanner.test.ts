import { describe, expect, it } from 'vitest'
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan, scanWithOsv } from '../lib/scanner-bin/engine.js'
import { queryOsv } from '../lib/scanner-bin/osv.js'
import { computeScore, computeVerdict } from '../lib/scanner-bin/score.js'
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
// fixture matrix (PLAN.md §9.1)
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
// scoring & verdict boundaries (PLAN.md §4.4)
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
// cache (PLAN.md §4.5)
// ---------------------------------------------------------------------------

describe('cache', () => {
  it('round-trips a report keyed by content hash', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-cache-'))
    process.env.DSH_PLUGIN_VET_CACHE_DIR = dir
    try {
      const files = [{ path: '/a.js', content: 'const x = 1' }]
      const key = cacheKey(files, undefined)
      const report = { engine: 'static-v1' as const, sourceCount: 1, findings: [], staticScore: 100, verdict: 'clean' as const }
      writeCached(key, report)
      expect(readCached(key)).toEqual(report)
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
// OSV 已知漏洞核对（PLAN.md §14.6）
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
})

function baseDir(): string {
  return join(import.meta.dirname, '..')
}
