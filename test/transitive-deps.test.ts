import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// Mock execFile before importing engine
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process')
  return {
    ...actual,
    execFile: vi.fn(),
  }
})

import { execFile } from 'node:child_process'
import { scanWithOsv } from '../lib/scanner-bin/engine.js'
import type { ScanRequest } from '../lib/scanner/protocol.js'

const mockExecFile = vi.mocked(execFile)

describe('transitive dependency scanning (scanWithOsv + transitiveDeps)', () => {
  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-transitive-test-'))
    vi.clearAllMocks()
  })

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true })
  })

  function createPackageJson(name: string, deps: Record<string, string> = {}): void {
    writeFileSync(
      join(testDir, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', dependencies: deps })
    )
  }

  function createIndexJs(content: string = 'module.exports = {}'): void {
    writeFileSync(join(testDir, 'index.js'), content)
  }

  it('transitiveDeps not set: no upstream-radar call, scan succeeds', async () => {
    createPackageJson('test-pkg', { lodash: '4.17.21' })
    createIndexJs()

    const request: ScanRequest = {
      kind: 'files',
      files: [join(testDir, 'package.json'), join(testDir, 'index.js')],
      targetKind: 'plugin',
    }

    const result = await scanWithOsv(request)
    expect(result.ok).toBe(true)
    expect(result.report).toBeDefined()
    // execFile should NOT be called for upstream-radar when transitiveDeps is not set
    expect(mockExecFile).not.toHaveBeenCalled()
  })

  it('transitiveDeps=false explicitly: no upstream-radar call', async () => {
    createPackageJson('test-pkg', { lodash: '4.17.21' })
    createIndexJs()

    const request: ScanRequest = {
      kind: 'files',
      files: [join(testDir, 'package.json'), join(testDir, 'index.js')],
      targetKind: 'plugin',
      transitiveDeps: false,
    }

    const result = await scanWithOsv(request)
    expect(result.ok).toBe(true)
    expect(mockExecFile).not.toHaveBeenCalled()
  })

  it('transitiveDeps=true + upstream-radar not installed: graceful degradation (no crash)', async () => {
    createPackageJson('test-pkg', { lodash: '4.17.21' })
    createIndexJs()

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const request: ScanRequest = {
      kind: 'files',
      files: [join(testDir, 'package.json'), join(testDir, 'index.js')],
      targetKind: 'plugin',
      transitiveDeps: true,
    }

    const result = await scanWithOsv(request)
    expect(result.ok).toBe(true)
    expect(result.report).toBeDefined()
    // Should not crash; upstream-radar is not installed so it degrades gracefully

    warnSpy.mockRestore()
  })

  it('#8 跨源去重：同一 CVE 在 OSV 与 upstream-radar 之间只报一条', async () => {
    createPackageJson('test-pkg', { lodash: '4.17.21' })
    createIndexJs()
    const fetchImpl = (async () => ({ ok: true, status: 200, json: async () => ({
      vulns: [{ id: 'CVE-2026-0001', aliases: [], summary: 'shared vuln' }],
    }) })) as unknown as typeof fetch
    const radarImpl = (async () => ({
      vulnerabilities: [{ id: 'CVE-2026-0001', package: 'minor-dep', severity: 'high', source: 'radar' }],
    }))
    const request: ScanRequest = {
      kind: 'files', files: [join(testDir, 'package.json'), join(testDir, 'index.js')],
      targetKind: 'plugin', osv: true, transitiveDeps: true,
    }
    const result = await scanWithOsv(request, { fetchImpl, radarImpl: radarImpl as never } as never)
    expect(result.ok).toBe(true)
    const osv = result.report!.findings.filter(f => f.rule === 'OSV' && f.message.includes('CVE-2026-0001'))
    const osvt = result.report!.findings.filter(f => f.rule === 'OSV-T' && f.message.includes('CVE-2026-0001'))
    expect(osv.length).toBe(1)
    // 同 id 已被 OSV 去重 → upstream-radar 不再重复报告（修复前会出第 2 条 OSV-T）
    expect(osvt.length).toBe(0)
  })

  it('scan without transitiveDeps: static scan works normally', async () => {
    createPackageJson('test-pkg')
    createIndexJs('const x = eval("1+1")')

    const request: ScanRequest = {
      kind: 'files',
      files: [join(testDir, 'package.json'), join(testDir, 'index.js')],
      targetKind: 'plugin',
    }

    const result = await scanWithOsv(request)
    expect(result.ok).toBe(true)
    expect(result.report).toBeDefined()
    // eval should trigger a finding
    const evalFindings = result.report!.findings.filter(f => f.evidence.includes('eval') || f.message.includes('eval'))
    expect(evalFindings.length).toBeGreaterThan(0)
  })

  it('scan with code kind: transitiveDeps has no effect (no package.json)', async () => {
    const request: ScanRequest = {
      kind: 'code',
      language: 'js',
      code: 'const x = 1',
      transitiveDeps: true,
    }

    const result = await scanWithOsv(request)
    expect(result.ok).toBe(true)
    expect(result.report).toBeDefined()
    // No execFile call since code mode has no package.json
    expect(mockExecFile).not.toHaveBeenCalled()
  })
})
