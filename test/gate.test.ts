import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// Mock scan and buildRequest before importing gate
vi.mock('../lib/scanner/client.js', () => ({
  scan: vi.fn(),
  // round-5（B-A5）：gate 的预算已收敛到 scanBudget 单源——mock 补真实实现
  scanBudget: (files: number, explicitMs?: number, capMs?: number) => {
    const base = explicitMs !== undefined && Number.isFinite(explicitMs) && explicitMs > 0 ? explicitMs : 15_000
    return Math.min(Math.max(base, files * 2000), capMs ?? 60_000)
  },
}))

vi.mock('../lib/tools/scan-plugin.js', () => ({
  buildRequest: vi.fn(),
}))

import { scan } from '../lib/scanner/client.js'
import { buildRequest } from '../lib/tools/scan-plugin.js'
import { runGate } from '../lib/gate.js'
import type { ScanResponse } from '../lib/scanner/protocol.js'

const mockScan = vi.mocked(scan)
const mockBuildRequest = vi.mocked(buildRequest)

describe('runGate', () => {
  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-gate-test-'))
    vi.clearAllMocks()

    // Default buildRequest mock
    mockBuildRequest.mockReturnValue({
      pluginName: 'test-plugin',
      pluginVersion: '1.0.0',
      request: {
        kind: 'files',
        files: [join(testDir, 'index.js')],
        targetKind: 'plugin',
      },
    })
  })

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true })
  })

  it('report mode: returns verdict without blocking', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: {
        engine: 'test',
        sourceCount: 1,
        findings: [],
        staticScore: 0,
        verdict: 'clean',
      },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({
      packagePath: testDir,
      mode: 'report',
    })

    expect(result.verdict).toBe('clean')
    expect(result.blocked).toBe(false)
    expect(result.pluginName).toBe('test-plugin')
    expect(result.pluginVersion).toBe('1.0.0')
    expect(result.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('deny mode + critical verdict → blocked=true', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: {
        engine: 'test',
        sourceCount: 1,
        findings: [{ rule: 'R1', severity: 'high', confidence: 'certain', message: 'eval', evidence: 'eval()', file: 'index.js' }],
        staticScore: 100,
        verdict: 'critical',
      },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({
      packagePath: testDir,
      mode: 'deny',
      denyOn: 'critical',
    })

    expect(result.verdict).toBe('critical')
    expect(result.blocked).toBe(true)
  })

  it('deny mode + clean verdict → blocked=false', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: {
        engine: 'test',
        sourceCount: 1,
        findings: [],
        staticScore: 0,
        verdict: 'clean',
      },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({
      packagePath: testDir,
      mode: 'deny',
      denyOn: 'critical',
    })

    expect(result.blocked).toBe(false)
  })

  it('deny mode + suspicious verdict + denyOn=critical → blocked=false', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: {
        engine: 'test',
        sourceCount: 1,
        findings: [{ rule: 'R5', severity: 'medium', confidence: 'heuristic', message: 'suspicious', evidence: '', file: 'x.js' }],
        staticScore: 50,
        verdict: 'suspicious',
      },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({
      packagePath: testDir,
      mode: 'deny',
      denyOn: 'critical',
    })

    // suspicious < critical → not blocked
    expect(result.blocked).toBe(false)
  })

  it('deny mode + suspicious verdict + denyOn=suspicious → blocked=true', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: {
        engine: 'test',
        sourceCount: 1,
        findings: [],
        staticScore: 50,
        verdict: 'suspicious',
      },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({
      packagePath: testDir,
      mode: 'deny',
      denyOn: 'suspicious',
    })

    // suspicious >= suspicious → blocked
    expect(result.blocked).toBe(true)
  })

  it('OSV default off: scan called with osv=false', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: { engine: 'test', sourceCount: 0, findings: [], staticScore: 0, verdict: 'clean' },
    }
    mockScan.mockResolvedValue(mockResponse)

    await runGate({ packagePath: testDir })

    expect(mockScan).toHaveBeenCalledOnce()
    const callArgs = mockScan.mock.calls[0]
    expect(callArgs[0].osv).toBe(false) // default off
  })

  it('OSV explicitly enabled: scan called with osv=true', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: { engine: 'test', sourceCount: 0, findings: [], staticScore: 0, verdict: 'clean' },
    }
    mockScan.mockResolvedValue(mockResponse)

    await runGate({ packagePath: testDir, osvCheck: true })

    const callArgs = mockScan.mock.calls[0]
    expect(callArgs[0].osv).toBe(true)
  })

  it('timeout calculation: fileCount * 2000, clamped [15000, 60000]', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: { engine: 'test', sourceCount: 0, findings: [], staticScore: 0, verdict: 'clean' },
    }
    mockScan.mockResolvedValue(mockResponse)

    // 5 files → 5*2000=10000 → clamped to 15000
    mockBuildRequest.mockReturnValue({
      pluginName: 'test',
      request: { kind: 'files', files: ['a.js', 'b.js', 'c.js', 'd.js', 'e.js'], targetKind: 'plugin' },
    })
    await runGate({ packagePath: testDir })
    expect(mockScan.mock.calls[0][1].timeoutMs).toBe(15000)

    // 20 files → 20*2000=40000
    mockBuildRequest.mockReturnValue({
      pluginName: 'test',
      request: { kind: 'files', files: Array(20).fill('x.js'), targetKind: 'plugin' },
    })
    await runGate({ packagePath: testDir })
    expect(mockScan.mock.calls[1][1].timeoutMs).toBe(40000)

    // 50 files → 50*2000=100000 → clamped to 60000
    mockBuildRequest.mockReturnValue({
      pluginName: 'test',
      request: { kind: 'files', files: Array(50).fill('x.js'), targetKind: 'plugin' },
    })
    await runGate({ packagePath: testDir })
    expect(mockScan.mock.calls[2][1].timeoutMs).toBe(60000)
  })

  it('custom timeoutMs overrides calculation', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: { engine: 'test', sourceCount: 0, findings: [], staticScore: 0, verdict: 'clean' },
    }
    mockScan.mockResolvedValue(mockResponse)

    await runGate({ packagePath: testDir, timeoutMs: 5000 })
    expect(mockScan.mock.calls[0][1].timeoutMs).toBe(5000)
  })

  it('scan failure → throws error', async () => {
    mockScan.mockResolvedValue({ ok: false, error: 'timeout' })

    await expect(runGate({ packagePath: testDir })).rejects.toThrow('vet gate: scan failed timeout')
  })

  it('default mode is report', async () => {
    const mockResponse: ScanResponse = {
      ok: true,
      report: { engine: 'test', sourceCount: 0, findings: [], staticScore: 100, verdict: 'critical' },
    }
    mockScan.mockResolvedValue(mockResponse)

    const result = await runGate({ packagePath: testDir })
    // mode defaults to 'report' → blocked is always false
    expect(result.blocked).toBe(false)
    expect(result.verdict).toBe('critical')
  })
})

describe('round-22：CLI 参数与 deny 判定 fail-closed', () => {
  it('parseCliArgs：--key=value 与 --key value 双形态等价（旧实现 --mode=deny 静默失效）', async () => {
    const { parseCliArgs } = await import('../lib/cli-args.js')
    const eq = parseCliArgs(['node', 'vet-gate', '--mode=deny', '--denyOn=suspicious', '--timeout=30000', '--osv'])
    expect(eq.mode).toBe('deny')
    expect(eq.denyOn).toBe('suspicious')
    expect(eq.timeout).toBe('30000')
    expect(eq.osv).toBe(true)
    const sp = parseCliArgs(['vet-gate', '--mode', 'deny', '--package', '/tmp/x'])
    expect(sp.mode).toBe('deny')
    expect(sp.package).toBe('/tmp/x')
    // 混合形态
    const mix = parseCliArgs(['--mode=deny', '--format', 'json'])
    expect(mix.mode).toBe('deny')
    expect(mix.format).toBe('json')
  })

  it('decideDenyBlock：非法 denyOn 归位最严档位 critical（fail-closed，不静默失效）', async () => {
    const { decideDenyBlock } = await import('../lib/gate.js')
    // 非法 denyOn：旧实现 `RANK[verdict] >= undefined` 恒 false → deny 对任何判定都失效；
    // 修复后按最严档位 critical 处理（可疑不拦、critical 拦）
    expect(decideDenyBlock('deny', 'bogus', 'suspicious', true)).toBe(false)
    expect(decideDenyBlock('deny', 'bogus', 'critical', true)).toBe(true)
    expect(decideDenyBlock('deny', 'bogus', 'clean', true)).toBe(false) // clean 仍放行
    // 合法值语义不变
    expect(decideDenyBlock('deny', 'critical', 'critical', true)).toBe(true)
    expect(decideDenyBlock('deny', 'critical', 'suspicious', true)).toBe(false)
    expect(decideDenyBlock('deny', 'suspicious', 'suspicious', true)).toBe(true)
    // report 模式不拦；未知 verdict fail-closed
    expect(decideDenyBlock('report', 'bogus', 'suspicious', true)).toBe(false)
    expect(decideDenyBlock('deny', 'critical', 'alien', false)).toBe(true)
  })
})
