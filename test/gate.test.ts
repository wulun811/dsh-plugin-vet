import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// Mock scan and buildRequest before importing gate
vi.mock('../src/scanner/client.js', () => ({
  scan: vi.fn(),
}))

vi.mock('../src/tools/scan-plugin.js', () => ({
  buildRequest: vi.fn(),
}))

import { scan } from '../src/scanner/client.js'
import { buildRequest } from '../src/tools/scan-plugin.js'
import { runGate } from '../src/gate.js'
import type { ScanResponse } from '../src/scanner/protocol.js'

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
