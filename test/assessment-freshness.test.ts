/**
 * 不变式 4：**情报时间、规则版本、扫描结果各带时间，不可合并成单一 clean。**
 *
 * 这条不变式要防的是一个很自然的简化："这个包是干净的"——干净是什么时候、按哪套规则、
 * 对着哪份字节说的？三样任一可漂移，合并成一个词就等于把可漂移的结论伪装成常量。
 *
 * 这里每一例都对应一个**可观察的字段**，不是理念：
 * - 规则集：扫描摘要带 `engine`，判读带 `ruleSetVersion`；
 * - 时间：`at` / `decidedAt` / `evaluatedAt` 各自是**产生时刻**，不是文件 mtime；
 * - 字节：审计档案的 `subject_sha256` 绑内容，内容一变即失效；但单纯的时间流逝不改变结论
 *   （审计不按保质期作废，那是设计选择，写在这里免得被当成疏漏）。
 *
 * 0.5.20：档案格式补上 `rule_set_version` + `scan_verdict`，资格状态机的 `standard_changed`
 * 终于有了生产者——而且带影响函数（只有新规则集确实会改判才要求重审）。这条缺口曾经被
 * 钉成断言放在下面，接上那天它会红；它确实红了，然后被换成下面那组正向用例。
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

vi.mock('../lib/scanner/client.js', () => ({
  scan: vi.fn(),
  scanBudget: () => 15_000,
}))
vi.mock('../lib/tools/scan-plugin.js', () => ({ buildRequest: vi.fn() }))

import { getScanSummary, recordScanSummary, setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { gateAssessment } from '../lib/gate-decision.js'
import { runGate } from '../lib/gate.js'
import { scan } from '../lib/scanner/client.js'
import { buildRequest } from '../lib/tools/scan-plugin.js'
import { archiveDir, probeQualification } from '../lib/audit/archive.js'
import { CURRENT_ENGINE } from '../lib/scanner/protocol.js'
import type { ScanReport } from '../lib/scanner/protocol.js'

const mockScan = vi.mocked(scan)
const mockBuildRequest = vi.mocked(buildRequest)

function report(over: Partial<ScanReport> = {}): ScanReport {
  return { engine: 'static-v27', sourceCount: 2, findings: [], staticScore: 0, verdict: 'clean', ...over }
}

function gateInput(over: Partial<Parameters<typeof gateAssessment>[0]> = {}) {
  return {
    mode: 'report' as const,
    report: report(),
    packagePath: '/tmp/pkg',
    pluginName: 'pkg',
    pluginVersion: '1.0.0',
    osvRequested: false,
    decidedAt: 1_700_000_000_000,
    ...over,
  }
}

describe('时间：每个时刻都是产生时刻', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-freshness-'))
    setSummariesDirForTest(dir)
  })
  afterEach(() => {
    setSummariesDirForTest(undefined)
    rmSync(dir, { recursive: true, force: true })
  })

  it('扫描摘要的 at 是调用方给的那一刻（不被 mtime / 当前时间覆盖）', () => {
    recordScanSummary({ name: 'pkg-a', at: 1_700_000_000_000, verdict: 'clean', staticScore: 0, ruleCodes: [] })
    expect(getScanSummary('pkg-a')?.at).toBe(1_700_000_000_000)
  })

  it('闸门：decidedAt / scannedAt 同源，判读的 evaluatedAt 也是同一刻', async () => {
    mockBuildRequest.mockReturnValue({
      pluginName: 'pkg-b',
      pluginVersion: '1.0.0',
      request: { kind: 'files', files: ['/tmp/pkg-b/index.js'], targetKind: 'plugin' },
    })
    mockScan.mockResolvedValue({ ok: true, report: report() })
    const result = await runGate({ packagePath: '/tmp/pkg-b' })
    expect(result.decision.decidedAt).toBe(Date.parse(result.scannedAt))
    expect(gateAssessment(gateInput({ decidedAt: result.decision.decidedAt })).evaluatedAt).toBe(result.decision.decidedAt)
  })
})

describe('规则集版本是结论的一部分', () => {
  it('判读记的是扫描器自述的引擎，不是 vet 自己的版本号', () => {
    const assessment = gateAssessment(gateInput({ report: report({ engine: 'static-v27' }) }))
    expect(assessment.ruleSetVersion).toBe('static-v27')
    expect(assessment.evaluatedAt).toBe(1_700_000_000_000)
  })

  it('换了引擎 → 决策里的判读随之换版本（同一份字节，两个规则集是两条判读）', () => {
    const a = gateAssessment(gateInput({ report: report({ engine: 'static-v26' }) }))
    const b = gateAssessment(gateInput({ report: report({ engine: 'static-v27' }) }))
    expect(a.ruleSetVersion).not.toBe(b.ruleSetVersion)
  })

  it('摘要记下引擎，换引擎即重写（否则旧规则集的结论会一直挂在「最近扫描」上）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-freshness-engine-'))
    setSummariesDirForTest(dir)
    try {
      recordScanSummary({ name: 'pkg-c', at: 1, verdict: 'clean', staticScore: 0, ruleCodes: [], engine: 'static-v26' })
      recordScanSummary({ name: 'pkg-c', at: 2, verdict: 'clean', staticScore: 0, ruleCodes: [], engine: 'static-v27' })
      expect(getScanSummary('pkg-c')).toMatchObject({ engine: 'static-v27', at: 2 })
    } finally {
      setSummariesDirForTest(undefined)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('0.5.12 之前的记录没有 engine：缺席就是缺席，不回填成当前版本', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-freshness-legacy-'))
    setSummariesDirForTest(dir)
    try {
      recordScanSummary({ name: 'pkg-d', at: 1, verdict: 'clean', staticScore: 0, ruleCodes: [] })
      expect(getScanSummary('pkg-d')?.engine).toBeUndefined()
    } finally {
      setSummariesDirForTest(undefined)
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('字节新鲜度是硬约束，时间不是', () => {
  const digest = 'a'.repeat(64)

  function writeArchive(fileName: string, sha256: string): void {
    mkdirSync(archiveDir(), { recursive: true })
    writeFileSync(join(archiveDir(), fileName), '# 健康档案\n\nsubject_sha256: ' + sha256 + '\n')
  }

  it('内容对得上 → qualified（哪怕档案是去年写的：审计不按保质期作废）', () => {
    writeArchive('pkg-e-1.0.0-20250101-000000.md', digest)
    const result = probeQualification({ name: 'pkg-e', version: '1.0.0', contentDigest: () => digest })
    expect(result.state.status).toBe('qualified')
    expect(result.state.basis).toBe('digest')
  })

  it('同版本不同字节 → recheck_required（这才是「过期」在这套系统里的意思）', () => {
    writeArchive('pkg-f-1.0.0-20260101-000000.md', digest)
    const result = probeQualification({ name: 'pkg-f', version: '1.0.0', contentDigest: () => 'b'.repeat(64) })
    expect(result.state.status).toBe('recheck_required')
    expect(result.state.reasons).toContain('content-changed')
  })

  it('老档案（没有 rule_set_version）不产生任何 standard 判定：不知道就是不知道', () => {
    writeArchive('pkg-g-1.0.0-20260101-000000.md', digest)
    const result = probeQualification({ name: 'pkg-g', version: '1.0.0', contentDigest: () => digest })
    // 档案里只有 subject_sha256；哪怕它是在 static-v01 下写的，这里也无法知道。
    expect(result.state.status).toBe('qualified')
    expect(result.state.reasons.some(r => r.startsWith('standard'))).toBe(false)
  })
})

/**
 * 0.5.20：`standard_changed` 的生产者。
 *
 * 三件事缺一不可——档案写规则集版本与当时的判读、加载时能拿到当前规则集对这个包的结论、
 * 且只在「新规则集会得出更差的判定」时才升级。缺最后一条就是升级当天全体重审。
 */
describe('规则集变了是否要重审：影响函数（0.5.20）', () => {
  const digest = 'c'.repeat(64)
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-standard-'))
    setSummariesDirForTest(dir)
  })
  afterEach(() => {
    setSummariesDirForTest(undefined)
    rmSync(dir, { recursive: true, force: true })
  })

  function write(name: string, extra: string): void {
    mkdirSync(archiveDir(), { recursive: true })
    writeFileSync(join(archiveDir(), `${name}-1.0.0-20260101-000000.md`), '# 健康档案\nsubject_sha256: ' + digest + '\n' + extra)
  }
  function probe(name: string) {
    return probeQualification({ name, version: '1.0.0', contentDigest: () => digest })
  }

  it('档案写的就是当前引擎：不产生 standard 事件', () => {
    write('std-same', 'rule_set_version: ' + CURRENT_ENGINE + '\nscan_verdict: clean\n')
    const r = probe('std-same')
    expect(r.state.status).toBe('qualified')
    expect(r.state.reasons.some(x => x.startsWith('standard'))).toBe(false)
  })

  it('旧引擎 + 当前规则集判定更差 → recheck_required', () => {
    recordScanSummary({ name: 'std-worse', version: '1.0.0', at: 1, verdict: 'suspicious', staticScore: 40, ruleCodes: ['R5'], engine: CURRENT_ENGINE })
    write('std-worse', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    const r = probe('std-worse')
    expect(r.state.status).toBe('recheck_required')
    expect(r.state.reasons).toContain('standard-changed')
  })

  it('旧引擎但判定持平 → 不重审（理由写明「与本次改动无关」）', () => {
    recordScanSummary({ name: 'std-equal', version: '1.0.0', at: 1, verdict: 'clean', staticScore: 0, ruleCodes: [], engine: CURRENT_ENGINE })
    write('std-equal', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    const r = probe('std-equal')
    expect(r.state.status).toBe('qualified')
    expect(r.state.reasons).toContain('standard-irrelevant')
  })

  it('旧引擎但新规则集更松（critical → clean）→ 不重审', () => {
    recordScanSummary({ name: 'std-looser', version: '1.0.0', at: 1, verdict: 'clean', staticScore: 0, ruleCodes: [], engine: CURRENT_ENGINE })
    write('std-looser', 'rule_set_version: static-v26\nscan_verdict: critical\n')
    expect(probe('std-looser').state.status).toBe('qualified')
  })

  it('没有当前引擎的扫描结论 → 判不了，放行并留 standard-unevaluated', () => {
    write('std-nosummary', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    const r = probe('std-nosummary')
    expect(r.state.status).toBe('qualified')
    expect(r.state.reasons).toContain('standard-unevaluated')
    // 判不了的时候不许顺手说一句「这次变化与本包无关」——那是没资格下的断言
    expect(r.state.reasons).not.toContain('standard-irrelevant')
  })

  it('摘要是更早的引擎产出的 → 不配当对照物', () => {
    recordScanSummary({ name: 'std-oldsum', version: '1.0.0', at: 1, verdict: 'critical', staticScore: 90, ruleCodes: ['R5'], engine: 'static-v25' })
    write('std-oldsum', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    const r = probe('std-oldsum')
    expect(r.state.status).toBe('qualified')
    expect(r.state.reasons).toContain('standard-unevaluated')
  })

  it('摘要的版本对不上 → 不比', () => {
    recordScanSummary({ name: 'std-ver', version: '2.0.0', at: 1, verdict: 'critical', staticScore: 90, ruleCodes: ['R5'], engine: CURRENT_ENGINE })
    write('std-ver', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    expect(probe('std-ver').state.reasons).toContain('standard-unevaluated')
  })

  it('档案写了规则集版本却没写判读 → 判不了，不重审', () => {
    recordScanSummary({ name: 'std-noverdict', version: '1.0.0', at: 1, verdict: 'critical', staticScore: 90, ruleCodes: ['R5'], engine: CURRENT_ENGINE })
    write('std-noverdict', 'rule_set_version: static-v26\n')
    const r = probe('std-noverdict')
    expect(r.state.status).toBe('qualified')
    expect(r.state.reasons).toContain('standard-unevaluated')
  })

  it('内容对不上时走 content_changed，不再叠加 standard 判定', () => {
    write('std-content', 'rule_set_version: static-v26\nscan_verdict: clean\n')
    const r = probeQualification({ name: 'std-content', version: '1.0.0', contentDigest: () => 'd'.repeat(64) })
    expect(r.state.reasons).toContain('content-changed')
    expect(r.state.reasons).not.toContain('standard-changed')
  })
})
