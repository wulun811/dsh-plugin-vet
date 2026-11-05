/**
 * 闸门决策（`gate-decision.ts` + `gate.ts` 的接线）。
 *
 * 这组测试要证明的是施工图 S2-03 那个过渡态**确实是等价的**：
 * `blocked`（旧布尔）与 `decision.action === 'deny'`（域对象）在 mode × denyOn × verdict
 * 的全组合上给出同一答案。两者只要有一格不同，就说明「翻译既有策略」翻译错了——而错的
 * 方向如果是「决策说拦、旧布尔说不拦」，0.6 切过去那天就是一次静默的 fail-open。
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../lib/scanner/client.js', () => ({
  scan: vi.fn(),
  scanBudget: () => 15_000,
}))
vi.mock('../lib/tools/scan-plugin.js', () => ({ buildRequest: vi.fn() }))

import { scan } from '../lib/scanner/client.js'
import { buildRequest } from '../lib/tools/scan-plugin.js'
import { decideDenyBlock, isKnownVerdict, runGate } from '../lib/gate.js'
import { gateDecision, GATE_SCOPE } from '../lib/gate-decision.js'
import { validateDecision } from '../lib/domain/validate.js'
import { DECISION_REASON, UNKNOWN_INPUT } from '../lib/domain/decision.js'
import type { OsvOutcome, ScanReport } from '../lib/scanner/protocol.js'

const mockScan = vi.mocked(scan)
const mockBuildRequest = vi.mocked(buildRequest)

function report(over: Partial<ScanReport> = {}): ScanReport {
  return {
    engine: 'static-v27',
    sourceCount: 3,
    findings: [],
    staticScore: 0,
    verdict: 'clean',
    ...over,
  }
}

function gate(over: {
  mode?: 'report' | 'deny'
  denyOn?: 'critical' | 'suspicious' | string
  verdict?: string
  osv?: OsvOutcome
  osvRequested?: boolean
  findings?: ScanReport['findings']
  pluginName?: string
  packagePath?: string
}) {
  return gateDecision({
    mode: over.mode ?? 'report',
    ...(over.denyOn !== undefined ? { denyOn: over.denyOn as 'critical' } : {}),
    report: report({
      verdict: (over.verdict ?? 'clean') as ScanReport['verdict'],
      ...(over.findings !== undefined ? { findings: over.findings } : {}),
      ...(over.osv !== undefined ? { osv: over.osv } : {}),
    }),
    packagePath: over.packagePath ?? '/tmp/pkg',
    ...(over.pluginName !== undefined ? { pluginName: over.pluginName } : { pluginName: 'test-plugin' }),
    pluginVersion: '1.0.0',
    osvRequested: over.osvRequested === true,
    decidedAt: 1_700_000_000_000,
  })
}

describe('S2-03 影子等价：blocked ≡ (decision.action === denial)', () => {
  const MODES = ['report', 'deny'] as const
  // 含非法 denyOn（未类型化调用方传入）：旧实现归位最严档位，新实现必须一致。
  const DENY_ON = [undefined, 'critical', 'suspicious', 'bogus'] as const
  // 含原型链上的名字（'constructor'）：`in` 判定会把它当成已知结论，那是旧实现的洞。
  const VERDICTS = ['clean', 'suspicious', 'critical', 'weird', 'constructor'] as const

  it('全组合逐格一致，且每条决策都能通过校验器', () => {
    const answers = new Set<boolean>()
    for (const mode of MODES) {
      for (const denyOn of DENY_ON) {
        for (const verdict of VERDICTS) {
          const label = `${mode}/${String(denyOn)}/${verdict}`
          const decision = gate({ mode, denyOn, verdict })
          const legacy = decideDenyBlock(mode, denyOn, verdict, isKnownVerdict(verdict))
          answers.add(legacy)
          expect(decision.action === 'deny', label).toBe(legacy)
          expect(validateDecision(decision), label).toEqual([])
          // 闸门永远给不出 allow：五个面里必然有本边界不做的（传递依赖、registry 对账）。
          expect(decision.action, label).not.toBe('allow')
        }
      }
    }
    // 防退化成「全都是 false 所以全相等」：矩阵里两种答案都必须真的出现过。
    expect([...answers].sort()).toEqual([false, true])
  })

  it('未知 verdict 在 deny 模式按失败关闭，且原因写在决策里', () => {
    const decision = gate({ mode: 'deny', verdict: 'weird' })
    expect(decision.action).toBe('deny')
    expect(decision.unknownInputs).toContain('verdict:unrecognized')
    expect(decision.reasonCodes).toContain(DECISION_REASON.failClosedOnUnknown)
  })

  it('report 模式没有拦截授权：critical 也不会 deny', () => {
    const decision = gate({ mode: 'report', verdict: 'critical' })
    expect(decision.action).toBe('report')
    expect(decision.reasonCodes).toContain(DECISION_REASON.findingNotAuthorized)
  })

  it('deny 模式命中曲线：critical 结论在 denyOn=critical 下被拦，suspicious 不被拦', () => {
    expect(gate({ mode: 'deny', denyOn: 'critical', verdict: 'critical' }).action).toBe('deny')
    expect(gate({ mode: 'deny', denyOn: 'critical', verdict: 'suspicious' }).action).toBe('report')
    expect(gate({ mode: 'deny', denyOn: 'suspicious', verdict: 'suspicious' }).action).toBe('deny')
  })
})

describe('闸门的未知输入：说清楚安装期缺了什么', () => {
  it('干净的包在闸门上也只能是 report，理由点名「范围没看全」', () => {
    const decision = gate({ verdict: 'clean' })
    expect(decision.action).toBe('report')
    // 关键：没有未知输入——excluded/unsupported 是已知边界，不该被说成「不知道」。
    expect(decision.unknownInputs).toEqual([])
    expect(decision.reasonCodes).toContain(DECISION_REASON.scopeNotFullyCovered)
  })

  it('OSV 未启用：deps_direct / intel_osv 是「明确不看」，不是未知', () => {
    const decision = gate({ osvRequested: false })
    expect(decision.unknownInputs).toEqual([])
  })

  it('OSV 启用了但相位被掐断（overran）→ 两个面都变成未知输入', () => {
    const decision = gate({ osvRequested: true, osv: { phase: 'overran', targets: 2, attempted: 1, answered: 1 } })
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.coverageGap('intel_osv'))
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.coverageGap('deps_direct'))
  })

  it('OSV 全问全答 → 没有未知输入（这一面真的看完了）', () => {
    const decision = gate({ osvRequested: true, osv: { phase: 'ran', targets: 1, attempted: 1, answered: 1 } })
    expect(decision.unknownInputs).toEqual([])
  })

  it('请求了 OSV 但扫描器没回报统计 → 只能算「问了没证到」，不能算「问到了」', () => {
    // 闸门走异步 scan（不像装载路径的 deny 分支会强制 osv:false），所以这里不编 osvSkipped；
    // 旧扫描器不回报统计时，intel_osv 只能是 partial——那正是未知输入。
    const decision = gate({ mode: 'deny', osvRequested: true })
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.coverageGap('intel_osv'))
    expect(decision.reasonCodes).toContain(DECISION_REASON.unknownInputsPresent)
  })

  it('扫描器跳过文件（R8）→ file_tree 是 partial，不能算看全', () => {
    const decision = gate({
      findings: [{ rule: 'R8', severity: 'info', message: '跳过超大文件', evidence: '', confidence: 'certain' }],
    })
    expect(decision.unknownInputs).toContain(UNKNOWN_INPUT.coverageGap('file_tree'))
  })

  it('范围恰好是五个静态面：运行时四面不在闸门的回答范围里', () => {
    expect([...GATE_SCOPE]).toEqual(['file_tree', 'deps_direct', 'deps_transitive', 'intel_osv', 'intel_registry'])
  })
})

describe('主体与策略快照', () => {
  it('有包名 → npm 主体；没有包名 → 本地路径主体（不编一个假名字）', () => {
    expect(gate({ pluginName: 'test-plugin' }).subject).toMatchObject({
      kind: 'npm',
      name: 'test-plugin',
      version: '1.0.0',
      subjectId: 'test-plugin@1.0.0',
    })
    expect(gate({ pluginName: '', packagePath: '/tmp/pkg' }).subject).toMatchObject({
      kind: 'local',
      name: '/tmp/pkg',
    })
  })

  it('policyId 编码模式与门槛：配置一变，旧决策就不再代表当前策略', () => {
    expect(gate({ mode: 'report' }).policyId).toBe('vet-gate:report:report-only')
    expect(gate({ mode: 'deny', denyOn: 'critical' }).policyId).toBe('vet-gate:deny:critical')
    expect(gate({ mode: 'deny', denyOn: 'suspicious' }).policyId).toBe('vet-gate:deny:medium')
    // 非法 denyOn 归位最严档位（与旧实现同一处失败关闭）。
    expect(gate({ mode: 'deny', denyOn: 'bogus' }).policyId).toBe('vet-gate:deny:critical')
  })

  it('判读带上扫描器引擎版本，不借用 vet 自己的版本号', () => {
    const decision = gate({})
    expect(decision.assessmentIds).toEqual(['gate-verdict:test-plugin@1.0.0'])
  })
})

describe('runGate 接线：决策随结果一起出去', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockBuildRequest.mockReturnValue({
      pluginName: 'test-plugin',
      pluginVersion: '1.0.0',
      request: { kind: 'files', files: ['/tmp/pkg/index.js'], targetKind: 'plugin' },
    })
  })

  it('clean + 默认模式 → blocked=false，决策是 report 且时间与 scannedAt 同源', async () => {
    mockScan.mockResolvedValue({ ok: true, report: report() })
    const result = await runGate({ packagePath: '/tmp/pkg' })
    expect(result.blocked).toBe(false)
    expect(result.decision.action).toBe('report')
    expect(validateDecision(result.decision)).toEqual([])
    expect(result.decision.decidedAt).toBe(Date.parse(result.scannedAt))
  })

  it('deny + critical → blocked=true，决策同为 deny（两份陈述一致）', async () => {
    mockScan.mockResolvedValue({ ok: true, report: report({ verdict: 'critical' }) })
    const result = await runGate({ packagePath: '/tmp/pkg', mode: 'deny' })
    expect(result.blocked).toBe(true)
    expect(result.decision.action).toBe('deny')
    expect(result.decision.boundary).toBe('pre_load')
  })
})
