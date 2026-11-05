/**
 * 安装闸门的决策（0.5.11，施工图 S2-03 的第一步）。
 *
 * S2-03 的原话是「把 gate 的既有策略行为翻译成 PolicyDecision，**先影子对照**，真实执行
 * 仍走旧函数」。所以这个文件只负责**说清楚闸门为什么拦或为什么放**，不改变拦不拦：
 * `GateResult.blocked` 仍然来自 `decideDenyBlock`，`decision` 是并排挂上去的第二份陈述。
 *
 * 为什么值得并排挂：`blocked: false` 这一个布尔把三件完全不同的事说成同一件——
 * 「查干净了」、「什么都没查」、「查了一半」。安装器拿到 `false` 没有任何办法区分，
 * 而这三种情况对用户的含义相差极大。决策对象把「我缺了什么」写进 `unknownInputs`，
 * 把「凭什么这么判」写进 `reasonCodes`，面板/日志/事后审计才有一份可读的东西。
 *
 * 闸门口径（与其它边界不同的三点，全部写进 policy 而不是散在 if 里）：
 * 1. `scope` 只含五个静态面——安装期没有任何钩子在看运行时，把四个运行时面写进范围
 *    等于自问自答；
 * 2. `denyFrom` 只在 `mode === 'deny'` 时存在——`report` 模式的闸门**没有**拦截授权，
 *    它连「我拦得住」这句话都不该有能力说出口（I07）；
 * 3. `failClosedOn: ['verdict:unrecognized']`——扫描器协议漂移（结论不在三值内）时，
 *    deny 模式的既有行为就是拦；这条失败关闭是被显式授权的，不是从排序巧合里漏出来的。
 */
import { buildDecision } from './domain/decision.js'
import type { DecisionPolicy } from './domain/decision.js'
import { npmSubject, localSubject } from './domain/project.js'
import type { Assessment, AssessmentSeverity, Decision, SubjectRef, Surface } from './domain/types.js'
import type { ScanReport } from './scanner/protocol.js'
import { coverageForScan } from './guard/coverage.js'

/**
 * 闸门回答哪五个面。
 *
 * `deps_transitive` 与 `intel_registry` 在这里是 `unsupported`（见 `coverageForScan` 的
 * `gate` 分支）：闸门没有传递依赖雷达，也不做 registry 对账。声明在范围里而不是悄悄
 * 不写——「这个边界不看」是可审计的，「没人提到」不是。
 */
export const GATE_SCOPE: readonly Surface[] = [
  'file_tree',
  'deps_direct',
  'deps_transitive',
  'intel_osv',
  'intel_registry',
]

/** 扫描器结论 → 评估严重度。`suspicious` 落 medium：它不是「很可能有问题」，是「值得看」。 */
const VERDICT_SEVERITY: Record<string, AssessmentSeverity> = {
  critical: 'critical',
  suspicious: 'medium',
  clean: 'info',
}

/** 结论严重度 → 拦截门槛。`denyOn` 是旧接口，只有两档。 */
function denyFromOf(denyOn: 'critical' | 'suspicious' | undefined): AssessmentSeverity {
  return denyOn === 'suspicious' ? 'medium' : 'critical'
}

export interface GateDecisionInput {
  readonly mode: 'report' | 'deny'
  readonly denyOn?: 'critical' | 'suspicious'
  readonly report: ScanReport
  readonly packagePath: string
  readonly pluginName?: string
  readonly pluginVersion?: string
  /** 本次扫描是否请求了 OSV（决定 `intel_osv`/`deps_direct` 两行怎么写）。 */
  readonly osvRequested: boolean
  readonly decidedAt: number
}

/** 闸门主体：有包名就是 npm 主体，没有就退回本地路径主体（不编一个假名字）。 */
function subjectOf(input: GateDecisionInput): SubjectRef {
  const name = input.pluginName ?? ''
  if (name === '') return localSubject(input.packagePath)
  return npmSubject(name, input.pluginVersion)
}

/**
 * 把一次扫描结论翻译成一条评估。
 *
 * 只有一条：闸门不看证据链，它看的是扫描器的**结论**。`evidenceIds` 于是必然是空的
 * ——填规则码进去是伪造（那是 `Finding.rule`，不是 `Evidence.id`）。空数组在这里是诚实的
 * 陈述：这条判读没有可回溯的证据对象，因为它来自一个把结论一次性交出来的子进程。
 *
 * 导出是因为它是「规则集版本从哪来」这个问题的唯一答案：`ruleSetVersion` 只能是扫描器
 * 自述的引擎标识，不能是 vet 自己的版本号（不变式 4：规则版本是结论的一部分）。
 */
export function gateAssessment(input: GateDecisionInput): Assessment {
  return verdictAssessment(subjectOf(input), input)
}
function verdictAssessment(subject: SubjectRef, input: GateDecisionInput): Assessment {
  const verdict = input.report.verdict as string
  const known = Object.hasOwn(VERDICT_SEVERITY, verdict)
  const limitations: string[] = ['静态扫描不执行插件代码']
  if (!known) {
    limitations.push('扫描器返回的结论不在 critical/suspicious/clean 之内（协议漂移）')
  } else if (verdict === 'clean') {
    limitations.push('未命中规则不等于安全：规则只覆盖它写得出来的那部分行为')
  }
  if (!input.osvRequested) limitations.push('未做 OSV 已知漏洞核对')
  return {
    id: `gate-verdict:${subject.subjectId}`,
    subject,
    claim: known ? `静态扫描结论：${verdict}` : `静态扫描结论不可判定：${verdict.slice(0, 64)}`,
    state: known ? (verdict === 'clean' ? 'not_observed' : 'finding') : 'insufficient_evidence',
    severity: known ? VERDICT_SEVERITY[verdict]! : 'unknown',
    evidenceIds: [],
    // 规则集版本的唯一诚实来源是扫描器自述的引擎标识（static-v27 之类）。
    ruleSetVersion: input.report.engine,
    evaluatedAt: input.decidedAt,
    limitations,
  }
}

/**
 * 构造闸门的决策。
 *
 * `policyId` 编码了本次生效的策略快照：模式 + 门槛。配置一变（`--mode deny` 改成
 * 默认 report）id 就变，旧决策不再代表当前策略——这正是 `policyId` 存在的理由。
 */
export function gateDecision(input: GateDecisionInput): Decision {
  const subject = subjectOf(input)
  const verdict = input.report.verdict as string
  const known = Object.hasOwn(VERDICT_SEVERITY, verdict)
  const policy: DecisionPolicy = {
    scope: GATE_SCOPE,
    ...(input.mode === 'deny' ? { denyFrom: denyFromOf(input.denyOn) } : {}),
    failClosedOn: ['verdict:unrecognized'],
  }
  return buildDecision({
    // 主体 + 策略 → 同一个 id：同一份字节、同一份策略反复过闸门，是**同一条决策**。
    // 时间与运行次数写进 `decidedAt`，不参与身份。
    id: `vet-gate:${subject.subjectId}`,
    subject,
    boundary: 'pre_load',
    policyId: `vet-gate:${input.mode}:${input.mode === 'deny' ? denyFromOf(input.denyOn) : 'report-only'}`,
    decidedAt: input.decidedAt,
    policy,
    assessments: [gateAssessment(input)],
    coverage: coverageForScan({
      osvEnabled: input.osvRequested,
      ...(input.report.osv !== undefined ? { osv: input.report.osv } : {}),
      transitiveDeps: false,
      // `gate` 分支在用到它之前就返回了（运行时四面不在安装期的回答范围里）；
      // 这里填 `off` 只是为了给必填字段一个诚实的值。
      runtimeGuard: 'off',
      scanFailed: false,
      sourceCount: input.report.sourceCount,
      skippedFiles: skipCountOf(input.report),
      observedAt: input.decidedAt,
      observerVersion: input.report.engine,
      scope: 'gate',
    }),
    ...(known ? {} : { unknownInputs: ['verdict:unrecognized'] }),
  })
}

/** R8 的跳过计数：扫描器为每个被跳过的文件留一条 R8 元 finding（与 scan-plugin/guard 同一口径）。 */
function skipCountOf(report: ScanReport): number {
  return (report.findings ?? []).filter((f) => f.rule === 'R8').length
}
