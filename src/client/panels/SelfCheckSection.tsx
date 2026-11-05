/**
 * 自检区（0.5.9 起是主面板上的折叠；0.5.12 用户反馈后搬进「审计 & 蜜罐」页）：
 * 它回答的是 **vet 自己看到了多少**，不是机器上新发生的事——两块内容：
 * - 覆盖面（0.5.0 九面，0.5.3 起跨主体取最差）：哪些面在看、哪些没在看、为什么；
 * - 生效姿态（0.5.2 六面）：想要的面挂了没有，没挂的原因。
 *
 * 搬家的理由（用户 2026-11-05）：主面板上它默认收起、只留一行「自检详情 · 未见异常」，
 * 占的是一行黄金位置，却天天说同一句话；下面「🍯｜⏳｜🆕」那条横条本来就是「去审计页」的
 * 入口。于是自检在横条上只留一个小图标（异常时才带数字），详情整块进审计页——主面板少一行，
 * 审计页多一段，入口仍然只有一个。
 *
 * 0.5.14：本组件只画内容，标题与「N 项异常」由审计页的段头负责（三段的标题必须长一样，
 * 否则又回到「三个小灰字谁是谁」的老问题）。
 *
 * 异常口径（0.5.9 定，未变）：只认两类——`result==='failed'`（试过、没成）与 desired≠effective
 * （配了、没挂上）。off / excluded / unsupported / unknown 是既定边界（多半是用户自己没开的
 * 运行时守卫），它们是「我们没在看」，不是「我们看坏了」，所以不按异常计数，但仍逐条列出。
 */
import type { ReactNode } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { GroupLabel, subCardStyle } from '../components/primitives.tsx'
import type { VetCoverageWire, VetDomainProjectionWire, VetEffectiveConfigWire, VetPostureWire } from '../types.ts'

/**
 * 自检异常计数（主面板横条上的小图标靠它决定颜色与数字）。
 * 与 `SelfCheckSection` 里的分组渲染共用同一口径——两处各算一遍就会漂。
 */
export function selfCheckProblemCount(
  coverage: VetCoverageWire[],
  posture: VetPostureWire[],
  config?: VetEffectiveConfigWire,
  projection?: VetDomainProjectionWire,
): number {
  const coverageFailed = coverage.filter((c) => c.result === 'failed').length
  const postureGaps = posture.filter((p) => p.effective !== 'enforced' && p.effective !== 'off').length
  // 0.5.20：配置里「设了但没生效」的键，与姿态的「配了没挂上」是同一个问题，进同一个数。
  // 最典型的一例：paranoid 档会把 denyOn 降成 suspicious，而档位**不**替你打开 deny 模式——
  // 那一个键一直是 inert，直到用户显式切 deny。这不是噪音，是那条档位说明的可计数版本。
  const configGaps = (config?.keys ?? []).filter((k) => k.status !== 'active').length
  // 投影差异按「有/没有」计一次：它是 vet 自己的不变式，不是 N 个独立问题。
  const projectionBroken = (projection?.mismatches ?? 0) > 0 ? 1 : 0
  return coverageFailed + postureGaps + configGaps + projectionBroken
}

/** `<key>[:<细节>]` 形态的理由串：key 走词典，细节原样附在括号里（缺译就退回原串）。 */
function reasonText(t: T, reason: string): string {
  const cut = reason.indexOf(':')
  const head = cut < 0 ? reason : reason.slice(0, cut)
  const tail = cut < 0 ? '' : reason.slice(cut + 1)
  const label = t('coverage.reason.' + head)
  const text = label === 'coverage.reason.' + head ? head : label
  return tail === '' ? text : text + '（' + tail + '）'
}

export function SelfCheckSection({ pal, dark, t, coverage, posture, coverageSubject, coverageSubjects, config, projection }: {
  pal: ThemeTokens
  dark: boolean
  t: T
  coverage: VetCoverageWire[]
  posture: VetPostureWire[]
  /** 0.5.20：生效配置视图（你动过的键里哪些真在起作用）。缺席 = 旧后端，整段不渲染。 */
  config?: VetEffectiveConfigWire
  /** 0.5.20：投影比对计数。只在有差异时渲染一行。 */
  projection?: VetDomainProjectionWire
  /** 九行只描述一个包时后端给出的包名（多主体时不给出）。 */
  coverageSubject?: string
  /** 九行聚合了几个主体（≥2 时给出）。 */
  coverageSubjects?: number
}): ReactNode {
  const configGaps = (config?.keys ?? []).filter((k) => k.status !== 'active')
  if (coverage.length === 0 && posture.length === 0 && configGaps.length === 0 && (projection?.mismatches ?? 0) === 0) return null

  const coverageCovered = coverage.filter((c) => c.result === 'covered').length
  const coverageGaps = coverage.filter((c) => c.result !== 'covered')
  const postureGaps = posture.filter((p) => p.effective !== 'enforced' && p.effective !== 'off')
  const postureEnforced = posture.filter((p) => p.effective === 'enforced').length
  const postureOff = posture.filter((p) => p.effective === 'off').length

  // 0.5.3：九行是**跨主体取最差**的聚合。单主体时写包名，多主体时写个数——
  // 拿一个包的名字去标注一张跨 N 个包的表，就是这次收缩要消灭的那种含糊。
  const scope = coverageSubject !== undefined
    ? ' · ' + coverageSubject
    : coverageSubjects !== undefined
      ? ' · ' + coverageSubjects + ' ' + t('coverage.packages')
      : ''
  /** 一个缺口行的标题：理由（说清为什么）→ 出自哪个包 → 是否已承认为已知边界。 */
  const gapTitle = (gap: VetCoverageWire): string => {
    const parts = (gap.reasons ?? []).map((r) => reasonText(t, r))
    if (gap.subject !== undefined && coverageSubject === undefined) parts.push(t('coverage.from') + ' ' + gap.subject)
    if (gap.acknowledged === true) parts.push(t('coverage.acknowledged'))
    return parts.join(' · ')
  }
  const card = subCardStyle(dark, pal, '7px 10px', 11)

  return (
    <>
      {coverage.length > 0 && (
        <>
          <GroupLabel pal={pal}>{t('coverage.title') + scope}</GroupLabel>
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: pal.muted }}>
              <span style={{ fontWeight: 600, color: coverageGaps.length === 0 ? pal.sage : pal.ink }}>
                {coverageCovered} {t('coverage.observedCount')}
              </span>
              {coverageGaps.length > 0 && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>{coverageGaps.length} {t('coverage.unobservedCount')}</span>
                </>
              )}
              {coverageGaps.length === 0 && <span style={{ marginLeft: 'auto', color: pal.sage }}>{t('coverage.allCovered')}</span>}
            </div>
            {coverageGaps.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 5 }}>
                {coverageGaps.map((gap) => (
                  <span
                    key={gap.surface}
                    title={gapTitle(gap)}
                    style={{
                      border: `1px solid ${gap.result === 'failed' ? pal.rose : pal.borderSoft}`,
                      borderRadius: 999,
                      padding: '1px 7px',
                      color: gap.acknowledged === true ? pal.faint : gap.result === 'failed' ? pal.rose : gap.result === 'unknown' ? pal.faint : pal.muted,
                      background: gap.acknowledged === true ? 'transparent' : undefined,
                    }}
                  >
                    {t('coverage.surface.' + gap.surface)}：{t('coverage.result.' + gap.result)}
                  </span>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {posture.length > 0 && (
        <>
          <GroupLabel pal={pal}>{t('posture.title')}</GroupLabel>
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: pal.muted }}>
              <span style={{ fontWeight: 600, color: postureGaps.length === 0 ? pal.sage : pal.ink }}>
                {postureEnforced} {t('posture.enforcedCount')}
              </span>
              {postureOff > 0 && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>{postureOff} {t('posture.offCount')}</span>
                </>
              )}
              {postureEnforced === posture.length && <span style={{ marginLeft: 'auto', color: pal.sage }}>{t('posture.allEnforced')}</span>}
            </div>
            {postureGaps.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 5 }}>
                {postureGaps.map((entry) => (
                  <span
                    key={entry.surface}
                    title={entry.gap ?? ''}
                    style={{
                      border: `1px solid ${entry.effective === 'degraded' ? pal.ochre : pal.borderSoft}`,
                      borderRadius: 999,
                      padding: '1px 7px',
                      color: entry.effective === 'degraded' ? pal.ochre : pal.faint,
                    }}
                  >
                    {t('posture.surface.' + entry.surface)}
                  </span>
                ))}
              </div>
            )}
          </div>
        </>
      )}
      {configGaps.length > 0 && config !== undefined && (
        <>
          <GroupLabel pal={pal}>{t('config.title')}</GroupLabel>
          <div style={card}>
            <div style={{ color: pal.muted }}>
              <span style={{ fontWeight: 600, color: pal.ink }}>{configGaps.length} {t('config.notInEffect')}</span>
              <span aria-hidden="true"> · </span>
              <span>{config.counts.changed} {t('config.changed')}</span>
            </div>
            <ul style={{ margin: '5px 0 0', padding: 0, listStyle: 'none' }}>
              {configGaps.map((k) => (
                <li key={k.key} style={{ display: 'flex', gap: 6, alignItems: 'baseline', padding: '2px 0' }}>
                  <code style={{ color: pal.ink, flexShrink: 0 }}>{k.key}</code>
                  <span style={{ color: k.status === 'inert' ? pal.ochre : pal.faint, flexShrink: 0 }}>
                    {t('config.status.' + k.status)}
                  </span>
                  <span style={{ color: pal.faint, overflow: 'hidden', textOverflow: 'ellipsis' }} title={k.note ?? ''}>
                    {k.because !== undefined ? t('config.because') + ' ' + k.because + ' — ' : ''}
                    {k.note ?? ''}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}

      {(projection?.mismatches ?? 0) > 0 && projection !== undefined && (
        <>
          <GroupLabel pal={pal}>{t('projection.title')}</GroupLabel>
          <div style={card}>
            <div style={{ color: pal.rose }}>
              {projection.mismatches} {t('projection.mismatches')}
            </div>
            {projection.first !== undefined && (
              <div style={{ marginTop: 4, color: pal.faint, wordBreak: 'break-word' }}>{projection.first}</div>
            )}
          </div>
        </>
      )}
    </>
  )
}
