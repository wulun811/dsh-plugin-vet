/**
 * 插件详情（P3，唯一的三级面板，计划 §三-D7）：从「一行结论」到「为什么」。
 * 数据：GET /vet/plugin?name=（只读聚合端点）——扫描摘要（规则墙/OSV/时间）+
 * 能力清单（雷达/营养标签）+ 版本史差分 + 审计态。404 → 诚实空态。
 * 雷达六维口径见 RadarChart 头注释；营养标签只报声明面（诚实边界，D5）。
 */
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'
import { SubPanel } from '../components/SubPanel.tsx'
import { RadarChart } from '../components/RadarChart.tsx'
import { fmtTime } from '../utils/format.ts'
import type { PluginDetailWire } from '../types.ts'

const VERDICT_COLOR: Record<string, 'rose' | 'ochre' | 'sage' | 'infoBright'> = {
  critical: 'rose',
  suspicious: 'ochre',
  clean: 'sage',
  info: 'infoBright',
}

/** 规则码展示色：OSV/关键规则红、其余命中金（客户端无全量规则注册表，不画未命中灰墙防漂移）。 */
function ruleTagColor(code: string): string {
  return code === 'OSV' || /^(R8|R11)$/.test(code) ? 'critical' : 'hit'
}

/** 有悬停说明的规则码全集（i18n 键：rule.<code>.name / rule.<code>.desc；与 scanner 引擎规则表同步）。 */
const RULE_KNOWN = new Set([
  'OSV', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9',
  'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'R16', 'R17', 'R18', 'R19',
])

export function PluginDetailPanel({ pal, dark, t, name, onBack }: {
  pal: ThemeTokens
  dark: boolean
  t: T
  /** 详情目标包名（变化时重新拉取）。 */
  name: string
  onBack?: () => void
}): ReactNode {
  const [state, setState] = useState<
    | { phase: 'loading' }
    | { phase: 'error'; note: string }
    | { phase: 'ready'; data: NonNullable<PluginDetailWire['plugin']> }
  >({ phase: 'loading' })

  useEffect(() => {
    let alive = true
    setState({ phase: 'loading' })
    const load = async (): Promise<void> => {
      try {
        const res = await fetch('/vet/plugin?name=' + encodeURIComponent(name), { cache: 'no-store' })
        if (!alive) return
        if (res.status === 404) {
          setState({ phase: 'error', note: t('detail.notFound') })
          return
        }
        const body = await res.json() as PluginDetailWire
        if (!alive) return
        if (body.ok === true && body.plugin !== undefined) {
          setState({ phase: 'ready', data: body.plugin })
        } else {
          setState({ phase: 'error', note: t('detail.notFound') })
        }
      } catch {
        if (alive) setState({ phase: 'error', note: t('guard.requestFailed') })
      }
    }
    void load()
    return () => { alive = false }
  }, [name, t])

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <SubPanel tok={pal} title={t('detail.title')} onBack={onBack} backLabel={t('panel.back')} ariaLabel={t('detail.title')}>
        {state.phase === 'loading' && (
          <div style={{ color: pal.faint, padding: '20px 0', textAlign: 'center' }}>{t('detail.loading')}</div>
        )}
        {state.phase === 'error' && (
          <div style={{ color: pal.faint, padding: '16px 6px', textAlign: 'center', lineHeight: 1.7 }}>{state.note}</div>
        )}
        {state.phase === 'ready' && <DetailBody pal={pal} dark={dark} t={t} data={state.data} />}
      </SubPanel>
    </div>
  )
}

function DetailBody({ pal, dark, t, data }: { pal: ThemeTokens; dark: boolean; t: T; data: NonNullable<PluginDetailWire['plugin']> }): ReactNode {
  const scan = data.scan
  const verdictColorKey = VERDICT_COLOR[scan?.verdict ?? 'info'] ?? 'infoBright'
  const verdictColor = pal[verdictColorKey]

  // —— 雷达六维（口径见 RadarChart 注释；全部来自声明能力清单）——
  const cap = data.capabilities
  const radarValues = [
    Math.min(100, ((cap?.hosts.length ?? 0) / 10) * 100),
    Math.min(100, ((cap?.fsPaths.length ?? 0) / 10) * 100),
    Math.min(100, ((cap?.spawnCmds.length ?? 0) / 6) * 100),
    Math.min(100, ((cap?.imports.length ?? 0) / 30) * 100),
    (cap?.hasExec ?? false) ? 100 : 4,
    (cap?.esmNamedBuiltins ?? false) ? 100 : 4,
  ]
  const radarLabels = [t('nut.network'), t('nut.fs'), t('nut.spawn'), t('nut.deps'), t('nut.exec'), t('nut.esm')]

  // —— 营养标签（声明面；无对应数据格不编造）——
  const nutrition: { icon: string; label: string; value: string; hit: boolean; detail: string }[] = [
    {
      icon: '\ud83c\udf10', label: t('nut.network'),
      value: (cap?.hasNetwork ?? false) || (cap?.hosts.length ?? 0) > 0 ? `${cap?.hosts.length ?? 0} host` : t('nut.none'),
      hit: (cap?.hosts.length ?? 0) > 0,
      detail: cap?.hosts.slice(0, 2).join('\n') || '',
    },
    {
      icon: '\ud83d\udcc1', label: t('nut.fs'),
      value: (cap?.fsPaths.length ?? 0) > 0 ? `${cap?.fsPaths.length} path` : t('nut.none'),
      hit: (cap?.fsPaths.length ?? 0) > 0,
      detail: cap?.fsPaths.slice(0, 2).join('\n') || '',
    },
    {
      icon: '\u26a1', label: t('nut.spawn'),
      value: (cap?.spawnCmds.length ?? 0) > 0 ? `spawn ×${cap?.spawnCmds.length}` : t('nut.none'),
      hit: (cap?.spawnCmds.length ?? 0) > 0,
      detail: cap?.spawnCmds.slice(0, 2).join('\n') || '',
    },
    {
      icon: '\ud83d\udce6', label: t('nut.deps'),
      value: (cap?.imports.length ?? 0) > 0 ? `${cap?.imports.length} import` : t('nut.none'),
      hit: (cap?.ghostDeps?.length ?? 0) > 0,
      detail: (cap?.ghostDeps?.length ?? 0) > 0 ? `ghost ×${cap?.ghostDeps?.length ?? 0}` : '',
    },
    {
      icon: '\u2699\ufe0f', label: t('nut.exec'),
      value: (cap?.hasExec ?? false) ? 'exec' : t('nut.none'),
      hit: cap?.hasExec ?? false,
      detail: '',
    },
    {
      icon: '\ud83d\udce2', label: t('nut.esm'),
      value: (cap?.esmNamedBuiltins ?? false) ? 'T2 blind' : t('nut.none'),
      hit: cap?.esmNamedBuiltins ?? false,
      detail: '',
    },
  ]

  return (
    <div>
      {/* headline：包名独占一行，verdict+分数独立一行（340px 内不被截断） */}
      <div style={{ marginBottom: 12, minWidth: 0 }}>
        <div style={{ fontWeight: 800, fontSize: 13, color: pal.ink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {data.name}{data.version !== undefined ? `@${data.version}` : ''}
        </div>
        {scan !== undefined && (
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: verdictColor, flexShrink: 0 }}>{scan.verdict}</span>
            <span style={{ fontSize: 19, fontWeight: 800, color: verdictColor, flexShrink: 0, lineHeight: 1.1 }}>
              {Number(scan.staticScore.toFixed(2))}
            </span>
            <span style={{ fontSize: 10, color: pal.faint }}>/ 100</span>
          </div>
        )}
      </div>

      {/* 状态 chips */}
      {(data.blocked === true || data.audited === true || data.official === true) && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
          {data.blocked === true && (
            <Chip pal={pal} text={t('audit.blocked')} color={pal.dangerBright} />
          )}
          {data.official === true && (
            <span title={t('audit.officialHint')} style={{ cursor: 'help' }}>
              <Chip pal={pal} text={t('audit.official')} color={pal.sage} />
            </span>
          )}
          {data.audited === true && (
            <Chip pal={pal} text={t('audit.audited')} color={pal.accentBright} />
          )}
        </div>
      )}

      {/* 雷达：六维口径与方向语义在悬停说明里（防误读为「越大越好」的评分），面板本体不占文字 */}
      <div title={t('detail.radarNote')} style={{ display: 'flex', justifyContent: 'center', marginBottom: 14, cursor: 'help' }}>
        <RadarChart tok={pal} values={radarValues} labels={radarLabels} color={verdictColor} />
      </div>

      {/* 规则命中墙（有扫描摘要才有） */}
      {scan !== undefined ? (
        <>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: pal.faint, marginBottom: 7 }}>
            {t('detail.rules')}（{scan.ruleCodes.length}）
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 12 }}>
            {scan.ruleCodes.length === 0 ? (
              <span style={{ fontSize: 10.5, color: pal.faint }}>{t('detail.ruleNone')}</span>
            ) : scan.ruleCodes.map(code => {
              const kind = ruleTagColor(code)
              const bg = kind === 'critical' ? 'rgba(154,74,74,0.15)' : 'rgba(154,138,74,0.13)'
              const fg = kind === 'critical' ? pal.dangerBright : pal.warnBright
              const bd = kind === 'critical' ? pal.borderDanger : pal.borderWarn
              return (
                <span key={code} title={RULE_KNOWN.has(code)
                  ? `${code} · ${t('rule.' + code + '.name')} — ${t('rule.' + code + '.desc')}`
                  : `${code} — ${t('rule.unknown')}`} style={{
                  fontSize: 9.5, fontWeight: 700, padding: '3px 7px', borderRadius: 4,
                  background: bg, color: fg, border: `1px solid ${bd}`, cursor: 'help',
                }}>{code}</span>
              )
            })}
          </div>
        </>
      ) : (
        <div style={{
          fontSize: 11, color: pal.faint, lineHeight: 1.6,
          border: '1px dashed ' + pal.borderSoft, borderRadius: 8, padding: '8px 10px', marginBottom: 12,
        }}>
          {data.note ?? t('detail.oldPkgNote')}
        </div>
      )}

      {/* 结论来源 meta */}
      {scan !== undefined && (
        <div style={{ borderTop: '1px solid ' + pal.borderSoft, paddingTop: 10, marginBottom: 12, fontSize: 10.5, color: pal.muted, lineHeight: 1.7 }}>
          <div><b style={{ color: ink(pal) }}>{t('detail.osv')}</b>{scan.osv ?? t('detail.ruleNone')}</div>
          <div><b style={{ color: ink(pal) }}>{t('detail.scannedAt')}</b>{fmtTime(scan.at)}</div>
          {scan.sourceCount !== undefined && (
            <div><b style={{ color: ink(pal) }}>{t('detail.sources')}</b>{scan.sourceCount}</div>
          )}
        </div>
      )}

      {/* 升级差分 */}
      {data.diffSummary != null && data.diffSummary.added.length > 0 && (
        <div style={{
          borderRadius: 10, padding: '9px 11px', marginBottom: 12,
          background: cardBg(dark),
          borderLeft: `3px solid ${pal.warnBright}`,
          borderTop: '1px solid ' + pal.borderWarn,
          borderRight: '1px solid ' + pal.borderWarn,
          borderBottom: '1px solid ' + pal.borderWarn,
          boxShadow: cardInset(dark),
        }}>
          <div style={{ fontSize: 10.5, fontWeight: 700, color: pal.warnBright, marginBottom: 5 }}>
            {t('detail.diff')} · {data.diffSummary.from} → {data.diffSummary.to}
          </div>
          {data.diffSummary.added.map((line, i) => (
            <div key={i} style={{ fontSize: 10.5, color: pal.muted, marginTop: 2 }}>＋{line}</div>
          ))}
        </div>
      )}

      {/* 能力营养标签（声明面） */}
      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: pal.faint, marginBottom: 7 }}>
        {t('detail.capabilities')}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
        {nutrition.map(cell => (
          <div key={cell.label} title={cell.detail !== '' ? cell.detail : undefined} style={{
            borderRadius: 8, padding: '9px 6px', textAlign: 'center',
            background: cardBg(dark),
            border: '1px solid ' + (cell.hit ? pal.borderWarn : pal.borderSoft),
            boxShadow: cardInset(dark),
          }}>
            <div aria-hidden="true" style={{ fontSize: 14, marginBottom: 3 }}>{cell.icon}</div>
            <div style={{ fontSize: 9, color: pal.faint, marginBottom: 2 }}>{cell.label}</div>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: cell.hit ? pal.warnBright : pal.muted }}>{cell.value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Chip({ pal, text, color }: { pal: ThemeTokens; text: string; color: string }): ReactNode {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 9px', borderRadius: 9,
      background: pal.cardGrad, border: '1px solid ' + pal.borderSoft, color,
    }}>{text}</span>
  )
}

function ink(pal: ThemeTokens): string {
  // meta 标签键用 muted 偏亮一档（正文对比度红线内）
  return pal.muted
}
