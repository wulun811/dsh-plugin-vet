/**
 * 审计 & 蜜罐中心（P3，L2 次级面板）：
 * - 审计状态列表：⛔已拦截 / ⚠静态存疑待审 / ⏳待审（无档案）/ ✅已审计，点行 → 插件详情；
 * - 蜜罐监控卡：armed 状态 + 触碰次数 + 最近触碰（诚实口径：诱饵具体数量 v1 不展示——
 *   服务端未持久化诱饵清单，只报「部署状态」与「触碰事件」，不编数字）。
 * 数据：snap.audit（status.json 增量字段；旧后端降级为空态提示）。
 */
import type { ReactNode } from 'react'
import { useState } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'
import { SubPanel, PluginNameButton } from '../components/SubPanel.tsx'
import { fmtShort } from '../utils/format.ts'
import type { AuditSummaryWire } from '../types.ts'

/** 审计状态行每页条数（round-21：分页追加渲染，第三方多时不全量画满）。 */
const PAGE = 14

export function AuditCenterPanel({ pal, dark, t, audit, onBack, onOpenPlugin }: {
  pal: ThemeTokens
  dark: boolean
  t: T
  audit?: AuditSummaryWire
  onBack?: () => void
  onOpenPlugin: (name: string) => void
}): ReactNode {
  const [limit, setLimit] = useState<number>(PAGE)
  const plugins = audit?.plugins ?? []
  const honey = audit?.honeypot

  /** 展示排序已在服务端做过；这里按「拦截 > 存疑 > 待审 > 已审计」重排徽标优先级。 */
  const rows = [...plugins].sort((a, b) => rank(b) - rank(a) || b.at - a.at)
  const pendingCount = (audit?.pendingAudits.length ?? 0)
  const shown = rows.slice(0, Math.min(limit, rows.length))
  const hasMore = shown.length < rows.length

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <SubPanel tok={pal} title={t('audit.center')} badge={pendingCount > 0 ? `${t('audit.pendingShort')} ${pendingCount}` : t('audit.audited')} badgeColor={pendingCount > 0 ? pal.ochre : pal.sage} onBack={onBack} backLabel={t('panel.back')} ariaLabel={t('audit.center')}>
        {/* —— 审计状态 —— */}
        <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: pal.faint, marginBottom: 8 }}>
          {t('audit.statusTitle')}
        </div>
        {rows.length === 0 ? (
          <div style={{ color: pal.faint, padding: '12px 4px', textAlign: 'center' }}>{t('plugins.empty')}</div>
        ) : (
          <>
            <ul style={{ margin: 0, padding: 0, listStyle: 'none', marginBottom: 14 }}>
              {shown.map(p => {
              const blocked = p.blocked === true
              const suspicious = p.verdict === 'suspicious' || p.verdict === 'critical'
              // 走廊只含第三方（round-19：官方包整体移出索引，不占格子）
              const icon = blocked ? '\u26d4' : suspicious ? '\u26a0' : p.audited === true ? '\u2705' : '\u23f3'
              const iconColor = blocked ? pal.dangerBright : suspicious ? pal.warnBright : p.audited === true ? pal.accentBright : pal.infoBright
              const stateText = blocked
                ? t('audit.blocked')
                : suspicious
                  ? t('audit.pendingReason')
                  : p.audited === true
                    ? t('audit.audited')
                    : t('audit.pendingPlain')
              return (
                <li
                  key={p.name}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 7,
                    background: cardBg(dark),
                    border: '1px solid ' + (blocked ? pal.borderDanger : pal.borderSoft),
                    borderRadius: 8,
                    boxShadow: cardInset(dark),
                    padding: '6px 9px',
                    marginBottom: 4,
                  }}
                >
                  <span aria-hidden="true" style={{ fontSize: 12, color: iconColor, flexShrink: 0 }}>{icon}</span>
                  <PluginNameButton tok={pal} name={p.name} onClick={() => onOpenPlugin(p.name)} fontSize={11} />
                  <span style={{
                    marginLeft: 'auto',
                    fontSize: 10,
                    color: blocked ? pal.dangerBright : p.audited === true ? pal.faint : pal.ochre,
                    flexShrink: 0,
                    maxWidth: 150,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    {stateText}{!blocked && p.verdict !== undefined ? ` · ${fmtShort(p.at)}` : ''}
                  </span>
                </li>
              )
            })}
            </ul>
            {/* 分页：round-21——点「加载更多」追加一页（每页 14），第三方多时不截断 */}
            {hasMore && (
              <div style={{ textAlign: 'center', marginBottom: 12 }}>
                <button
                  type="button"
                  onClick={() => setLimit(l => l + PAGE)}
                  title={t('plugins.pageHint')}
                  style={{
                    border: '1px solid ' + pal.border,
                    background: 'transparent',
                    color: pal.ink,
                    borderRadius: 7,
                    padding: '3px 14px',
                    cursor: 'pointer',
                    fontSize: 10.5,
                    fontFamily: 'inherit',
                  }}
                >
                  {t('plugins.loadMore')}（{shown.length}/{rows.length}）
                </button>
              </div>
            )}
          </>
        )}

        {/* —— 蜜罐监控 —— */}
        <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: pal.faint, marginBottom: 8 }}>
          {t('audit.honeyTitle')}
        </div>
        <div style={{
          background: cardBg(dark),
          border: '1px solid ' + ((honey?.armed ?? false) ? pal.borderWarn : pal.borderSoft),
          boxShadow: ((honey?.touches ?? 0) > 0 ? `inset 0 0 40px ${pal.glowDanger}, ` : '') + cardInset(dark),
          borderRadius: 10,
          padding: '10px 12px',
        }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: (honey?.armed ?? false) ? pal.warnBright : pal.muted, marginBottom: 6 }}>
            {(honey?.armed ?? false) ? t('honey.armed') : t('honey.disarmed')}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: pal.muted }}>
            <span>{t('honey.touches')}</span>
            <b style={{ color: (honey?.touches ?? 0) > 0 ? pal.dangerBright : pal.muted }}>{honey?.touches ?? 0}</b>
          </div>
          {(honey?.lastTouch !== undefined) ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 11, color: pal.muted, marginTop: 3 }}>
                <span style={{ flexShrink: 0 }}>@</span>
                <PluginNameButton tok={pal} name={honey.lastTouch.plugin} onClick={() => onOpenPlugin(honey.lastTouch?.plugin ?? '')} />
              </div>
              <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid ' + pal.borderWarn, fontSize: 11, fontWeight: 700, color: pal.dangerBright, wordBreak: 'break-all' }}>
                {honey.lastTouch.file} · {fmtShort(honey.lastTouch.at)}
              </div>
            </>
          ) : (
            <div style={{ marginTop: 3, fontSize: 11, color: pal.faint }}>{t('honey.noTouch')}</div>
          )}
        </div>
      </SubPanel>
    </div>
  )
}

function rank(p: { blocked?: boolean; audited?: boolean; verdict?: string }): number {
  if (p.blocked === true) return 4
  if (p.verdict === 'suspicious' || p.verdict === 'critical') return 3
  if (p.audited !== true) return 2
  return 1
}
