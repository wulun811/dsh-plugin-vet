/**
 * 最近插件列表（P3，D7 定案的 L2「走廊」）：最近扫描留档按时间倒序，
 * 每行 包名 + verdict 徽标 + 分数 + 审计态 + 相对时间；点击行 → 三级插件详情。
 * 分页（round-21）：数据经 status.json 5s 轮询全量下发（服务端上限 200），
 * 这里按 PAGE=20 逐页渲染，点「加载更多」再追加一页——避免一次画满全部行。
 * 数据：snap.audit.plugins（status.json 增量字段；旧后端无此字段时显示空态）。
 */
import { useState } from 'react'
import type { ReactNode } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { cardInset } from '../theme.ts'
import { SubPanel } from '../components/SubPanel.tsx'
import { fmtRel } from '../utils/format.ts'
import type { PluginIndexEntry } from '../types.ts'

/** 每页行数（20 行的 DOM 节点在 340px 面板内滚动无压力；点击追加时再画下一页）。 */
const PAGE = 20
/** 服务端索引上限兜底（与 audit-summary PLUGIN_INDEX_CAP 一致的口径）。 */
const MAX_ROWS = 200

export function PluginsListPanel({ pal, dark, t, plugins, onBack, onOpenPlugin }: {
  pal: ThemeTokens
  dark: boolean
  t: T
  /** 已按 at 倒序的索引（服务端保证）；本组件分页展示全部（最多 MAX_ROWS）。 */
  plugins: PluginIndexEntry[]
  onBack?: () => void
  onOpenPlugin: (name: string) => void
}): ReactNode {
  const [limit, setLimit] = useState<number>(PAGE)
  const now = Date.now()
  const relUnits = { now: t('rel.now'), min: t('rel.min'), hour: t('rel.hour') }
  const total = Math.min(plugins.length, MAX_ROWS)
  const shown = plugins.slice(0, Math.min(limit, total))
  const hasMore = shown.length < total
  return (
    <div style={{ width: '100%', height: '100%' }}>
      <SubPanel tok={pal} title={t('plugins.title')} badge={total > 0 ? `${total}` : undefined} onBack={onBack} backLabel={t('panel.back')} ariaLabel={t('plugins.title')}>
        {shown.length === 0 ? (
          <div style={{ color: pal.faint, padding: '20px 8px', textAlign: 'center', lineHeight: 1.7 }}>
            {t('plugins.empty')}
          </div>
        ) : (
          <>
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {shown.map(p => {
                const blocked = p.blocked === true
                const suspicious = p.verdict === 'suspicious' || p.verdict === 'critical'
                // 走廊只含第三方（round-19：官方包整体移出索引，不占格子）
                const icon = blocked ? '\u26d4' : suspicious ? '\u26a0' : p.audited === true ? '\u2705' : '\u23f3'
                const verdictColor = blocked ? pal.rose : suspicious ? pal.ochre : pal.sage
                return (
                  <li key={p.name} style={{ marginBottom: 5 }}>
                    <button
                      type="button"
                      onClick={() => onOpenPlugin(p.name)}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 7,
                        textAlign: 'left',
                        cursor: 'pointer',
                        fontFamily: 'inherit',
                        background: pal.cardGrad,
                        border: '1px solid ' + (blocked ? pal.borderDanger : pal.borderSoft),
                        borderRadius: 9,
                        boxShadow: cardInset(dark),
                        padding: '8px 10px',
                        color: pal.muted,
                        transition: 'border-color 0.2s ' + pal.ease,
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.borderColor = pal.sage }}
                      onMouseLeave={(e) => { e.currentTarget.style.borderColor = blocked ? pal.borderDanger : pal.borderSoft }}
                    >
                      <span aria-hidden="true" style={{ fontSize: 12, flexShrink: 0 }}>{icon}</span>
                      <span style={{
                        fontWeight: 600,
                        fontSize: 11.5,
                        color: pal.ink,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        minWidth: 0,
                      }}>{p.name}</span>
                      <span style={{ marginLeft: 'auto', flexShrink: 0, display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                        <span style={{ fontSize: 10.5, fontWeight: 700, color: verdictColor }}>
                          {p.verdict ?? t('plugins.never')}
                        </span>
                        {p.staticScore !== undefined && (
                          <span style={{ fontSize: 10, color: pal.faint }}>{p.staticScore.toFixed(2)}</span>
                        )}
                        <span style={{ fontSize: 10, color: pal.faint }}>{fmtRel(p.at, now, relUnits)}</span>
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
            {/* 分页：round-21——点「加载更多」追加一页（每页 20），全量 200 条内逐页渲染 */}
            {hasMore ? (
              <div style={{ textAlign: 'center', marginTop: 8 }}>
                <button
                  type="button"
                  onClick={() => setLimit(l => l + PAGE)}
                  title={t('plugins.pageHint')}
                  style={{
                    border: '1px solid ' + pal.border,
                    background: 'transparent',
                    color: pal.ink,
                    borderRadius: 7,
                    padding: '4px 16px',
                    cursor: 'pointer',
                    fontSize: 11,
                    fontFamily: 'inherit',
                  }}
                >
                  {t('plugins.loadMore')}（{shown.length}/{total}）
                </button>
              </div>
            ) : (
              total > PAGE && (
                <div style={{ textAlign: 'center', marginTop: 8, fontSize: 10, color: pal.faint }}>
                  {t('plugins.allShown')}（{total}）
                </div>
              )
            )}
          </>
        )}
      </SubPanel>
    </div>
  )
}