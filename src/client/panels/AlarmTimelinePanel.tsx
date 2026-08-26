/**
 * 报警时间线（P3 重构版）：rail + 状态点 + 卡片的时序叙事（mock .timeline 版式）。
 * 交互与 P0 迁移版完全一致：展开详情/复制（带元信息丢给 LLM）/忽略/已忽略区恢复。
 * 新增：插件名可点 → 三级插件详情（onOpenPlugin）；头部 ← 返回（onBack，层栈 D2）。
 */
import { useState } from 'react'
import type { ReactNode } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'
import { SubPanel, PluginNameButton } from '../components/SubPanel.tsx'
import { fmtTime } from '../utils/format.ts'
import type { VetAlarmWire } from '../types.ts'
import { zh } from '../i18n.ts'

export function AlarmTimelinePanel({ pal, t, alarms, dismissed, dark, onDismiss, onRestore, onBack, onOpenPlugin }: {
  pal: ThemeTokens
  t: T
  alarms: VetAlarmWire[]
  dismissed: VetAlarmWire[]
  dark: boolean
  onDismiss: (id: string) => void
  onRestore: (id: string) => void
  onBack?: () => void
  /** 点插件名 → 插件详情层（未传则名字不可点）。 */
  onOpenPlugin?: (name: string) => void
}): ReactNode {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [dismissedCollapsed, setDismissedCollapsed] = useState(true)
  const [expandedDismissedIds, setExpandedDismissedIds] = useState<Set<string>>(new Set())

  const toggleExpand = (id: string): void => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleDismissedExpand = (id: string): void => {
    setExpandedDismissedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const copyAlarm = async (a: VetAlarmWire): Promise<void> => {
    // 构造带元信息的文本（丢给 DSH 里的 LLM 继续深挖用）
    // pluginHint 有 @scope/name 与裸名两种形态（归因链产出），统一补 @ 前缀
    const plugin = a.pluginHint !== undefined ? (a.pluginHint.startsWith('@') ? a.pluginHint : '@' + a.pluginHint) : '(unattributed)'
    const time = new Date(a.at).toLocaleString()
    const text = `VET 插件警报，请查实后给出解决方案：\n\n` +
      `时间：${time}\n` +
      `插件：${plugin}\n` +
      `类型：${a.kind}\n` +
      `严重度：${a.severity ?? 'unknown'}\n` +
      `信息：${a.message}`

    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(a.id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      // 降级：创建临时 textarea
      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopiedId(a.id)
      setTimeout(() => setCopiedId(null), 2000)
    }
  }

  /** 处置标签（诚实口径）：severity 分档文案，不虚构「已拦截」。 */
  const severityLabel = (a: VetAlarmWire): string =>
    a.severity === 'red' ? t('timeline.critical') : a.severity === 'yellow' ? t('timeline.warned') : t('timeline.logged')
  const sevColor = (a: VetAlarmWire): string =>
    a.severity === 'red' ? pal.rose : a.severity === 'yellow' ? pal.ochre : pal.infoBright

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <SubPanel tok={pal} title={t('timeline.title')} badge={alarms.length} onBack={onBack} backLabel={t('panel.back')} ariaLabel={t('alarmPanel.aria')}>
        {alarms.length === 0 ? (
          <div style={{ color: pal.faint, padding: '20px 0', textAlign: 'center' }}>{t('alarmPanel.empty')}</div>
        ) : (
          <div style={{ position: 'relative', paddingLeft: 24 }}>
            {/* rail：danger→warn→info 纵向渐变轨道 */}
            <div aria-hidden="true" style={{
              position: 'absolute',
              left: 6,
              top: 2,
              bottom: 2,
              width: 2,
              borderRadius: 1,
              background: `linear-gradient(180deg, ${pal.rose}, ${pal.ochre}, ${pal.infoBright}, ${pal.borderSoft})`,
            }} />
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {alarms.map((a) => {
                const expanded = expandedIds.has(a.id)
                const copied = copiedId === a.id
                const color = sevColor(a)
                return (
                  <li key={a.id} style={{ position: 'relative', marginBottom: 14 }}>
                    {/* 状态点 */}
                    <span aria-hidden="true" style={{
                      position: 'absolute',
                      left: -24,
                      top: 4,
                      width: 12,
                      height: 12,
                      borderRadius: 6,
                      background: color,
                      border: `2px solid ${pal.bg}`,
                      boxShadow: `0 0 8px ${color}66`,
                    }} />
                    <div style={{ fontSize: 10, color: pal.faint, marginBottom: 4 }}>{fmtTime(a.at)}</div>
                    <div style={{
                      background: cardBg(dark),
                      borderRadius: 10,
                      borderLeft: `3px solid ${color}`,
                      borderTop: '1px solid ' + pal.borderSoft,
                      borderRight: '1px solid ' + pal.borderSoft,
                      borderBottom: '1px solid ' + pal.borderSoft,
                      boxShadow: cardInset(dark),
                      padding: '9px 11px',
                      fontSize: 12,
                    }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color, marginBottom: 4, letterSpacing: '0.02em' }}>
                        {a.kind} · {severityLabel(a)}
                        {a.count !== undefined && a.count > 1 && (
                          <span style={{ marginLeft: 6, opacity: 0.85 }}>×{a.count}</span>
                        )}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, minWidth: 0 }}>
                        {a.pluginHint !== undefined ? (
                          onOpenPlugin !== undefined
                            ? <PluginNameButton tok={pal} name={a.pluginHint} onClick={() => onOpenPlugin(a.pluginHint ?? '')} />
                            : <span style={{ fontWeight: 600, color: pal.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint.replace(/^@/, '')}</span>
                        ) : (
                          <span style={{ fontSize: 10.5, color: pal.faint }}>(unattributed)</span>
                        )}
                        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 5, flexShrink: 0 }}>
                          <button
                            type="button"
                            onClick={() => { void copyAlarm(a) }}
                            title={t('alarmPanel.copyHint')}
                            style={{
                              border: '1px solid ' + pal.borderSoft,
                              background: copied ? pal.sage : 'transparent',
                              color: copied ? pal.onSlate : pal.muted,
                              borderRadius: 5,
                              padding: '0 7px',
                              cursor: 'pointer',
                              fontSize: 10,
                              transition: 'all 120ms ease',
                            }}
                          >
                            {copied ? t('alarmPanel.copied') : t('alarmPanel.copy')}
                          </button>
                          <button
                            type="button"
                            onClick={() => onDismiss(a.id)}
                            title={t('alerts.dismissHint')}
                            style={{
                              border: '1px solid ' + pal.borderSoft,
                              background: 'transparent',
                              color: pal.muted,
                              borderRadius: 5,
                              padding: '0 7px',
                              cursor: 'pointer',
                              fontSize: 10,
                            }}
                          >
                            {t('alerts.dismiss')}
                          </button>
                        </span>
                      </div>
                      <div
                        onClick={() => toggleExpand(a.id)}
                        style={{ cursor: 'pointer', wordBreak: 'break-word' }}
                      >
                        <div style={{ fontSize: 11.5, color: pal.muted, lineHeight: 1.55 }}>
                          {expanded ? a.message : (a.message.length > 64 ? a.message.slice(0, 64) + '…' : a.message)}
                        </div>
                      </div>
                      {expanded && (
                        <div style={{ marginTop: 6, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 6 }}>
                          {(() => {
                            // 归因分层建议文案
                            let suggestKey: string
                            if (a.pluginHint === undefined) {
                              suggestKey = a.sessionLog === true
                                ? 'suggest.' + a.kind + '.unattributed.sessionLog'
                                : 'suggest.' + a.kind + '.unattributed'
                            } else {
                              suggestKey = 'suggest.' + a.kind
                            }
                            const hasSuggest = (zh as Record<string, string>)[suggestKey] !== undefined
                            if (!hasSuggest) return null
                            return (
                              <div style={{ fontSize: 11, color: pal.ochre, marginBottom: 4 }}>{t('alerts.suggest')}{t(suggestKey)}</div>
                            )
                          })()}
                          <div style={{ fontSize: 10.5, color: pal.muted }}>
                            <div><b>ID:</b> {a.id}</div>
                            <div><b>时间:</b> {new Date(a.at).toLocaleString()}</div>
                            <div><b>严重度:</b> {a.severity ?? 'unknown'}</div>
                            {a.target !== undefined && <div><b>目标:</b> {a.target}</div>}
                          </div>
                        </div>
                      )}
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        {/* 已忽略警报区域 */}
        {dismissed.length > 0 && (
          <div style={{ flexShrink: 0, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 10, marginTop: 8 }}>
            <div
              onClick={() => setDismissedCollapsed(v => !v)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                cursor: 'pointer',
                padding: '4px 0',
                userSelect: 'none',
              }}
            >
              <span style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: pal.faint, fontWeight: 700 }}>
                {t('alerts.dismissed')}
              </span>
              <span style={{ fontSize: 11, color: pal.muted, background: cardBg(dark), border: '1px solid ' + pal.borderSoft, borderRadius: 9, padding: '1px 8px' }}>
                {dismissed.length}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 10, color: pal.faint }}>
                {dismissedCollapsed ? '▸' : '▾'}
              </span>
            </div>
            {!dismissedCollapsed && (
              <div className="vet-scrollbar" style={{ maxHeight: 140, overflowY: 'auto', marginTop: 6 }}>
                <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                  {dismissed.map(a => {
                    const expanded = expandedDismissedIds.has(a.id)
                    return (
                      <li
                        key={a.id}
                        style={{
                          background: dark
                            ? 'linear-gradient(180deg, rgba(16,20,16,0.85), rgba(12,16,12,0.85))'
                            : 'linear-gradient(180deg, #f2f5ec, #ebeee4)',
                          border: '1px solid ' + (dark ? 'rgba(30,45,30,0.5)' : pal.borderSoft),
                          borderRadius: 6,
                          padding: '6px 8px',
                          marginBottom: 4,
                          opacity: 0.8,
                        }}
                      >
                        <div
                          onClick={() => toggleDismissedExpand(a.id)}
                          style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
                        >
                          <span style={{ fontSize: 10, fontWeight: 700, color: pal.faint }}>{a.kind}</span>
                          <span style={{ fontSize: 10, color: pal.faint }}>{fmtTime(a.at)}</span>
                          {a.pluginHint !== undefined && (
                            <span style={{ fontSize: 9.5, color: pal.faint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint.replace(/^@/, '')}</span>
                          )}
                          <span style={{ fontSize: 9, color: pal.faint, marginLeft: 'auto' }}>
                            {expanded ? '▾' : '▸'}
                          </span>
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); onRestore(a.id) }}
                            title={t('alerts.restoreHint')}
                            style={{
                              border: '1px solid ' + pal.borderSoft,
                              background: 'transparent',
                              color: pal.muted,
                              borderRadius: 4,
                              padding: '0 6px',
                              cursor: 'pointer',
                              fontSize: 9,
                              flexShrink: 0,
                            }}
                          >
                            {t('alerts.restore')}
                          </button>
                        </div>
                        {expanded && (
                          <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid ' + pal.borderSoft }}>
                            <div style={{ fontSize: 10.5, color: pal.muted, wordBreak: 'break-word' }}>{a.message}</div>
                          </div>
                        )}
                      </li>
                    )
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
      </SubPanel>
    </div>
  )
}
