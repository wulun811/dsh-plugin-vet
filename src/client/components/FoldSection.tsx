/**
 * 折叠区 FoldSection（P1，mock .fold-header/.fold-body 的组件化）：
 * ▸ 图标旋转 + 标题 + 右侧摘要；体部 max-height 动画（--ease）。
 * 开合状态由父层受控（D3 默认态策略：green 收起、yellow/red 自动展开危险项）。
 */
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'
import { cardInset } from '../theme.ts'

export function FoldSection({ tok, dark, open, onToggle, title, summary, children }: {
  tok: ThemeTokens
  dark: boolean
  open: boolean
  onToggle: () => void
  title: string
  /** 右侧摘要（如「1234 MB · 6项」）。 */
  summary: ReactNode
  children: ReactNode
}): ReactNode {
  return (
    <div style={{ margin: '0 0 8px' }}>
      <div
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '8px 12px',
          borderRadius: 10,
          cursor: 'pointer',
          userSelect: 'none',
          background: tok.cardGrad,
          border: '1px solid ' + tok.borderSoft,
          boxShadow: cardInset(dark),
          transition: 'border-color 0.25s ' + tok.ease,
        }}
        onMouseEnter={(e) => { e.currentTarget.style.borderColor = tok.sage }}
        onMouseLeave={(e) => { e.currentTarget.style.borderColor = tok.borderSoft }}
      >
        <span style={{
          fontSize: 10,
          color: tok.faint,
          display: 'inline-block',
          width: 14,
          textAlign: 'center',
          transition: 'transform 0.3s ' + tok.ease,
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
        }}>▶</span>
        <span style={{ fontSize: 11, fontWeight: 700, color: tok.muted, letterSpacing: '0.02em' }}>{title}</span>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: tok.faint, display: 'flex', alignItems: 'center', gap: 6 }}>
          <b style={{ color: tok.muted }}>{summary}</b>
        </span>
      </div>
      <div style={{
        maxHeight: open ? 420 : 0,
        overflow: 'hidden',
        opacity: open ? 1 : 0,
        transition: `max-height 0.4s ${tok.ease}, opacity 0.3s ease`,
      }}>
        <div style={{ paddingTop: open ? 8 : 0 }}>{children}</div>
      </div>
    </div>
  )
}
