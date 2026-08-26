/**
 * 次级面板外壳（P3）：「← 返回 + 标题 + 徽标」头部 + 玻璃卡体。
 * 定位（级联 x 坐标）由编排层负责；本组件只负责壳。层栈规则见计划 §三-D2/D7。
 */
import { useState } from 'react'
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'
import { GlassLayers } from './Glass.tsx'

export function SubPanel({ tok, title, badge, badgeColor, onBack, backLabel, ariaLabel, children }: {
  tok: ThemeTokens
  title: string
  /** 头部右侧徽标文本（数量/状态）。 */
  badge?: ReactNode
  badgeColor?: string
  onBack?: () => void
  backLabel: string
  ariaLabel: string
  children: ReactNode
}): ReactNode {
  const [hovered, setHovered] = useState(false)
  return (
    <aside
      role="dialog"
      aria-label={ariaLabel}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: '100%',
        height: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: tok.glass,
        backdropFilter: 'blur(36px) saturate(1.15)',
        WebkitBackdropFilter: 'blur(36px) saturate(1.15)',
        borderRadius: 16,
        boxShadow: tok.shadow,
        padding: '14px 14px 12px',
        fontSize: 12,
        color: tok.muted,
        lineHeight: 1.5,
      }}
    >
      <GlassLayers tok={tok} hovered={hovered} />
      <div style={{ position: 'relative', zIndex: 2, height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexShrink: 0 }}>
          {onBack !== undefined && (
            <button
              type="button"
              onClick={onBack}
              style={{
                border: 'none',
                background: 'transparent',
                color: tok.muted,
                cursor: 'pointer',
                fontSize: 12,
                fontFamily: 'inherit',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '3px 8px',
                borderRadius: 6,
                transition: 'color 0.2s ease, background 0.2s ease',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.color = tok.ink; e.currentTarget.style.background = tok.cardSoft }}
              onMouseLeave={(e) => { e.currentTarget.style.color = tok.muted; e.currentTarget.style.background = 'transparent' }}
            >
              <span aria-hidden="true">&larr;</span> {backLabel}
            </button>
          )}
          <span style={{ fontWeight: 800, fontSize: 13.5, color: tok.ink }}>{title}</span>
          {badge !== undefined && (
            <span style={{
              marginLeft: 'auto',
              fontSize: 11,
              fontWeight: 700,
              color: badgeColor ?? tok.muted,
              background: tok.cardGrad,
              border: '1px solid ' + tok.borderSoft,
              borderRadius: 9,
              padding: '1px 10px',
            }}>{badge}</span>
          )}
        </div>
        <div className="vet-scrollbar" style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
          {children}
        </div>
      </div>
    </aside>
  )
}

/** 行内插件名按钮（时间线/列表/审计中心通用的「点名字看详情」交互）。 */
export function PluginNameButton({ tok, name, onClick, fontSize = 11 }: {
  tok: ThemeTokens
  name: string
  onClick: () => void
  fontSize?: number
}): ReactNode {
  return (
    <button
      type="button"
      onClick={onClick}
      title={name}
      style={{
        border: 'none',
        background: 'transparent',
        padding: 0,
        cursor: 'pointer',
        fontFamily: 'inherit',
        fontSize,
        fontWeight: 600,
        color: tok.muted,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        textDecoration: 'underline',
        textDecorationColor: 'rgba(106,154,106,0.35)',
        textUnderlineOffset: 2,
      }}
      onMouseEnter={(e) => { e.currentTarget.style.color = tok.ink }}
      onMouseLeave={(e) => { e.currentTarget.style.color = tok.muted }}
    >
      {name.startsWith('@') || name === '(unattributed)' ? name : '@' + name}
    </button>
  )
}
