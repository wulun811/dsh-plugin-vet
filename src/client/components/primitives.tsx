/**
 * 面板小型展示件（P0 从 Shield.tsx 拆出）：SectionLabel / GroupLabel / Metric。
 * 背景改走主题令牌 cardGrad + inset 高光（原 CARD_BG_* 常量的收敛点）。
 */
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'

export function SectionLabel({ pal, children }: { pal: ThemeTokens; children: ReactNode }): ReactNode {
  return (
    <div style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: pal.faint, margin: '12px 0 6px', fontWeight: 700 }}>
      {children}
    </div>
  )
}

export function GroupLabel({ pal, children }: { pal: ThemeTokens; children: ReactNode }): ReactNode {
  return (
    <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: pal.faint, margin: '2px 0 4px' }}>
      {children}
    </div>
  )
}

export function Metric({ pal, label, value, hint, wide, dark = true }: { pal: ThemeTokens; label: string; value: string; hint?: string; wide?: boolean; dark?: boolean }): ReactNode {
  return (
    <div
      title={hint}
      style={{
        background: cardBg(dark),
        borderRadius: 8,
        border: '1px solid ' + (dark ? 'rgba(35,50,35,0.5)' : pal.borderSoft),
        boxShadow: cardInset(dark),
        padding: '6px 10px',
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
        minWidth: 0,
        ...(wide === true ? { gridColumn: '1 / -1' } : {}),
      }}
    >
      <span style={{ fontSize: 10, color: pal.faint }}>{label}</span>
      <span style={{ fontSize: 12.5, fontWeight: 700, color: pal.ink, wordBreak: 'break-word' }}>{value}</span>
    </div>
  )
}
