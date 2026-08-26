/**
 * 玻璃拟态共用件（P0 从 Shield/Intro/Alarm 三处复制粘贴的 crystal-edge 层收敛而来）：
 * - GlassLayers：渐变描边 + 顶部高光 + 双层镜面散光（hover 切换），配方取自主题令牌；
 * - StatusBand：面板顶部状态色带（green/yellow/red 渐变 + 底部光晕，颜色由状态色派生）。
 * 配方来源：docs/local/vet-panel-obsidian-moss-gold (XX).html（深色样例）；浅色走令牌。
 */
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'

/** crystal edge 四层（描边/高光/散光×2）。原三处 inline 复制粘贴的收敛点。 */
export function GlassLayers({ tok, hovered }: { tok: ThemeTokens; hovered: boolean }): ReactNode {
  return (
    <>
      {/* Crystal Edge: 渐变边框层 */}
      <div style={{
        position: 'absolute',
        inset: 0,
        borderRadius: 16,
        padding: 1.5,
        background: tok.edge,
        WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
        WebkitMaskComposite: 'xor',
        maskComposite: 'exclude',
        pointerEvents: 'none',
        zIndex: 10,
        transition: 'opacity 0.5s ' + tok.ease,
        opacity: hovered ? 1 : 0.7,
      }} />
      {/* Crystal Edge: 顶部高光线条 */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: '12%',
        right: '12%',
        height: 1.5,
        background: tok.topSheen,
        pointerEvents: 'none',
        zIndex: 10,
        opacity: 0.6,
      }} />
      {/* Mirror Sheen: 散光层（默认）→ 聚光层（hover） */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: tok.sheenA,
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.5s ' + tok.ease,
        opacity: hovered ? 0 : 0.5,
      }} />
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: tok.sheenB,
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.5s ' + tok.ease,
        opacity: hovered ? 0.5 : 0,
      }} />
    </>
  )
}

export type ShieldLevel = 'green' | 'yellow' | 'red'

/**
 * 面板顶缘状态色带：4px 渐变 + 底部 8px 光晕渐隐（mock .status-band）。
 * 负外边距使其贴住面板圆角顶端（面板 padding 14px）。
 */
export function StatusBand({ tok, level }: { tok: ThemeTokens; level: ShieldLevel }): ReactNode {
  const color = level === 'green' ? tok.sage : level === 'yellow' ? tok.ochre : tok.rose
  return (
    <div
      aria-hidden="true"
      style={{
        height: 4,
        margin: '-14px -14px 10px',
        borderRadius: '16px 16px 0 0',
        background: `linear-gradient(90deg, ${color}55, ${color})`,
        boxShadow: `0 2px 12px ${color}44`,
      }}
    />
  )
}
