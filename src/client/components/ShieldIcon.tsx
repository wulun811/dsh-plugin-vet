/**
 * 盾牌图标（三态符号，纯路径绘制不依赖字体）：green → 盾内 √；yellow → 盾内 ?；red → 盾内 !。
 * 从 Shield.tsx 拆出（P0 目录化），绘制逻辑不变。
 */
import type { ReactNode } from 'react'

const SHIELD_PATH = 'M8 0.9 L13.1 2.9 V7 C13.1 10.7 11 13.3 8 14.3 C5 13.3 2.9 10.7 2.9 7 V2.9 Z'

export function ShieldIcon({ level, color, size = 20 }: { level: 'green' | 'yellow' | 'red'; color: string; size?: number }): ReactNode {
  // 符号掏空：用 mask 让符号区域真正透明，露出面板底色
  const maskId = `shield-mask-${level}`
  const maskContent =
    level === 'green' ? (
      <path d="M5.2 8.2 L7.1 10.1 L10.8 5.9" stroke="black" strokeWidth={2} fill="none" strokeLinecap="round" strokeLinejoin="round" />
    ) : level === 'red' ? (
      <>
        <line x1={8} y1={4.5} x2={8} y2={9.3} stroke="black" strokeWidth={2} strokeLinecap="round" />
        <circle cx={8} cy={11.4} r={1.15} fill="black" />
      </>
    ) : (
      <>
        <path d="M6.3 5.5 C6.3 4.4 7 3.8 8 3.8 C9 3.8 9.7 4.4 9.7 5.3 C9.7 6.2 9.1 6.6 8.6 7.1 C8.1 7.6 8 8 8 8.8" stroke="black" strokeWidth={1.7} fill="none" strokeLinecap="round" />
        <circle cx={8} cy={11.3} r={0.95} fill="black" />
      </>
    )
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <defs>
        <mask id={maskId}>
          <rect width="16" height="16" fill="white" />
          {maskContent}
        </mask>
      </defs>
      <path d={SHIELD_PATH} fill={color} stroke={color} strokeWidth={0.6} opacity="0.95" mask={`url(#${maskId})`} />
    </svg>
  )
}
