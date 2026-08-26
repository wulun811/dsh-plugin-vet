/**
 * 环趋势复合卡 RingSparkCard（P1，决策 ②(b)）：环里套趋势——一张卡读全
 * 「当前值 + 方向」。三指标（内存/CPU/fd）各一张，替代 mock 的两排（三环 + 三火花线）。
 * 纯展示组件：ringPct/danger/delta 全部由父层算好传入；SVG 手绘零依赖。
 * 阈值语义：danger 仅影响配色（zone-danger），不参与任何执法判断（计划 §三-D4）。
 */
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'

/** 趋势分档：稳定 / 关注（温和抬升）/ 恶化（陡升）。 */
export type TrendKind = 'stable' | 'watch' | 'worse'

export interface TrendInfo {
  kind: TrendKind
  /** 展示串（含箭头与幅度）；stable 时为「→ 稳」类文案，由父层用 t() 生成。 */
  label: string
}

/**
 * 趋势判定。
 * - rel 模式（内存/fd）：窗口首尾相对变化，>20% 大变化、>5% 关注；
 * - abs 模式（CPU）：首尾绝对差（百分点），>15pp 大变化、>5pp 关注；
 * - 样本 <2 或含非有限值 → stable（数据不足不妄判）。
 * 箭头与符号跟随真实方向（上升 ↑↑/↑ +，下降 ↓↓/↓ −）——旧实现只算幅度、
 * 箭头恒向上，内存/句柄下降时误显示「↑↑ +30%」（方向与符号双重错误）。
 */
export function trendOf(points: number[], mode: 'rel' | 'abs'): TrendInfo {
  if (points.length < 2) return { kind: 'stable', label: '' }
  const first = points[0]
  const last = points[points.length - 1]
  if (!Number.isFinite(first) || !Number.isFinite(last)) return { kind: 'stable', label: '' }
  if (mode === 'rel') {
    const base = Math.max(Math.abs(first), 1e-6)
    const rel = (last - first) / base
    const mag = Math.round(Math.abs(rel) * 100)
    if (mag > 20) return { kind: 'worse', label: trendLabel('↑↑', '↓↓', rel, mag) + '%' }
    if (mag > 5) return { kind: 'watch', label: trendLabel('↑', '↓', rel, mag) + '%' }
    return { kind: 'stable', label: '' }
  }
  const diff = last - first
  const mag = Math.round(Math.abs(diff))
  if (Math.abs(diff) > 15) return { kind: 'worse', label: trendLabel('↑↑', '↓↓', diff, mag) + 'pp' }
  if (Math.abs(diff) > 5) return { kind: 'watch', label: trendLabel('↑', '↓', diff, mag) + 'pp' }
  return { kind: 'stable', label: '' }
}

/** 趋势标签：方向箭头 + 带符号幅度（rel 用 %，abs 用 pp；正负号随方向）。 */
function trendLabel(upArrow: string, downArrow: string, delta: number, mag: number): string {
  return delta >= 0 ? upArrow + ' +' + mag : downArrow + ' −' + mag
}

/** 环几何：size=44, stroke=4, r=18。 */
const RING = 44
const R = 18
const CIRC = 2 * Math.PI * R

function ringSvg(color: string, pct: number): ReactNode {
  const clamped = Math.min(100, Math.max(0, pct))
  const offset = CIRC * (1 - clamped / 100)
  return (
    <svg width={RING} height={RING} viewBox={`0 0 ${RING} ${RING}`} aria-hidden="true">
      <circle cx={RING / 2} cy={RING / 2} r={R} fill="none" stroke="rgba(128,150,128,0.18)" strokeWidth={5} />
      <circle
        cx={RING / 2} cy={RING / 2} r={R} fill="none"
        stroke={color} strokeWidth={3.5} strokeLinecap="round"
        strokeDasharray={CIRC.toFixed(1)} strokeDashoffset={offset.toFixed(1)}
        transform={`rotate(-90 ${RING / 2} ${RING / 2})`}
      />
    </svg>
  )
}

/** 归一化到 viewBox 100×26 的迷你面积折线；样本 <2 不画线只画基线。 */
function sparkSvg(color: string, points: number[]): ReactNode {
  const W = 100
  const H = 26
  if (points.length < 2) {
    return (
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: '100%', height: 22, display: 'block' }} aria-hidden="true">
        <line x1={0} y1={H - 2} x2={W} y2={H - 2} stroke="rgba(128,150,128,0.25)" strokeWidth={1} />
      </svg>
    )
  }
  const min = Math.min(...points)
  const max = Math.max(...points)
  const span = Math.max(max - min, 1e-6)
  // y 轴反转：值越大越靠上；留 2px 上下内边距
  const coords = points.map((v, i) => {
    const x = points.length === 1 ? W / 2 : (i / (points.length - 1)) * W
    const y = H - 2 - ((v - min) / span) * (H - 4)
    return x.toFixed(1) + ',' + y.toFixed(1)
  })
  const line = coords.join(' ')
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: '100%', height: 22, display: 'block' }} aria-hidden="true">
      <polyline fill="none" stroke={color} strokeOpacity={0.65} strokeWidth={1.5} points={line} />
      <polygon fill={color} fillOpacity={0.1} points={'0,' + (H - 1) + ' ' + line + ' ' + W + ',' + (H - 1)} />
    </svg>
  )
}

export function RingSparkCard({ tok, dark, label, center, ringPct, delta, trendPoints, danger, hint }: {
  tok: ThemeTokens
  dark: boolean
  /** 指标名（内存/CPU/fd）。 */
  label: string
  /** 环心短值（如 1234MB / 12% / 128）。 */
  center: string
  /** 环填充百分比 0-100（父层按软上限归一）。 */
  ringPct: number
  /** 趋势分档 + 展示串（trendOf 的结果 + t() 文案）。 */
  delta: { kind: TrendKind; label: string }
  /** 趋势样本（旧→新），≥2 才画线。 */
  trendPoints: number[]
  /** 危险染色（zone-danger 配方；仅视觉）。 */
  danger?: boolean
  /** 悬停说明（口径/单位/非上限等——防止用户误解数值含义）。 */
  hint?: string
}): ReactNode {
  const kindColor = delta.kind === 'worse' ? tok.rose : delta.kind === 'watch' ? tok.ochre : tok.sage
  const ringColor = danger === true ? tok.dangerBright : kindColor
  const deltaColor = danger === true ? tok.dangerBright : kindColor
  return (
    <div
      title={hint !== undefined && hint !== '' ? hint : undefined}
      style={{
        flex: 1,
        minWidth: 0,
        borderRadius: 10,
        padding: '8px 10px 6px',
        cursor: hint !== undefined && hint !== '' ? 'help' : undefined,
        background: danger === true
          ? `linear-gradient(180deg, rgba(28,14,14,0.55), rgba(18,10,10,0.35)), ${cardBg(dark)}`
          : cardBg(dark),
        border: '1px solid ' + (danger === true ? tok.borderDanger : tok.borderSoft),
        boxShadow: (danger === true ? `inset 0 0 40px ${tok.glowDanger}, ` : '') + cardInset(dark),
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ position: 'relative', width: RING, height: RING, flexShrink: 0 }}>
          {ringSvg(ringColor, ringPct)}
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 9.5, fontWeight: 700, color: danger === true ? tok.dangerBright : tok.ink,
          }}>{center}</div>
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 10, color: tok.faint, letterSpacing: '0.05em' }}>{label}</div>
          <div style={{ fontSize: 11, fontWeight: 700, color: deltaColor, whiteSpace: 'nowrap' }}>
            {delta.label !== '' ? delta.label : '\u2192'}
          </div>
        </div>
      </div>
      {sparkSvg(danger === true ? tok.rose : kindColor, trendPoints)}
    </div>
  )
}
