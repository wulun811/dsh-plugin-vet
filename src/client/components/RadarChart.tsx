/**
 * 六轴雷达图（P3，纯 SVG 手绘零依赖）。移植 mock 的雷达算法（mock:1015-1066）为受控组件。
 * 维度归一化公式（口径注释，计划 §五）：
 *   网络  = min(hosts.length, 10) / 10
 *   文件  = min(fsPaths.length, 10) / 10
 *   子进程 = min(spawnCmds.length, 6) / 6
 *   依赖  = min(imports.length, 30) / 30
 *   执行  = hasExec ? 1 : 0.05（有执行能力即满格，无则近零）
 *   ESM  = esmNamedBuiltins ? 1 : 0.05（具名导入内建危险模块 = T2 盲区满格）
 * 全部由父层算好传入（本组件不做语义判断），values ∈ [0,100]。
 */
import type { ReactNode } from 'react'
import type { ThemeTokens } from '../theme.ts'

const SIZE = 190
const CX = SIZE / 2
const CY = SIZE / 2
const MAX_R = SIZE / 2 - 26

function polygonPoints(values: number[], scale: number): string {
  return values.map((v, i) => {
    const rad = (Math.max(0, Math.min(100, v)) / 100) * MAX_R * scale
    const ang = (Math.PI / 3) * i - Math.PI / 2
    return (CX + rad * Math.cos(ang)).toFixed(1) + ',' + (CY + rad * Math.sin(ang)).toFixed(1)
  }).join(' ')
}

export function RadarChart({ tok, values, labels, color }: {
  tok: ThemeTokens
  /** 六维数值 0-100，顺序：网络/文件/子进程/依赖/执行/ESM。 */
  values: number[]
  labels: string[]
  /** 数据面描边色（按 verdict 派生）。 */
  color: string
}): ReactNode {
  const gridScales = [1, 0.66, 0.33]
  const axisEnds = [0, 2, 4].map(i => {
    const ang = (Math.PI / 3) * i - Math.PI / 2
    return {
      x2: CX + MAX_R * Math.cos(ang),
      y2: CY + MAX_R * Math.sin(ang),
    }
  })
  const labelNodes = labels.map((label, i) => {
    const ang = (Math.PI / 3) * i - Math.PI / 2
    const lr = MAX_R + 14
    const x = CX + lr * Math.cos(ang)
    const y = CY + lr * Math.sin(ang) + 4
    return (
      <text key={label} x={x} y={y} fontSize={10} fill={tok.faint} textAnchor="middle">{label}</text>
    )
  })
  return (
    <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-label="radar">
      {gridScales.map(s => (
        <polygon key={s} points={polygonPoints([100, 100, 100, 100, 100, 100], s)}
          fill="none" stroke={tok.borderSoft} strokeWidth={1} />
      ))}
      {axisEnds.map((e, i) => (
        <line key={i} x1={CX} y1={CY} x2={e.x2} y2={e.y2} stroke={tok.borderSoft} strokeWidth={1} opacity={0.6} />
      ))}
      <polygon points={polygonPoints(values, 1)}
        fill={color} fillOpacity={0.16} stroke={color} strokeWidth={1.8} strokeLinejoin="round" />
      {values.map((v, i) => {
        if (v <= 0) return null
        const rad = (v / 100) * MAX_R
        const ang = (Math.PI / 3) * i - Math.PI / 2
        return <circle key={i} cx={CX + rad * Math.cos(ang)} cy={CY + rad * Math.sin(ang)} r={2.5} fill={color} />
      })}
      {labelNodes}
    </svg>
  )
}
