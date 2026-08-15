/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：纯展示，
 * 不提供任何操作——处置留给用户在 DSH 上完成（PLAN §2.1 D21）。
 * 不能编译期依赖私有 @deepseek-ai/dsh-client-* 包：类型用本地最小结构。
 */
import { useEffect, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'

export interface VetAlarmWire {
  kind: string
  message: string
  pluginHint?: string
}

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
}

const POLL_MS = 5000

const COLOR: Record<'green' | 'yellow' | 'red', string> = {
  green: '#30a46c',
  yellow: '#f5a623',
  red: '#e5484d',
}

const LABEL: Record<'green' | 'yellow' | 'red', string> = {
  green: '守护中',
  yellow: '有情况',
  red: '有风险',
}

const rowStyle: CSSProperties = { display: 'inline-flex', alignItems: 'center', gap: 5, padding: '0 8px', height: 28, cursor: 'default' }

/** 盾牌图标（内联 SVG，避免 CSS/图标库依赖）。 */
function ShieldIcon({ color }: { color: string }): ReactNode {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M8 1 L13 3 V7 C13 10.6 10.9 13.2 8 14.2 C5.1 13.2 3 10.6 3 7 V3 Z"
        fill={color}
        opacity="0.9"
      />
    </svg>
  )
}

/**
 * 会话头部盾牌。props 由槽渲染器传入（空 owner share，本组件自给自足），
 * 这里忽略全部 props。
 */
export function Shield(_props: Record<string, unknown>): ReactNode {
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)

  useEffect(() => {
    let alive = true
    const load = async (): Promise<void> => {
      try {
        const res = await fetch('/vet/status.json', { cache: 'no-store' })
        if (!alive || !res.ok) return
        setSnap(await res.json() as ShieldSnapshotWire)
      } catch {
        // 路由不可用（非 web profile / 未重启）→ 保持上次状态，静默
      }
    }
    void load()
    const timer = window.setInterval(() => { void load() }, POLL_MS)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [])

  const level = snap?.level ?? 'green'
  const color = COLOR[level]
  const count = snap?.alarmCount ?? 0
  const details = snap?.alarms.slice(0, 4)
    .map(a => `- [${a.kind}${a.pluginHint !== undefined ? ' @' + a.pluginHint : ''}] ${a.message}`)
    .join('\n') ?? ''
  const title = level === 'green'
    ? 'vet 守护中（绿色）'
    : `vet ${LABEL[level]}：${count} 条报警\n${details}\n\n处置请到 DSH 日志/你的操作完成（vet 只报警不代劳）`

  return (
    <div style={rowStyle} title={title} role="status" aria-label={`vet ${LABEL[level]}`}>
      <ShieldIcon color={color} />
      {count > 0 && <span style={{ fontSize: 11, color, fontWeight: 600, lineHeight: 1 }}>{count}</span>}
    </div>
  )
}
