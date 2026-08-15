/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：纯展示，
 * 不提供任何操作——处置留给用户在 DSH 上完成（PLAN §2.1 D21）。
 * 交互：点击展开报警面板（最近报警 + 扫描回显 + 建议 + 刷新），外部点击/切换关闭。
 * 不能编译期依赖私有 @deepseek-ai/dsh-client-* 包：类型用本地最小结构；
 * 主题用 --dsw-* CSS 变量（带兜底值），明暗主题自适应。
 */
import { useEffect, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'

export interface VetAlarmWire {
  kind: string
  message: string
  severity?: 'yellow' | 'red'
  pluginHint?: string
}

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
  lastScan?: { pluginName: string; verdict: string; staticScore: number }
}

const POLL_MS = 5000

/** 主题感知颜色（--dsw-* 语义令牌，带兜底）。 */
const COLOR: Record<'green' | 'yellow' | 'red', string> = {
  green: 'var(--dsw-alias-state-success-primary, #30a46c)',
  yellow: 'var(--dsw-alias-state-warn-primary, #f5a623)',
  red: 'var(--dsw-alias-state-error-primary, #e5484d)',
}

const LABEL: Record<'green' | 'yellow' | 'red', string> = {
  green: '守护中',
  yellow: '有情况',
  red: '有风险',
}

const LEVEL_TEXT: Record<'green' | 'yellow' | 'red', string> = {
  green: '当前无报警，静态扫描与运行时守护正常。',
  yellow: '有警告或可疑扫描结果，建议查看详情后自行处置。',
  red: '检测到高风险报警，请查看详情并在 DSH 中处置（vet 只报警不代劳）。',
}

const panelStyle: CSSProperties = {
  position: 'absolute',
  top: 'calc(100% + 6px)',
  right: 0,
  zIndex: 1000,
  width: 320,
  maxHeight: 380,
  overflow: 'auto',
  background: 'var(--dsw-alias-bg-overlay, #ffffff)',
  border: '1px solid var(--dsw-alias-border-l2, rgba(0,0,0,0.12))',
  borderRadius: 8,
  boxShadow: 'var(--dsw-shadow-lv2, 0 8px 24px rgba(0,0,0,0.16))',
  fontSize: 12,
  color: 'var(--dsw-alias-label-primary, #111827)',
  padding: 10,
  textAlign: 'left',
  lineHeight: 1.5,
}

/** 盾牌图标（内联 SVG，避免图标库依赖）。 */
function ShieldIcon({ color, size = 20 }: { color: string; size?: number }): ReactNode {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M8 1 L13 3 V7 C13 10.6 10.9 13.2 8 14.2 C5.1 13.2 3 10.6 3 7 V3 Z"
        fill={color}
        opacity="0.92"
      />
    </svg>
  )
}

function fmtTime(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/**
 * 会话头部盾牌。props 由槽渲染器传入（空 owner share，本组件自给自足），
 * 这里忽略全部 props。
 */
export function Shield(_props: Record<string, unknown>): ReactNode {
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)
  const [open, setOpen] = useState(false)
  const [loadedAt, setLoadedAt] = useState(0)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const loadRef = useRef<() => void>(() => {})

  useEffect(() => {
    let alive = true
    const load = async (): Promise<void> => {
      try {
        const res = await fetch('/vet/status.json', { cache: 'no-store' })
        if (!alive || !res.ok) return
        setSnap(await res.json() as ShieldSnapshotWire)
        setLoadedAt(Date.now())
      } catch {
        // 路由不可用（非 web profile / 未重启）→ 保持上次状态，静默
      }
    }
    loadRef.current = load
    void load()
    const timer = window.setInterval(() => { void load() }, POLL_MS)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [])

  // 外部点击关闭面板
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      if (rootRef.current !== null && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const level = snap?.level ?? 'green'
  const color = COLOR[level]
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan

  return (
    <div ref={rootRef} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
        aria-label={`vet ${LABEL[level]}（${count} 条报警）`}
        title={`vet ${LABEL[level]}${count > 0 ? `：${count} 条报警（点击查看详情）` : ''}`}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '2px 8px',
          height: 28,
          border: 'none',
          background: 'transparent',
          cursor: 'pointer',
          borderRadius: 6,
          position: 'relative',
        }}
      >
        <ShieldIcon color={color} />
        {/* 报警计数徽标：有报警才显示 */}
        {count > 0 && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color,
              background: 'var(--dsw-alias-bg-layer-2, rgba(0,0,0,0.06))',
              borderRadius: 9,
              padding: '1px 5px',
              lineHeight: 1.4,
              minWidth: 18,
              textAlign: 'center',
            }}
          >
            {count}
          </span>
        )}
      </button>

      {open && (
        <div style={panelStyle} role="dialog" aria-label="vet 报警面板">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <ShieldIcon color={color} size={14} />
            <span style={{ fontWeight: 700 }}>vet {LABEL[level]}</span>
            <span style={{ marginLeft: 'auto', color: 'var(--dsw-alias-label-secondary, #6b7280)' }}>
              {count} 条报警
            </span>
          </div>
          <div style={{ color: 'var(--dsw-alias-label-secondary, #6b7280)', marginBottom: 8 }}>{LEVEL_TEXT[level]}</div>

          {lastScan !== undefined && (
            <div style={{ marginBottom: 8, padding: '6px 8px', background: 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,0.05))', borderRadius: 6 }}>
              最近扫描：{lastScan.pluginName} → <b>{lastScan.verdict}</b>（{lastScan.staticScore} 分）
            </div>
          )}

          {alarms.length === 0 ? (
            <div style={{ color: 'var(--dsw-alias-label-tertiary, #9ca3af)', padding: '6px 0' }}>暂无报警记录</div>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {alarms.slice(0, 8).map((a, i) => (
                <li
                  key={i}
                  style={{
                    padding: '5px 6px',
                    borderRadius: 6,
                    borderLeft: `3px solid ${a.severity === 'red' ? COLOR.red : a.severity === 'yellow' ? COLOR.yellow : 'transparent'}`,
                    marginBottom: 2,
                  }}
                >
                  <div style={{ fontWeight: 600 }}>
                    [{a.kind}]{a.pluginHint !== undefined ? ` @${a.pluginHint}` : ''}
                  </div>
                  <div style={{ color: 'var(--dsw-alias-label-secondary, #6b7280)', wordBreak: 'break-word' }}>{a.message}</div>
                </li>
              ))}
            </ul>
          )}

          <div style={{ marginTop: 8, paddingTop: 6, borderTop: '1px solid var(--dsw-alias-border-l3, rgba(0,0,0,0.08))', color: 'var(--dsw-alias-label-secondary, #6b7280)' }}>
            处置请到 DSH 日志 / 你的操作完成——vet 只报警不代劳。
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
            <span style={{ color: 'var(--dsw-alias-label-tertiary, #9ca3af)' }}>
              {loadedAt > 0 ? `更新于 ${fmtTime(loadedAt)}` : '加载中…'}
            </span>
            <button
              type="button"
              onClick={() => { loadRef.current() }}
              style={{
                marginLeft: 'auto',
                border: '1px solid var(--dsw-alias-border-l2, rgba(0,0,0,0.12))',
                background: 'transparent',
                color: 'inherit',
                borderRadius: 6,
                padding: '2px 10px',
                cursor: 'pointer',
                fontSize: 11,
              }}
            >
              刷新
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
