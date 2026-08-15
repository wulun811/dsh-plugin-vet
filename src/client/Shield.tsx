/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一动作是「开启运行时守卫」按钮——用户主动点击，vet 按其指令写自己的配置（重启生效）。
 * 交互：点击展开面板（实时指标/守卫状态/报警列表含建议），外部点击/切换关闭。
 * 主题用 --dsw-* CSS 变量（带兜底），明暗自适应；类型本地最小结构（私有包不可编译期依赖）。
 */
import { useEffect, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'

export interface VetAlarmWire {
  kind: string
  message: string
  severity?: 'yellow' | 'red'
  pluginHint?: string
}

export interface VetMetricsWire {
  /** 进程总 RSS（MB）= DSH + 全部插件 + vet。 */
  rssMb: number
  heapUsedMb: number
  heapTotalMb: number
  externalMb: number
  cpuPct: number
  ioReadMb: number
  ioWriteMb: number
  childCount: number
  fdCount: number
  at: number
}

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
  lastScan?: { pluginName: string; verdict: string; staticScore: number }
  runtimeGuard?: 'off' | 'watch'
  metrics?: VetMetricsWire
}

const POLL_MS = 5000

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
  yellow: '有警告或可疑扫描结果，建议查看详情。',
  red: '检测到高风险报警，请查看详情并在 DSH 中处置（vet 只报警不代劳）。',
}

/** 每类报警的可执行建议（把"报警"变成"下一步做什么"）。 */
const SUGGEST: Record<string, string> = {
  mem: '检查是否有插件无界分配内存（R9-1），或调高 runtimeMemLimitMb',
  fork: '检查是否有插件循环 spawn 子进程（R9-1 fork 炸弹）',
  fd: '检查是否有插件泄漏文件句柄',
  spawn: '检查该插件为何启动子进程（非官方归因）',
  'fs-destroy': '检查该插件删除敏感路径的意图',
  'fs-write': '检查该插件写入敏感路径的意图',
  'fs-read': '检查该插件读取密钥文件的意图',
}

const panelStyle: CSSProperties = {
  position: 'absolute',
  top: 'calc(100% + 6px)',
  right: 0,
  zIndex: 1000,
  width: 340,
  maxHeight: 420,
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

const btnStyle: CSSProperties = {
  border: '1px solid var(--dsw-alias-border-l2, rgba(0,0,0,0.12))',
  background: 'var(--dsw-alias-button-floating-fill, transparent)',
  color: 'inherit',
  borderRadius: 6,
  padding: '2px 10px',
  cursor: 'pointer',
  fontSize: 11,
}

function ShieldIcon({ color, size = 20 }: { color: string; size?: number }): ReactNode {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 1 L13 3 V7 C13 10.6 10.9 13.2 8 14.2 C5.1 13.2 3 10.6 3 7 V3 Z" fill={color} opacity="0.92" />
    </svg>
  )
}

function fmtTime(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function Metric({ label, value }: { label: string; value: string }): ReactNode {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,0.05))', borderRadius: 5, padding: '1px 6px' }}>
      <span style={{ color: 'var(--dsw-alias-label-secondary, #6b7280)' }}>{label}</span>
      <span style={{ fontWeight: 600 }}>{value}</span>
    </span>
  )
}

/**
 * 会话头部盾牌。props 由槽渲染器传入（空 owner share，本组件自给自足），忽略。
 */
export function Shield(_props: Record<string, unknown>): ReactNode {
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)
  const [open, setOpen] = useState(false)
  const [loadedAt, setLoadedAt] = useState(0)
  const [toggleMsg, setToggleMsg] = useState<string | null>(null)
  const [toggling, setToggling] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const loadRef = useRef<() => void>(() => {})

  useEffect(() => {
    let alive = true
    const load = async (): Promise<void> => {
      try {
        const res = await fetch('/vet/status.json', { cache: 'no-store' })
        if (!alive) return
        const text = await res.text()
        setSnap(JSON.parse(text) as ShieldSnapshotWire)
        setLoadedAt(Date.now())
      } catch {
        // 路由不可用/非 JSON（SPA fallback）→ 保持上次状态
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

  const toggleGuard = async (enable: boolean): Promise<void> => {
    setToggling(true)
    setToggleMsg(null)
    try {
      const res = await fetch('/vet/runtime-guard', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ enable }),
      })
      const body = await res.json() as { ok?: boolean; note?: string }
      setToggleMsg(body.note ?? (res.ok ? '已写入' : '写入失败'))
    } catch {
      setToggleMsg('请求失败（路由未注册？重启后重试）')
    } finally {
      setToggling(false)
    }
  }

  const level = snap?.level ?? 'green'
  const color = COLOR[level]
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan
  const metrics = snap?.metrics
  const guard = snap?.runtimeGuard ?? 'off'

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
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: 'var(--dsw-alias-label-secondary, #6b7280)', fontWeight: 600, lineHeight: 1 }}
            title="DSH + 全部插件总内存（同一进程，仅总量）"
          >
            ≈{Math.round(metrics.rssMb)}M
          </span>
        )}
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

          {/* 实时指标：进程总量 = DSH + 全部插件 */}
          {metrics !== undefined && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 4 }}>
                <Metric label="总内存" value={`${metrics.rssMb} MB`} />
                <Metric label="V8 堆" value={`${metrics.heapUsedMb}/${metrics.heapTotalMb} MB`} />
                <Metric label="原生+外部" value={`${metrics.externalMb} MB`} />
                <Metric label="CPU" value={`${metrics.cpuPct}%`} />
                <Metric label="I/O 读" value={`${metrics.ioReadMb} MB`} />
                <Metric label="I/O 写" value={`${metrics.ioWriteMb} MB`} />
                <Metric label="子进程" value={`${metrics.childCount >= 0 ? metrics.childCount : '—'}`} />
                <Metric label="fd" value={`${metrics.fdCount >= 0 ? metrics.fdCount : '—'}`} />
              </div>
              <div style={{ color: 'var(--dsw-alias-label-tertiary, #9ca3af)' }}>
                总内存 = DSH 宿主 + 全部插件 + vet（同一进程）。Node 共享堆无法按插件拆分（无分配归因 API）；按需堆快照分析列为远期实验。
              </div>
            </div>
          )}

          {/* 运行时守卫状态 + 开关 */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              marginBottom: 8,
              padding: '5px 8px',
              borderRadius: 6,
              background: 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,0.05))',
            }}
          >
            <span style={{ fontWeight: 600 }}>
              运行时守卫：{guard === 'watch' ? '开启中（watch）' : '未开启'}
            </span>
            {guard === 'off' && (
              <button type="button" disabled={toggling} onClick={() => { void toggleGuard(true) }} style={{ ...btnStyle, marginLeft: 'auto' }}>
                {toggling ? '写入中…' : '开启'}
              </button>
            )}
          </div>
          {toggleMsg !== null && (
            <div style={{ marginBottom: 8, color: 'var(--dsw-alias-state-warn-primary, #b45309)' }}>{toggleMsg}</div>
          )}

          {lastScan !== undefined && (
            <div style={{ marginBottom: 8, padding: '5px 8px', background: 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,0.05))', borderRadius: 6 }}>
              最近扫描：{lastScan.pluginName} → <b>{lastScan.verdict}</b>（{lastScan.staticScore} 分）
            </div>
          )}

          {alarms.length === 0 ? (
            <div style={{ color: 'var(--dsw-alias-label-tertiary, #9ca3af)', padding: '4px 0' }}>暂无报警记录</div>
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
                  {SUGGEST[a.kind] !== undefined && (
                    <div style={{ color: 'var(--dsw-alias-state-warn-primary, #b45309)' }}>建议：{SUGGEST[a.kind]}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, paddingTop: 6, borderTop: '1px solid var(--dsw-alias-border-l3, rgba(0,0,0,0.08))' }}>
            {loadedAt > 0 && (
              <span style={{ color: 'var(--dsw-alias-label-tertiary, #9ca3af)' }}>更新于 {fmtTime(loadedAt)}</span>
            )}
            <button type="button" onClick={() => { loadRef.current() }} style={{ ...btnStyle, marginLeft: 'auto' }}>
              刷新
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
