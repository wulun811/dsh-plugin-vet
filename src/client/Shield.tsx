/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一动作是「开启运行时守卫」按钮——用户主动点击，vet 按其指令写自己的配置（重启生效）。
 * 设计：纯静态 inline 样式 + --dsw-* 主题令牌（带兜底），无动画/无库，资源开销≈0。
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

/** 主题语义令牌（全部带兜底，明暗自适应）。 */
const T = {
  success: 'var(--dsw-alias-state-success-primary, #30a46c)',
  warn: 'var(--dsw-alias-state-warn-primary, #f5a623)',
  error: 'var(--dsw-alias-state-error-primary, #e5484d)',
  bgOverlay: 'var(--dsw-alias-bg-overlay, #ffffff)',
  bgLayer1: 'var(--dsw-alias-bg-layer-1, rgba(0,0,0,0.03))',
  bgLayer2: 'var(--dsw-alias-bg-layer-2, rgba(0,0,0,0.06))',
  hover: 'var(--dsw-alias-interactive-bg-hover, rgba(0,0,0,0.05))',
  border: 'var(--dsw-alias-border-l2, rgba(0,0,0,0.12))',
  borderLight: 'var(--dsw-alias-border-l3, rgba(0,0,0,0.08))',
  textPrimary: 'var(--dsw-alias-label-primary, #111827)',
  textSecondary: 'var(--dsw-alias-label-secondary, #6b7280)',
  textTertiary: 'var(--dsw-alias-label-tertiary, #9ca3af)',
  shadow: 'var(--dsw-shadow-lv2, 0 8px 24px rgba(0,0,0,0.16))',
  buttonPrimary: 'var(--dsw-alias-button-primary-fill, #3b82f6)',
}

const COLOR: Record<'green' | 'yellow' | 'red', string> = {
  green: T.success,
  yellow: T.warn,
  red: T.error,
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

const SUGGEST: Record<string, string> = {
  mem: '检查是否有插件无界分配内存（R9-1），或调高 runtimeMemLimitMb',
  growth: '检查是否有插件内存泄漏（对象/缓存持续累积）；可重启 DSH 或调高 runtimeGrowthMb 降噪',
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
  maxHeight: 480,
  overflow: 'auto',
  background: T.bgOverlay,
  border: `1px solid ${T.border}`,
  borderRadius: 10,
  boxShadow: T.shadow,
  fontSize: 12,
  color: T.textPrimary,
  padding: '12px 12px 8px',
  textAlign: 'left',
  lineHeight: 1.5,
}

function ShieldIcon({ color, size = 20 }: { color: string; size?: number }): ReactNode {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 1 L13 3 V7 C13 10.6 10.9 13.2 8 14.2 C5.1 13.2 3 10.6 3 7 V3 Z" fill={color} opacity="0.92" />
    </svg>
  )
}

function SectionLabel({ children }: { children: ReactNode }): ReactNode {
  return (
    <div style={{ fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', color: T.textTertiary, margin: '10px 0 6px', fontWeight: 600 }}>
      {children}
    </div>
  )
}

/** 指标卡：标签在上、数值在下（2 列网格，对齐美观）。 */
function Metric({ label, value, hint }: { label: string; value: string; hint?: string }): ReactNode {
  return (
    <div
      title={hint}
      style={{ background: T.bgLayer1, borderRadius: 7, padding: '6px 9px', display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}
    >
      <span style={{ fontSize: 10, color: T.textTertiary }}>{label}</span>
      <span style={{ fontSize: 12.5, fontWeight: 700, color: T.textPrimary, wordBreak: 'break-word' }}>{value}</span>
    </div>
  )
}

function fmtTime(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
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
          background: open ? T.hover : 'transparent',
          cursor: 'pointer',
          borderRadius: 6,
          transition: 'background 120ms ease',
        }}
      >
        <ShieldIcon color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: T.textSecondary, fontWeight: 600, lineHeight: 1 }}
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
              background: T.bgLayer2,
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
          {/* 头部：状态点 + 标题 + 计数 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13 }}>vet {LABEL[level]}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: T.textSecondary, background: T.bgLayer1, borderRadius: 9, padding: '1px 8px' }}>
              {count} 条报警
            </span>
          </div>
          <div style={{ color: T.textSecondary, marginTop: 4 }}>{LEVEL_TEXT[level]}</div>

          {/* 实时指标：2 列卡片网格 */}
          {metrics !== undefined && (
            <>
              <SectionLabel>实时指标</SectionLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric label="总内存" value={`${metrics.rssMb} MB`} hint="DSH 宿主 + 全部插件 + vet（同一进程，OS 仅见总量）" />
                <Metric label="V8 堆" value={`${metrics.heapUsedMb} / ${metrics.heapTotalMb} MB`} />
                <Metric label="原生 + 外部" value={`${metrics.externalMb} MB`} />
                <Metric label="CPU" value={`${metrics.cpuPct}%`} />
                <Metric label="I/O 读" value={`${metrics.ioReadMb} MB`} />
                <Metric label="I/O 写" value={`${metrics.ioWriteMb} MB`} />
                <Metric label="子进程" value={`${metrics.childCount >= 0 ? metrics.childCount : '—'}`} />
                <Metric label="fd" value={`${metrics.fdCount >= 0 ? metrics.fdCount : '—'}`} />
              </div>
            </>
          )}

          {/* 运行时守卫：状态 + 代价说明 + 开启按钮 */}
          <SectionLabel>运行时守卫</SectionLabel>
          <div style={{ background: T.bgLayer1, borderRadius: 8, padding: '8px 10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? T.success : T.textTertiary, display: 'inline-block' }} />
              <span style={{ fontWeight: 700 }}>{guard === 'watch' ? '已开启（watch）' : '未开启'}</span>
              {guard === 'off' && (
                <button
                  type="button"
                  disabled={toggling}
                  onClick={() => { void toggleGuard(true) }}
                  style={{
                    marginLeft: 'auto',
                    border: 'none',
                    background: T.buttonPrimary,
                    color: '#fff',
                    borderRadius: 6,
                    padding: '3px 14px',
                    fontSize: 11.5,
                    fontWeight: 700,
                    cursor: toggling ? 'default' : 'pointer',
                    opacity: toggling ? 0.6 : 1,
                  }}
                >
                  {toggling ? '写入中…' : '开启'}
                </button>
              )}
            </div>
            {guard === 'off' && (
              <div style={{ marginTop: 6, fontSize: 10.5, color: T.textSecondary, lineHeight: 1.45 }}>
                开启代价：哨兵子进程约占 10–30 MB 内存 + 轻量轮询；T2 钩子使文件/子进程调用开销增加约 5%（热点场景更高）。写入配置后需重启生效。
              </div>
            )}
          </div>
          {toggleMsg !== null && (
            <div style={{ marginTop: 6, fontSize: 11, color: T.warn }}>{toggleMsg}</div>
          )}

          {/* 最近扫描 */}
          {lastScan !== undefined && (
            <>
              <SectionLabel>最近扫描</SectionLabel>
              <div style={{ background: T.bgLayer1, borderRadius: 8, padding: '7px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? T.success : lastScan.verdict === 'suspicious' ? T.warn : T.error }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: T.textTertiary }}>{lastScan.staticScore} 分</span>
              </div>
            </>
          )}

          {/* 报警列表 */}
          <SectionLabel>报警</SectionLabel>
          {alarms.length === 0 ? (
            <div style={{ color: T.textTertiary, padding: '4px 2px' }}>暂无报警记录</div>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {alarms.slice(0, 8).map((a, i) => (
                <li
                  key={i}
                  style={{
                    background: T.bgLayer1,
                    borderRadius: 8,
                    borderLeft: `3px solid ${a.severity === 'red' ? T.error : a.severity === 'yellow' ? T.warn : 'transparent'}`,
                    padding: '7px 10px',
                    marginBottom: 5,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, background: T.bgLayer2, borderRadius: 4, padding: '1px 6px', color: T.textSecondary }}>
                      {a.kind}
                    </span>
                    {a.pluginHint !== undefined && (
                      <span style={{ fontSize: 10.5, color: T.textTertiary, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint}</span>
                    )}
                  </div>
                  <div style={{ marginTop: 3, wordBreak: 'break-word' }}>{a.message}</div>
                  {SUGGEST[a.kind] !== undefined && (
                    <div style={{ marginTop: 3, fontSize: 11, color: T.warn }}>建议：{SUGGEST[a.kind]}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {/* 底部：更新时间 + 刷新 */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: 10, paddingTop: 8, borderTop: `1px solid ${T.borderLight}` }}>
            {loadedAt > 0 && (
              <span style={{ fontSize: 10.5, color: T.textTertiary }}>更新于 {fmtTime(loadedAt)}</span>
            )}
            <button
              type="button"
              onClick={() => { loadRef.current() }}
              style={{
                marginLeft: 'auto',
                border: `1px solid ${T.border}`,
                background: 'transparent',
                color: T.textSecondary,
                borderRadius: 6,
                padding: '2px 12px',
                cursor: 'pointer',
                fontSize: 11,
                transition: 'background 120ms ease',
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
