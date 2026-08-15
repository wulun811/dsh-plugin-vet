/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一动作是「开启运行时守卫」按钮——用户主动点击，vet 按其指令写自己的配置（重启生效）。
 * 设计：莫兰迪色系双套（浅色暖灰 / 深色暖炭，跟随 DSH 主题自动切换），纯静态 inline 样式，无动画无库。
 * 主题检测：优先读 --dsw-alias-bg-base 的计算值亮度判断明暗；变量缺失时回退 prefers-color-scheme。
 * i18n：文案全部走 t(key)（槽渲染器注入，随页面语言 zh/en 自动切换）；t 缺失回退 zh。
 * 版本号由构建脚本注入（__VET_VERSION__，esbuild define）。
 */
import { useEffect, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { zh } from './i18n.ts'

/** 构建时注入：package.json version（scripts/build-client.mjs define）。 */
declare const __VET_VERSION__: string

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
  mcpRssMb: number
  mcpCount: number
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
  lastScan?: { pluginName: string; verdict: string; staticScore: number; at?: number }
  runtimeGuard?: 'off' | 'watch'
  metrics?: VetMetricsWire
}

const POLL_MS = 5000

/** 槽渲染器注入的翻译函数（DSH locale 服务）。 */
type T = (key: string) => string

/** t 缺失时的回退：zh 词典直查。 */
const zhT: T = key => (zh as Record<string, string>)[key] ?? key

/** 莫兰迪色板（每套：背景/卡片/边框 + 尘色调状态色 + 墨色文字）。 */
export interface MorandiPalette {
  sage: string
  ochre: string
  rose: string
  slate: string
  ink: string
  muted: string
  faint: string
  bg: string
  card: string
  cardSoft: string
  border: string
  borderSoft: string
  /** slate 主按钮上的文字色（浅色板深字 / 深色板浅字）。 */
  onSlate: string
}

/** 浅色板：暖米底 + 低饱和尘色（默认）。 */
const M: MorandiPalette = {
  sage: '#7E9A7C',
  ochre: '#B39263',
  rose: '#A87171',
  slate: '#6E7E99',
  ink: '#4B4A45',
  muted: '#837D73',
  faint: '#A39D90',
  bg: '#F1EEE7',
  card: '#E8E4DA',
  cardSoft: '#EDEAE2',
  border: '#D8D2C4',
  borderSoft: '#E0DBCD',
  onSlate: '#F6F4EE',
}

/** 深色板：暖炭底 + 提亮的尘色（暗色主题分支）。 */
const MD: MorandiPalette = {
  sage: '#93B191',
  ochre: '#C2A378',
  rose: '#BE8B8B',
  slate: '#8CA3C0',
  ink: '#E6E2D8',
  muted: '#B5AEA0',
  faint: '#8D8578',
  bg: '#23211C',
  card: '#2C2923',
  cardSoft: '#353128',
  border: '#464138',
  borderSoft: '#37332B',
  onSlate: '#22201B',
}

const COLOR: Record<'green' | 'yellow' | 'red', keyof MorandiPalette> = {
  green: 'sage',
  yellow: 'ochre',
  red: 'rose',
}

/** 介绍栏卖点骨架：标题/正文走 t()，序号是通用符号。 */
const INTRO_POINTS = [
  { n: '①', titleKey: 'intro.p1title', bodyKey: 'intro.p1body' },
  { n: '②', titleKey: 'intro.p2title', bodyKey: 'intro.p2body' },
  { n: '③', titleKey: 'intro.p3title', bodyKey: 'intro.p3body' },
]

/* ------------------------- 主题检测 ------------------------- */

function linearize(c: number): number {
  const v = c / 255
  return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)
}

/** 解析 #rgb/#rrggbb/rgb()/rgba() → WCAG 相对亮度（0 黑 ~ 1 白）。解析失败返回 null。 */
function parseLuma(value: string): number | null {
  const t = value.trim()
  if (t === '') return null
  let m = /^#([0-9a-f]{6})$/i.exec(t)
  if (m === null) m = /^#([0-9a-f]{3})$/i.exec(t)
  if (m !== null) {
    let hex = m[1]
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('')
    const r = parseInt(hex.slice(0, 2), 16)
    const g = parseInt(hex.slice(2, 4), 16)
    const b = parseInt(hex.slice(4, 6), 16)
    return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
  }
  m = /^rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)/.exec(t)
  if (m !== null) {
    return 0.2126 * linearize(Number(m[1])) + 0.7152 * linearize(Number(m[2])) + 0.0722 * linearize(Number(m[3]))
  }
  return null
}

/** 当前是否暗色：优先读 DSH 主题变量 --dsw-alias-bg-base 的计算值，缺失时回退系统配色。 */
function isDark(): boolean {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue('--dsw-alias-bg-base')
    const luma = parseLuma(v)
    if (luma !== null) return luma < 0.28
  } catch {
    // 继续走媒体查询回退
  }
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches
}

/* ------------------------- 视图片段 ------------------------- */

function panelStyle(pal: MorandiPalette): CSSProperties {
  return {
    width: 340,
    // 面板整体向下延伸（最高到视口 92%），日常内容无需滚动；极矮视口才出现滚动条。
    maxHeight: 'min(92vh, 800px)',
    overflowY: 'auto',
    background: pal.bg,
    border: '1px solid ' + pal.border,
    borderRadius: 12,
    boxShadow: 'var(--dsw-shadow-lv2, 0 10px 28px rgba(20,18,14,0.35))',
    fontSize: 12,
    color: pal.ink,
    padding: '14px 14px 10px',
    textAlign: 'left',
    lineHeight: 1.5,
  }
}

/**
 * 盾牌图标（三态符号，纯路径绘制不依赖字体）：
 * green → 盾内 √；yellow → 盾内 ?；red → 盾内 !。
 */
const SHIELD_PATH = 'M8 0.9 L13.1 2.9 V7 C13.1 10.7 11 13.3 8 14.3 C5 13.3 2.9 10.7 2.9 7 V2.9 Z'

function ShieldIcon({ level, color, size = 20 }: { level: 'green' | 'yellow' | 'red'; color: string; size?: number }): ReactNode {
  const symbol =
    level === 'green' ? (
      <path d="M5.2 8.2 L7.1 10.1 L10.8 5.9" stroke="#FFFFFF" strokeWidth={2} fill="none" strokeLinecap="round" strokeLinejoin="round" />
    ) : level === 'red' ? (
      <>
        <line x1={8} y1={4.5} x2={8} y2={9.3} stroke="#FFFFFF" strokeWidth={2} strokeLinecap="round" />
        <circle cx={8} cy={11.4} r={1.15} fill="#FFFFFF" />
      </>
    ) : (
      <>
        <path d="M6.3 5.5 C6.3 4.4 7 3.8 8 3.8 C9 3.8 9.7 4.4 9.7 5.3 C9.7 6.2 9.1 6.6 8.6 7.1 C8.1 7.6 8 8 8 8.8" stroke="#FFFFFF" strokeWidth={1.7} fill="none" strokeLinecap="round" />
        <circle cx={8} cy={11.3} r={0.95} fill="#FFFFFF" />
      </>
    )
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <path d={SHIELD_PATH} fill={color} stroke={color} strokeWidth={0.6} opacity="0.95" />
      {symbol}
    </svg>
  )
}

function SectionLabel({ pal, children }: { pal: MorandiPalette; children: ReactNode }): ReactNode {
  return (
    <div style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: pal.faint, margin: '12px 0 6px', fontWeight: 700 }}>
      {children}
    </div>
  )
}

function GroupLabel({ pal, children }: { pal: MorandiPalette; children: ReactNode }): ReactNode {
  return (
    <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: pal.faint, margin: '2px 0 4px' }}>
      {children}
    </div>
  )
}

function Metric({ pal, label, value, hint, wide }: { pal: MorandiPalette; label: string; value: string; hint?: string; wide?: boolean }): ReactNode {
  return (
    <div
      title={hint}
      style={{
        background: pal.card,
        borderRadius: 8,
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

function fmtTime(at: number): string {
  const d = new Date(at)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
}

/** 内存：≥1 GB 显示 GB（1 位小数），否则 MB 取整。 */
function fmtRam(mb: number): string {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB'
  return Math.round(mb) + ' MB'
}

/** 右侧介绍栏：绝对定位贴住主框右缘（主框不动），等高；width 按右侧可用空间传入。 */
function VetIntroPanel({ pal, width, t }: { pal: MorandiPalette; width: number; t: T }): ReactNode {
  return (
    <aside
      role="dialog"
      aria-label={t('intro.aria')}
      style={{
        position: 'absolute',
        top: 0,
        bottom: 0,
        left: 'calc(100% + 8px)',
        width,
        background: pal.bg,
        border: '1px solid ' + pal.border,
        borderRadius: 12,
        boxShadow: 'var(--dsw-shadow-lv2, 0 10px 28px rgba(20,18,14,0.35))',
        padding: '14px 14px 12px',
        fontSize: 12,
        color: pal.ink,
        lineHeight: 1.6,
        overflowY: 'auto',
        maxHeight: 'min(92vh, 800px)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
        <ShieldIcon level="green" color={pal.sage} size={16} />
        <span style={{ fontWeight: 800, fontSize: 13, letterSpacing: '0.02em' }}>{t('intro.title')}</span>
      </div>
      <div style={{ fontSize: 10.5, color: pal.faint, marginBottom: 8 }}>
        @jieai/dsh-plugin-vet v{typeof __VET_VERSION__ === 'string' ? __VET_VERSION__ : '0.1.0'}
      </div>

      <div style={{ fontWeight: 800, fontSize: 11.5, color: pal.ink, marginBottom: 6 }}>
        {t('intro.lines')}
      </div>

      <div style={{ background: pal.card, borderRadius: 8, padding: '7px 10px', marginBottom: 10, fontSize: 11, color: pal.muted }}>
        <div>
          <b style={{ color: pal.ink }}>{t('intro.stat1')}</b>
          {t('intro.stat1b')}
        </div>
        <div style={{ marginTop: 1 }}>
          <b style={{ color: pal.ink }}>{t('intro.stat2')}</b>
          {t('intro.stat2b')}
        </div>
        <div style={{ marginTop: 1 }}>
          <b style={{ color: pal.ink }}>{t('intro.stat3')}</b>
          {t('intro.stat3b')}
        </div>
      </div>

      {INTRO_POINTS.map(p => (
        <div key={p.n} style={{ marginBottom: 10 }}>
          <div style={{ fontWeight: 700 }}>
            <span style={{ color: pal.sage }}>{p.n}</span> {t(p.titleKey)}
          </div>
          <div style={{ color: pal.muted, marginTop: 2 }}>{t(p.bodyKey)}</div>
        </div>
      ))}

      <div style={{ background: pal.cardSoft, borderRadius: 8, padding: '6px 10px', fontWeight: 700, color: pal.ink, margin: '8px 0 10px' }}>
        {t('intro.tagline')}
      </div>

      <div style={{ fontSize: 10.5, color: pal.faint, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 8 }}>
        {t('intro.cost')}
      </div>
    </aside>
  )
}

/**
 * 会话头部盾牌。props 由槽渲染器传入（含 t 翻译函数；owner share 为空，本组件自给自足）。
 */
export function Shield(props: { t?: T } & Record<string, unknown>): ReactNode {
  const t = typeof props.t === 'function' ? props.t : zhT
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)
  const [open, setOpen] = useState(false)
  const [loadedAt, setLoadedAt] = useState(0)
  const [toggleMsg, setToggleMsg] = useState<string | null>(null)
  const [toggling, setToggling] = useState(false)
  const [dark, setDark] = useState<boolean>(() => isDark())
  const [helpOpen, setHelpOpen] = useState(false)
  const [introW, setIntroW] = useState(250)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const loadRef = useRef<() => void>(() => {})
  const openTimer = useRef<number | null>(null)
  const closeTimer = useRef<number | null>(null)

  useEffect(() => {
    let alive = true
    const load = async (): Promise<void> => {
      try {
        const res = await fetch('/vet/status.json', { cache: 'no-store' })
        if (!alive) return
        const text = await res.text()
        setSnap(JSON.parse(text) as ShieldSnapshotWire)
        setDark(isDark())
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

  // 系统配色变化时即时切换色板（DSH 主题切换也会在下次轮询时被 isDark() 捕获）。
  useEffect(() => {
    if (typeof matchMedia === 'undefined') return
    const mq = matchMedia('(prefers-color-scheme: dark)')
    const update = (): void => setDark(isDark())
    mq.addEventListener('change', update)
    return () => mq.removeEventListener('change', update)
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
      if (body.ok === true) {
        setToggleMsg(t('guard.written'))
      } else {
        const note = typeof body.note === 'string' && body.note !== '' ? ' — ' + body.note : ''
        setToggleMsg(t('guard.writeFailed') + note)
      }
    } catch {
      setToggleMsg(t('guard.requestFailed'))
    } finally {
      setToggling(false)
    }
  }

  const pal = dark ? MD : M
  const level = snap?.level ?? 'green'
  const color = pal[COLOR[level]]
  const statusLabel = t('status.' + level)
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan
  const metrics = snap?.metrics
  const guard = snap?.runtimeGuard ?? 'off'

  // 「?」右侧介绍栏：悬停 400ms 或点击打开；弹层内部移动不误关（容器级 mouseleave 才关）。
  const cancelHelpClose = (): void => {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current)
      closeTimer.current = null
    }
  }
  const scheduleHelpClose = (): void => {
    cancelHelpClose()
    closeTimer.current = window.setTimeout(() => setHelpOpen(false), 300)
  }
  const onHelpEnter = (): void => {
    cancelHelpClose()
    if (openTimer.current !== null) window.clearTimeout(openTimer.current)
    openTimer.current = window.setTimeout(() => setHelpOpen(true), 400)
  }
  const onHelpToggle = (): void => {
    cancelHelpClose()
    if (openTimer.current !== null) {
      window.clearTimeout(openTimer.current)
      openTimer.current = null
    }
    setHelpOpen(v => !v)
  }

  // 面板收起时同步关闭帮助浮层。
  useEffect(() => {
    if (!open) setHelpOpen(false)
  }, [open])

  // 介绍栏贴在主框右侧（左缘 = 主框右缘 + 8px，主框位置不动）；
  // 宽度按盾牌右侧可用空间收窄（160-280），至少保证能放进视口。
  useEffect(() => {
    if (!open) return
    const measure = (): void => {
      const el = rootRef.current
      if (el === null) return
      const r = el.getBoundingClientRect()
      const availRight = Math.max(0, window.innerWidth - r.right - 8 - 8)
      setIntroW(Math.max(160, Math.min(280, availRight)))
    }
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [open, helpOpen])

  // 卸载时清理定时器。
  useEffect(() => () => {
    if (openTimer.current !== null) window.clearTimeout(openTimer.current)
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current)
  }, [])

  return (
    <div
      ref={rootRef}
      onMouseEnter={cancelHelpClose}
      onMouseLeave={scheduleHelpClose}
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
    >
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
        aria-label={'vet ' + statusLabel + '（' + count + ' ' + t('alerts.count') + '）'}
        title={'vet ' + statusLabel + (level !== 'green' ? t('clickDetail') : '') + (count > 0 ? ' · ' + count + ' ' + t('alerts.count') : '')}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '2px 8px',
          height: 28,
          border: 'none',
          background: open ? pal.cardSoft : 'transparent',
          cursor: 'pointer',
          borderRadius: 8,
          transition: 'background 120ms ease',
        }}
      >
        <ShieldIcon level={level} color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: pal.muted, fontWeight: 600, lineHeight: 1 }}
            title={t('ram.hint')}
          >
            RAM {fmtRam(metrics.rssMb + metrics.mcpRssMb)}
          </span>
        )}
        {count > 0 && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color,
              background: pal.card,
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
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 1000,
          }}
        >
          <div style={panelStyle(pal)} role="dialog" aria-label={t('panel.label')}>
          {/* 头部 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13.5, letterSpacing: '0.02em' }}>vet {statusLabel}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: pal.muted, background: pal.card, borderRadius: 9, padding: '1px 8px' }}>
              {count} {t('alerts.count')}
            </span>
          </div>
          <div style={{ color: pal.muted, marginTop: 5 }}>
            {level === 'yellow'
              ? (alarms.length > 0 ? t('level.yellowAlarm') : t('level.yellowScan'))
              : t('level.' + level)}
          </div>

          {/* 黄灯且无报警：唯一来源是最近扫描 suspicious → 直接展示预警详情（这就是可点的「详情」） */}
          {level === 'yellow' && alarms.length === 0 && lastScan !== undefined && (
            <div style={{ marginTop: 8, background: pal.card, borderRadius: 8, borderLeft: '3px solid ' + pal.ochre, padding: '8px 10px' }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: pal.ochre, letterSpacing: '0.02em' }}>
                {t('warn.title')}
              </div>
              <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {lastScan.pluginName}
                </span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: pal[COLOR[level]], flexShrink: 0 }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: pal.faint, flexShrink: 0 }}>{lastScan.staticScore} {t('points')}</span>
              </div>
              <div style={{ marginTop: 3, fontSize: 10.5, color: pal.faint }}>
                {lastScan.at !== undefined ? t('warn.scannedAt') + fmtTime(lastScan.at) + ' · ' : ''}
                {t('warn.body')}
              </div>
            </div>
          )}

          {/* 实时指标：内存（含堆外）与运行/I-O 分组，IO 不混进内存 */}
          {metrics !== undefined && (
            <>
              <SectionLabel pal={pal}>{t('metrics.title')}</SectionLabel>
              <GroupLabel pal={pal}>{t('metrics.memory')}</GroupLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric pal={pal} label={t('metric.total')} value={Math.round(metrics.rssMb + metrics.mcpRssMb) + ' MB'} hint={t('metric.totalHint')} />
                <Metric pal={pal} label={t('metric.heap')} value={Math.round(metrics.heapUsedMb) + ' / ' + Math.round(metrics.heapTotalMb) + ' MB'} hint={t('metric.heapHint')} />
                <Metric pal={pal} label={t('metric.native')} value={Math.round(metrics.externalMb) + ' MB'} hint={t('metric.nativeHint')} />
                <Metric pal={pal} label={t('metric.other')} value={Math.round(Math.max(0, metrics.rssMb - metrics.heapUsedMb - metrics.externalMb)) + ' MB'} hint={t('metric.otherHint')} />
                <Metric pal={pal} label={t('metric.mcp')} value={Math.round(metrics.mcpRssMb) + ' MB · ' + metrics.mcpCount + ' ' + t('metric.mcpUnit')} hint={t('metric.mcpHint')} wide />
              </div>
              <GroupLabel pal={pal}>{t('metrics.runtime')}</GroupLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric pal={pal} label={t('metric.cpu')} value={metrics.cpuPct + '%'} />
                <Metric pal={pal} label={t('metric.ioRead')} value={metrics.ioReadMb + ' MB'} />
                <Metric pal={pal} label={t('metric.ioWrite')} value={metrics.ioWriteMb + ' MB'} />
                <Metric pal={pal} label={t('metric.children')} value={metrics.childCount >= 0 ? String(metrics.childCount) : '—'} />
              </div>
              {metrics.fdCount >= 0 && (
                <div style={{ marginTop: 5, fontSize: 10.5, color: pal.faint }}>
                  {t('fd.label')}{metrics.fdCount}
                </div>
              )}
            </>
          )}

          {/* 运行时守卫：状态 + ? 提示 */}
          <SectionLabel pal={pal}>{t('guard.title')}</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', background: pal.card, borderRadius: 8, padding: '8px 10px' }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? pal.sage : pal.faint, display: 'inline-block' }} />
            <span style={{ fontWeight: 700, marginLeft: 8 }}>{guard === 'watch' ? t('guard.on') : t('guard.off')}</span>
            {guard === 'off' && (
              <button
                type="button"
                disabled={toggling}
                onClick={() => { void toggleGuard(true) }}
                style={{
                  marginLeft: 'auto',
                  border: 'none',
                  background: pal.slate,
                  color: pal.onSlate,
                  borderRadius: 7,
                  padding: '3px 14px',
                  fontSize: 11.5,
                  fontWeight: 700,
                  cursor: toggling ? 'default' : 'pointer',
                  opacity: toggling ? 0.6 : 1,
                }}
              >
                {toggling ? t('guard.writing') : t('guard.enable')}
              </button>
            )}
            <span
              tabIndex={0}
              role="button"
              aria-label={t('guard.helpLabel')}
              onClick={onHelpToggle}
              onMouseEnter={onHelpEnter}
              onFocus={onHelpEnter}
              onBlur={scheduleHelpClose}
              style={{
                marginLeft: 8,
                width: 16,
                height: 16,
                borderRadius: 8,
                background: pal.cardSoft,
                color: pal.faint,
                fontSize: 10.5,
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'help',
                flexShrink: 0,
              }}
            >
              ?
            </span>
          </div>
          {toggleMsg !== null && (
            <div style={{ marginTop: 6, fontSize: 11, color: pal.ochre }}>{toggleMsg}</div>
          )}

          {/* 最近扫描 */}
          {lastScan !== undefined && (
            <>
              <SectionLabel pal={pal}>{t('scan.recent')}</SectionLabel>
              <div style={{ background: pal.card, borderRadius: 8, padding: '7px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? pal.sage : lastScan.verdict === 'suspicious' ? pal.ochre : pal.rose }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: pal.faint }}>{lastScan.staticScore} {t('points')}</span>
              </div>
            </>
          )}

          {/* 报警列表 */}
          <SectionLabel pal={pal}>{t('alerts.title')}</SectionLabel>
          {alarms.length === 0 ? (
            <div style={{ color: pal.faint, padding: '4px 2px' }}>{t('alerts.empty')}</div>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {alarms.slice(0, 8).map((a, i) => (
                <li
                  key={i}
                  style={{
                    background: pal.card,
                    borderRadius: 8,
                    borderLeft: '3px solid ' + (a.severity === 'red' ? pal.rose : a.severity === 'yellow' ? pal.ochre : 'transparent'),
                    padding: '7px 10px',
                    marginBottom: 5,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, background: pal.cardSoft, borderRadius: 4, padding: '1px 6px', color: pal.muted }}>
                      {a.kind}
                    </span>
                    {a.pluginHint !== undefined && (
                      <span style={{ fontSize: 10.5, color: pal.faint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint}</span>
                    )}
                  </div>
                  <div style={{ marginTop: 3, wordBreak: 'break-word' }}>{a.message}</div>
                  {(zh as Record<string, string>)['suggest.' + a.kind] !== undefined && (
                    <div style={{ marginTop: 3, fontSize: 11, color: pal.ochre }}>{t('alerts.suggest')}{t('suggest.' + a.kind)}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {/* 底部 */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: 12, paddingTop: 8, borderTop: '1px solid ' + pal.borderSoft }}>
            {loadedAt > 0 && (
              <span style={{ fontSize: 10.5, color: pal.faint }}>{t('footer.updated')}{fmtTime(loadedAt)}</span>
            )}
            <button
              type="button"
              onClick={() => { loadRef.current() }}
              style={{
                marginLeft: 'auto',
                border: '1px solid ' + pal.border,
                background: 'transparent',
                color: pal.muted,
                borderRadius: 7,
                padding: '2px 12px',
                cursor: 'pointer',
                fontSize: 11,
                transition: 'background 120ms ease',
              }}
            >
              {t('footer.refresh')}
            </button>
          </div>
        </div>

        {helpOpen && <VetIntroPanel pal={pal} width={introW} t={t} />}
        </div>
      )}
    </div>
  )
}
