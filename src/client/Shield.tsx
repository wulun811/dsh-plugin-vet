
/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一动作是「开启运行时守卫」按钮——用户主动点击，vet 按其指令写自己的配置（重启生效）。
 * 设计：莫兰迪色系双套（浅色暖灰 / 深色暖炭，跟随 DSH 主题自动切换），纯静态 inline 样式，无动画无库。
 * 主题检测：优先读 --dsw-alias-bg-base 的计算值亮度判断明暗；变量缺失时回退 prefers-color-scheme。
 * 版本号由构建脚本注入（__VET_VERSION__，esbuild define）。
 */
import { useEffect, useRef, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'

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

const LABEL: Record<'green' | 'yellow' | 'red', string> = {
  green: '守护中',
  yellow: '有情况',
  red: '有风险',
}

const LEVEL_TEXT: Record<'green' | 'yellow' | 'red', string> = {
  green: '当前无报警，静态扫描与运行时守护正常。',
  yellow: '有警告或可疑扫描结果。',
  red: '检测到高风险报警，请查看下方报警列表；可在 DSH 对话中把这段预警发给 LLM，让它协助排查处置。',
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

/** 「?」悬停提示：插件简介 + 版本 + 守卫代价。 */
const GUARD_HELP = [
  '@jieai/dsh-plugin-vet v' + (typeof __VET_VERSION__ === 'string' ? __VET_VERSION__ : '0.1.0'),
  'DSH 插件信任流水线：静态规则判定 + LLM 审计 + 运行时守卫（T1 哨兵 / T2 钩子）；报警与建议可发给 DSH 对话中的 LLM 协助排查。',
  '',
  '开启运行时守卫的代价：',
  '· 哨兵子进程约占 10-30 MB 内存 + 轻量轮询；',
  '· T2 钩子使文件/子进程调用开销增加约 5%（热点场景更高）。',
  '写入配置后需重启 dsh web 生效。',
].join('\n')

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
    position: 'absolute',
    top: 'calc(100% + 6px)',
    right: 0,
    zIndex: 1000,
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

function ShieldIcon({ color, size = 20 }: { color: string; size?: number }): ReactNode {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 1 L13 3 V7 C13 10.6 10.9 13.2 8 14.2 C5.1 13.2 3 10.6 3 7 V3 Z" fill={color} opacity="0.92" />
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

function Metric({ pal, label, value, hint }: { pal: MorandiPalette; label: string; value: string; hint?: string }): ReactNode {
  return (
    <div
      title={hint}
      style={{ background: pal.card, borderRadius: 8, padding: '6px 10px', display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}
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

/**
 * 会话头部盾牌。props 由槽渲染器传入（空 owner share，本组件自给自足），忽略。
 */
export function Shield(_props: Record<string, unknown>): ReactNode {
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)
  const [open, setOpen] = useState(false)
  const [loadedAt, setLoadedAt] = useState(0)
  const [toggleMsg, setToggleMsg] = useState<string | null>(null)
  const [toggling, setToggling] = useState(false)
  const [dark, setDark] = useState<boolean>(() => isDark())
  const [helpOpen, setHelpOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const loadRef = useRef<() => void>(() => {})
  const helpElRef = useRef<HTMLSpanElement | null>(null)
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
      setToggleMsg(body.note ?? (res.ok ? '已写入' : '写入失败'))
    } catch {
      setToggleMsg('请求失败（路由未注册？重启后重试）')
    } finally {
      setToggling(false)
    }
  }

  const pal = dark ? MD : M
  const level = snap?.level ?? 'green'
  const color = pal[COLOR[level]]
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan
  const metrics = snap?.metrics
  const guard = snap?.runtimeGuard ?? 'off'

  // 「?」帮助提示：自定义浮层（替代浏览器 title 的迟钝延迟），悬停 400ms 弹出。
  const cancelHelpClose = (): void => {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current)
      closeTimer.current = null
    }
  }
  const scheduleHelpClose = (): void => {
    cancelHelpClose()
    closeTimer.current = window.setTimeout(() => setHelpOpen(false), 160)
  }
  const onHelpEnter = (): void => {
    cancelHelpClose()
    if (openTimer.current !== null) window.clearTimeout(openTimer.current)
    openTimer.current = window.setTimeout(() => setHelpOpen(true), 400)
  }
  const onHelpLeave = (): void => {
    if (openTimer.current !== null) {
      window.clearTimeout(openTimer.current)
      openTimer.current = null
    }
    scheduleHelpClose()
  }

  // 浮层挂到 document.body（面板 overflow 会裁剪内部绝对定位，不能放面板里）。
  useEffect(() => {
    if (!helpOpen) return
    const anchor = helpElRef.current
    if (anchor === null) return
    const tip = document.createElement('div')
    tip.style.position = 'fixed'
    tip.style.zIndex = '2000'
    tip.style.width = '280px'
    tip.style.maxHeight = '50vh'
    tip.style.overflowY = 'auto'
    tip.style.padding = '10px 12px'
    tip.style.borderRadius = '10px'
    tip.style.fontSize = '11.5px'
    tip.style.lineHeight = '1.6'
    tip.style.whiteSpace = 'pre-line'
    tip.style.background = pal.bg
    tip.style.border = '1px solid ' + pal.border
    tip.style.color = pal.ink
    tip.style.boxShadow = '0 10px 28px rgba(20,18,14,0.35)'
    tip.textContent = GUARD_HELP
    document.body.appendChild(tip)
    const r = anchor.getBoundingClientRect()
    const gap = 8
    let left = Math.max(8, Math.min(r.left, window.innerWidth - tip.offsetWidth - 8))
    let top = r.bottom + gap
    if (top + tip.offsetHeight > window.innerHeight - 8) {
      top = Math.max(8, r.top - tip.offsetHeight - gap)
    }
    tip.style.left = left + 'px'
    tip.style.top = top + 'px'
    const onTipEnter = (): void => cancelHelpClose()
    const onTipLeave = (): void => scheduleHelpClose()
    tip.addEventListener('mouseenter', onTipEnter)
    tip.addEventListener('mouseleave', onTipLeave)
    return () => {
      tip.removeEventListener('mouseenter', onTipEnter)
      tip.removeEventListener('mouseleave', onTipLeave)
      if (tip.parentNode !== null) tip.parentNode.removeChild(tip)
    }
  }, [helpOpen, pal])

  // 面板收起时同步关闭帮助浮层。
  useEffect(() => {
    if (!open) setHelpOpen(false)
  }, [open])

  // 卸载时清理定时器。
  useEffect(() => () => {
    if (openTimer.current !== null) window.clearTimeout(openTimer.current)
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current)
  }, [])

  return (
    <div ref={rootRef} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
        aria-label={'vet ' + LABEL[level] + '（' + count + ' 条报警）'}
        title={'vet ' + LABEL[level] + (level !== 'green' ? '（点击查看详情）' : '') + (count > 0 ? '：' + count + ' 条报警' : '')}
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
        <ShieldIcon color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: pal.muted, fontWeight: 600, lineHeight: 1 }}
            title="RAM = DSH 宿主 + 全部插件总内存（同一进程，仅总量）"
          >
            RAM {fmtRam(metrics.rssMb)}
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
        <div style={panelStyle(pal)} role="dialog" aria-label="vet 报警面板">
          {/* 头部 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13.5, letterSpacing: '0.02em' }}>vet {LABEL[level]}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: pal.muted, background: pal.card, borderRadius: 9, padding: '1px 8px' }}>
              {count} 条报警
            </span>
          </div>
          <div style={{ color: pal.muted, marginTop: 5 }}>
            {level === 'yellow'
              ? (alarms.length > 0 ? '有警告报警，详见下方报警列表。' : '有可疑扫描结果，详见下方「预警详情」。')
              : LEVEL_TEXT[level]}
          </div>

          {/* 黄灯且无报警：唯一来源是最近扫描 suspicious → 直接展示预警详情（这就是可点的「详情」） */}
          {level === 'yellow' && alarms.length === 0 && lastScan !== undefined && (
            <div style={{ marginTop: 8, background: pal.card, borderRadius: 8, borderLeft: '3px solid ' + pal.ochre, padding: '8px 10px' }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: pal.ochre, letterSpacing: '0.02em' }}>
                预警详情 · 最近扫描存在可疑结果
              </div>
              <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {lastScan.pluginName}
                </span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: pal[COLOR[level]], flexShrink: 0 }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: pal.faint, flexShrink: 0 }}>{lastScan.staticScore} 分</span>
              </div>
              <div style={{ marginTop: 3, fontSize: 10.5, color: pal.faint }}>
                {lastScan.at !== undefined ? '扫描于 ' + fmtTime(lastScan.at) + ' · ' : ''}
                静态判定存疑（非结论）：可对该插件执行深度审计复核，或把这段预警发给 DSH 对话让 LLM 协助排查。
              </div>
            </div>
          )}

          {/* 实时指标 */}
          {metrics !== undefined && (
            <>
              <SectionLabel pal={pal}>实时指标</SectionLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric pal={pal} label="总内存" value={metrics.rssMb + ' MB'} hint="DSH 宿主 + 全部插件 + vet（同一进程，OS 仅见总量）" />
                <Metric pal={pal} label="V8 堆" value={metrics.heapUsedMb + ' / ' + metrics.heapTotalMb + ' MB'} />
                <Metric pal={pal} label="原生 + 外部" value={metrics.externalMb + ' MB'} />
                <Metric pal={pal} label="MCP 服务" value={metrics.mcpRssMb + ' MB · ' + metrics.mcpCount + ' 个'} hint="独立 MCP 服务进程（命令行含 mcp，如 dsh-malong-bridge），不在 DSH 进程内、单独统计" />
                <Metric pal={pal} label="CPU" value={metrics.cpuPct + '%'} />
                <Metric pal={pal} label="I/O 读" value={metrics.ioReadMb + ' MB'} />
                <Metric pal={pal} label="I/O 写" value={metrics.ioWriteMb + ' MB'} />
                <Metric pal={pal} label="子进程" value={metrics.childCount >= 0 ? String(metrics.childCount) : '—'} />
              </div>
              {metrics.fdCount >= 0 && (
                <div style={{ marginTop: 5, fontSize: 10.5, color: pal.faint }}>
                  fd：{metrics.fdCount}
                </div>
              )}
            </>
          )}

          {/* 运行时守卫：状态 + ? 提示 */}
          <SectionLabel pal={pal}>运行时守卫</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', background: pal.card, borderRadius: 8, padding: '8px 10px' }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? pal.sage : pal.faint, display: 'inline-block' }} />
            <span style={{ fontWeight: 700, marginLeft: 8 }}>{guard === 'watch' ? '已开启（watch）' : '未开启'}</span>
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
                {toggling ? '写入中…' : '开启'}
              </button>
            )}
            <span
              ref={helpElRef}
              tabIndex={0}
              role="button"
              aria-label="运行时守卫说明（悬停查看）"
              onMouseEnter={onHelpEnter}
              onMouseLeave={onHelpLeave}
              onFocus={onHelpEnter}
              onBlur={onHelpLeave}
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
              <SectionLabel pal={pal}>最近扫描</SectionLabel>
              <div style={{ background: pal.card, borderRadius: 8, padding: '7px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? pal.sage : lastScan.verdict === 'suspicious' ? pal.ochre : pal.rose }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: pal.faint }}>{lastScan.staticScore} 分</span>
              </div>
            </>
          )}

          {/* 报警列表 */}
          <SectionLabel pal={pal}>报警</SectionLabel>
          {alarms.length === 0 ? (
            <div style={{ color: pal.faint, padding: '4px 2px' }}>暂无报警记录</div>
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
                  {SUGGEST[a.kind] !== undefined && (
                    <div style={{ marginTop: 3, fontSize: 11, color: pal.ochre }}>建议：{SUGGEST[a.kind]}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {/* 底部 */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: 12, paddingTop: 8, borderTop: '1px solid ' + pal.borderSoft }}>
            {loadedAt > 0 && (
              <span style={{ fontSize: 10.5, color: pal.faint }}>更新于 {fmtTime(loadedAt)}</span>
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
              刷新
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
