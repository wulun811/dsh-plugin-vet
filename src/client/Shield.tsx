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
import { createPortal } from 'react-dom'
import type { CSSProperties, ReactNode } from 'react'
import { zh } from './i18n.ts'

/** 构建时注入：package.json version（scripts/build-client.mjs define）。 */
declare const __VET_VERSION__: string

/** 细滚动条样式（注入一次）。 */
const SCROLLBAR_STYLE_ID = 'vet-scrollbar-style'
function injectScrollbarStyle(): void {
  if (typeof document === 'undefined') return
  if (document.getElementById(SCROLLBAR_STYLE_ID) !== null) return
  const style = document.createElement('style')
  style.id = SCROLLBAR_STYLE_ID
  style.textContent = `
    .vet-scrollbar::-webkit-scrollbar { width: 4px; }
    .vet-scrollbar::-webkit-scrollbar-track { background: transparent; }
    .vet-scrollbar::-webkit-scrollbar-thumb { background: rgba(128, 128, 128, 0.3); border-radius: 2px; }
    .vet-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(128, 128, 128, 0.5); }
    .vet-scrollbar { scrollbar-width: thin; scrollbar-color: rgba(128, 128, 128, 0.3) transparent; }
  `
  document.head.appendChild(style)
}

export interface VetAlarmWire {
  /** 去重键（source+kind+target），忽略/恢复按它寻址。 */
  id: string
  kind: string
  message: string
  severity?: 'yellow' | 'red'
  pluginHint?: string
  /** 目标是否为会话日志文件（归因分层文案用，见 status.ts VetAlarm）。 */
  sessionLog?: boolean
  /** 触发告警的目标（主机:端口、文件路径等），见 status.ts VetAlarm.target。 */
  target?: string
  /** 同类报警合并后的累计次数（跨 target 折叠，见 status.ts VetAlarm.count）。 */
  count?: number
  at: number
}

export interface VetMetricsWire {
  rssMb: number
  heapUsedMb: number
  heapTotalMb: number
  externalMb: number
  mcpRssMb: number
  mcpCount: number
  vetRssMb: number
  vetCount: number
  cpuPct: number
  ioReadMb: number
  ioWriteMb: number
  childCount: number
  fdCount: number
  at: number
}

/** 0.1.20：防御统计数据 */
export interface VetStatsWire {
  scannedCount: number
  alarmsRecorded: number
  blockedCount: number
  activeDefenseCount: number
  updatedAt: number
}

export interface ShieldSnapshotWire {
  level: 'green' | 'yellow' | 'red'
  alarmCount: number
  alarms: VetAlarmWire[]
  /** 用户已忽略的报警（可恢复）。 */
  dismissed?: VetAlarmWire[]
  lastScan?: { pluginName: string; verdict: string; staticScore: number; at?: number }
  runtimeGuard?: 'off' | 'watch'
  metrics?: VetMetricsWire
  /** 0.1.20：防御统计 */
  stats?: VetStatsWire
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

// 卡片渐变背景常量
const CARD_BG_LIGHT = 'linear-gradient(180deg, #F5F3ED 0%, #F0EDE6 100%)'
const CARD_BG_DARK = 'linear-gradient(180deg, rgba(58,56,50,1) 0%, rgba(50,48,43,1) 100%)'


/** 介绍栏卖点骨架：5 个分区，每个有图标 + 标题 + 短要点列表。 */
const INTRO_SECTIONS = [
  { icon: '🛡', titleKey: 'intro.s1title', bullets: ['intro.s1b1', 'intro.s1b2', 'intro.s1b3'] },
  { icon: '👁', titleKey: 'intro.s2title', bullets: ['intro.s2b1', 'intro.s2b2', 'intro.s2b3'] },
  { icon: '🍯', titleKey: 'intro.s3title', bullets: ['intro.s3b1', 'intro.s3b2', 'intro.s3b3'] },
  { icon: '📋', titleKey: 'intro.s4title', bullets: ['intro.s4b1', 'intro.s4b2', 'intro.s4b3'] },
  { icon: '🔔', titleKey: 'intro.s5title', bullets: ['intro.s5b1', 'intro.s5b2', 'intro.s5b3'] },
]

/* ------------------------- 主题检测 ------------------------- */

/** 当前是否暗色：检测 DSH 主题属性。 */
function isDark(): boolean {
  // 检测 DSH 的 data-ds-dark-theme 属性
  if (typeof document !== 'undefined' && document.body) {
    // DSH web UI 的逻辑：有 data-ds-dark-theme 就是深色，没有就是浅色
    return document.body.hasAttribute('data-ds-dark-theme')
  }
  // 回退到系统偏好
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches
}

/* ------------------------- 视图片段 ------------------------- */

/** 浅色模式下调整颜色以保证对比度（半透明玻璃背景需要更深的文字） */
function adjustForLightMode(pal: MorandiPalette, dark: boolean): MorandiPalette {
  if (dark) return pal
  // 浅色模式：Minimal White 风格，柔和的深蓝黑色调
  return {
    ...pal,
    // 主文字色（带蓝色调，不刺眼）
    ink: '#1a1a2e',    // 深蓝黑色
    muted: '#4a4a6a',  // 蓝灰色
    faint: '#6a6a8a',  // 浅蓝灰色
    // 强调色（保持柔和）
    sage: '#5A7A58',   // 深绿色
    ochre: '#8A6D45',  // 深赭石色
    rose: '#8A5656',   // 深玫瑰色
    slate: '#4F5E78',  // 深石板蓝
  }
}

function panelStyle(pal: MorandiPalette, dark: boolean): CSSProperties {
  // Crystal Edge 底板：极简透明 + 强模糊，边框和高光交给 overlay div
  return {
    width: 340,
    maxHeight: 'min(92vh, 800px)',
    overflowY: 'auto',
    // 几乎完全透明的底色，让 backdrop-filter 发挥
    background: dark ? 'rgba(30, 28, 24, 0.55)' : 'rgba(180, 180, 180, 0.25)',
    backdropFilter: 'blur(24px) saturate(1.4)',
    WebkitBackdropFilter: 'blur(24px) saturate(1.4)',
    borderRadius: 12,
    // Minimal White 风格边框效果
    boxShadow: dark
      ? '0 12px 40px rgba(0,0,0,0.5), 0 2px 8px rgba(0,0,0,0.3)'
      : '0 10px 40px rgba(0, 0, 0, 0.1), inset 0 1.5px 0 rgba(255, 255, 255, 1)',
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

function Metric({ pal, label, value, hint, wide, dark }: { pal: MorandiPalette; label: string; value: string; hint?: string; wide?: boolean; dark?: boolean }): ReactNode {
  return (
    <div
      title={hint}
      style={{
        // 微渐变背景 + Crystal Edge 顶部高光
        background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
        borderRadius: 8,
        boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
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

/** 右侧介绍栏：外层容器固定边框，内层 aside 滚动内容。 */
function VetIntroPanel({ pal, width, t, dark }: { pal: MorandiPalette; width: number; t: T; dark: boolean }): ReactNode {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      role="dialog"
      aria-label={t('intro.aria')}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'absolute',
        top: 0,
        bottom: 0,
        left: 'calc(100% + 8px)',
        width,
        borderRadius: 12,
        overflow: 'hidden',
      }}
    >
      {/* 背景层 */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: dark ? 'rgba(30, 28, 24, 0.55)' : 'rgba(180, 180, 180, 0.25)',
        backdropFilter: 'blur(24px) saturate(1.4)',
        WebkitBackdropFilter: 'blur(24px) saturate(1.4)',
        borderRadius: 12,
        boxShadow: dark
          ? '0 12px 40px rgba(0,0,0,0.5), 0 2px 8px rgba(0,0,0,0.3)'
          : '0 10px 40px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 1)',
      }} />
      {/* Crystal Edge: 渐变边框层（固定在外层容器，不随滚动） */}
      <div style={{
        position: 'absolute',
        inset: 0,
        borderRadius: 12,
        padding: 2,
        background: dark
          ? 'linear-gradient(135deg, rgba(255,255,255,0.5), rgba(255,255,255,0.05) 40%, rgba(255,255,255,0.05) 60%, rgba(255,255,255,0.4))'
          : 'linear-gradient(135deg, rgba(255,255,255,1), rgba(255,255,255,0.4) 40%, rgba(255,255,255,0.4) 60%, rgba(255,255,255,0.9))',
        WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
        WebkitMaskComposite: 'xor',
        maskComposite: 'exclude',
        pointerEvents: 'none',
        zIndex: 10,
        transition: 'opacity 0.5s ease',
        opacity: hovered ? 1 : 0.7,
      }} />
      {/* Crystal Edge: 顶部高光线条（固定） */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: 0.5,
        background: dark
          ? 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)'
          : 'linear-gradient(90deg, transparent, rgba(255,255,255,0.72), transparent)',
        pointerEvents: 'none',
        zIndex: 10,
      }} />
      {/* Mirror Sheen: 散光层（固定） */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: 'linear-gradient(135deg, transparent 20%, rgba(255,255,255,0.03) 35%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 65%, transparent 80%)',
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.4s ease',
        opacity: hovered ? 0 : 0.5,
      }} />
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: 'linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12) 50%, transparent 60%)',
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.4s ease',
        opacity: hovered ? 0.5 : 0,
      }} />
      {/* 可滚动内容层 */}
      <aside
        style={{
          position: 'relative',
          zIndex: 2,
          height: '100%',
          overflowY: 'auto',
          padding: '14px 14px 24px',
          fontSize: 12,
          color: pal.ink,
          lineHeight: 1.6,
        }}
        className="vet-scrollbar"
      >
      <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <ShieldIcon level="green" color={pal.sage} size={18} />
        <span style={{ fontWeight: 800, fontSize: 15, letterSpacing: '0.02em' }}>{t('intro.title')}</span>
      </div>
      <div style={{ fontSize: 12, color: pal.faint, marginBottom: 10 }}>
        @jieai/dsh-plugin-vet v{typeof __VET_VERSION__ === 'string' ? __VET_VERSION__ : '0.1.0'}
      </div>

      <div style={{ fontWeight: 800, fontSize: 13, color: pal.ink, marginBottom: 8 }}>
        {t('intro.lines')}
      </div>

      <div style={{ background: dark ? CARD_BG_DARK : CARD_BG_LIGHT, borderRadius: 8, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: pal.muted, boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') }}>
        <div>
          <b style={{ color: pal.ink }}>{t('intro.stat1')}</b>
          {t('intro.stat1b')}
        </div>
        <div style={{ marginTop: 2 }}>
          <b style={{ color: pal.ink }}>{t('intro.stat2')}</b>
          {t('intro.stat2b')}
        </div>
        <div style={{ marginTop: 2 }}>
          <b style={{ color: pal.ink }}>{t('intro.stat3')}</b>
          {t('intro.stat3b')}
        </div>
      </div>

      {INTRO_SECTIONS.map(s => (
        <div key={s.titleKey} style={{ marginBottom: 12 }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
            <span style={{ marginRight: 6 }}>{s.icon}</span>
            <span style={{ color: pal.ink }}>{t(s.titleKey)}</span>
          </div>
          <div style={{ paddingLeft: 24 }}>
            {s.bullets.map(b => (
              <div key={b} style={{ color: pal.muted, fontSize: 12, lineHeight: 1.6, marginTop: 2 }}>
                <span style={{ color: pal.faint, marginRight: 6 }}>·</span>{t(b)}
              </div>
            ))}
          </div>
        </div>
      ))}

      <div style={{ background: dark ? CARD_BG_DARK : CARD_BG_LIGHT, borderRadius: 8, padding: '10px 14px', fontWeight: 700, fontSize: 13, color: pal.ink, margin: '16px 0 12px', boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') }}>
        {t('intro.tagline')}
      </div>

      <div style={{ fontSize: 12, color: pal.faint, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 10 }}>
        {t('intro.cost')}
      </div>
      {/* 底部空白，确保内容可以完全滚动显示 */}
      <div style={{ height: '20px' }}></div>
      </div>
      </aside>
    </div>
  )
}

/**
 * 报警详情窗口（独立窗口，放在主面板右侧）。
 * 每个报警可折叠/展开，带复制按钮（复制时带元信息）。
 */
function VetAlarmPanel({ pal, width, t, alarms, dismissed, dark, onDismiss, onRestore }: {
  pal: MorandiPalette
  width: number
  t: T
  alarms: VetAlarmWire[]
  dismissed: VetAlarmWire[]
  dark: boolean
  onDismiss: (id: string) => void
  onRestore: (id: string) => void
}): ReactNode {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [hovered, setHovered] = useState(false)
  const [dismissedCollapsed, setDismissedCollapsed] = useState(true)
  const [expandedDismissedIds, setExpandedDismissedIds] = useState<Set<string>>(new Set())

  const toggleExpand = (id: string): void => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleDismissedExpand = (id: string): void => {
    setExpandedDismissedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const copyAlarm = async (a: VetAlarmWire): Promise<void> => {
    // 构造带元信息的文本
    const plugin = a.pluginHint !== undefined ? `@${a.pluginHint}` : '(unattributed)'
    const time = new Date(a.at).toLocaleString()
    const text = `VET 插件警报，请查实后给出解决方案：\n\n` +
      `时间：${time}\n` +
      `插件：${plugin}\n` +
      `类型：${a.kind}\n` +
      `严重度：${a.severity ?? 'unknown'}\n` +
      `信息：${a.message}`
    
    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(a.id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      // 降级：创建临时 textarea
      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopiedId(a.id)
      setTimeout(() => setCopiedId(null), 2000)
    }
  }

  return (
    <aside
      role="dialog"
      aria-label={t('alarmPanel.aria')}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'absolute',
        top: 0,
        bottom: 0,
        left: 'calc(100% + 8px)',
        width,
        background: dark ? 'rgba(30, 28, 24, 0.55)' : 'rgba(180, 180, 180, 0.25)',
        backdropFilter: 'blur(24px) saturate(1.4)',
        WebkitBackdropFilter: 'blur(24px) saturate(1.4)',
        borderRadius: 12,
        boxShadow: dark
          ? '0 12px 40px rgba(0,0,0,0.5), 0 2px 8px rgba(0,0,0,0.3)'
          : '0 10px 40px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 1)',
        padding: '14px 14px 12px',
        fontSize: 12,
        color: pal.ink,
        lineHeight: 1.5,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}
    >
      {/* Crystal Edge: 渐变边框层 */}
      <div style={{
        position: 'absolute',
        inset: 0,
        borderRadius: 12,
        padding: 2,
        background: dark
          ? 'linear-gradient(135deg, rgba(255,255,255,0.5), rgba(255,255,255,0.05) 40%, rgba(255,255,255,0.05) 60%, rgba(255,255,255,0.4))'
          : 'linear-gradient(135deg, rgba(255,255,255,0.9), rgba(255,255,255,0.2) 40%, rgba(255,255,255,0.2) 60%, rgba(255,255,255,0.8))',
        WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
        WebkitMaskComposite: 'xor',
        maskComposite: 'exclude',
        pointerEvents: 'none',
        zIndex: 10,
        transition: 'opacity 0.5s ease',
        opacity: hovered ? 1 : 0.7,
      }} />
      {/* Crystal Edge: 顶部高光线条 */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: 0.5,
        background: dark
          ? 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)'
          : 'linear-gradient(90deg, transparent, rgba(255,255,255,0.72), transparent)',
        pointerEvents: 'none',
        zIndex: 10,
      }} />
      {/* Mirror Sheen: 散光层（默认）→ 聚光层（hover） */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: 'linear-gradient(135deg, transparent 20%, rgba(255,255,255,0.03) 35%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 65%, transparent 80%)',
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.4s ease',
        opacity: hovered ? 0 : 0.5,
      }} />
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: 'linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12) 50%, transparent 60%)',
        pointerEvents: 'none',
        zIndex: 5,
        transition: 'opacity 0.4s ease',
        opacity: hovered ? 0.5 : 0,
      }} />
      <div style={{ position: 'relative', zIndex: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, flexShrink: 0 }}>
        <ShieldIcon level={alarms.length > 0 ? (alarms[0].severity === 'red' ? 'red' : 'yellow') : 'green'} color={alarms.length > 0 ? (alarms[0].severity === 'red' ? pal.rose : pal.ochre) : pal.sage} size={16} />
        <span style={{ fontWeight: 800, fontSize: 13, letterSpacing: '0.02em' }}>{t('alarmPanel.title')}</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: pal.muted, background: dark ? CARD_BG_DARK : CARD_BG_LIGHT, borderRadius: 9, padding: '1px 8px', boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') }}>
          {alarms.length}
        </span>
      </div>

      <div className="vet-scrollbar" style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
      {alarms.length === 0 ? (
        <div style={{ color: pal.faint, padding: '20px 0', textAlign: 'center' }}>{t('alarmPanel.empty')}</div>
      ) : (
        <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
          {alarms.map((a, index) => {
            const expanded = expandedIds.has(a.id)
            const copied = copiedId === a.id
            return (
              <li
                key={a.id}
                style={{
                  background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
                  borderRadius: 8,
                  borderLeft: '3px solid transparent',
                  borderImage: a.severity === 'red'
                    ? 'linear-gradient(180deg, ' + pal.rose + ', ' + pal.rose + '44) 1'
                    : a.severity === 'yellow'
                    ? 'linear-gradient(180deg, ' + pal.ochre + ', ' + pal.ochre + '44) 1'
                    : 'none',
                  boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
                  padding: '8px 10px',
                  marginBottom: 6,
                }}
              >
                <div 
                  onClick={() => toggleExpand(a.id)}
                  style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: 6,
                    cursor: 'pointer',
                    transition: 'opacity 120ms ease',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.7' }}
                  onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
                >
                  <span style={{ fontSize: 11, fontWeight: 700, color: pal.sage, minWidth: 20 }}>
                    #{index + 1}
                  </span>
                  <span style={{ fontSize: 10, fontWeight: 700, background: dark ? CARD_BG_DARK : CARD_BG_LIGHT, borderRadius: 4, padding: '1px 6px', color: pal.muted, boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') }}>
                    {a.kind}
                  </span>
                  {a.pluginHint !== undefined && (
                    <span style={{ fontSize: 10.5, color: pal.faint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint}</span>
                  )}
                  {a.count !== undefined && a.count > 1 && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: pal.rose, borderRadius: 4, padding: '0 5px', background: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)' }}>×{a.count}</span>
                  )}
                  <span style={{ fontSize: 10, color: pal.faint, flexShrink: 0 }}>{fmtTime(a.at)}</span>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); void copyAlarm(a) }}
                    title={t('alarmPanel.copyHint')}
                    style={{
                      border: '1px solid ' + pal.borderSoft,
                      background: copied ? pal.sage : 'transparent',
                      color: copied ? pal.onSlate : pal.muted,
                      borderRadius: 5,
                      padding: '0 7px',
                      cursor: 'pointer',
                      fontSize: 10,
                      flexShrink: 0,
                      transition: 'all 120ms ease',
                    }}
                  >
                    {copied ? t('alarmPanel.copied') : t('alarmPanel.copy')}
                  </button>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onDismiss(a.id) }}
                    title={t('alerts.dismissHint')}
                    style={{
                      border: '1px solid ' + pal.borderSoft,
                      background: 'transparent',
                      color: pal.muted,
                      borderRadius: 5,
                      padding: '0 7px',
                      cursor: 'pointer',
                      fontSize: 10,
                      flexShrink: 0,
                    }}
                  >
                    {t('alerts.dismiss')}
                  </button>
                </div>
                {expanded && (
                  <div style={{ marginTop: 6, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 6 }}>
                    <div style={{ wordBreak: 'break-word', fontSize: 11.5, marginBottom: 4 }}>{a.message}</div>
                    {(() => {
                      // 归因分层文案
                      let suggestKey: string
                      if (a.pluginHint === undefined) {
                        suggestKey = a.sessionLog === true
                          ? 'suggest.' + a.kind + '.unattributed.sessionLog'
                          : 'suggest.' + a.kind + '.unattributed'
                      } else {
                        suggestKey = 'suggest.' + a.kind
                      }
                      const hasSuggest = (zh as Record<string, string>)[suggestKey] !== undefined
                      if (!hasSuggest) return null
                      return (
                        <div style={{ fontSize: 11, color: pal.ochre, marginBottom: 4 }}>{t('alerts.suggest')}{t(suggestKey)}</div>
                      )
                    })()}
                    <div style={{ fontSize: 10.5, color: pal.muted }}>
                      <div><b>ID:</b> {a.id}</div>
                      <div><b>时间:</b> {new Date(a.at).toLocaleString()}</div>
                      <div><b>严重度:</b> {a.severity ?? 'unknown'}</div>
                      {a.target !== undefined && <div><b>目标:</b> {a.target}</div>}
                    </div>
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
      </div>

      {/* 已忽略警报区域 */}
      {dismissed.length > 0 && (
        <div style={{ flexShrink: 0, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 10, marginTop: 8 }}>
          <div 
            onClick={() => setDismissedCollapsed(v => !v)}
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 6,
              cursor: 'pointer',
              padding: '4px 0',
              userSelect: 'none',
            }}
          >
            <span style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: pal.faint, fontWeight: 700 }}>
              {t('alerts.dismissed')}
            </span>
            <span style={{ fontSize: 11, color: pal.muted, background: dark ? CARD_BG_DARK : CARD_BG_LIGHT, borderRadius: 9, padding: '1px 8px', boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') }}>
              {dismissed.length}
            </span>
            <span style={{ marginLeft: 'auto', fontSize: 10, color: pal.faint }}>
              {dismissedCollapsed ? '▸' : '▾'}
            </span>
          </div>
          {!dismissedCollapsed && (
            <div className="vet-scrollbar" style={{ maxHeight: 120, overflowY: 'auto', marginTop: 6 }}>
              <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                {dismissed.map(a => {
                  const expanded = expandedDismissedIds.has(a.id)
                  return (
                    <li
                      key={a.id}
                      style={{
                        background: dark
                          ? 'linear-gradient(180deg, rgba(52,50,45,0.9) 0%, rgba(46,44,40,0.9) 100%)'
                          : 'linear-gradient(180deg, #F0EDE6 0%, #EBE8E1 100%)',
                        borderRadius: 6,
                        boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.3)' : 'rgba(255,255,255,0.8)'),
                        padding: '6px 8px',
                        marginBottom: 4,
                        opacity: 0.8,
                      }}
                    >
                      <div 
                        onClick={() => toggleDismissedExpand(a.id)}
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: 6,
                          cursor: 'pointer',
                        }}
                      >
                        <span style={{ fontSize: 10, fontWeight: 700, color: pal.faint }}>{a.kind}</span>
                        <span style={{ fontSize: 10, color: pal.faint }}>{fmtTime(a.at)}</span>
                        {a.pluginHint !== undefined && (
                          <span style={{ fontSize: 9.5, color: pal.faint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint}</span>
                        )}
                        <span style={{ fontSize: 9, color: pal.faint, marginLeft: 'auto' }}>
                          {expanded ? '▾' : '▸'}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); onRestore(a.id) }}
                          title={t('alerts.restoreHint')}
                          style={{
                            border: '1px solid ' + pal.borderSoft,
                            background: 'transparent',
                            color: pal.muted,
                            borderRadius: 4,
                            padding: '0 6px',
                            cursor: 'pointer',
                            fontSize: 9,
                            flexShrink: 0,
                          }}
                        >
                          {t('alerts.restore')}
                        </button>
                      </div>
                      {expanded && (
                        <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid ' + pal.borderSoft }}>
                          <div style={{ fontSize: 10.5, color: pal.muted, wordBreak: 'break-word' }}>{a.message}</div>
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          )}
        </div>
      )}
      </div>
    </aside>
  )
}

/**
 * 会话头部盾牌。props 由槽渲染器传入（含 t 翻译函数；owner share 为空，本组件自给自足）。
 */
export function Shield(props: { t?: T } & Record<string, unknown>): ReactNode {
  const t = typeof props.t === 'function' ? props.t : zhT
  injectScrollbarStyle()
  const [snap, setSnap] = useState<ShieldSnapshotWire | null>(null)
  const [open, setOpen] = useState(false)
  const [loadedAt, setLoadedAt] = useState(0)
  const [toggleMsg, setToggleMsg] = useState<string | null>(null)
  const [toggling, setToggling] = useState(false)
  const [dark, setDark] = useState<boolean>(() => isDark())
  const [helpOpen, setHelpOpen] = useState(false)
  const [alarmPanelOpen, setAlarmPanelOpen] = useState(false)
  const [panelHovered, setPanelHovered] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const panelRef = useRef<HTMLDivElement | null>(null)
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
    const timer = window.setInterval(() => { 
      void load()
      setDark(isDark())  // 每次轮询也检查主题变化
    }, POLL_MS)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [])

  // 监听主题变化：MutationObserver 监听 data-ds-dark-theme 属性变化
  useEffect(() => {
    if (typeof document === 'undefined' || !document.body) return
    
    const update = (): void => setDark(isDark())
    
    // 监听 body 属性变化
    const observer = new MutationObserver(update)
    observer.observe(document.body, { 
      attributes: true, 
      attributeFilter: ['data-ds-dark-theme'] 
    })
    
    // 同时监听系统配色变化（作为后备）
    let mq: MediaQueryList | null = null
    if (typeof matchMedia !== 'undefined') {
      mq = matchMedia('(prefers-color-scheme: dark)')
      mq.addEventListener('change', update)
    }
    
    return () => {
      observer.disconnect()
      if (mq) mq.removeEventListener('change', update)
    }
  }, [])

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      const inRoot = rootRef.current !== null && rootRef.current.contains(e.target as Node)
      const inPanel = panelRef.current !== null && panelRef.current.contains(e.target as Node)
      if (!inRoot && !inPanel) setOpen(false)
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

  // 忽略/恢复：只改 vet 的内存聚合（不删记录、不碰插件），下一轮轮询即生效。
  const postAlarmAction = async (url: string, id: string): Promise<void> => {
    try {
      await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id }),
      })
      loadRef.current()
    } catch {
      // 路由暂不可用：轮询会自动带回原状
    }
  }
  const dismissAlarm = (id: string): void => { void postAlarmAction('/vet/dismiss', id) }
  const restoreAlarm = (id: string): void => { void postAlarmAction('/vet/restore', id) }

  // 浅色模式下调整颜色以保证在半透明玻璃背景上的对比度
  const pal = adjustForLightMode(dark ? MD : M, dark)
  const level = snap?.level ?? 'green'
  const color = pal[COLOR[level]]
  const statusLabel = t('status.' + level)
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan
  const metrics = snap?.metrics
  const guard = snap?.runtimeGuard ?? 'off'
  const stats = snap?.stats

  // 「?」右侧介绍栏：悬停 400ms 或点击打开；弹层内部移动不误关（容器级 mouseleave 才关）。
  const cancelHelpClose = (): void => {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current)
      closeTimer.current = null
    }
  }
  const scheduleHelpClose = (): void => {
    cancelHelpClose()
    // M6：关闭延迟必须 > 打开延迟(400ms)——鼠标从按钮移向介绍栏的途中会短暂离开
    // root（mouseleave 触发），若关闭太快会先关后开造成闪烁。600ms 足够穿越间隔，
    // 且进入介绍栏（root 子元素）时 onMouseEnter 会 cancelHelpClose 取消关闭。
    closeTimer.current = window.setTimeout(() => setHelpOpen(false), 600)
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
    setHelpOpen(v => {
      // 互斥：打开帮助窗口时关闭报警窗口
      if (!v) setAlarmPanelOpen(false)
      return !v
    })
  }

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
          background: open ? (dark ? CARD_BG_DARK : CARD_BG_LIGHT) : 'transparent',
          cursor: 'pointer',
          borderRadius: 8,
          boxShadow: open ? 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)') : undefined,
          transition: 'background 120ms ease',
        }}
      >
        <ShieldIcon level={level} color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: pal.muted, fontWeight: 600, lineHeight: 1 }}
            title={t('ram.hint')}
          >
            RAM {fmtRam(metrics.rssMb + metrics.mcpRssMb + (metrics.vetRssMb ?? 0))}
          </span>
        )}
        {count > 0 && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color,
              background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
              borderRadius: 9,
              padding: '1px 5px',
              boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
              lineHeight: 1.4,
              minWidth: 18,
              textAlign: 'center',
            }}
          >
            {count}
          </span>
        )}
      </button>

      {open && createPortal(
        <div
          ref={panelRef}
          onMouseEnter={cancelHelpClose}
          onMouseLeave={scheduleHelpClose}
          style={{
            position: 'fixed',
            top: 56,
            left: 320,
            zIndex: 1000,
          }}
        >
          <div 
            style={{...panelStyle(pal, dark), position: 'relative', overflowY: 'auto'}}
            role="dialog" 
            aria-label={t('panel.label')}
            onMouseEnter={() => setPanelHovered(true)}
            onMouseLeave={() => setPanelHovered(false)}
          >
          {/* Crystal Edge: 渐变边框层 */}
          <div style={{
            position: 'absolute',
            inset: 0,
            borderRadius: 12,
            padding: 2,
            background: dark
              ? 'linear-gradient(135deg, rgba(255,255,255,0.5), rgba(255,255,255,0.05) 40%, rgba(255,255,255,0.05) 60%, rgba(255,255,255,0.4))'
              : 'linear-gradient(135deg, rgba(255,255,255,0.9), rgba(255,255,255,0.2) 40%, rgba(255,255,255,0.2) 60%, rgba(255,255,255,0.8))',
            WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
            WebkitMaskComposite: 'xor',
            maskComposite: 'exclude',
            pointerEvents: 'none',
            zIndex: 10,
            transition: 'opacity 0.5s ease',
            opacity: panelHovered ? 1 : 0.7,
          }} />
          {/* Crystal Edge: 顶部高光线条 */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: 0.5,
            background: dark
              ? 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)'
              : 'linear-gradient(90deg, transparent, rgba(255,255,255,0.72), transparent)',
            pointerEvents: 'none',
            zIndex: 10,
          }} />
          {/* Mirror Sheen: 散光层（默认）→ 聚光层（hover） */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            background: 'linear-gradient(135deg, transparent 20%, rgba(255,255,255,0.03) 35%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 65%, transparent 80%)',
            pointerEvents: 'none',
            zIndex: 5,
            transition: 'opacity 0.6s ease',
            opacity: panelHovered ? 0 : 0.5,
          }} />
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            background: 'linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12) 50%, transparent 60%)',
            pointerEvents: 'none',
            zIndex: 5,
            transition: 'opacity 0.6s ease',
            opacity: panelHovered ? 0.5 : 0,
          }} />
          {/* 顶部状态色带 */}
          <div style={{
            height: 3,
            borderRadius: '10px 10px 0 0',
            background: level === 'green'
              ? 'linear-gradient(90deg, ' + pal.sage + ', ' + pal.sage + '88)'
              : level === 'yellow'
              ? 'linear-gradient(90deg, ' + pal.ochre + ', ' + pal.ochre + '88)'
              : 'linear-gradient(90deg, ' + pal.rose + ', ' + pal.rose + '88)',
            marginBottom: 10,
          }} />
          {/* 头部 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13.5, letterSpacing: '0.02em' }}>vet {statusLabel}</span>
            <button
              type="button"
              onClick={() => {
                setAlarmPanelOpen(v => !v)
                // 互斥：打开报警窗口时关闭帮助窗口
                if (!alarmPanelOpen) setHelpOpen(false)
              }}
              style={{
                marginLeft: 'auto',
                fontSize: 11,
                color: alarmPanelOpen ? pal.ink : pal.muted,
                background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
                border: 'none',
                borderRadius: 9,
                boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
                padding: '1px 8px',
                cursor: 'pointer',
                transition: 'all 120ms ease',
              }}
              title={count > 0 ? '查看报警详情' : '暂无报警'}
            >
              {count} {t('alerts.count')}
            </button>
          </div>
          <div style={{ color: pal.muted, marginTop: 5 }}>
            {level === 'yellow'
              ? (alarms.length > 0 ? t('level.yellowAlarm') : t('level.yellowScan'))
              : t('level.' + level)}
          </div>

          {/* 黄灯且无报警：唯一来源是最近扫描 suspicious → 直接展示预警详情（这就是可点的「详情」） */}
          {level === 'yellow' && alarms.length === 0 && lastScan !== undefined && (
            <div style={{
              marginTop: 8,
              background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
              borderRadius: 8,
              borderLeft: '3px solid transparent',
              borderImage: 'linear-gradient(180deg, ' + pal.ochre + ', ' + pal.ochre + '44) 1',
              boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
              padding: '8px 10px',
            }}>
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
                <Metric pal={pal} dark={dark} label={t('metric.total')} value={Math.round(metrics.rssMb + metrics.mcpRssMb + (metrics.vetRssMb ?? 0)) + ' MB'} hint={t('metric.totalHint')} />
                <Metric pal={pal} dark={dark} label={t('metric.heap')} value={Math.round(metrics.heapUsedMb) + ' / ' + Math.round(metrics.heapTotalMb) + ' MB'} hint={t('metric.heapHint')} />
                <Metric pal={pal} dark={dark} label={t('metric.native')} value={Math.round(metrics.externalMb) + ' MB'} hint={t('metric.nativeHint')} />
                <Metric pal={pal} dark={dark} label={t('metric.other')} value={Math.round(Math.max(0, metrics.rssMb - metrics.heapUsedMb - metrics.externalMb)) + ' MB'} hint={t('metric.otherHint')} />
                <Metric pal={pal} dark={dark} label={t('metric.mcp')} value={Math.round(metrics.mcpRssMb) + ' MB · ' + metrics.mcpCount + ' ' + t('metric.mcpUnit')} hint={t('metric.mcpHint')} />
                <Metric pal={pal} dark={dark} label={t('metric.vet')} value={Math.round(metrics.vetRssMb ?? 0) + ' MB · ' + (metrics.vetCount ?? 0) + ' ' + t('metric.vetUnit')} hint={t('metric.vetHint')} />
              </div>
              <GroupLabel pal={pal}>{t('metrics.runtime')}</GroupLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric pal={pal} dark={dark} label={t('metric.cpu')} value={metrics.cpuPct + '%'} />
                <Metric pal={pal} dark={dark} label={t('metric.ioRead')} value={metrics.ioReadMb + ' MB'} />
                <Metric pal={pal} dark={dark} label={t('metric.ioWrite')} value={metrics.ioWriteMb + ' MB'} />
                <Metric pal={pal} dark={dark} label={t('metric.children')} value={metrics.childCount >= 0 ? String(metrics.childCount) : '—'} />
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
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
            borderRadius: 8,
            boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
            padding: '8px 10px',
          }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? pal.sage : pal.faint, display: 'inline-block' }} />
            <span style={{ fontWeight: 700, marginLeft: 8 }}>{guard === 'watch' ? t('guard.on') : t('guard.off')}</span>
            {guard === 'off' ? (
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
            ) : (
              <button
                type="button"
                disabled={toggling}
                onClick={() => { void toggleGuard(false) }}
                style={{
                  marginLeft: 'auto',
                  border: 'none',
                  background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
                  color: pal.muted,
                  borderRadius: 7,
                  boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
                  padding: '3px 14px',
                  fontSize: 11.5,
                  fontWeight: 700,
                  cursor: toggling ? 'default' : 'pointer',
                  opacity: toggling ? 0.6 : 1,
                }}
              >
                {toggling ? t('guard.writing') : t('guard.disable')}
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
                boxShadow: dark ? undefined : 'inset 0 1px 0 rgba(255, 255, 255, 1)',
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
              <div style={{
                background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
                borderRadius: 8,
                boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
                padding: '7px 10px',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? pal.sage : lastScan.verdict === 'suspicious' ? pal.ochre : pal.rose }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: pal.faint }}>{lastScan.staticScore} {t('points')}</span>
              </div>
            </>
          )}

          {/* 0.1.20：防御统计——让用户知道"被保护了多少次"（始终显示，0 也展示） */}
          {stats !== undefined && (
            <>
              <SectionLabel pal={pal}>{t('stats.title')}</SectionLabel>
              <div style={{
                background: dark ? CARD_BG_DARK : CARD_BG_LIGHT,
                borderRadius: 8,
                boxShadow: 'inset 0 1px 0 ' + (dark ? 'rgba(255,255,255,0.4)' : 'rgba(255,255,255,1)'),
                padding: '8px 10px',
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: 8,
                textAlign: 'center',
              }}>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: pal.sage }}>{stats.scannedCount}</div>
                  <div style={{ fontSize: 10, color: pal.faint, marginTop: 2 }}>{t('stats.scanned')}</div>
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: pal.ochre }}>{stats.alarmsRecorded}</div>
                  <div style={{ fontSize: 10, color: pal.faint, marginTop: 2 }}>{t('stats.alarms')}</div>
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: pal.rose }}>{stats.blockedCount}</div>
                  <div style={{ fontSize: 10, color: pal.faint, marginTop: 2 }}>{t('stats.blocked')}</div>
                </div>
              </div>
            </>
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
                // 浅色模式下用更深的颜色保证在玻璃背景上的可见性
                color: dark ? pal.muted : '#4A4640',
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

        {helpOpen && <VetIntroPanel pal={pal} width={340} t={t} dark={dark} />}
        {alarmPanelOpen && <VetAlarmPanel pal={pal} width={340} t={t} alarms={alarms} dismissed={snap?.dismissed ?? []} dark={dark} onDismiss={dismissAlarm} onRestore={restoreAlarm} />}
        </div>
        ,
        document.body,
      )}
    </div>
  )
}
