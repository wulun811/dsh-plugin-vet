/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一写路径是「开启运行时守卫 / 安全档位」按钮——用户主动点击，vet 按其指令写自己的配置。
 * P0 目录化改版：主题令牌在 theme.ts（OBSIDIAN MOSS GOLD 换肤），共用件在 components/，
 * 面板在 panels/；本文件只做编排（轮询/手势/写配置请求/布局定位）。
 * 布局（D2/P5 修订）：主弹层右锚定下挂于触发器，不随层开合移动；次级面板从主面板右缘
 * 滑出（不学 mock 的浏览器右缘抽屉）；插件详情为三级面板（P3 落地）。层间并排级联、
 * 与主面板等高、贴主面板外延，永不叠放（用户 2026-08-26：恢复旧版「贴外延」形态，
 * 取消整组左移）。
 * 主题检测：读 data-ds-dark-theme 属性（MutationObserver + 系统偏好后备）。
 * i18n：文案全部走 t(key)；t 缺失回退 zh。版本号由构建脚本注入（__VET_VERSION__）。
 */
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'
import { zh } from './i18n.ts'
import { cardBg, cardInset, getTheme, injectScrollbarStyle, isDark, panelStyle } from './theme.ts'
import type { T, ThemeTokens } from './theme.ts'
import { ShieldIcon } from './components/ShieldIcon.tsx'
import { GlassLayers, StatusBand } from './components/Glass.tsx'
import { SectionLabel, GroupLabel, Metric } from './components/primitives.tsx'
import { FoldSection } from './components/FoldSection.tsx'
import { RingSparkCard, trendOf } from './components/RingSparkCard.tsx'
import type { TrendKind } from './components/RingSparkCard.tsx'
import { fmtTime, fmtRam } from './utils/format.ts'
import { IntroPanel } from './panels/IntroPanel.tsx'
import { AlarmTimelinePanel } from './panels/AlarmTimelinePanel.tsx'
import { PluginsListPanel } from './panels/PluginsListPanel.tsx'
import { AuditCenterPanel } from './panels/AuditCenterPanel.tsx'
import { PluginDetailPanel } from './panels/PluginDetailPanel.tsx'
import { isShieldSnapshotShape } from '../guard/shield-shape.ts'
import type { ShieldSnapshotWire } from './types.ts'

/** wire 类型从 types.ts 再导出（历史导入路径兼容）。 */
export type { ShieldSnapshotWire, VetAlarmWire, VetMetricsWire, VetStatsWire } from './types.ts'
/** 旧调色板类型名兼容别名。 */
export type { MorandiPalette } from './theme.ts'

/** 主弹层宽度（用户反馈 2026-08-25：mock 的 420 太宽，回到原 340 紧凑宽）。 */
const PANEL_W = 340

/** 次级/三级面板统一宽度（与主面板同宽；层间并排级联，永不叠放）。 */
const SUB_W = 340

/** L2 次级面板种类（D2/D7）：时间线 / 审计&蜜罐 / 最近插件 / 关于；插件详情是独立 L3。 */
type L2Kind = 'timeline' | 'audit' | 'plugins' | 'about'

/** 复合卡趋势窗口样本上限（≈64 × 5s ≈ 5 分钟；P2 切服务端 history 后保留为后备）。 */
const HIST_CAP = 64

/** 显示用参考线（D4）：仅用于画环与危险染色，不参与任何执法判断。
 * 内存环：3.5GB = 总占用近似上限（Node/V8 默认堆上限约 2GB + 原生/子进程开销；
 * 官方讨论观测 OOM 崩溃在堆 2.2GB、总占用 3GB+，无配置化硬上限）——
 * 环填充 = 跨进程总占用相对该近似上限的比值。 */
const SOFT_MEM_MB = 3584
const SOFT_FD = 1024

const POLL_MS = 5000

/** t 缺失时的回退：zh 词典直查。 */
const zhT: T = key => (zh as Record<string, string>)[key] ?? key

/** 盾牌等级 → 令牌状态色字段。 */
const COLOR: Record<'green' | 'yellow' | 'red', keyof ThemeTokens> = {
  green: 'sage',
  yellow: 'ochre',
  red: 'rose',
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
  const [tierMsg, setTierMsg] = useState<string | null>(null)
  const [tierSaving, setTierSaving] = useState(false)
  const [savingTier, setSavingTier] = useState<'standard' | 'hardened' | 'paranoid' | null>(null)
  /** 0.3.1：守卫/档位写入后服务端返回的即时防御等级——覆盖快照徽标
   * （进程内档位预设随 DSH 重载展开前，快照仍是旧值，徽标必须展示已写入的档位）。 */
  const [tierOverride, setTierOverride] = useState<string | null>(null)
  const [tierOpen, setTierOpen] = useState(false)
  const [dark, setDark] = useState<boolean>(() => isDark())
  /** L2 次级面板（层栈 D2/D7）：单状态天然互斥；null = 全关。 */
  const [l2, setL2] = useState<L2Kind | null>(null)
  /** L3 插件详情（唯一三级面板）：从任意层点插件名推入。 */
  const [detail, setDetail] = useState<{ name: string } | null>(null)
  const [panelHovered, setPanelHovered] = useState(false)
  /** 主弹层右锚定位置（D2）：贴触发器右缘，防溢出 clamp。
   * 层栈不依赖此处的任何数值：层以左:'100%' 相对定位（= 根容器收缩宽度 =
   * 主面板真实渲染宽），与旧版 left:calc(100%+8px) 同构，免疫宿主 box-sizing/padding。 */
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 56, left: 320 })
  /** 折叠区开合（D3）：undefined = 跟随自动策略（green 收起 / yellow·red 展开）。 */
  const [folds, setFolds] = useState<{ mem?: boolean; run?: boolean }>({})
  const rootRef = useRef<HTMLDivElement | null>(null)
  const panelRef = useRef<HTMLDivElement | null>(null)
  const loadRef = useRef<() => void>(() => {})
  /** 开关成功提示的自动消失定时器（「开启/关闭完毕！」2s 后消失，用户 2026-08-26 反馈）。 */
  const doneTimer = useRef<number | null>(null)
  const clearDone = (): void => {
    if (doneTimer.current !== null) {
      window.clearTimeout(doneTimer.current)
      doneTimer.current = null
    }
  }
  /** 指标历史环形缓冲（复合卡火花线；进程内，刷新即清零可接受）。 */
  const histRef = useRef<{ m: number[]; c: number[]; f: number[] }>({ m: [], c: [], f: [] })

  useEffect(() => {
    let alive = true
    // round-22：轮询竞态序号——5s 间隔 + 手动刷新都可能让两个请求同时在途；慢的旧响应
    // 若晚于新响应到达会整体覆盖新快照（安全指示器回退到陈旧状态，与「宁可保留上次
    // 状态」的语义冲突）。响应落地前校验自己仍是「最新一次发起的请求」，过期即弃。
    let seq = 0
    const load = async (): Promise<void> => {
      const mySeq = ++seq
      try {
        const res = await fetch('/vet/status.json', { cache: 'no-store' })
        if (!alive) return
        const text = await res.text()
        const parsed: unknown = JSON.parse(text)
        // round-21（安全信号完整性）：可解析的**非快照 JSON 信封**（SEC-6 跨源 403
        // {ok:false,note}、宿主错误信封等）若直接 setSnap，会把旧快照整体覆盖成缺省
        // 形状——渲染层 `??` 回退把「数据拿不到」画成**假全绿 0 报警**（对安全插件是
        // 最坏静默）。形状谓词与服务端共用单源（guard/shield-shape）。校验不过 =
        // 与 fetch 失败同级：保留上次状态，绝不覆盖。
        if (!isShieldSnapshotShape(parsed)) return
        if (mySeq !== seq) return // 已有更新的请求发起——过期响应丢弃，不让旧数据覆盖新数据
        setSnap(parsed as ShieldSnapshotWire)
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

  // 右锚定定位（D2/P5 修订）：主面板始终贴触发器右缘（仅自身做视口 clamp），
  // 不随层开合移动；层栈由渲染层以 left:'100%' 相对定位（见层栈注释），
  // 浏览器按主面板真实渲染宽度算右缘——与旧版 left:calc(100%+8px) 同构。窗口尺寸变化时重算。
  useLayoutEffect(() => {
    if (!open) return
    const update = (): void => {
      const r = rootRef.current?.getBoundingClientRect()
      if (r === undefined || r === null) return
      const vw = typeof window !== 'undefined' ? window.innerWidth : 1280
      const left = Math.min(Math.max(8, r.right - PANEL_W), Math.max(8, vw - PANEL_W - 8))
      const top = Math.min(r.bottom + 8, Math.max(8, (typeof window !== 'undefined' ? window.innerHeight : 800) - 120))
      setPos({ top, left })
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [open])

  // 指标历史采样：每次快照追加（环形 64 点），供复合卡火花线与趋势分档。
  useEffect(() => {
    const m = snap?.metrics
    if (m === undefined) return
    const push = (arr: number[], v: number): void => {
      if (!Number.isFinite(v)) return
      arr.push(v)
      if (arr.length > HIST_CAP) arr.shift()
    }
    push(histRef.current.m, m.rssMb + m.mcpRssMb + (m.vetRssMb ?? 0))
    push(histRef.current.c, m.cpuPct)
    if (m.fdCount >= 0) push(histRef.current.f, m.fdCount)
  }, [snap])

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
    clearDone()
    try {
      const res = await fetch('/vet/runtime-guard', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ enable }),
      })
      const body = await res.json() as { ok?: boolean; note?: string; profile?: string }
      if (typeof body.profile === 'string') setTierOverride(body.profile)
      if (body.ok === true) {
        // 即时生效完成 → 「开启/关闭完毕！」短暂展示 2s 后自动消失（按钮期间已显示「开启中……」）。
        setToggleMsg(t(enable ? 'guard.doneOn' : 'guard.doneOff'))
        doneTimer.current = window.setTimeout(() => setToggleMsg(null), 2000)
      } else {
        // 失败路径保留服务端 note（红色，不自动消失，需阅读后处理）
        const note = typeof body.note === 'string' && body.note !== '' ? ' — ' + body.note : ''
        setToggleMsg(t('guard.writeFailed') + note)
      }
    } catch {
      setToggleMsg(t('guard.requestFailed'))
    } finally {
      setToggling(false)
    }
  }

  // 安全档位切换：写入 profile patch（保留其他配置键），重启后生效。
  const setTier = async (tier: 'standard' | 'hardened' | 'paranoid'): Promise<void> => {
    setTierSaving(true)
    setSavingTier(tier)
    setTierMsg(null)
    try {
      const res = await fetch('/vet/profile', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tier }),
      })
      const body = await res.json() as { ok?: boolean; note?: string; profile?: string }
      if (typeof body.profile === 'string') setTierOverride(body.profile)
      if (body.ok === true) {
        setTierMsg(t('profile.written'))
      } else {
        const note = typeof body.note === 'string' && body.note !== '' ? ' — ' + body.note : ''
        setTierMsg(t('profile.writeFailed') + note)
      }
    } catch {
      setTierMsg(t('guard.requestFailed'))
    } finally {
      setTierSaving(false)
      setSavingTier(null)
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

  // moss 主题令牌（深/浅双板自包含，不再需要浅色二次修正）
  const tok = getTheme(dark)
  const level = snap?.level ?? 'green'
  const color = tok[COLOR[level]]
  const statusLabel = t('status.' + level)
  const count = snap?.alarmCount ?? 0
  const alarms = snap?.alarms ?? []
  const lastScan = snap?.lastScan
  const metrics = snap?.metrics
  const guard = snap?.runtimeGuard ?? 'off'
  const profile = tierOverride ?? snap?.profile ?? 'standard'
  const stats = snap?.stats

  // 「?」介绍面板：纯点击开合（原 400ms hover 弹出被用户反馈「经过就弹」不舒服，
  // 2026-08-27 改为与时间线/审计一致的点开/再点关；Esc 与主面板收起同样能关）。
  const toggleL2 = (kind: L2Kind): void => {
    setL2(v => (v === kind ? null : kind))
  }

  // Esc：逐层退回（L3 → L2 → 关主面板）——P5 a11y 提前落地。
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== 'Escape') return
      if (detail !== null) setDetail(null)
      else if (l2 !== null) setL2(null)
      else setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, l2, detail])

  // 面板收起时同步关闭所有层。
  useEffect(() => {
    if (!open) { setL2(null); setDetail(null) }
  }, [open])

  // 卸载时清理定时器。
  useEffect(() => () => {
    clearDone()
  }, [])

  return (
    <div
      ref={rootRef}
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
          background: open ? cardBg(dark) : 'transparent',
          cursor: 'pointer',
          borderRadius: 8,
          boxShadow: open ? cardInset(dark) : undefined,
          transition: 'background 120ms ease',
        }}
      >
        <ShieldIcon level={level} color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: tok.muted, fontWeight: 600, lineHeight: 1 }}
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
              background: cardBg(dark),
              border: '1px solid ' + (level === 'red' ? tok.borderDanger : level === 'yellow' ? tok.borderWarn : tok.borderSoft),
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

      {open && createPortal(
        <div
          ref={panelRef}
          className="vet-panel-root"
          style={{
            position: 'fixed',
            top: pos.top,
            left: pos.left,
            zIndex: 1000,
          }}
        >
          <div
            style={{...panelStyle(tok, PANEL_W), position: 'relative', overflowY: 'auto'}}
            role="dialog"
            aria-label={t('panel.label')}
            onMouseEnter={() => setPanelHovered(true)}
            onMouseLeave={() => setPanelHovered(false)}
          >
          <GlassLayers tok={tok} hovered={panelHovered} />
          {/* 顶部状态色带 */}
          <StatusBand tok={tok} level={level} />

          {/* 头部 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, boxShadow: `0 0 10px ${color}55`, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13.5, letterSpacing: '0.02em', color: tok.ink }}>vet {statusLabel}</span>
            <button
              type="button"
              onClick={() => toggleL2('timeline')}
              aria-expanded={l2 === 'timeline'}
              style={{
                marginLeft: 'auto',
                fontSize: 11,
                color: l2 === 'timeline' ? tok.ink : tok.muted,
                background: cardBg(dark),
                border: `1px solid ${l2 === 'timeline' ? tok.sage : tok.borderSoft}`,
                borderRadius: 9,
                boxShadow: cardInset(dark),
                padding: '1px 8px',
                cursor: 'pointer',
                transition: 'all 120ms ease',
              }}
              title={count > 0 ? '查看报警详情' : '暂无报警'}
            >
              {count} {t('alerts.count')} →
            </button>
          </div>
          <div style={{ color: tok.muted, marginTop: 5 }}>
            {level === 'yellow'
              ? (alarms.length > 0 ? t('level.yellowAlarm') : t('level.yellowScan'))
              : t('level.' + level)}
          </div>

          {/* 黄灯且无报警：唯一来源是最近扫描 suspicious → 直接展示预警详情（这就是可点的「详情」） */}
          {level === 'yellow' && alarms.length === 0 && lastScan !== undefined && (
            <div style={{
              marginTop: 8,
              background: cardBg(dark),
              borderRadius: 8,
              borderLeft: `3px solid ${tok.ochre}`,
              borderRight: '1px solid ' + tok.borderWarn,
              borderTop: '1px solid ' + tok.borderWarn,
              borderBottom: '1px solid ' + tok.borderWarn,
              boxShadow: cardInset(dark),
              padding: '8px 10px',
            }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: tok.ochre, letterSpacing: '0.02em' }}>
                {t('warn.title')}
              </div>
              <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: tok.ink }}>
                  {lastScan.pluginName}
                </span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: tok[COLOR[level]], flexShrink: 0 }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: tok.faint, flexShrink: 0 }}>{lastScan.staticScore} {t('points')}</span>
              </div>
              <div style={{ marginTop: 3, fontSize: 10.5, color: tok.faint }}>
                {lastScan.at !== undefined ? t('warn.scannedAt') + fmtTime(lastScan.at) + ' · ' : ''}
                {t('warn.body')}
              </div>
            </div>
          )}

          {/* 实时指标（P1）：三张环趋势复合卡（当前值+方向一卡读全）+ 两个折叠区收纳细节。
              软上限仅用于画环/染色（D4），不参与执法判断。 */}
          {metrics !== undefined && (() => {
            const totalMb = metrics.rssMb + metrics.mcpRssMb + (metrics.vetRssMb ?? 0)
            const fd = metrics.fdCount
            const memTrend = trendOf(histRef.current.m, 'rel')
            const cpuTrend = trendOf(histRef.current.c, 'abs')
            const fdTrend = trendOf(histRef.current.f, 'rel')
            const deltaText = (tr: { kind: TrendKind; label: string }): string =>
              tr.label !== '' ? tr.label : t('trend.stable')
            const memDanger = level === 'red' || totalMb >= SOFT_MEM_MB * 0.88
            const cpuDanger = level === 'red' || metrics.cpuPct >= 85
            const fdDanger = level === 'red' || (fd >= 0 && fd >= SOFT_FD * 0.88)
            // D3 默认态：green 收起 / yellow·red 展开；用户手动开合后以手动为准
            const memOpen = folds.mem ?? (level !== 'green')
            const runOpen = folds.run ?? (level !== 'green')
            const foldToggle = (key: 'mem' | 'run', cur: boolean): void => {
              setFolds(f => ({ ...f, [key]: !cur }))
            }
            // red 场景危险区配方：红调底色 + 危险描边 + 内发光
            const zone = level === 'red'
              ? {
                  background: `linear-gradient(180deg, rgba(28,14,14,0.55), rgba(18,10,10,0.4)), ${cardBg(dark)}`,
                  border: '1px solid ' + tok.borderDanger,
                  boxShadow: `inset 0 0 40px ${tok.glowDanger}, ${cardInset(dark)}`,
                }
              : {
                  background: cardBg(dark),
                  border: '1px solid ' + tok.borderSoft,
                  boxShadow: cardInset(dark),
                }
            return (
              <>
                <div style={{ display: 'flex', gap: 6, marginTop: 12 }}>
                  <RingSparkCard tok={tok} dark={dark} label={t('ring.memory')} center={fmtRam(totalMb)}
                    ringPct={(totalMb / SOFT_MEM_MB) * 100}
                    delta={{ kind: memTrend.kind, label: deltaText(memTrend) }}
                    trendPoints={histRef.current.m} danger={memDanger} hint={t('ring.memoryHint')} />
                  <RingSparkCard tok={tok} dark={dark} label={t('ring.cpu')} center={metrics.cpuPct + '%'}
                    ringPct={Math.min(100, metrics.cpuPct)}
                    delta={{ kind: cpuTrend.kind, label: deltaText(cpuTrend) }}
                    trendPoints={histRef.current.c} danger={cpuDanger} hint={t('ring.cpuHint')} />
                  <RingSparkCard tok={tok} dark={dark} label={t('ring.fd')}
                    center={fd >= 0 ? String(fd) : '—'}
                    ringPct={fd >= 0 ? (fd / SOFT_FD) * 100 : 0}
                    delta={{ kind: fdTrend.kind, label: deltaText(fdTrend) }}
                    trendPoints={histRef.current.f} danger={fdDanger} hint={t('ring.fdHint')} />
                </div>

                <FoldSection tok={tok} dark={dark} open={memOpen}
                  onToggle={() => foldToggle('mem', memOpen)}
                  title={t('fold.memory')}
                  summary={fmtRam(totalMb)}>
                  <div style={{ ...zone, borderRadius: 10, padding: 8 }}>
                    <GroupLabel pal={tok}>{t('metrics.memory')}</GroupLabel>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                      <Metric pal={tok} dark={dark} label={t('metric.total')} value={Math.round(totalMb) + ' MB'} hint={t('metric.totalHint')} />
                      <Metric pal={tok} dark={dark} label={t('metric.heap')} value={Math.round(metrics.heapUsedMb) + ' / ' + Math.round(metrics.heapTotalMb) + ' MB'} hint={t('metric.heapHint')} />
                      <Metric pal={tok} dark={dark} label={t('metric.native')} value={Math.round(metrics.externalMb) + ' MB'} hint={t('metric.nativeHint')} />
                      <Metric pal={tok} dark={dark} label={t('metric.other')} value={Math.round(Math.max(0, metrics.rssMb - metrics.heapUsedMb - metrics.externalMb)) + ' MB'} hint={t('metric.otherHint')} />
                      <Metric pal={tok} dark={dark} label={t('metric.mcp')} value={Math.round(metrics.mcpRssMb) + ' MB · ' + metrics.mcpCount + ' ' + t('metric.mcpUnit')} hint={t('metric.mcpHint')} />
                      <Metric pal={tok} dark={dark} label={t('metric.vet')} value={Math.round(metrics.vetRssMb ?? 0) + ' MB · ' + (metrics.vetCount ?? 0) + ' ' + t('metric.vetUnit')} hint={t('metric.vetHint')} />
                    </div>
                  </div>
                </FoldSection>

                <FoldSection tok={tok} dark={dark} open={runOpen}
                  onToggle={() => foldToggle('run', runOpen)}
                  title={t('fold.runtime')}
                  summary={'CPU ' + metrics.cpuPct + '%'}>
                  <div style={{ borderRadius: 10 }}>
                    <div style={{ ...zone, borderRadius: 10, padding: 8 }}>
                      <GroupLabel pal={tok}>{t('metrics.runtime')}</GroupLabel>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                        <Metric pal={tok} dark={dark} label={t('metric.cpu')} value={metrics.cpuPct + '%'} />
                        <Metric pal={tok} dark={dark} label={t('metric.ioRead')} value={metrics.ioReadMb >= 0 ? metrics.ioReadMb + ' MB' : '—'} />
                        <Metric pal={tok} dark={dark} label={t('metric.ioWrite')} value={metrics.ioWriteMb >= 0 ? metrics.ioWriteMb + ' MB' : '—'} />
                        <Metric pal={tok} dark={dark} label={t('metric.children')} value={metrics.childCount >= 0 ? String(metrics.childCount) : '—'} />
                      </div>
                    </div>
                    <div style={{ marginTop: 6, fontSize: 10.5, color: fdDanger ? tok.dangerBright : tok.faint, padding: '0 2px' }}>
                      {t('fd.label')}{fd >= 0 ? fd : '—'}{fdDanger ? ' · ' + t('fold.leakWarn') : ''}
                    </div>
                  </div>
                </FoldSection>
              </>
            )
          })()}

          {/* 运行时守卫：状态 + ? 提示 */}
          <SectionLabel pal={tok}>{t('guard.title')}</SectionLabel>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: cardBg(dark),
            border: '1px solid ' + tok.borderSoft,
            borderRadius: 8,
            boxShadow: cardInset(dark),
            padding: '8px 10px',
          }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? tok.sage : tok.faint, boxShadow: guard === 'watch' ? `0 0 8px ${tok.glow}` : undefined, display: 'inline-block' }} />
            <span style={{ fontWeight: 700, marginLeft: 8, color: tok.ink }}>{guard === 'watch' ? t('guard.on') : t('guard.off')}</span>
            <button
              type="button"
              onClick={() => { setTierOpen(v => !v) }}
              style={{
                marginLeft: 8,
                border: '1px solid ' + tok.border,
                borderRadius: 7,
                padding: '3px 10px',
                fontSize: 11.5,
                fontWeight: 700,
                cursor: 'pointer',
                background: cardBg(dark),
                color: tok.ink,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                whiteSpace: 'nowrap',
              }}
            >
              {t('profile.' + profile)}
              <span style={{ fontSize: 8, opacity: 0.8 }}>{tierOpen ? '▲' : '▼'}</span>
            </button>
            {guard === 'off' ? (
              <button
                type="button"
                disabled={toggling}
                onClick={() => { void toggleGuard(true) }}
                style={{
                  marginLeft: 'auto',
                  border: '1px solid rgba(60,100,60,0.35)',
                  background: `linear-gradient(180deg, ${tok.sage}, ${dark ? '#2a3a2a' : '#42603e'})`,
                  color: dark ? tok.ink : tok.onSlate,
                  borderRadius: 7,
                  padding: '3px 14px',
                  fontSize: 11.5,
                  fontWeight: 700,
                  cursor: toggling ? 'default' : 'pointer',
                  opacity: toggling ? 0.6 : 1,
                  boxShadow: '0 0 10px ' + tok.glow,
                }}
              >
                {toggling ? t('guard.togglingOn') : t('guard.enable')}
              </button>
            ) : (
              <button
                type="button"
                disabled={toggling}
                onClick={() => { void toggleGuard(false) }}
                style={{
                  marginLeft: 'auto',
                  border: '1px solid ' + tok.border,
                  background: cardBg(dark),
                  color: tok.muted,
                  borderRadius: 7,
                  boxShadow: cardInset(dark),
                  padding: '3px 14px',
                  fontSize: 11.5,
                  fontWeight: 700,
                  cursor: toggling ? 'default' : 'pointer',
                  opacity: toggling ? 0.6 : 1,
                }}
              >
                {toggling ? t('guard.togglingOff') : t('guard.disable')}
              </button>
            )}
            <span
              tabIndex={0}
              role="button"
              aria-label={t('guard.helpLabel')}
              onClick={() => toggleL2('about')}
              style={{
                marginLeft: 8,
                width: 16,
                height: 16,
                borderRadius: 8,
                background: tok.cardSoft,
                color: tok.faint,
                fontSize: 10.5,
                border: '1px solid ' + tok.border,
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                flexShrink: 0,
              }}
            >
              ?
            </span>
          </div>
          {toggleMsg !== null && (
            <div style={{ marginTop: 6, fontSize: 11, color: tok.ochre }}>{toggleMsg}</div>
          )}

          {/* 防御档位选择：收进守卫条（点徽标展开三档），说明在 ? 帮助面板 */}
          {tierOpen && (
            <div style={{
              marginTop: 6,
              background: cardBg(dark),
              border: '1px solid ' + tok.borderSoft,
              borderRadius: 8,
              boxShadow: cardInset(dark),
              padding: '8px 10px',
            }}>
              <div style={{ display: 'flex', gap: 6 }}>
                {(['standard', 'hardened', 'paranoid'] as const).map(tier => (
                  <button
                    key={tier}
                    type="button"
                    disabled={tierSaving}
                    onClick={() => { void setTier(tier) }}
                    style={{
                      flex: 1,
                      border: 'none',
                      borderRadius: 7,
                      padding: '5px 0',
                      fontSize: 11.5,
                      fontWeight: 700,
                      cursor: tierSaving ? 'default' : 'pointer',
                      background: tier === profile ? tok.slate : 'transparent',
                      color: tier === profile ? tok.onSlate : tok.muted,
                      boxShadow: tier === profile ? undefined : 'inset 0 0 0 1px ' + tok.borderSoft,
                      opacity: tierSaving ? 0.6 : 1,
                    }}
                  >
                    {savingTier === tier ? t('profile.writing') : t('profile.' + tier)}
                  </button>
                ))}
              </div>
              {tierMsg !== null && (
                <div style={{ marginTop: 6, fontSize: 11, color: tok.ochre }}>{tierMsg}</div>
              )}
            </div>
          )}

          {/* 最近扫描（D7：点击整块 → L2 最近插件列表；不再直跳详情） */}
          {lastScan !== undefined && (
            <>
              <SectionLabel pal={tok}>{t('scan.recent')}</SectionLabel>
              <div
                role="button"
                tabIndex={0}
                aria-expanded={l2 === 'plugins'}
                onClick={() => toggleL2('plugins')}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleL2('plugins') } }}
                title={t('plugins.title')}
                style={{
                  background: cardBg(dark),
                  border: `1px solid ${l2 === 'plugins' ? tok.sage : tok.borderSoft}`,
                  borderRadius: 8,
                  boxShadow: cardInset(dark),
                  padding: '7px 10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  cursor: 'pointer',
                }}
              >
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: tok.ink }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? tok.sage : lastScan.verdict === 'suspicious' ? tok.ochre : tok.rose }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: tok.faint }}>{lastScan.staticScore} {t('points')}</span>
                <span aria-hidden="true" style={{ fontSize: 10, color: tok.faint }}>→</span>
              </div>
            </>
          )}

          {/* 0.1.20：防御统计——让用户知道"被保护了多少次"（始终显示，0 也展示） */}
          {stats !== undefined && (
            <>
              <SectionLabel pal={tok}>{t('stats.title')}</SectionLabel>
              <div style={{
                background: cardBg(dark),
                border: '1px solid ' + tok.borderSoft,
                borderRadius: 10,
                boxShadow: cardInset(dark),
                padding: '8px 10px',
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: 8,
                textAlign: 'center',
              }}>
                <div>
                  <div style={{ fontSize: 22, fontWeight: 800, lineHeight: 1, color: tok.sage }}>{stats.scannedCount}</div>
                  <div style={{ fontSize: 10, color: tok.faint, marginTop: 2 }}>{t('stats.scanned')}</div>
                </div>
                <div>
                  <div style={{ fontSize: 22, fontWeight: 800, lineHeight: 1, color: tok.ochre }}>{stats.alarmsRecorded}</div>
                  <div style={{ fontSize: 10, color: tok.faint, marginTop: 2 }}>{t('stats.alarms')}</div>
                </div>
                <div>
                  <div style={{ fontSize: 22, fontWeight: 800, lineHeight: 1, color: tok.rose }}>{stats.blockedCount}</div>
                  <div style={{ fontSize: 10, color: tok.faint, marginTop: 2 }}>{t('stats.blocked')}</div>
                </div>
              </div>
            </>
          )}

          {/* 审计栏（P3，row13）：🍯蜜罐状态｜⏳待审｜🆕新装 → 整行打开审计&蜜罐中心。
              旧后端无 audit 字段时整行隐藏（向后兼容）。 */}
          {snap?.audit !== undefined && (() => {
            const a = snap.audit
            const pendingN = a.pendingAudits.length
            const freshN = a.newPlugins.length
            return (
              <button
                type="button"
                onClick={() => toggleL2('audit')}
                aria-expanded={l2 === 'audit'}
                style={{
                  marginTop: 10,
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontFamily: 'inherit',
                  fontSize: 11,
                  color: tok.faint,
                  background: 'transparent',
                  border: `1px solid ${l2 === 'audit' ? tok.sage : tok.borderSoft}`,
                  borderRadius: 9,
                  padding: '6px 12px',
                  cursor: 'pointer',
                  textAlign: 'left',
                }}
              >
                <span>🍯 {a.honeypot.armed ? (a.honeypot.touches > 0 ? t('bar.honey.triggered') + ` · ${a.honeypot.touches}` : t('bar.honey.armed')) : t('bar.honey.off')}</span>
                <span aria-hidden="true" style={{ color: tok.borderSoft }}>|</span>
                <span>⏳ {t('audit.pendingShort')} <b style={{ color: pendingN > 0 ? tok.ochre : tok.muted }}>{pendingN}</b></span>
                <span aria-hidden="true" style={{ color: tok.borderSoft }}>|</span>
                <span>🆕 {t('audit.newShort')} <b style={{ color: freshN > 0 ? tok.ochre : tok.muted }}>{freshN}</b></span>
                <span aria-hidden="true" style={{ marginLeft: 'auto', color: tok.faint }}>→</span>
              </button>
            )
          })()}

          {/* 底部（关于入口 = 守卫行的 ? 问号，footer 不再重复） */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: 12, paddingTop: 8, borderTop: '1px solid ' + tok.borderSoft }}>
            {loadedAt > 0 && (
              <span style={{ fontSize: 10.5, color: tok.faint }}>{t('footer.updated')}{fmtTime(loadedAt)}</span>
            )}
            <button
              type="button"
              onClick={() => { loadRef.current() }}
              style={{
                marginLeft: 'auto',
                border: '1px solid ' + tok.border,
                background: 'transparent',
                color: tok.muted,
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

        {/* —— 浮动卡（P4，mock 版式；随条件出现于主面板正下方，同宽不遮挡）—— */}
        {snap?.lastUpgradeDiff !== undefined && (() => {
          const d = snap.lastUpgradeDiff
          // 0.3.6：升级差分降档——info 蓝色（tok.info），red 组合保持 rose；yellow 仅兜底
          const sevColor = d.severity === 'red' ? tok.rose : d.severity === 'info' ? tok.info : tok.ochre
          return (
            <div
              role="button"
              tabIndex={0}
              onClick={() => setDetail({ name: d.plugin })}
              onKeyDown={(e) => { if (e.key === 'Enter') setDetail({ name: d.plugin }) }}
              title={t('detail.title')}
              style={{
                width: PANEL_W,
                marginTop: 12,
                borderRadius: 10,
                padding: '9px 12px',
                background: cardBg(dark),
                borderLeft: `3px solid ${sevColor}`,
                borderTop: `1px solid ${sevColor}44`,
                borderRight: `1px solid ${sevColor}44`,
                borderBottom: `1px solid ${sevColor}44`,
                boxShadow: cardInset(dark),
                cursor: 'pointer',
              }}
            >
              <div style={{ fontSize: 10.5, fontWeight: 700, color: sevColor, marginBottom: 5 }}>
                {t('diff.title')} · {d.plugin}{d.from !== null && d.to !== null ? ` · ${d.from} → ${d.to}` : ''}
              </div>
              {d.added.map((line, i) => (
                <div key={i} style={{ fontSize: 10.5, color: tok.muted, marginTop: 2 }}>＋{line}</div>
              ))}
            </div>
          )
        })()}
        {snap?.audit?.honeypot !== undefined && snap.audit.honeypot.touches > 0 && (
          <button
            type="button"
            onClick={() => {
              const last = snap.audit?.honeypot.lastTouch
              if (last !== undefined) setDetail({ name: last.plugin })
              else toggleL2('timeline')
            }}
            style={{
              width: PANEL_W,
              marginTop: 12,
              fontFamily: 'inherit',
              textAlign: 'left',
              borderRadius: 10,
              padding: '9px 12px',
              background: cardBg(dark),
              border: `1px solid ${tok.borderDanger}`,
              boxShadow: `inset 0 0 40px ${tok.glowDanger}, ${cardInset(dark)}`,
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: 10.5, fontWeight: 700, color: tok.dangerBright, marginBottom: 5 }}>
              {t('honeyalert.title')}
            </div>
            {snap.audit.honeypot.lastTouch !== undefined && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: tok.muted }}>
                  <span>@{(snap.audit.honeypot.lastTouch.plugin ?? '').replace(/^@/, '')}</span>
                  <span style={{ color: tok.faint }}>{fmtTime(snap.audit.honeypot.lastTouch.at)}</span>
                </div>
                <div style={{ fontSize: 10.5, color: tok.dangerBright, marginTop: 2, wordBreak: 'break-all' }}>
                  {snap.audit.honeypot.lastTouch.file}
                </div>
              </>
            )}
          </button>
        )}

        {/* —— 层栈（D2/D7/P5 收尾）：次级面板与主面板并排级联（无间隙，不悬浮）。
             定位恢复旧版同构：left:'100%'（根容器收缩宽度 = 主面板真实渲染宽）、
             top:0/bottom:0 等高——浏览器自算外缘，不依赖任何数值偏移，
             免疫宿主 box-sizing/padding 造成的宽度差；永不叠放。 —— */}
        {(() => {
          const hasL2 = l2 !== null
          // L3 槽位：紧跟 L2 右缘（紧贴）；L2 未开（浮动卡直推详情）时贴主面板右缘
          const xDetail = hasL2 ? 'calc(100% + ' + SUB_W + 'px)' : '100%'
          return (
            <>
              {l2 === 'timeline' && (
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: '100%', width: SUB_W, zIndex: 20 }}>
                  <AlarmTimelinePanel pal={tok} dark={dark} t={t}
                    alarms={alarms} dismissed={snap?.dismissed ?? []}
                    onDismiss={dismissAlarm} onRestore={restoreAlarm}
                    onBack={() => setL2(null)} onOpenPlugin={name => setDetail({ name })} />
                </div>
              )}
              {l2 === 'plugins' && (
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: '100%', width: SUB_W, zIndex: 20 }}>
                  <PluginsListPanel pal={tok} dark={dark} t={t}
                    plugins={snap?.audit?.plugins ?? []}
                    onBack={() => setL2(null)} onOpenPlugin={name => setDetail({ name })} />
                </div>
              )}
              {l2 === 'audit' && (
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: '100%', width: SUB_W, zIndex: 20 }}>
                  <AuditCenterPanel pal={tok} dark={dark} t={t}
                    audit={snap?.audit}
                    onBack={() => setL2(null)} onOpenPlugin={name => setDetail({ name })} />
                </div>
              )}
              {l2 === 'about' && (
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: '100%', width: SUB_W, zIndex: 20 }}>
                  <IntroPanel pal={tok} dark={dark} t={t} onBack={() => setL2(null)} />
                </div>
              )}
              {detail !== null && (
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: xDetail, width: SUB_W, zIndex: 30 }}>
                  <PluginDetailPanel pal={tok} dark={dark} t={t}
                    name={detail.name} onBack={() => setDetail(null)} />
                </div>
              )}
            </>
          )
        })()}
        </div>
        ,
        document.body,
      )}
    </div>
  )
}
