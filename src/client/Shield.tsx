/**
 * vet 盾牌状态灯（D22）：会话头部动作区的守护指示器。
 * 数据：轮询宿主 webServer /vet/status.json（5s）。alarm-only：面板只展示与建议，
 * 唯一动作是「开启运行时守卫」按钮——用户主动点击，vet 按其指令写自己的配置（重启生效）。
 * 设计：莫兰迪色系（暖灰底 + 鼠尾草绿/燕麦赭石/灰玫瑰/雾蓝），纯静态 inline 样式，无动画无库。
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
  lastScan?: { pluginName: string; verdict: string; staticScore: number }
  runtimeGuard?: 'off' | 'watch'
  metrics?: VetMetricsWire
}

const POLL_MS = 5000

/** 莫兰迪色系（暖灰底 + 低饱和尘色调）。 */
const M = {
  sage: '#7E9A7C',     // 鼠尾草绿：守护
  ochre: '#B39263',    // 燕麦赭石：警告
  rose: '#A87171',     // 灰玫瑰：风险
  slate: '#6E7E99',    // 雾蓝：主按钮
  ink: '#4B4A45',      // 墨色：主文本
  muted: '#837D73',    // 灰褐：次文本
  faint: '#A39D90',    // 浅褐：弱文本
  bg: '#F1EEE7',       // 暖米：面板底
  card: '#E8E4DA',     // 暖灰：卡片
  cardSoft: '#EDEAE2', // 更浅卡片
  border: '#D8D2C4',   // 暖灰边框
  borderSoft: '#E0DBCD',
}

const COLOR: Record<'green' | 'yellow' | 'red', string> = {
  green: M.sage,
  yellow: M.ochre,
  red: M.rose,
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

/** 「?」悬停提示：插件简介 + 版本 + 守卫代价。 */
const GUARD_HELP = [
  '@jieai/dsh-plugin-vet v' + (typeof __VET_VERSION__ === 'string' ? __VET_VERSION__ : '0.1.0'),
  'DSH 插件信任流水线：静态规则判定 + LLM 审计 + 运行时守卫（T1 哨兵 / T2 钩子），只报警不代劳。',
  '',
  '开启运行时守卫的代价：',
  '· 哨兵子进程约占 10-30 MB 内存 + 轻量轮询；',
  '· T2 钩子使文件/子进程调用开销增加约 5%（热点场景更高）。',
  '写入配置后需重启 dsh web 生效。',
].join('\n')

const panelStyle: CSSProperties = {
  position: 'absolute',
  top: 'calc(100% + 6px)',
  right: 0,
  zIndex: 1000,
  width: 340,
  maxHeight: 500,
  overflow: 'auto',
  background: M.bg,
  border: `1px solid ${M.border}`,
  borderRadius: 12,
  boxShadow: 'var(--dsw-shadow-lv2, 0 10px 28px rgba(74,70,60,0.22))',
  fontSize: 12,
  color: M.ink,
  padding: '14px 14px 10px',
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
    <div style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: M.faint, margin: '12px 0 6px', fontWeight: 700 }}>
      {children}
    </div>
  )
}

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }): ReactNode {
  return (
    <div
      title={hint}
      style={{ background: M.card, borderRadius: 8, padding: '6px 10px', display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}
    >
      <span style={{ fontSize: 10, color: M.faint }}>{label}</span>
      <span style={{ fontSize: 12.5, fontWeight: 700, color: M.ink, wordBreak: 'break-word' }}>{value}</span>
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
          background: open ? M.cardSoft : 'transparent',
          cursor: 'pointer',
          borderRadius: 8,
          transition: 'background 120ms ease',
        }}
      >
        <ShieldIcon color={color} />
        {metrics !== undefined && metrics.rssMb > 0 && (
          <span
            style={{ fontSize: 10, color: M.muted, fontWeight: 600, lineHeight: 1 }}
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
              background: M.card,
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
          {/* 头部 */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'inline-block' }} />
            <span style={{ fontWeight: 800, fontSize: 13.5, letterSpacing: '0.02em' }}>vet {LABEL[level]}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: M.muted, background: M.card, borderRadius: 9, padding: '1px 8px' }}>
              {count} 条报警
            </span>
          </div>
          <div style={{ color: M.muted, marginTop: 5 }}>{LEVEL_TEXT[level]}</div>

          {/* 实时指标 */}
          {metrics !== undefined && (
            <>
              <SectionLabel>实时指标</SectionLabel>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                <Metric label="总内存" value={`${metrics.rssMb} MB`} hint="DSH 宿主 + 全部插件 + vet（同一进程，OS 仅见总量）" />
                <Metric label="V8 堆" value={`${metrics.heapUsedMb} / ${metrics.heapTotalMb} MB`} />
                <Metric label="原生 + 外部" value={`${metrics.externalMb} MB`} />
                <Metric label="MCP 服务" value={`${metrics.mcpRssMb} MB · ${metrics.mcpCount} 个`} hint="独立 MCP 服务进程（命令行含 mcp，如 dsh-malong-bridge），不在 DSH 进程内、单独统计" />
                <Metric label="CPU" value={`${metrics.cpuPct}%`} />
                <Metric label="I/O 读" value={`${metrics.ioReadMb} MB`} />
                <Metric label="I/O 写" value={`${metrics.ioWriteMb} MB`} />
                <Metric label="子进程" value={`${metrics.childCount >= 0 ? metrics.childCount : '—'}`} />
              </div>
              {metrics.fdCount >= 0 && (
                <div style={{ marginTop: 5, fontSize: 10.5, color: M.faint }}>
                  fd：{metrics.fdCount}
                </div>
              )}
            </>
          )}

          {/* 运行时守卫：状态 + ? 提示 */}
          <SectionLabel>运行时守卫</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', background: M.card, borderRadius: 8, padding: '8px 10px' }}>
            <span style={{ width: 8, height: 8, borderRadius: 4, background: guard === 'watch' ? M.sage : M.faint, display: 'inline-block' }} />
            <span style={{ fontWeight: 700, marginLeft: 8 }}>{guard === 'watch' ? '已开启（watch）' : '未开启'}</span>
            {guard === 'off' && (
              <button
                type="button"
                disabled={toggling}
                onClick={() => { void toggleGuard(true) }}
                style={{
                  marginLeft: 'auto',
                  border: 'none',
                  background: M.slate,
                  color: '#F6F4EE',
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
              title={GUARD_HELP}
              style={{
                marginLeft: 8,
                width: 16,
                height: 16,
                borderRadius: 8,
                background: M.cardSoft,
                color: M.faint,
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
            <div style={{ marginTop: 6, fontSize: 11, color: M.ochre }}>{toggleMsg}</div>
          )}

          {/* 最近扫描 */}
          {lastScan !== undefined && (
            <>
              <SectionLabel>最近扫描</SectionLabel>
              <div style={{ background: M.card, borderRadius: 8, padding: '7px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lastScan.pluginName}</span>
                <span style={{ marginLeft: 'auto', fontWeight: 700, color: lastScan.verdict === 'clean' ? M.sage : lastScan.verdict === 'suspicious' ? M.ochre : M.rose }}>
                  {lastScan.verdict}
                </span>
                <span style={{ fontSize: 11, color: M.faint }}>{lastScan.staticScore} 分</span>
              </div>
            </>
          )}

          {/* 报警列表 */}
          <SectionLabel>报警</SectionLabel>
          {alarms.length === 0 ? (
            <div style={{ color: M.faint, padding: '4px 2px' }}>暂无报警记录</div>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
              {alarms.slice(0, 8).map((a, i) => (
                <li
                  key={i}
                  style={{
                    background: M.card,
                    borderRadius: 8,
                    borderLeft: `3px solid ${a.severity === 'red' ? M.rose : a.severity === 'yellow' ? M.ochre : 'transparent'}`,
                    padding: '7px 10px',
                    marginBottom: 5,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, background: M.cardSoft, borderRadius: 4, padding: '1px 6px', color: M.muted }}>
                      {a.kind}
                    </span>
                    {a.pluginHint !== undefined && (
                      <span style={{ fontSize: 10.5, color: M.faint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{a.pluginHint}</span>
                    )}
                  </div>
                  <div style={{ marginTop: 3, wordBreak: 'break-word' }}>{a.message}</div>
                  {SUGGEST[a.kind] !== undefined && (
                    <div style={{ marginTop: 3, fontSize: 11, color: M.ochre }}>建议：{SUGGEST[a.kind]}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {/* 底部 */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: 12, paddingTop: 8, borderTop: `1px solid ${M.borderSoft}` }}>
            {loadedAt > 0 && (
              <span style={{ fontSize: 10.5, color: M.faint }}>更新于 {fmtTime(loadedAt)}</span>
            )}
            <button
              type="button"
              onClick={() => { loadRef.current() }}
              style={{
                marginLeft: 'auto',
                border: `1px solid ${M.border}`,
                background: 'transparent',
                color: M.muted,
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
