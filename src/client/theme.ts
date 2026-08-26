/**
 * vet 盾牌主题令牌（P0 目录化 + OBSIDIAN MOSS GOLD 换肤）。
 * 设计稿：docs/local/vet-panel-obsidian-moss-gold (XX).html（**仅深色样例**）——
 * 深色板按稿内 :root 配方翻译；浅色板为同构降饱和变体（稿内没有，自行设计并守对比度红线：
 * faint 只作装饰性辅助，正文/数值最低 muted 档，两套主题正文对比度均 ≥ 4.5:1）。
 * 兼容：字段名沿用旧 MorandiPalette（sage/ochre/rose/slate/ink/...），存量组件零改动换肤；
 * 新增扩展令牌（edge/glow/ease 等）供 P1+ 的复合卡、折叠区、侧栏使用。
 */
import type { CSSProperties } from 'react'

/** 槽渲染器注入的翻译函数（DSH locale 服务）。 */
export type T = (key: string) => string

export interface ThemeTokens {
  /* —— 状态三色（字段名沿用莫兰迪旧名，值 = moss 配方）—— */
  /** 良性绿。 */
  sage: string
  /** 警示金。 */
  ochre: string
  /** 危险红。 */
  rose: string
  /** 主按钮底色。 */
  slate: string
  /** slate 主按钮上的文字色。 */
  onSlate: string
  /* —— 文字 —— */
  ink: string
  muted: string
  faint: string
  /* —— 底色/描边 —— */
  bg: string
  card: string
  cardSoft: string
  border: string
  borderSoft: string
  /* —— 扩展令牌（moss 配方，P1+ 消费）—— */
  accentBright: string
  warnBright: string
  dangerBright: string
  info: string
  infoBright: string
  borderWarn: string
  borderDanger: string
  glow: string
  glowWarn: string
  glowDanger: string
  /** 面板玻璃底（配合 backdropFilter）。 */
  glass: string
  /** crystal edge 渐变描边（GlassLayers 用）。 */
  edge: string
  /** 顶部高光线渐变。 */
  topSheen: string
  /** 镜面散光层（默认）/ 聚光层（hover）。 */
  sheenA: string
  sheenB: string
  /** 小卡渐变背景（metric/alarm 卡通用）。 */
  cardGrad: string
  /** 面板外投影。 */
  shadow: string
  /** 全局缓动曲线（mock --ease）。 */
  ease: string
}

/** 旧类型名兼容别名（历史导入不断）。 */
export type MorandiPalette = ThemeTokens

/** 深色板：OBSIDIAN MOSS——黑曜石底 + 苔绿主色 + 金色警示（mock :root 直译）。 */
const MOSS_DARK: ThemeTokens = {
  sage: '#6a9a6a',
  ochre: '#b8a860',
  rose: '#c07070',
  slate: '#3f5c3f',
  onSlate: '#d8e0d8',
  ink: '#d8e0d8',
  // mock 的 ink-dim；正文底线（faint 不做正文）
  muted: '#a8b8a8',
  // 较 mock #4a5a4a 提亮一档守对比度红线；仅装饰性辅助
  faint: '#6b7b6b',
  bg: '#030503',
  card: '#0c100c',
  cardSoft: '#101410',
  border: '#1a221a',
  borderSoft: '#161e16',
  accentBright: '#6a9a6a',
  warnBright: '#b8a860',
  dangerBright: '#c07070',
  info: '#4a5a6a',
  infoBright: '#6a8aaa',
  borderWarn: '#2a2515',
  borderDanger: '#2a1818',
  glow: 'rgba(60,100,60,0.15)',
  glowWarn: 'rgba(154,138,74,0.15)',
  glowDanger: 'rgba(154,74,74,0.2)',
  glass: 'linear-gradient(180deg, rgba(16,24,16,0.92), rgba(8,14,8,0.94))',
  edge: 'linear-gradient(135deg, rgba(120,150,120,0.30), rgba(60,90,60,0.10) 40%, rgba(60,90,60,0.06) 60%, rgba(120,150,120,0.22))',
  topSheen: 'linear-gradient(90deg, transparent, rgba(140,170,140,0.40), rgba(180,200,180,0.22), transparent)',
  sheenA: 'linear-gradient(135deg, transparent 20%, rgba(255,255,255,0.03) 35%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 65%, transparent 80%)',
  sheenB: 'linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12) 50%, transparent 60%)',
  cardGrad: 'linear-gradient(180deg, rgba(18,24,18,0.9), rgba(12,18,12,0.9))',
  shadow: '0 32px 80px rgba(0,0,0,0.85), 0 0 0 1px rgba(60,90,60,0.18)',
  ease: 'cubic-bezier(0.22, 1, 0.36, 1)',
}

/** 浅色板：纸面苔藓——暖白底 + 压暗的 moss 三色（自研同构变体）。 */
const MOSS_LIGHT: ThemeTokens = {
  sage: '#4f7a4f',
  ochre: '#8a6d35',
  rose: '#a05656',
  slate: '#567352',
  onSlate: '#f4f7f0',
  ink: '#26302a',
  muted: '#54644f',
  faint: '#7d8a78',
  bg: '#edf0e8',
  card: '#f6f8f2',
  cardSoft: '#fbfcf8',
  border: '#d3dcc6',
  borderSoft: '#e2e8da',
  accentBright: '#4f7a4f',
  warnBright: '#8a6d35',
  dangerBright: '#8f4040',
  info: '#55666f',
  infoBright: '#4f6076',
  borderWarn: '#ddd2ae',
  borderDanger: '#e0c6c6',
  glow: 'rgba(90,130,80,0.22)',
  glowWarn: 'rgba(160,140,70,0.22)',
  glowDanger: 'rgba(160,80,80,0.25)',
  glass: 'linear-gradient(180deg, rgba(255,255,255,0.86), rgba(244,247,238,0.9))',
  edge: 'linear-gradient(135deg, rgba(255,255,255,0.95), rgba(190,205,175,0.45) 40%, rgba(190,205,175,0.35) 60%, rgba(255,255,255,0.85))',
  topSheen: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.9), rgba(120,150,110,0.25), transparent)',
  sheenA: 'linear-gradient(135deg, transparent 20%, rgba(255,255,255,0.4) 35%, rgba(255,255,255,0.55) 50%, rgba(255,255,255,0.4) 65%, transparent 80%)',
  sheenB: 'linear-gradient(135deg, transparent 40%, rgba(90,130,80,0.10) 50%, transparent 60%)',
  cardGrad: 'linear-gradient(180deg, #ffffff, #f2f5ec)',
  shadow: '0 18px 48px rgba(50,70,45,0.18), 0 0 0 1px rgba(120,150,105,0.22)',
  ease: 'cubic-bezier(0.22, 1, 0.36, 1)',
}

/** 取当前主题令牌（dark = DSH data-ds-dark-theme 存在）。 */
export function getTheme(dark: boolean): ThemeTokens {
  return dark ? MOSS_DARK : MOSS_LIGHT
}

/** 当前是否暗色：优先检测 DSH 主题属性，回退系统偏好。 */
export function isDark(): boolean {
  if (typeof document !== 'undefined' && document.body) {
    return document.body.hasAttribute('data-ds-dark-theme')
  }
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches
}

/** 小卡渐变背景（替代散落各处的 CARD_BG_* 常量）。 */
export function cardBg(dark: boolean): string {
  return dark ? MOSS_DARK.cardGrad : MOSS_LIGHT.cardGrad
}

/** 小卡顶部 inset 高光（moss 配方：深色弱高光 / 浅色纯白高光）。 */
export function cardInset(dark: boolean): string {
  return 'inset 0 1px 0 ' + (dark ? 'rgba(140,170,140,0.10)' : 'rgba(255,255,255,0.9)')
}

/* ------------------------- 细滚动条（注入一次） ------------------------- */

const SCROLLBAR_STYLE_ID = 'vet-scrollbar-style'

export function injectScrollbarStyle(): void {
  if (typeof document === 'undefined') return
  if (document.getElementById(SCROLLBAR_STYLE_ID) !== null) return
  const style = document.createElement('style')
  style.id = SCROLLBAR_STYLE_ID
  style.textContent = `
    .vet-scrollbar::-webkit-scrollbar { width: 4px; }
    .vet-scrollbar::-webkit-scrollbar-track { background: transparent; }
    .vet-scrollbar::-webkit-scrollbar-thumb { background: rgba(106, 154, 106, 0.28); border-radius: 2px; }
    .vet-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(106, 154, 106, 0.45); }
    .vet-scrollbar { scrollbar-width: thin; scrollbar-color: rgba(106, 154, 106, 0.28) transparent; }
    /* P5：prefers-reduced-motion 降级——盾牌所有过渡动画直切（作用域限定 vet 面板树） */
    @media (prefers-reduced-motion: reduce) {
      .vet-panel-root, .vet-panel-root *, .vet-panel-root *::before, .vet-panel-root *::after {
        transition: none !important;
        animation: none !important;
      }
    }
  `
  document.head.appendChild(style)
}

/** 面板容器样式（P0：宽度由调用方传入——默认 340 紧凑宽，mock 的 420 经用户反馈弃用；定位由 Shield 编排层负责）。 */
export function panelStyle(tok: ThemeTokens, width = 340): CSSProperties {
  return {
    width,
    maxWidth: 'calc(100vw - 16px)',
    maxHeight: 'min(88vh, 800px)',
    overflowY: 'auto',
    background: tok.glass,
    backdropFilter: 'blur(36px) saturate(1.15)',
    WebkitBackdropFilter: 'blur(36px) saturate(1.15)',
    borderRadius: 16,
    boxShadow: tok.shadow,
    fontSize: 12,
    color: tok.muted,
    padding: '14px 14px 10px',
    textAlign: 'left',
    lineHeight: 1.5,
  }
}
