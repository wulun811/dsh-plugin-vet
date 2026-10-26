/**
 * 「关于 vet」介绍面板（P3 迁入次级面板层栈；顶栏 ? 点击打开同一组件）。
 * 内容与 P0 版一致；壳统一走 SubPanel（玻璃/头部/滚动），定位由编排层负责。
 */
import type { ReactNode } from 'react'
import type { T, ThemeTokens } from '../theme.ts'
import { cardBg, cardInset } from '../theme.ts'
import { SubPanel } from '../components/SubPanel.tsx'
import { ShieldIcon } from '../components/ShieldIcon.tsx'
import type { UpdateCardPresentation } from '../../guard/update-card.ts'
import type { VetUpdateWire } from '../types.ts'
// 内嵌 logo（build-client.mjs define 注入的 data URI，见 assets.d.ts）
const vetLogo = __VET_ASSETS__.vetLogo
const dshSoLogo = __VET_ASSETS__.dshSoLogo

/** 构建时注入：package.json version（scripts/build-client.mjs define）。 */
declare const __VET_VERSION__: string

/** 介绍栏卖点骨架：5 个分区，每个有图标 + 标题 + 短要点列表。 */
const INTRO_SECTIONS = [
  { icon: '🛡', titleKey: 'intro.s1title', bullets: ['intro.s1b1', 'intro.s1b2', 'intro.s1b3', 'intro.s1b4'] },
  { icon: '👁', titleKey: 'intro.s2title', bullets: ['intro.s2b1', 'intro.s2b2', 'intro.s2b3'] },
  { icon: '🍯', titleKey: 'intro.s3title', bullets: ['intro.s3b1', 'intro.s3b2', 'intro.s3b3'] },
  { icon: '📋', titleKey: 'intro.s4title', bullets: ['intro.s4b1', 'intro.s4b2', 'intro.s4b3', 'intro.s4b4'] },
  { icon: '🔔', titleKey: 'intro.s5title', bullets: ['intro.s5b1', 'intro.s5b2', 'intro.s5b3'] },
]

export function IntroPanel({ pal, dark, t, onBack, update, updatePres }: {
  pal: ThemeTokens
  dark: boolean
  t: T
  /** 层栈内打开时传返回；hover 浮层形态不传。 */
  onBack?: () => void
  /** 0.4.1：版本与适配的原始数据（收起后可在此查看；缺省 = 旧后端，不渲染该区块）。 */
  update?: VetUpdateWire
  /** 0.4.1：与主面板卡片**同一份** presentation（单源，防两处漂移）。 */
  updatePres?: UpdateCardPresentation | null
}): ReactNode {
  // 版本与适配：主面板卡片收起后的常驻查看入口（信息不丢，只是不再占着主面板）
  const showUpdate = update !== undefined && updatePres !== undefined && updatePres !== null
  // 版本号单一口径：优先用**服务端实时值**（与主面板表头 `VET {currentVersion}` 同一个字段），
  // 构建期常量只在旧后端不汇报时兜底。此前这里独占一份 `__VET_VERSION__`：面板头显示 0.4.1
  // 而「关于」页显示构建时烘死的旧号（浏览器里跑的是上一次构建的 bundle 时尤其明显），
  // 同一件事实两处来源必然漂移。
  const version = update !== undefined && update.currentVersion !== ''
    ? update.currentVersion
    : (typeof __VET_VERSION__ === 'string' ? __VET_VERSION__ : '0.1.0')
  /** 占位符填充；值本身可能是 i18n key（如 `update.rangeNone`），查表后填入。 */
  const fillText = (key: string, vars: Record<string, string>): string =>
    t(key).replace(/\{(\w+)\}/g, (_m, k: string) => {
      const v = vars[k] ?? ''
      return v.startsWith('update.') ? t(v) : v
    })
  return (
    <div style={{ width: '100%', height: '100%' }}>
      <SubPanel tok={pal} title={t('intro.title')} ariaLabel={t('intro.aria')} onBack={onBack} backLabel={t('panel.back')}>
        <div style={{ paddingBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <ShieldIcon level="green" color={pal.sage} size={18} />
            <span style={{ fontWeight: 800, fontSize: 15, letterSpacing: '0.02em', color: pal.ink }}>{t('intro.headline')}</span>
          </div>
          {/* 用户反馈 2026-08-27：自家 logo 独占一排 200px（品牌位）；dsh.so logo
              降格为低调的一行并排（不独占、不跳转）——SVG 已裁白边，
              33% 宽下字标 ~17px 可读。 */}
          <div style={{ display: 'flex', justifyContent: 'center', margin: '2px 0 6px' }}>
            <img src={vetLogo} alt="vet" style={{ width: 200, height: 'auto' }} />
          </div>
          <div style={{ textAlign: 'center', fontSize: 12, color: pal.faint, marginBottom: 10 }}>
            @jieai/dsh-plugin-vet v{version}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: pal.faint, marginBottom: 10 }}>
            <img src={dshSoLogo} alt="dsh.so" style={{ width: '33%', height: 'auto', flexShrink: 0 }} />
            <span>{t('intro.provider')}</span>
          </div>

          <div style={{ fontWeight: 800, fontSize: 13, color: pal.ink, marginBottom: 8 }}>
            {t('intro.lines')}
          </div>

          <div style={{ background: cardBg(dark), border: '1px solid ' + pal.borderSoft, boxShadow: cardInset(dark), borderRadius: 10, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: pal.muted }}>
            <div><b style={{ color: pal.ink }}>{t('intro.stat1')}</b>{t('intro.stat1b')}</div>
            <div style={{ marginTop: 2 }}><b style={{ color: pal.ink }}>{t('intro.stat2')}</b>{t('intro.stat2b')}</div>
            <div style={{ marginTop: 2 }}><b style={{ color: pal.ink }}>{t('intro.stat3')}</b>{t('intro.stat3b')}</div>
          </div>

          <div style={{ background: cardBg(dark), border: '1px solid ' + pal.borderSoft, boxShadow: cardInset(dark), borderRadius: 10, padding: '8px 12px', marginBottom: 12, fontSize: 11.5, color: pal.muted }}>
            <div style={{ fontWeight: 700, fontSize: 12.5, marginBottom: 3, color: pal.ink }}>🪜 {t('intro.tierTitle')}</div>
            <div style={{ lineHeight: 1.6 }}>{t('intro.tier1')}</div>
            <div style={{ lineHeight: 1.6, marginTop: 2 }}>{t('intro.tier2')}</div>
            <div style={{ lineHeight: 1.6, marginTop: 2 }}>{t('intro.tier3')}</div>
            <div style={{ lineHeight: 1.6, marginTop: 4, color: pal.faint }}>{t('intro.tierNote')}</div>
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

          <div style={{
            background: `linear-gradient(135deg, ${pal.cardSoft}, ${pal.slate})`,
            border: '1px solid ' + (dark ? 'rgba(60,100,60,0.35)' : pal.border),
            boxShadow: '0 0 20px ' + pal.glow,
            borderRadius: 10, padding: '10px 14px', fontWeight: 700, fontSize: 13,
            color: dark ? pal.ink : pal.onSlate, margin: '16px 0 12px', textAlign: 'center',
          }}>
            {t('intro.tagline')}
          </div>

          <div style={{ fontSize: 12, color: pal.faint, borderTop: '1px solid ' + pal.borderSoft, paddingTop: 10 }}>
            {t('intro.cost')}
          </div>
          <div style={{ fontSize: 12, color: pal.faint, marginTop: 4 }}>
            {t('intro.position')}
          </div>

          {/* 0.4.1：版本与适配（主面板卡片安静态收起后的常驻入口）。与卡片共用 presentation，
              故文案/优先级不会漂移；这里始终展示（不看 20 分钟窗口——用户主动进来就是要看）。 */}
          {showUpdate && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontWeight: 800, fontSize: 13, color: pal.ink, marginBottom: 6 }}>
                {t('update.title')}
              </div>
              <div style={{ background: cardBg(dark), border: '1px solid ' + pal.borderSoft, boxShadow: cardInset(dark), borderRadius: 10, padding: '8px 12px', fontSize: 11.5, color: pal.muted }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span aria-hidden="true" style={{ fontSize: 11, color: updatePres.accent ? pal.ochre : pal.faint }}>{updatePres.icon}</span>
                  <span style={{ fontWeight: 700, color: updatePres.accent ? pal.ochre : pal.ink }}>{t(updatePres.labelKey)}</span>
                  <span style={{ marginLeft: 'auto', fontSize: 10.5, color: pal.faint }}>
                    DSH {update!.dshVersion === '' ? '?' : update!.dshVersion} · VET {update!.currentVersion}
                  </span>
                </div>
                <div style={{ marginTop: 5, lineHeight: 1.6 }}>{fillText(updatePres.noteKey, updatePres.vars)}</div>
                {/* 升级命令只在**确有可升级版本**时给出。安静态下 latestVersion 可能比本机旧
                    （本机是开发版/预发布版），无条件给出会变成「降级命令」——故按 tone 门控。 */}
                {update!.status === 'update-available' && update!.latestVersion !== '' && (
                  <div style={{ marginTop: 6, fontSize: 10.5, color: pal.faint }}>
                    {t('update.cmdLabel')}：<code style={{ userSelect: 'all' }}>{`npm i -g @jieai/dsh-plugin-vet@${update!.latestVersion}`}</code>
                  </div>
                )}
                <div style={{ marginTop: 4, fontSize: 10.5, color: pal.faint }}>{t('update.sourceNote')}</div>
              </div>
            </div>
          )}
        </div>
      </SubPanel>
    </div>
  )
}
