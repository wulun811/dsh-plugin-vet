/**
 * 自检区搬家回归（用户 2026-11-05）：
 * 「自检详情」原本是主面板上的一个折叠（0.5.9），默认收起、安静时只占一行却不给新信息；
 * 现在整块搬进「审计 & 蜜罐」页，主面板的审计横条上只留一个小图标。
 *
 * 本测试钉住两件事，都是搬家容易搬坏的：
 * 1. **异常口径**：只有 `failed`（试过没成）与 desired≠effective（配了没挂）算异常；
 *    `off` 是用户自己关的、`partial/unknown/excluded/unsupported` 是既定边界——不算。
 *    这条口径主面板图标和面板细节共用同一个函数，算两遍迟早漂。
 * 2. **内容确实在审计页里**：覆盖面/生效姿态两段都在 AuditCenterPanel 的输出里，
 *    且没有因为搬家变成只渲染标题不渲染内容。
 *
 * 环境：Node + react-dom/server（无 DOM）。theme 令牌用 Proxy 兜底，只验结构不验配色。
 */
import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { AuditCenterPanel } from '../src/client/panels/AuditCenterPanel.tsx'
import { SelfCheckSection, selfCheckProblemCount } from '../src/client/panels/SelfCheckSection.tsx'
import { zh } from '../src/client/i18n.ts'
import type { T, ThemeTokens } from '../src/client/theme.ts'
import type { AuditSummaryWire, VetCoverageWire, VetEffectiveConfigWire, VetPostureWire } from '../src/client/types.ts'

/** 任意令牌都返回一个色值：这些组件只把令牌拼进 style，不需要真实主题。 */
const pal = new Proxy({}, { get: (_o, k) => (typeof k === 'string' ? '#123456' : undefined) }) as unknown as ThemeTokens
const t: T = (k) => zh[k] ?? k

const cov = (surface: string, result: VetCoverageWire['result'], extra: Partial<VetCoverageWire> = {}): VetCoverageWire => ({
  surface,
  result,
  reasons: [],
  observedAt: 1,
  ...extra,
})
const pos = (surface: string, effective: VetPostureWire['effective']): VetPostureWire => ({
  surface,
  desired: true,
  supported: true,
  installed: true,
  healthy: true,
  effective,
})

describe('自检异常口径（selfCheckProblemCount）', () => {
  it('空表 → 0（主面板不显示数字）', () => {
    expect(selfCheckProblemCount([], [])).toBe(0)
  })

  it('覆盖面只把 failed 算异常：partial/unknown/excluded/unsupported 都是既定边界', () => {
    expect(selfCheckProblemCount([cov('file_tree', 'failed')], [])).toBe(1)
    expect(selfCheckProblemCount([
      cov('file_tree', 'partial'),
      cov('deps_direct', 'unknown'),
      cov('deps_transitive', 'excluded'),
      cov('intel_osv', 'unsupported'),
      cov('intel_registry', 'covered'),
    ], [])).toBe(0)
  })

  it('姿态只把「想要却没得到」算异常：off 是用户的选择，enforced 是正常', () => {
    expect(selfCheckProblemCount([], [pos('runtime_fs', 'degraded')])).toBe(1)
    expect(selfCheckProblemCount([], [
      pos('runtime_fs', 'off'),
      pos('runtime_net', 'enforced'),
      pos('audit_gate', 'unsupported'),
      pos('confirm_block', 'unknown'),
    ])).toBe(2)
  })
})

describe('自检区渲染（SelfCheckSection）', () => {
  it('两段都空 → 什么都不渲染（不给空壳标题）', () => {
    expect(renderToStaticMarkup(createElement(SelfCheckSection, { pal, dark: true, t, coverage: [], posture: [] }))).toBe('')
  })

  it('覆盖面：计数、未覆盖面胶囊、单主体标注与理由都进了输出', () => {
    const html = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t,
      coverage: [
        cov('file_tree', 'covered'),
        cov('runtime_fs', 'partial', { reasons: ['esm-named-import'], subject: 'evil-pkg' }),
        cov('intel_osv', 'failed', { reasons: ['osv-unanswered'], acknowledged: false }),
      ],
      posture: [],
      coverageSubject: 'evil-pkg',
    }))
    expect(html).toContain('1 个面在看')
    expect(html).toContain('2 个面没在看')
    expect(html).toContain('运行时·文件：部分')
    expect(html).toContain('情报·OSV：失败')
    // 理由走词典（zh），细节原样跟在括号里
    expect(html).toContain('该包用 ESM 具名导入引用内建模块')
    expect(html).toContain('查询发出去了但没拿到应答')
    // 单一主体时，标题后面直接写包名
    expect(html).toContain('evil-pkg')
  })

  it('多主体：标题写「N 个包」，缺口胶囊的 tooltip 标出处', () => {
    const html = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t,
      coverage: [cov('runtime_net', 'partial', { reasons: ['not-reported'], subject: 'a-pkg' })],
      posture: [],
      coverageSubjects: 3,
    }))
    expect(html).toContain('3 个包')
    expect(html).toContain('来自 a-pkg')
  })

  it('姿态：生效数、按配置关闭数、缺口面在输出里', () => {
    const html = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t,
      coverage: [],
      posture: [
        pos('runtime_fs', 'enforced'),
        pos('runtime_net', 'off'),
        pos('confirm_block', 'degraded'),
      ],
    }))
    expect(html).toContain('1 个执行面生效')
    expect(html).toContain('1 个按配置关闭')
    // 0.5.14：标题与「N 项异常」由审计页的段头画（三段标题必须长一样），这里只管内容
    expect(html).toContain('N7 确认拦截')
    expect(html).not.toContain('1 项异常')
  })
})

describe('审计 & 蜜罐页承接自检（AuditCenterPanel）', () => {
  const audit: AuditSummaryWire = {
    honeypot: { armed: true, touches: 0 },
    pendingAudits: [],
    newPlugins: [],
    plugins: [],
  }

  it('页面里能找到「自检详情」这个标题（它不再挂主面板）', () => {
    const html = renderToStaticMarkup(createElement(AuditCenterPanel, {
      pal, dark: true, t, audit,
      coverage: [cov('file_tree', 'covered')],
      posture: [],
      onOpenPlugin: () => {},
    }))
    expect(html).toContain('自检详情')
    expect(html).toContain('覆盖面')
  })

  it('0.5.20：只有配置缺口时，审计页也出「自检详情」段（不再被覆盖面/姿态的空数组挡住）', () => {
    const html = renderToStaticMarkup(createElement(AuditCenterPanel, {
      pal, dark: true, t, audit,
      coverage: [], posture: [],
      config: configWire(),
      onOpenPlugin: () => {},
    }))
    expect(html).toContain('自检详情')
    expect(html).toContain('配置：设了但没生效')
    expect(html).toContain('1 项异常')
  })

  it('三段各有自己的段头（0.5.14：用户说「没有分区，看不清哪块是哪块」）', () => {
    const html = renderToStaticMarkup(createElement(AuditCenterPanel, {
      pal, dark: true, t, audit,
      coverage: [cov('file_tree', 'covered')],
      posture: [pos('runtime_fs', 'degraded')],
      onOpenPlugin: () => {},
    }))
    expect(html).toContain('审计状态')
    expect(html).toContain('蜜罐监控')
    expect(html).toContain('自检详情')
    // 段头右上角那句状态（异常计数只在这里出现一次，不重复到内容里）
    expect(html).toContain('1 项异常')
    expect(html.match(/1 项异常/g)).toHaveLength(1)
  })

  it('没有自检数据时，页面不渲染自检标题（旧后端降级）', () => {
    const html = renderToStaticMarkup(createElement(AuditCenterPanel, {
      pal, dark: true, t, audit,
      coverage: [], posture: [],
      onOpenPlugin: () => {},
    }))
    expect(html).not.toContain('自检详情')
    expect(html).toContain('蜜罐监控')
  })
})


/**
 * 0.5.20：自检区多了两段——「配置：设了但没生效」（`effectiveConfig`，0.5.12 就推导出来，
 * 但客户端从来没读过）与「投影比对」（`domainProjection`，0.5.18 起三种模式都比对，结果同样
 * 没人读）。两段的口径与前面一致：**只报「你配了但它没照着做」**。
 */
const configWire = (over: Partial<VetEffectiveConfigWire> = {}): VetEffectiveConfigWire => ({
  profile: 'paranoid',
  keys: [{ key: 'denyOn', status: 'inert', because: 'mode', note: 'report 模式下没有任何拦截判定，这个门槛用不上' }],
  counts: { changed: 1, active: 0, inert: 1, partial: 0 },
  ...over,
})

describe('0.5.20：配置与投影进自检', () => {
  it('配置里没生效的键计入异常数（与姿态缺口同一个口径）', () => {
    expect(selfCheckProblemCount([], [], configWire())).toBe(1)
    expect(selfCheckProblemCount([], [], configWire({
      keys: [
        { key: 'denyOn', status: 'inert' },
        { key: 'honeypot.enabled', status: 'partial', because: 'runtimeGuard' },
        { key: 'mode', status: 'active' },
      ],
    }))).toBe(2)
  })

  it('投影差异按一次计，不管差了几处（它是 vet 自己的不变式，不是 N 个独立问题）', () => {
    expect(selfCheckProblemCount([], [], undefined, { mode: 'active', mismatches: 3 })).toBe(1)
    expect(selfCheckProblemCount([], [], undefined, { mode: 'active', mismatches: 0 })).toBe(0)
  })

  it('只有配置/投影也有内容时，自检区不再提前返回空', () => {
    const html = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t, coverage: [], posture: [], config: configWire(),
    }))
    expect(html).toContain('配置：设了但没生效')
    expect(html).toContain('denyOn')
    expect(html).toContain('由 mode')
    expect(html).toContain('report 模式下没有任何拦截判定')
  })

  it('投影差异为 0 时整段不渲染（没有差异就不该有一行「0 处不一致」）', () => {
    const html = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t, coverage: [], posture: [], projection: { mode: 'active', mismatches: 0 },
    }))
    expect(html).toBe('')
    const shown = renderToStaticMarkup(createElement(SelfCheckSection, {
      pal, dark: true, t, coverage: [], posture: [],
      projection: { mode: 'active', mismatches: 2, first: 'severity: 旧="yellow" 投影="red"' },
    }))
    expect(shown).toContain('投影比对')
    expect(shown).toContain('severity')
  })
})
