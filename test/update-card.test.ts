/**
 * 0.4.1：「版本与适配」卡的展示决策（20 分钟安静窗口 + 真消息永不收起）。
 *
 * 背景（用户 2026-10-13）：「这张卡按道理展示一次就收起来，不能一直展示」——安静态每次说的都是
 * 同一句话，属于一次性通知而非常驻仪表；真消息（超出已复验范围 / 可升级）则必须留下。
 *
 * 与 `guard/shield-shape.ts` 同款单源纪律：判定逻辑放服务端可编译的纯模块，客户端与单测共用。
 */
import { describe, expect, it } from 'vitest'
import {
  UPDATE_CARD_TTL_MS,
  isUpdateNews,
  parseSeen,
  shouldShowUpdateCard,
  updateCardSignature,
  updateCardPresentation,
  type UpdateCardInput,
} from '../lib/guard/update-card.js'

/** 安静态基线：已复验支持当前 DSH（本机真机就是这个状态）。 */
function quiet(over: Partial<UpdateCardInput> = {}): UpdateCardInput {
  return {
    compat: 'ok',
    status: 'up-to-date',
    dshVersion: '0.2.0-rc.2',
    currentVersion: '0.4.1',
    testedRange: '^0.1.1-rc.1 || ^0.2.0-rc.2',
    latestVersion: '0.3.18',
    ...over,
  }
}

describe('0.4.1 update-card：真消息判定（永不收起的那两类）', () => {
  it('超出已复验范围 / 可升级 = 真消息', () => {
    expect(isUpdateNews(quiet({ compat: 'out-of-range' }))).toBe(true)
    expect(isUpdateNews(quiet({ status: 'update-available' }))).toBe(true)
  })

  it('已复验支持 / 已是最新 / 未知 = 无新消息（按 20 分钟收起）', () => {
    expect(isUpdateNews(quiet())).toBe(false)
    expect(isUpdateNews(quiet({ status: 'unknown' }))).toBe(false)
    expect(isUpdateNews(quiet({ compat: 'unknown', status: 'unknown' }))).toBe(false)
  })
})

describe('0.4.1 update-card：shouldShowUpdateCard（20 分钟窗口）', () => {
  const T0 = 1_700_000_000_000
  const sig = updateCardSignature(quiet())

  it('首次（无记录）→ 展示；记录损坏（at 非数）→ 展示', () => {
    expect(shouldShowUpdateCard(quiet(), null, T0)).toBe(true)
    expect(shouldShowUpdateCard(quiet(), { sig, at: Number.NaN }, T0)).toBe(true)
  })

  it('窗口内展示、窗口外收起（边界：恰好 TTL 即收起）', () => {
    const seen = { sig, at: T0 }
    expect(shouldShowUpdateCard(quiet(), seen, T0)).toBe(true)
    expect(shouldShowUpdateCard(quiet(), seen, T0 + UPDATE_CARD_TTL_MS - 1)).toBe(true)
    expect(shouldShowUpdateCard(quiet(), seen, T0 + UPDATE_CARD_TTL_MS)).toBe(false)
    expect(shouldShowUpdateCard(quiet(), seen, T0 + UPDATE_CARD_TTL_MS + 1)).toBe(false)
  })

  it('20 分钟 = 1200000ms（防手滑改错量级）', () => {
    expect(UPDATE_CARD_TTL_MS).toBe(20 * 60 * 1000)
    expect(UPDATE_CARD_TTL_MS).toBe(1_200_000)
  })

  it('真消息：即使远超窗口、甚至存储不可用，也必须展示', () => {
    const old = { sig, at: T0 }
    const wayPast = T0 + 10 * UPDATE_CARD_TTL_MS
    expect(shouldShowUpdateCard(quiet({ compat: 'out-of-range' }), old, wayPast)).toBe(true)
    expect(shouldShowUpdateCard(quiet({ status: 'update-available' }), null, wayPast)).toBe(true)
    expect(shouldShowUpdateCard(quiet({ compat: 'out-of-range' }), { sig: 'stale', at: T0 }, wayPast)).toBe(true)
  })

  it('消息变化（指纹不同）→ 重新计时：新消息从此刻起再展示 20 分钟', () => {
    const seen = { sig, at: T0 }
    const past = T0 + UPDATE_CARD_TTL_MS + 1
    expect(shouldShowUpdateCard(quiet(), seen, past)).toBe(false) // 老消息已收起
    // DSH 升级 → 指纹变化 = 新消息 → 重新展示，并从此重新计时
    const upgraded = quiet({ dshVersion: '0.3.0' })
    expect(shouldShowUpdateCard(upgraded, seen, past)).toBe(true)
    const newSig = updateCardSignature(upgraded)
    expect(newSig).not.toBe(sig)
    expect(shouldShowUpdateCard(upgraded, { sig: newSig, at: past }, past + UPDATE_CARD_TTL_MS - 1)).toBe(true)
    expect(shouldShowUpdateCard(upgraded, { sig: newSig, at: past }, past + UPDATE_CARD_TTL_MS)).toBe(false)
  })

  it('指纹不含 latestVersion：registry 抖动不会把安静态卡片重新弹出来', () => {
    // 关键防误报面：registry 发了新版但没声明 dshCompat → status 仍 unknown、卡片内容一字未变。
    // 若指纹含 latestVersion，这里会重新展示 20 分钟。
    const a = quiet({ latestVersion: '0.3.18' })
    const b = quiet({ latestVersion: '0.3.19' })
    expect(updateCardSignature(a)).toBe(updateCardSignature(b))
    const seen = { sig: updateCardSignature(a), at: T0 }
    expect(shouldShowUpdateCard(b, seen, T0 + UPDATE_CARD_TTL_MS)).toBe(false) // 不因抖动重弹
  })

  it('时钟回拨（seen.at 在未来）→ 继续展示，不误收起', () => {
    expect(shouldShowUpdateCard(quiet(), { sig, at: T0 + 5 * UPDATE_CARD_TTL_MS }, T0)).toBe(true)
  })
})

describe('0.4.1 update-card：parseSeen（损坏记录一律归一为 null = 首次看到）', () => {
  it('合法记录往返', () => {
    expect(parseSeen(JSON.stringify({ sig: 'ok|up-to-date|1|2', at: 123 }))).toEqual({ sig: 'ok|up-to-date|1|2', at: 123 })
  })

  it('null / 坏 JSON → null', () => {
    expect(parseSeen(null)).toBeNull()
    expect(parseSeen('{not json')).toBeNull()
    expect(parseSeen('')).toBeNull()
  })

  it('非对象（数组/字面量）→ null', () => {
    expect(parseSeen('[1,2]')).toBeNull()
    expect(parseSeen('"str"')).toBeNull()
    expect(parseSeen('123')).toBeNull()
    expect(parseSeen('null')).toBeNull()
  })

  it('缺字段 / 类型漂移 → null（at=null、at 字符串、sig 非字符串）', () => {
    expect(parseSeen(JSON.stringify({ sig: 'x' }))).toBeNull()
    expect(parseSeen(JSON.stringify({ at: 1 }))).toBeNull()
    expect(parseSeen(JSON.stringify({ sig: 'x', at: null }))).toBeNull()
    expect(parseSeen(JSON.stringify({ sig: 'x', at: 'soon' }))).toBeNull()
    expect(parseSeen(JSON.stringify({ sig: 1, at: 1 }))).toBeNull()
  })

  it('at 非有限数（NaN/Infinity）→ null，绝不因坏数据误收起', () => {
    // JSON 本身不能表达 NaN/Infinity，但经字符串塞入的 "NaN" 解析后仍可到达（防御性）
    expect(parseSeen('{"sig":"x","at":1e999}')).toBeNull() // Infinity
  })
})

describe('0.4.1 update-card：存储故障绝不吞掉真消息（实机边界取证的口径固化）', () => {
  it('storage 不可用时（seen=null）真消息照样展示', () => {
    const now = 1_700_000_000_000
    expect(shouldShowUpdateCard(quiet({ compat: 'out-of-range' }), null, now)).toBe(true)
    expect(shouldShowUpdateCard(quiet({ status: 'update-available' }), null, now)).toBe(true)
  })

  it('storage 不可用时安静态退化为常驻（每次算首次）——宁可多显示，不可漏警告', () => {
    const now = 1_700_000_000_000
    // 连续多次「首次」判定恒为展示；这正是无存储时的真实行为
    expect(shouldShowUpdateCard(quiet(), null, now)).toBe(true)
    expect(shouldShowUpdateCard(quiet(), null, now + 10 * UPDATE_CARD_TTL_MS)).toBe(true)
  })

  it('古老记录（远超窗口）安静态收起', () => {
    const now = 1_700_000_000_000
    const seen = { sig: updateCardSignature(quiet()), at: now - 365 * 24 * 3600 * 1000 }
    expect(shouldShowUpdateCard(quiet(), seen, now)).toBe(false)
  })
})

describe('0.4.1 update-card：presentation 单源（主面板与「关于」共用，防两处漂移）', () => {
  it('优先级：超出范围 > 可升级 > 已复验支持 > 已是最新 > 未知', () => {
    // 同时 out-of-range 且 update-available → 档位仍是 out（兼容性更紧迫），但正文必须给出
    // **出路**：升级到声明覆盖它的那个版本，而不是只喊「先回退 DSH」。
    const both = updateCardPresentation(quiet({ compat: 'out-of-range', status: 'update-available' }))
    expect(both.tone).toBe('out')
    expect(both.noteKey).toBe('update.noteOutWithUpdate')
    expect(both.vars.latest).toBe('0.3.18')
    // 只有 out 没有可升级版本 → 仍旧文案，不虚构 latest
    expect(updateCardPresentation(quiet({ compat: 'out-of-range' })).noteKey).toBe('update.noteOut')
    expect(updateCardPresentation(quiet({ compat: 'out-of-range' })).vars.latest).toBeUndefined()
    expect(updateCardPresentation(quiet({ status: 'update-available' })).tone).toBe('available')
    expect(updateCardPresentation(quiet()).tone).toBe('ok')
    expect(updateCardPresentation(quiet({ compat: 'unknown' })).tone).toBe('uptodate')
    expect(updateCardPresentation(quiet({ compat: 'unknown', status: 'unknown' })).tone).toBe('unknown')
  })

  it('诚实口径：compat=ok 才说「已复验支持」；compat 判不出来时不得声称已复验', () => {
    // compat=ok（且 compatStatus 保证此时 dshVersion 非空）→ 可以说「已是最新且已复验支持」
    expect(updateCardPresentation(quiet()).noteKey).toBe('update.noteUpToDate')
    // compat=unknown + status=up-to-date 是**可达状态**（读不到运行中的 DSH 版本，但 registry 查得到
    // 且不比本机新）。此时绝不能说「已复验支持 DSH」——那会把「不知道」渲染成「已验证」，
    // 而且 dshVersion 为空时会输出「已复验支持 DSH 。」这种悬空占位。
    const unknowable = updateCardPresentation(quiet({ compat: 'unknown', dshVersion: '' }))
    expect(unknowable.noteKey).toBe('update.noteUpToDateUnverified')
    expect(unknowable.noteKey).not.toBe('update.noteUpToDate')
    // 该正文明不得引用 {dsh}（否则空版本号会渲染成悬空）
    expect(unknowable.noteKey).not.toContain('{dsh}')
  })

  it('tone=uptodate 分支恒为「复验状态不可知」（该分支只在 compat 非 ok 非 out-of-range 时到达）', () => {
    for (const compat of ['ok', 'unknown', 'out-of-range'] as const) {
      const p = updateCardPresentation(quiet({ compat, status: 'up-to-date', dshVersion: compat === 'unknown' ? '' : '0.2.0-rc.2' }))
      if (p.tone === 'uptodate') {
        expect(compat).toBe('unknown') // 只有不可知才会落到这个 tone
        expect(p.noteKey).toBe('update.noteUpToDateUnverified')
      }
    }
  })

  it('accent 只在真消息上为真；图标随档位', () => {
    expect(updateCardPresentation(quiet({ compat: 'out-of-range' })).accent).toBe(true)
    expect(updateCardPresentation(quiet({ status: 'update-available' })).accent).toBe(true)
    expect(updateCardPresentation(quiet()).accent).toBe(false)
    expect(updateCardPresentation(quiet({ compat: 'out-of-range' })).icon).toBe('⚠')
    expect(updateCardPresentation(quiet({ status: 'update-available' })).icon).toBe('↑')
    expect(updateCardPresentation(quiet()).icon).toBe('·')
  })

  it('未声明范围 → range 占位符回退 update.rangeNone（不渲空串）', () => {
    const p = updateCardPresentation(quiet({ testedRange: '' }))
    expect(p.vars.range).toBe('update.rangeNone')
    // 已声明则原样透传
    expect(updateCardPresentation(quiet()).vars.range).toBe('^0.1.1-rc.1 || ^0.2.0-rc.2')
  })

  it('占位符齐全：out 用 dsh/range；available 用 latest/dsh/current', () => {
    const out = updateCardPresentation(quiet({ compat: 'out-of-range' }))
    expect(Object.keys(out.vars).sort()).toEqual(['dsh', 'range'])
    const avail = updateCardPresentation(quiet({ status: 'update-available' }))
    expect(Object.keys(avail.vars).sort()).toEqual(['current', 'dsh', 'latest'])
  })
})
