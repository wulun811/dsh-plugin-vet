/**
 * 0.5.15：盾牌的第四态「未连接」。
 *
 * 旧实现是 `snap?.level ?? 'green'`：后端没应答时（路由没注册 / 宿主没起来 / CSP 挡了 /
 * 网络断了），盾牌永远显示绿色「守护中」、0 报警，页脚的"更新于"又因为 loadedAt===0 被
 * 隐藏——**一个字都不说**。对一个卖"我帮你盯着"的产品，这是最坏的一种静默：把"我不知道"
 * 画成了"一切正常"。
 *
 * 这里测的是**纯函数** `shieldLevel()`，不是渲染树：把"什么时候该说不知道"从 JSX 里拆出来，
 * 才有一条能红的断言。渲染层只负责把 level 画成颜色和图标。
 *
 * 反面用例同样重要：**有数据时不能被降级成 unknown**。一个"总是说不知道"的盾牌和
 * "总是说没问题"的盾牌一样没用。
 */
import { describe, expect, it } from 'vitest'
import { shieldLevel, STALE_MS } from '../src/client/shield-level.ts'

const NOW = 1_700_000_000_000

describe('shieldLevel：没有数据不等于一切正常（0.5.15）', () => {
  it('从未拿到快照 → unknown，不是 green', () => {
    expect(shieldLevel({ hasSnapshot: false, level: undefined, loadedAt: 0, now: NOW })).toBe('unknown')
  })

  it('拿到了但当场就是 green → green（不能把有数据降成不知道）', () => {
    expect(shieldLevel({ hasSnapshot: true, level: 'green', loadedAt: NOW, now: NOW })).toBe('green')
  })

  it('拿到了但已陈旧（超过 3 个轮询周期）→ unknown', () => {
    expect(shieldLevel({ hasSnapshot: true, level: 'green', loadedAt: NOW - STALE_MS - 1, now: NOW })).toBe('unknown')
  })

  it('陈旧边界之内仍然采信服务端结论', () => {
    expect(shieldLevel({ hasSnapshot: true, level: 'yellow', loadedAt: NOW - STALE_MS, now: NOW })).toBe('yellow')
  })

  it('陈旧时即使是 red 也不保留红色——陈旧的 red 同样是"我不知道现在"', () => {
    // 这一条是刻意选择：留着旧的 red 会让人以为"还在出事"，而它可能只是 15 秒前的
    // 一次瞬时尖峰。诚实的是「不知道现在」，不是「最后一次是红的」。
    expect(shieldLevel({ hasSnapshot: true, level: 'red', loadedAt: NOW - STALE_MS - 1, now: NOW })).toBe('unknown')
  })

  it('快照缺 level 字段（旧后端/协议漂移）→ unknown，不默认 green', () => {
    expect(shieldLevel({ hasSnapshot: true, level: undefined, loadedAt: NOW, now: NOW })).toBe('unknown')
  })

  it('未知的 level 字符串（协议漂移）→ unknown，不默认 green', () => {
    expect(shieldLevel({ hasSnapshot: true, level: 'bogus' as never, loadedAt: NOW, now: NOW })).toBe('unknown')
  })
})
