/**
 * 钩子品牌必须**不可伪造**（0.5.15）。
 *
 * 心跳（`hookHeartbeat`）靠 `isVetHook(fn)` 判断「当前模块导出还是不是 vet 的包装」。
 * 这个判断的强弱决定了「另一个插件把 T2 整个换掉」能不能被看见。
 *
 * 0.1.21–0.5.14 用的是函数上的一个 `Symbol()` 属性，注释还写着「闭包私有、不可复制/伪造」。
 * 那条断言是错的：`Symbol()` 只是不进全局注册表，函数上的 symbol 属性**可枚举**——
 * `Object.getOwnPropertySymbols(fn)` 抄走、贴到假函数上，`isVetHook(fake)` 就返回 true。
 * 本文件把这条攻击变成一条会红的断言，并钉住新实现（WeakSet 按对象身份判定）。
 *
 * 注：这里测的是「品牌机制」本身，不是心跳的完整链路（那条在 coverage-honesty 里）。
 */
import { describe, expect, it } from 'vitest'
import { brandVetHook, isVetHook, hookHeartbeat, registerHookTarget, resetHookRegistry } from '../lib/guard/runtime-heartbeat.js'

describe('钩子品牌不可伪造（0.5.15：WeakSet 按身份）', () => {
  it('打过品牌的函数被认出', () => {
    const fn = (): unknown => 'real'
    expect(isVetHook(fn)).toBe(false) // 前提：没打之前不是
    brandVetHook(fn)
    expect(isVetHook(fn)).toBe(true)
  })

  it('**把 Symbol 属性抄到假函数上不生效**（旧实现的绕过路径）', () => {
    const real = (): unknown => 'real'
    brandVetHook(real)

    // 攻击者能做的全部事情：把 real 上所有 symbol 属性逐个复制到自己的函数
    const fake = (): unknown => 'pwned'
    for (const sym of Object.getOwnPropertySymbols(real)) {
      try {
        Object.defineProperty(fake, sym, { value: (real as unknown as Record<symbol, unknown>)[sym] })
      } catch {
        // 有些描述符抄不过去——抄不过去更好，不需要断言
      }
    }
    // 旧实现（Symbol 属性）在这里返回 true；新实现必须返回 false
    expect(isVetHook(fake)).toBe(false)
    // 真函数不受影响
    expect(isVetHook(real)).toBe(true)
  })

  it('外观完全相同（同源码、同名字）的另一个函数也不算', () => {
    const make = (): (() => unknown) => () => 'same'
    const a = make()
    const b = make()
    brandVetHook(a)
    expect(isVetHook(b)).toBe(false)
  })

  it('心跳在导出被换成「抄过品牌的假函数」时报告失守', () => {
    resetHookRegistry()
    const real = (): unknown => 'real'
    brandVetHook(real)
    const mod: Record<string, unknown> = { readFileSync: real }
    registerHookTarget('node:fs', mod, ['readFileSync'])

    // 还完好
    expect(hookHeartbeat().ok).toBe(true)

    // 换成假函数（连带抄走 symbol）
    const fake = (): unknown => 'pwned'
    for (const sym of Object.getOwnPropertySymbols(real)) {
      try {
        Object.defineProperty(fake, sym, { value: (real as unknown as Record<symbol, unknown>)[sym] })
      } catch {
        // ignore
      }
    }
    mod.readFileSync = fake
    const hb = hookHeartbeat()
    expect(hb.ok).toBe(false)
    expect(hb.checks.find(c => c.module === 'node:fs' && c.op === 'readFileSync')?.intact).toBe(false)
    resetHookRegistry()
  })
})
