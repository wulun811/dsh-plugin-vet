import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  patchModule, patchNetworkModule, hookHeartbeat, isVetHook, resetHookRegistry,
  registerHookTarget, DEFAULT_HOOK_CONFIG, brandVetHook,
} from '../lib/guard/runtime-hooks.js'
import { installRuntimeGuard } from '../lib/guard/runtime-guard.js'
import { VetStatus } from '../lib/guard/status.js'
import fsDefault from 'node:fs'

/**
 * P0-2 #2：钩子完整性心跳——T2 包装被剥离/替换（插件改 require.cache 后的模块导出 / 直接覆盖导出）
 * 的唯一 in-process 绕过向量必须可被确定性观测。标记 = 闭包私有 Symbol 品牌（可析出、不可伪造）。
 */

const cfg = { ...DEFAULT_HOOK_CONFIG }
const sink = (): void => {}
const rootIndex = (): Map<string, string> => new Map()

beforeEach(() => {
  resetHookRegistry()
})

describe('钩子完整性心跳（unit）', () => {
  it('patchModule 后：全部 op 完好（ok=true）；剥离一个 → 该项失守、其余仍完好', () => {
    const mod: Record<string, unknown> = { readFileSync: () => 'x', writeFileSync: () => {} }
    const origRead = mod.readFileSync
    patchModule(mod, 'fs', cfg, sink, rootIndex)

    const hb = hookHeartbeat()
    expect(hb.ok).toBe(true)
    expect(hb.checks.find(c => c.module === 'fs' && c.op === 'readFileSync')?.intact).toBe(true)
    expect(hb.checks.find(c => c.op === 'writeFileSync')?.intact).toBe(true)

    // 攻击：把 readFileSync 写回原始函数（剥离 vet 包装）
    mod.readFileSync = origRead
    const hb2 = hookHeartbeat()
    expect(hb2.ok).toBe(false)
    expect(hb2.checks.find(c => c.op === 'readFileSync')?.intact).toBe(false)
    expect(hb2.checks.find(c => c.op === 'writeFileSync')?.intact).toBe(true)
  })

  it('patchNetworkModule 后：request/connect/get 完好；覆盖 export → 失守', () => {
    const mod: Record<string, unknown> = { request: () => ({}), connect: () => ({}), get: () => ({}) }
    patchNetworkModule(mod, 'http', cfg, sink, rootIndex)
    expect(hookHeartbeat().ok).toBe(true)

    mod.request = (() => {}) as unknown
    const hb = hookHeartbeat()
    expect(hb.ok).toBe(false)
    expect(hb.checks.find(c => c.module === 'http' && c.op === 'request')?.intact).toBe(false)
    expect(hb.checks.find(c => c.module === 'http' && c.op === 'get')?.intact).toBe(true)
  })

  it('registerHookTarget + brandVetHook：手工包装（fetch/dgram 形态）同样可被心跳复查', () => {
    const g: Record<string, unknown> = { fetch: () => Promise.resolve() }
    brandVetHook(g.fetch as (...a: unknown[]) => unknown)
    registerHookTarget('fetch-fake', g, ['fetch'])
    expect(hookHeartbeat().ok).toBe(true)

    g.fetch = (() => Promise.resolve(42)) as unknown // 攻击：换成另一个函数（品牌是函数对象上的，换对象即失守）
    const hb = hookHeartbeat()
    expect(hb.ok).toBe(false)
    expect(hb.checks.find(c => c.module === 'fetch-fake' && c.op === 'fetch')?.intact).toBe(false)
  })

  it('isVetHook：普通函数 false、品牌函数 true、非函数 false', () => {
    expect(isVetHook(() => 1)).toBe(false)
    expect(isVetHook(123)).toBe(false)
    const fn = (() => 1) as (...a: unknown[]) => unknown
    brandVetHook(fn)
    expect(isVetHook(fn)).toBe(true)
    // 打标是幂等的（重复打标同一函数不报错）
    brandVetHook(fn)
    expect(isVetHook(fn)).toBe(true)
  })

  it('resetHookRegistry 清空注册表（测试隔离）', () => {
    const mod: Record<string, unknown> = { readFileSync: () => 'x' }
    patchModule(mod, 'fs', cfg, sink, rootIndex)
    expect(hookHeartbeat().ok).toBe(true)
    resetHookRegistry()
    expect(hookHeartbeat().checks).toHaveLength(0)
    expect(hookHeartbeat().ok).toBe(true)
  })
})

describe('钩子完整性心跳（installRuntimeGuard 集成）', () => {
  it('watch 模式安装后：真实 fs/cp 表面全部完好；篡改真实 fs → 心跳报失守；dispose 收尾', () => {
    // 记录原始导出，供模拟"剥离"用（不 dispose 的全局修改必须在测试尾部恢复）
    const origReadFileSync = fsDefault.readFileSync
    const mkCtx = (): { logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }; baseUrl?: string; loader?: unknown } => ({
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    })
    const ctx = mkCtx() as never
    const status = new VetStatus()
    const config = {
      runtimeGuard: 'watch' as const,
      runtimeIntervalMs: 2000, runtimeMemLimitMb: 1024, runtimeForkBurstN: 5,
      runtimeFdLimit: 512, runtimeGrowthMb: 256, runtimeGrowthWindowMs: 600_000,
      honeypot: { enabled: false, dir: '' },
    } as never
    const dispose = installRuntimeGuard(ctx, config, status)
    try {
      const hb = hookHeartbeat()
      expect(hb.ok).toBe(true)
      expect(hb.checks.some(c => c.module === 'fs' && c.op === 'readFileSync' && c.intact)).toBe(true)
      expect(hb.checks.some(c => c.module === 'child_process' && c.op === 'spawn' && c.intact)).toBe(true)

      // 攻击：写回原始 readFileSync（不清除品牌，仅替换导出）→ heartbeat 必须捕获
      ;(fsDefault as { readFileSync: unknown }).readFileSync = origReadFileSync
      const hb2 = hookHeartbeat()
      expect(hb2.ok).toBe(false)
      expect(hb2.checks.find(c => c.module === 'fs' && c.op === 'readFileSync')?.intact).toBe(false)
    } finally {
      dispose()
      // 收尾：无论如何把篡改恢复回原始（dispose 会把"当前导出"写回 original 快照，但我们在
      // dispose 前已篡改，快照是包装后的 fn —— 必须显式恢复原始，避免污染后续测试/进程）
      ;(fsDefault as { readFileSync: unknown }).readFileSync = origReadFileSync
    }
  })
})
