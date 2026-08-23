import { describe, expect, it } from 'vitest'
import { isTrackedNetHost, isLoopbackHost, isControlPlanePath } from '../lib/guard/runtime-net.js'
import { patchNetworkModule } from '../lib/guard/runtime-patch.js'
import { DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-ops.js'
import type { HookAlarm } from '../lib/guard/runtime-ops.js'

describe('Phase 3.1 本地 API 回环观测（P15/P17/G-2/G-5，round-13）', () => {
  it('isTrackedNetHost：默认回环不追踪；observeLoopback=true 才追踪；外联主机恒追踪', () => {
    expect(isTrackedNetHost('127.0.0.1')).toBe(false)
    expect(isTrackedNetHost('localhost')).toBe(false)
    expect(isTrackedNetHost('::1')).toBe(false)
    expect(isTrackedNetHost('127.0.0.1', { observeLoopback: true })).toBe(true)
    expect(isTrackedNetHost('webhook.site')).toBe(true)
    expect(isTrackedNetHost('registry.npmjs.org')).toBe(false) // 白名单
    expect(isTrackedNetHost('unix-socket')).toBe(false)
  })

  it('isControlPlanePath：/api/、session.*、/plugins/ 命中；普通路径不命中', () => {
    expect(isControlPlanePath('/api/session.list')).toBe(true)
    expect(isControlPlanePath('/api/v1/models')).toBe(true)
    expect(isControlPlanePath('/plugins/foo')).toBe(true)
    expect(isControlPlanePath('/session.prompt?x=1')).toBe(true)
    expect(isControlPlanePath('/status')).toBe(false)
    expect(isControlPlanePath('/favicon.ico')).toBe(false)
    expect(isControlPlanePath('/')).toBe(false)
  })

  it('patchNetworkModule：observeLoopback 关 → 回环控制面零报警零台账', () => {
    const sink: HookAlarm[] = []
    const ledger: unknown[] = []
    const mod = { request: (_opts: unknown, cb?: () => void) => { if (typeof cb === 'function') cb() ; return { write() { return true }, end() { return true } } } } as unknown as Record<string, unknown>
    const dispose = patchNetworkModule(mod, 'http', { ...DEFAULT_HOOK_CONFIG }, (a) => sink.push(a), () => new Map(), (e) => ledger.push(e))
    try {
      ;(mod.request as unknown as (o: unknown) => unknown)('http://127.0.0.1:3080/api/session.list')
      ;(mod.request as unknown as (o: unknown) => unknown)('http://127.0.0.1:3080/status')
    } finally { dispose() }
    expect(sink.length).toBe(0)
  })

  it('patchNetworkModule：observeLoopback 开 + 控制面路径 + 第三方归因 → yellow loopback-control', () => {
    const sink: HookAlarm[] = []
    const ledger: unknown[] = []
    const mod = { request: (_opts: unknown, cb?: () => void) => { if (typeof cb === 'function') cb(); return { write() { return true }, end() { return true } } } } as unknown as Record<string, unknown>
    const cfg = { ...DEFAULT_HOOK_CONFIG, observeLoopback: true }
    // 归因：把调用方（本测试文件所在目录）映射到第三方插件名
    const rootIndex = () => new Map([[process.cwd() + '/test', 'evil-plugin']])
    const dispose = patchNetworkModule(mod, 'http', cfg, (a) => sink.push(a), rootIndex, (e) => ledger.push(e))
    try {
      ;(mod.request as unknown as (o: unknown) => unknown)('http://127.0.0.1:3080/api/session.list')
      ;(mod.request as unknown as (o: unknown) => unknown)('http://127.0.0.1:3080/status.json')
      ;(mod.request as unknown as (o: unknown) => unknown)('http://webhook.site/x') // 敏感主机仍走既有 alarm
    } finally { dispose() }
    const lc = sink.filter(a => a.kind === 'loopback-control')
    expect(lc.length).toBe(1)
    expect(lc[0].severity).toBe('yellow')
    expect(lc[0].pluginHint).toBe('evil-plugin')
    expect(lc[0].target).toContain('session.list')
    // 普通路径不入控制面观测
    expect(sink.some(a => a.kind === 'loopback-control' && a.target.includes('status.json'))).toBe(false)
    // 敏感主机既有 net-egress 报警不受影响
    expect(sink.some(a => a.kind === 'net-egress' && a.target.includes('webhook.site'))).toBe(true)
  })

  it('isLoopbackHost 单元', () => {
    expect(isLoopbackHost('127.0.0.1')).toBe(true)
    expect(isLoopbackHost('LOCALHOST')).toBe(true)
    expect(isLoopbackHost('8.8.8.8')).toBe(false)
  })
})