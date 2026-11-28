/**
 * sameOrigin 桌面端例外（`dsh-app://` 面板写请求）。
 *
 * DSH 桌面端用 `dsh-app://` 自定义协议加载面板，fetch 不带 `Origin`——忽略/恢复、
 * 守卫开关、档位切换这些 POST 因此全部 403。面板写请求统一携带 `x-vet-panel: 1`，
 * 服务端 Origin 缺失时只认它；其余（无头、跨站 Origin）保持原有严格语义。
 */
import { describe, it, expect } from 'vitest'
import type { IncomingMessage } from 'node:http'
import { sameOrigin } from '../lib/guard/status-route.js'

const req = (headers: Record<string, string>): IncomingMessage =>
  ({ headers } as unknown as IncomingMessage)

describe('sameOrigin（POST 写入口）', () => {
  it('Origin 缺失：面板标记头放行，无标记拒绝（桌面端 dsh-app:// 修复）', () => {
    expect(sameOrigin(req({ 'x-vet-panel': '1' }))).toBe(true)
    expect(sameOrigin(req({}))).toBe(false)
    expect(sameOrigin(req({ 'x-vet-panel': '0' }))).toBe(false)
  })

  it('带 Origin：仍要求与 Host 同源且 Host 是本机权威', () => {
    expect(sameOrigin(req({ origin: 'http://127.0.0.1:1234', host: '127.0.0.1:1234' }))).toBe(true)
    expect(sameOrigin(req({ origin: 'http://evil.example:1234', host: '127.0.0.1:1234' }))).toBe(false)
    expect(sameOrigin(req({ origin: 'http://127.0.0.1:1234' }))).toBe(false)
  })
})
