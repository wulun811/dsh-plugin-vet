/**
 * 控制面对端判定（0.5.13 · 专家复审 Q4）单测：写入口该向谁开放。
 * 这里钉的是「本机」的边界——回环、本机网卡、IPv4-mapped/zone id 归一，
 * 以及拿不到地址时**失败即拒**（不给未知来源开口子）。
 */
import { describe, expect, it } from 'vitest'
import { isLocalPeer, localInterfaceAddresses } from '../lib/guard/local-peer.js'

const none = new Set<string>()

describe('isLocalPeer（对端是不是本机）', () => {
  it('回环：127.0.0.0/8 整个网段 + ::1 + IPv4-mapped 写法', () => {
    for (const addr of ['127.0.0.1', '127.5.5.5', '127.255.255.254', '::1', '::ffff:127.0.0.1', '::FFFF:127.0.0.1']) {
      expect(isLocalPeer(addr, none), addr).toBe(true)
    }
  })

  it('公网 / 局域网对端 → 不是本机（这是 Q4 要拦的那一类）', () => {
    for (const addr of ['203.0.113.7', '192.168.1.20', '10.0.0.5', '::ffff:203.0.113.7', '2001:db8::1']) {
      expect(isLocalPeer(addr, none), addr).toBe(false)
    }
  })

  it('本机网卡地址 → 是本机：本机浏览器访问 http://192.168.x.x:3456 的真实形态', () => {
    expect(isLocalPeer('192.168.3.9', new Set(['192.168.3.9']))).toBe(true)
    expect(isLocalPeer('192.168.3.10', new Set(['192.168.3.9']))).toBe(false)
  })

  it('IPv6 zone id 先剥掉再比（fe80::1%en0 与 fe80::1 同一个地址）', () => {
    expect(isLocalPeer('fe80::1%en0', new Set(['fe80::1']))).toBe(true)
  })

  it('拿不到地址 / 空串 → 不是本机（失败即拒，不给未知来源开口子）', () => {
    expect(isLocalPeer(undefined, none)).toBe(false)
    expect(isLocalPeer('', none)).toBe(false)
    expect(isLocalPeer('   ', none)).toBe(false)
  })

  it('非法 IPv4 不会被当成回环（999.1.1.1 不是 127/8）', () => {
    expect(isLocalPeer('999.1.1.1', none)).toBe(false)
    expect(isLocalPeer('127.0.0.256', none)).toBe(false)
  })

  it('默认参数真去问内核：至少包含回环地址', () => {
    // 不假设具体网卡（CI/容器形态各异），只要求「本机一定有回环」这一条恒真事实。
    expect(localInterfaceAddresses().has('127.0.0.1')).toBe(true)
    expect(isLocalPeer('127.0.0.1')).toBe(true)
  })
})
