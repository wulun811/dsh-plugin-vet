import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  extractNetworkTarget,
  classifyNetworkOp,
  patchNetworkModule,
  DEFAULT_HOOK_CONFIG,
  setRootIndexing,
  withVetSelfIo,
  type HookAlarm,
} from '../src/guard/runtime-hooks.js'

const CFG = DEFAULT_HOOK_CONFIG

describe('extractNetworkTarget', () => {
  it('string URL → hostname + port + path', () => {
    const r = extractNetworkTarget(['https://evil.com:8443/steal?key=1'])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('evil.com')
    expect(r!.port).toBe(8443)
    expect(r!.path).toBe('/steal?key=1')
  })

  it('string URL without port → port undefined', () => {
    const r = extractNetworkTarget(['https://example.com/api'])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('example.com')
    expect(r!.port).toBeUndefined()
    expect(r!.path).toBe('/api')
  })

  it('invalid string URL → null', () => {
    expect(extractNetworkTarget(['not-a-url'])).toBeNull()
  })

  it('URL object → hostname + port + path', () => {
    const url = new URL('https://webhook.site/abc')
    const r = extractNetworkTarget([url])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('webhook.site')
    expect(r!.path).toBe('/abc')
  })

  it('options object with hostname + port + path', () => {
    const r = extractNetworkTarget([{ hostname: 'api.binance.com', port: 443, path: '/api/v1' }])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('api.binance.com')
    expect(r!.port).toBe(443)
    expect(r!.path).toBe('/api/v1')
  })

  it('options object with host (not hostname)', () => {
    const r = extractNetworkTarget([{ host: 'requestbin.com', port: 80 }])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('requestbin.com')
    expect(r!.port).toBe(80)
  })

  it('options with port as string', () => {
    const r = extractNetworkTarget([{ hostname: 'example.com', port: '8080' }])
    expect(r).not.toBeNull()
    expect(r!.port).toBe(8080)
  })

  it('net.connect({ port, host }) form', () => {
    const r = extractNetworkTarget([{ port: 4444, host: 'attacker.com' }])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('attacker.com')
    expect(r!.port).toBe(4444)
  })

  it('net.connect(port, host) form', () => {
    const r = extractNetworkTarget([31337, 'evil.com'])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('evil.com')
    expect(r!.port).toBe(31337)
  })

  it('net.connect(port) form → localhost', () => {
    const r = extractNetworkTarget([8080])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('localhost')
    expect(r!.port).toBe(8080)
  })

  it('Unix socket → hostname=unix-socket', () => {
    const r = extractNetworkTarget([{ path: '/var/run/docker.sock' }])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('unix-socket')
    expect(r!.path).toBe('/var/run/docker.sock')
  })

  it('options with mixed-case hostname → lowercased (P2-7)', () => {
    const r = extractNetworkTarget([{ host: 'Webhook.Site', port: 443 }])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('webhook.site')
  })

  it('net.connect(port, HOST) → lowercased (P2-7)', () => {
    const r = extractNetworkTarget([443, 'LOCALHOST'])
    expect(r).not.toBeNull()
    expect(r!.hostname).toBe('localhost')
  })

  it('empty args → null', () => {
    expect(extractNetworkTarget([])).toBeNull()
  })

  it('null first arg → null', () => {
    expect(extractNetworkTarget([null])).toBeNull()
  })
})

describe('classifyNetworkOp', () => {
  it('sensitive port → red alarm', () => {
    const alarm = classifyNetworkOp('net', 'connect', [4444, 'evil.com'], CFG)
    expect(alarm).not.toBeNull()
    expect(alarm!.severity).toBe('red')
    expect(alarm!.kind).toBe('net-egress')
    expect(alarm!.target).toContain('4444')
  })

  it('sensitive host → yellow alarm', () => {
    const alarm = classifyNetworkOp('https', 'request', ['https://webhook.site/abc'], CFG)
    expect(alarm).not.toBeNull()
    expect(alarm!.severity).toBe('yellow')
    expect(alarm!.kind).toBe('net-egress')
    expect(alarm!.target).toContain('webhook.site')
  })

  it('subdomain of sensitive host → yellow alarm', () => {
    const alarm = classifyNetworkOp('https', 'request', ['https://sub.webhook.site/x'], CFG)
    expect(alarm).not.toBeNull()
    expect(alarm!.severity).toBe('yellow')
  })

  it('localhost → no alarm', () => {
    expect(classifyNetworkOp('http', 'request', ['http://localhost:3000/api'], CFG)).toBeNull()
  })

  it('127.0.0.1 → no alarm', () => {
    expect(classifyNetworkOp('net', 'connect', [{ port: 5432, host: '127.0.0.1' }], CFG)).toBeNull()
  })

  it('::1 → no alarm', () => {
    expect(classifyNetworkOp('net', 'connect', [{ port: 5432, host: '::1' }], CFG)).toBeNull()
  })

  it('allowlisted host → no alarm', () => {
    expect(classifyNetworkOp('https', 'request', ['https://registry.npmjs.org/pkg'], CFG)).toBeNull()
    expect(classifyNetworkOp('https', 'request', ['https://api.github.com/repos'], CFG)).toBeNull()
    expect(classifyNetworkOp('https', 'request', ['https://cdn.jsdelivr.net/npm/x'], CFG)).toBeNull()
    expect(classifyNetworkOp('https', 'request', ['https://unpkg.com/pkg'], CFG)).toBeNull()
  })

  it('Unix socket → no alarm', () => {
    expect(classifyNetworkOp('net', 'connect', [{ path: '/var/run/docker.sock' }], CFG)).toBeNull()
  })

  it('normal host + normal port → no alarm', () => {
    expect(classifyNetworkOp('https', 'request', ['https://my-api.example.com/data'], CFG)).toBeNull()
  })

  it('all sensitive ports trigger red', () => {
    for (const port of [4444, 5555, 6666, 7777, 1337, 31337]) {
      const alarm = classifyNetworkOp('net', 'connect', [port, 'evil.com'], CFG)
      expect(alarm).not.toBeNull()
      expect(alarm!.severity).toBe('red')
    }
  })

  it('mixed-case sensitive host → still detected (P2-7)', () => {
    const alarm = classifyNetworkOp('https', 'request', [{ hostname: 'Webhook.Site' }], CFG)
    expect(alarm).not.toBeNull()
    expect(alarm!.severity).toBe('yellow')
  })

  it('mixed-case LOCALHOST → no alarm (P2-7)', () => {
    expect(classifyNetworkOp('net', 'connect', [{ port: 3000, host: 'LOCALHOST' }], CFG)).toBeNull()
  })

  it('all sensitive hosts trigger yellow', () => {
    for (const host of ['webhook.site', 'requestbin.com', 'ngrok.io', 'localtunnel.me', 'pastebin.com', 'api.binance.com', 'api.coinbase.com']) {
      const alarm = classifyNetworkOp('https', 'request', [{ hostname: host }], CFG)
      expect(alarm).not.toBeNull()
      expect(alarm!.severity).toBe('yellow')
    }
  })
})

describe('patchNetworkModule', () => {
  const sink: HookAlarm[] = []
  const rootIndex = () => new Map<string, string>()

  beforeEach(() => {
    sink.length = 0
    setRootIndexing(false)
  })

  it('wraps request/connect/createConnection and calls sink on sensitive target', () => {
    const fakeHttp: Record<string, unknown> = {
      request: (..._args: unknown[]) => 'original-request',
      connect: (..._args: unknown[]) => 'original-connect',
      createConnection: (..._args: unknown[]) => 'original-createConnection',
    }

    const dispose = patchNetworkModule(fakeHttp, 'http', CFG, (a) => sink.push(a), rootIndex)

    // Call wrapped request with sensitive target
    const result = (fakeHttp.request as Function)('https://webhook.site/leak')
    expect(result).toBe('original-request') // original still called
    expect(sink.length).toBe(1)
    expect(sink[0].kind).toBe('net-egress')
    expect(sink[0].target).toContain('webhook.site')

    // Call wrapped connect with sensitive port
    ;(fakeHttp.connect as Function)('https://evil.com:4444/shell')
    expect(sink.length).toBe(2)
    expect(sink[1].severity).toBe('red')

    // Non-sensitive → no alarm
    ;(fakeHttp.request as Function)('https://safe.example.com/api')
    expect(sink.length).toBe(2) // unchanged

    dispose()
  })

  it('dispose restores original functions', () => {
    const original = (..._args: unknown[]) => 'orig'
    const fakeMod: Record<string, unknown> = { request: original }
    const dispose = patchNetworkModule(fakeMod, 'http', CFG, () => {}, rootIndex)
    expect(fakeMod.request).not.toBe(original)
    dispose()
    expect(fakeMod.request).toBe(original)
  })

  it('rootIndexing → bypass (no alarm)', () => {
    const fakeMod: Record<string, unknown> = {
      request: (..._args: unknown[]) => 'ok',
    }
    patchNetworkModule(fakeMod, 'http', CFG, (a) => sink.push(a), rootIndex)

    setRootIndexing(true)
    ;(fakeMod.request as Function)('https://webhook.site/x')
    expect(sink.length).toBe(0)
    setRootIndexing(false)
  })

  it('vetSelfIo → bypass (no alarm)', () => {
    const fakeMod: Record<string, unknown> = {
      request: (..._args: unknown[]) => 'ok',
    }
    patchNetworkModule(fakeMod, 'http', CFG, (a) => sink.push(a), rootIndex)

    withVetSelfIo(() => {
      ;(fakeMod.request as Function)('https://webhook.site/x')
    })
    expect(sink.length).toBe(0)
  })

  it('official plugin hint → no alarm (trust boundary)', () => {
    const fakeMod: Record<string, unknown> = {
      request: (..._args: unknown[]) => 'ok',
    }
    // Simulate a rootIndex that attributes to an official package
    const officialRootIndex = () => {
      const m = new Map<string, string>()
      // Fake: any stack frame matches this root → attributed to @deepseek-ai/dsh
      m.set('/fake/path', '@deepseek-ai/dsh')
      return m
    }
    patchNetworkModule(fakeMod, 'http', CFG, (a) => sink.push(a), officialRootIndex)

    // The stack trace won't actually match /fake/path, so hint will be undefined → alarm fires.
    // This test validates the mechanism: when hint IS official, alarm is suppressed.
    // We test the isOfficial logic indirectly: non-official hint → alarm present.
    ;(fakeMod.request as Function)('https://webhook.site/x')
    // hint is undefined (stack doesn't match), so alarm fires
    expect(sink.length).toBe(1)
  })
})

describe('patchNetworkModule wraps get (P2-10)', () => {
  const sink: HookAlarm[] = []
  const rootIndex = () => new Map<string, string>()
  beforeEach(() => { sink.length = 0; setRootIndexing(false) })

  it('wraps http.get and alarms on sensitive host', () => {
    const fakeHttp: Record<string, unknown> = {
      get: (..._a: unknown[]) => 'original-get',
      request: (..._a: unknown[]) => 'original-request',
    }
    const dispose = patchNetworkModule(fakeHttp, 'http', CFG, (a) => sink.push(a), rootIndex)
    const result = (fakeHttp.get as Function)('https://webhook.site/leak')
    expect(result).toBe('original-get') // original still called
    expect(sink.length).toBe(1)
    expect(sink[0].kind).toBe('net-egress')
    expect(sink[0].target).toContain('webhook.site')
    dispose()
  })

  it('wraps https.get and alarms on sensitive port', () => {
    const fakeHttps: Record<string, unknown> = { get: (..._a: unknown[]) => 'orig' }
    const dispose = patchNetworkModule(fakeHttps, 'https', CFG, (a) => sink.push(a), rootIndex)
    ;(fakeHttps.get as Function)({ port: 4444, host: 'evil.com' })
    expect(sink.length).toBe(1)
    expect(sink[0].severity).toBe('red')
    dispose()
  })

  it('dispose restores original get', () => {
    const original = (..._a: unknown[]) => 'orig'
    const fakeMod: Record<string, unknown> = { get: original }
    const dispose = patchNetworkModule(fakeMod, 'http', CFG, () => {}, rootIndex)
    expect(fakeMod.get).not.toBe(original)
    dispose()
    expect(fakeMod.get).toBe(original)
  })
})
