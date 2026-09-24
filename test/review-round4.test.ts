import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  classifyNetworkOp, extractNetworkTarget, isLoopbackHost, isTrackedNetHost, normNetworkHost,
} from '../lib/guard/runtime-net.js'
import {
  DEFAULT_HOOK_CONFIG, classifyOp, attachCanaryScanner,
} from '../lib/guard/runtime-hooks.js'
import { canaryStore, resetCanaryStore, generateCanary } from '../lib/guard/canary.js'
import { ensureHoneypot } from '../lib/guard/honeypot.js'
import { hashShort, createT2Sink } from '../lib/guard/runtime-sink.js'
import { VetStatus } from '../lib/guard/status.js'
import { installToolExecuteGuard } from '../lib/guards/tool-execute.js'
import { setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'

/**
 * round-4 review 回归：尾点 FQDN / 空 hostname / IPv6 回环归一、成对路径蜜罐完整性目标侧、
 * canary 首窗、孤儿金丝雀、金丝雀明文指纹化、deny 扫描失败 fail-closed、N6 损坏记录守卫。
 */

const CFG = { ...DEFAULT_HOOK_CONFIG }

describe('round-4：网络目标归一（尾点 FQDN / 空 hostname / IPv6 回环）', () => {
  it('normNetworkHost：小写 + 去尾点 + 剥 IPv6 括号', () => {
    expect(normNetworkHost('Webhook.Site.')).toBe('webhook.site')
    expect(normNetworkHost('webhook.site.')).toBe('webhook.site')
    expect(normNetworkHost('[::1]')).toBe('::1')
    expect(normNetworkHost('LOCALHOST.')).toBe('localhost')
    expect(normNetworkHost('registry.npmjs.org.')).toBe('registry.npmjs.org')
  })

  it('extractNetworkTarget：字符串 URL 尾点归一', () => {
    const t = extractNetworkTarget(['https://webhook.site./leak'])
    expect(t?.hostname).toBe('webhook.site')
  })

  it('classifyNetworkOp：尾点 FQDN 不再绕过敏感主机', () => {
    expect(classifyNetworkOp('https', 'get', ['https://webhook.site./leak'], CFG)).not.toBeNull()
    expect(classifyNetworkOp('http', 'request', ['https://x.webhook.site./leak'], CFG)).not.toBeNull()
  })

  it('options 形态空 hostname 回退 host（不再拿到空串失明）', () => {
    const t = extractNetworkTarget([{ hostname: '', host: 'Webhook.Site', port: 80, path: '/' }])
    expect(t?.hostname).toBe('webhook.site')
    expect(classifyNetworkOp('http', 'request', [{ hostname: '', host: 'webhook.site', port: 80, path: '/' }], CFG)).not.toBeNull()
  })

  it('IPv6 括号形态与 127.0.0.0/8 视为回环（台账/报警不追踪）', () => {
    expect(isLoopbackHost('[::1]')).toBe(true)
    expect(isLoopbackHost('127.0.0.2')).toBe(true)
    expect(isLoopbackHost('127.255.255.254')).toBe(true)
    expect(isLoopbackHost('localhost.')).toBe(true)
    expect(isTrackedNetHost('[::1]')).toBe(false)
    expect(isTrackedNetHost('127.0.0.2')).toBe(false)
    // 回环 URL 不报警
    expect(classifyNetworkOp('http', 'request', ['http://[::1]:8080/x'], CFG)).toBeNull()
    expect(classifyNetworkOp('http', 'request', ['http://127.0.0.2/x'], CFG)).toBeNull()
  })
})

describe('round-4：成对路径操作的蜜罐/完整性目标侧判定（M5）', () => {
  let dir: string
  let hpDir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-r4-pair-'))
    hpDir = join(dir, '.local')
  })
  afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

  it('cp 目标侧命中蜜罐 → honeypot 报警（此前盲区：只查首参源侧）', () => {
    mkdirSync(hpDir, { recursive: true })
    const marker = join(hpDir, 'id_rsa.pem')
    writeFileSync(marker, 'fake')
    const cfg = { ...CFG, honeypotRoots: [hpDir] }
    // 旧实现：target=首参 /tmp/x → 不命中；新实现：候选含目标侧 → 报
    const alarm = classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/x', join(hpDir, 'id_rsa.pem')] }, cfg)
    expect(alarm?.kind).toBe('honeypot')
    // 源侧触碰原本就报，行为保持
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: [join(hpDir, 'id_rsa.pem'), '/tmp/out'] }, cfg)?.kind).toBe('honeypot')
  })

  it('cp/rename 目标侧命中完整性金丝雀 → red integrity（读源侧不报）', () => {
    const marker = join(dir, 'vet-integrity-1')
    writeFileSync(marker, 'x')
    // sensitiveRoots 去 /var：macOS tmpdir=/var/folders/** 落在系统根下，marker 会被
    // fs-write 误伤（测试假设 tmpdir 不在敏感根——Linux /tmp 成立，macOS /var 不成立）。
    // integrity 判定独立于 sensitiveRoots，语义不受影响。
    const cfg = { ...CFG, integrityRoots: [marker], sensitiveRoots: ['/etc', '/usr', '/boot', '/bin', '/sbin'] }
    const cp = classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/x', marker] }, cfg)
    expect(cp?.kind).toBe('integrity')
    expect(cp?.severity).toBe('red')
    expect(classifyOp({ module: 'fs', op: 'rename', args: ['/tmp/x', marker] }, cfg)?.kind).toBe('integrity')
    // 源侧读取（cp 金丝雀 → 备份）不是破坏，不报 integrity
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: [marker, '/tmp/backup'] }, cfg)).toBeNull()
  })
})

describe('round-4：canary 出站扫描首窗（M4：>64KB 请求体前段不再漏）', () => {
  it('单 chunk > 64KB 且金丝雀在头部 → 首窗保留可命中', () => {
    resetCanaryStore()
    const c = generateCanary()
    canaryStore.register(c)
    const texts: string[] = []
    const obj = { write(c: unknown) { return true }, end(c?: unknown) {} } as { write: (c: unknown) => boolean; end: (c?: unknown) => void }
    attachCanaryScanner(obj, (t) => texts.push(t))
    // 100KB 单块：金丝雀在开头，100KB 垫料在后
    obj.write(('A'.repeat(100 * 1024)).replace(/^A+/, c + 'A'.repeat(100 * 1024)))
    expect(canaryStore.match(texts[texts.length - 1])).toBe(c)
  })

  it('多 chunk 累计 > 64KB、金丝雀在前段 → 尾部窗口之外仍命中（head 保留，任一回调可命中）', () => {
    resetCanaryStore()
    const c = generateCanary()
    canaryStore.register(c)
    const texts: string[] = []
    const obj = { write(c: unknown) { return true }, end(c?: unknown) {} } as { write: (c: unknown) => boolean; end: (c?: unknown) => void }
    attachCanaryScanner(obj, (t) => texts.push(t))
    obj.write('B'.repeat(40 * 1024) + c)
    obj.write('C'.repeat(60 * 1024))
    // 任一回调命中即可（金丝雀在首个 64KB 内 → 填满 head 的那次回调携带 head+tail 合并体）
    expect(texts.some(t => canaryStore.match(t) === c)).toBe(true)
    // 内存有界：任意回调 ≤ 128KB（head 64KB + tail 64KB）
    for (const t of texts) expect(t.length).toBeLessThanOrEqual(128 * 1024)
  })
})

describe('round-4：孤儿金丝雀（H：id_rsa 不注册永不命中的金丝雀）', () => {
  let dir: string
  beforeEach(() => {
    resetCanaryStore()
    dir = mkdtempSync(join(tmpdir(), 'vet-r4-hp-'))
  })
  afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

  it('ensureHoneypot：注册金丝雀数 = 5（仅可嵌诱饵），id_rsa.pem/.pub 不在集合', () => {
    ensureHoneypot(dir)
    const reg = canaryStore.snapshot()
    // .env / credentials.json / .npmrc / .netrc / aws-credentials 各一枚；id_rsa 两枚不再注册
    expect(reg.length).toBe(5)
    const rsa = readFileSync(join(dir, 'id_rsa.pem'), 'utf8')
    expect(reg.some(c => rsa.includes(c))).toBe(false)
  })
})

describe('round-4：金丝雀/密钥报警不落明文（M1/M2 指纹化）', () => {
  it('recordCanary：id/target 含 hashShort 指纹，不含金丝雀原文', () => {
    const status = new VetStatus()
    const { recordCanary } = createT2Sink(status)
    const c = generateCanary()
    recordCanary('body', c, 'evil-plugin')
    const alarm = status.snapshot().alarms.find(a => a.kind === 'canary-leak')
    expect(alarm).toBeDefined()
    expect(alarm!.id).toBe(`n4-canary:${hashShort(c)}:evil-plugin`)
    expect(alarm!.target).toBe(hashShort(c))
    expect(alarm!.id).not.toContain(c)
    expect(alarm!.target).not.toContain(c)
    // 可读信息保留在 message（前 16 位 + 长度）
    expect(alarm!.message).toContain(c.slice(0, 16))
    expect(alarm!.message).toContain(`${c.length} 位`)
  })
})

describe('round-4：deny 模式扫描失败 fail-closed（M3，与 internal-plugin M9 对齐）', () => {
  it('deny + 扫描超时失败 → 不调 next、返回 isError（此前 fail-open 放行）', async () => {
    const makeCtx = () => {
      const handlers = new Map<string, Function[]>()
      return {
        handlers,
        logger: { warn: () => {}, info: () => {} },
        on(event: string, handler: Function) {
          const list = handlers.get(event) ?? []
          list.push(handler)
          handlers.set(event, list)
        },
      }
    }
    const ctx = makeCtx()
    // 超短超时：scan 必然 `{ok:false, error:'scanner timeout…'}` → 走扫描失败分支
    installToolExecuteGuard(ctx as never, {
      mode: 'deny', denyOn: 'critical', scannerTimeoutMs: 1,
    } as never)
    const handler = ctx.handlers.get('tools/execute')![0] as (exec: unknown, next: () => unknown) => Promise<unknown>
    let nextCalled = false
    const result = await handler(
      { name: 'run_code', arguments: { code: 'console.log(1)' } },
      async () => { nextCalled = true; return { content: [] } },
    ) as { isError?: boolean; content: { type: string; text: string }[] }
    expect(nextCalled).toBe(false)
    expect(result.isError).toBe(true)
    expect(result.content[0].text).toMatch(/^VET BLOCKED.*scan-error/)
    // report 模式同场景：不拦截但前缀保留 scan-error 提示（行为不回归）
    const ctx2 = makeCtx()
    installToolExecuteGuard(ctx2 as never, {
      mode: 'report', denyOn: 'critical', scannerTimeoutMs: 1,
    } as never)
    const handler2 = ctx2.handlers.get('tools/execute')![0] as (exec: unknown, next: () => unknown) => Promise<unknown>
    let nextCalled2 = false
    const r2 = await handler2(
      { name: 'run_code', arguments: { code: 'console.log(1)' } },
      async () => { nextCalled2 = true; return { content: [{ type: 'text', text: 'out' }] } },
    ) as { isError?: boolean; content: { type: string; text: string }[] }
    expect(nextCalled2).toBe(true)
    expect(r2.isError).not.toBe(true)
    expect(r2.content[0].text).toContain('scan-error')
  })

  it('notes 非空 + next 返回非 text content → notes 前置为独立文本（M4 不静默丢弃）', async () => {
    const makeCtx = () => {
      const handlers = new Map<string, Function[]>()
      return {
        handlers,
        logger: { warn: () => {}, info: () => {} },
        on(event: string, handler: Function) {
          const list = handlers.get(event) ?? []
          list.push(handler)
          handlers.set(event, list)
        },
      }
    }
    const ctx = makeCtx()
    installToolExecuteGuard(ctx as never, {
      mode: 'report', denyOn: 'critical', scannerTimeoutMs: 1,
    } as never)
    const handler = ctx.handlers.get('tools/execute')![0] as (exec: unknown, next: () => unknown) => Promise<unknown>
    const r = await handler(
      { name: 'run_code', arguments: { code: 'console.log(1)' } },
      async () => ({ content: [{ type: 'image', data: 'x' }] }),
    ) as { content: { type: string; text?: string }[] }
    // 首元素是 text notes（此前 image 首元素时 notes 整体静默丢失）
    expect(r.content[0].type).toBe('text')
    expect(r.content[0].text).toContain('scan-error')
    expect(r.content[1].type).toBe('image')
  })
})

describe('round-4：C3 homedir 快照簇（改 process.env.HOME 无法重定向默认存储路径）', () => {
  it('stats/baseline/capabilities/forensics 默认目录在模块加载时定值', async () => {
    const oldHome = process.env.HOME
    // 先加载模块（快照真实 HOME），再改 HOME 验证路径不变
    const { vetStoreRoot } = await import('../lib/guard/store-root.js')
    const { statsPath } = await import('../lib/guard/stats.js')
    const { baselinePath } = await import('../lib/guards/content-baseline.js')
    const { capabilitiesPath } = await import('../lib/guard/version-diff.js')
    const { forensicsRoot } = await import('../lib/guard/forensics.js')
    const before = {
      stats: statsPath(), baseline: baselinePath(), caps: capabilitiesPath(), fx: forensicsRoot(),
    }
    try {
      // 模块加载后改 HOME：所有默认路径必须仍指向模块加载时解析出的根（0.3.15 起由 store-root 统一解析）
      process.env.HOME = join(tmpdir(), '.r4-fake-home-')
      const root = vetStoreRoot()
      expect(statsPath()).toBe(before.stats)
      expect(statsPath()).toBe(join(root, 'stats.json'))
      expect(baselinePath()).toBe(before.baseline)
      expect(baselinePath()).toBe(join(root, 'baseline.json'))
      expect(capabilitiesPath()).toBe(before.caps)
      expect(capabilitiesPath()).toBe(join(root, 'capabilities.json'))
      expect(forensicsRoot()).toBe(before.fx)
      expect(forensicsRoot()).toBe(join(root, 'forensics'))
    } finally {
      if (oldHome === undefined) delete process.env.HOME
      else process.env.HOME = oldHome
    }
  })

  it('生产口径（纯解析）：默认根 = <home>/.dsh/vet，与测试运行时无关', async () => {
    const { resolveStoreRoot } = await import('../lib/guard/store-root.js')
    // Windows 兼容：期望值用 join（resolveStoreRoot 内部用 join，win32 分隔符为 \）
    expect(resolveStoreRoot({ env: {}, home: '/home/real', isTestRuntime: false })).toBe(join('/home/real', '.dsh', 'vet'))
  })
})

describe('round-4：N6 损坏记录守卫（H2：单条坏记录不再瘫痪整包差分）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-r4-n6-'))
    setCapabilitiesDirForTest(dir)
  })
  afterEach(() => {
    setCapabilitiesDirForTest(undefined)
    rmSync(dir, { recursive: true, force: true })
  })

  it('diffManifests：prev/next 非对象 → 空差分不抛 TypeError', async () => {
    const vd = await import('../lib/guard/version-diff.js')
    const r = vd.diffManifests(undefined as never, { hosts: ['a.com'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })
    expect(r.added.hosts).toEqual([])
    expect(r.removed.hosts).toEqual([])
    const r2 = vd.diffManifests({ hosts: ['a.com'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false }, null as never)
    expect(r2.added.imports).toEqual([])
  })

  it('recordScan：prev 记录缺 capabilities 时差分不抛错、不瘫痪（守卫返回空差分）', async () => {
    const vd = await import('../lib/guard/version-diff.js')
    vd.saveCapabilities({ records: { '@x/bad@0.9.0': { name: '@x/bad', version: '0.9.0', recordedAt: Date.now(), capabilities: undefined as never } } })
    const outcome = vd.recordScan('@x/bad', '1.0.0', { hosts: ['a.com'], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })
    // 旧版存在（from 非 null）但差分按空处理（坏记录守卫）→ 不产生升级报警，不抛 TypeError
    expect(outcome.from).toBe('0.9.0')
    expect(outcome.added).not.toBeNull()
    expect(outcome.added!.hosts).toEqual([])
    expect(outcome.alarm).toBeNull()
    // 新记录照常写入（后续升级可正常差分）
    expect(vd.loadCapabilities().records['@x/bad@1.0.0']).toBeDefined()
  })
})