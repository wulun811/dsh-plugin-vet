import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { cacheKey, readCached, writeCached } from '../lib/scanner-bin/cache.js'
import { ENGINE_VERSION } from '../lib/scanner-bin/protocol.js'
import { setCapabilitiesDirForTest, capabilitiesPath } from '../lib/guard/version-diff.js'
import type { ScanRequest } from '../lib/scanner-bin/protocol.js'

const FIX = join(import.meta.dirname, 'fixtures')
const secretFixture = join(FIX, 'secret-in-plugin.js')

describe('0.1.16 加固——缓存反投毒与 env 快照（C3）', () => {
  describe('缓存 nonce 校验', () => {
    it('带 nonce 扫描：条目写入 nonce，同 nonce 二次命中', () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-nonce-'))
      try {
        const reqA: ScanRequest = { kind: 'files', files: [secretFixture], cacheDir: dir, cacheNonce: 'nonce-A' }
        const a = scan(reqA)
        expect(a.ok).toBe(true)
        expect(a.report!.verdict).toBe('suspicious')
        expect(readdirSync(dir).length).toBeGreaterThan(0)
        const b = scan(reqA)
        expect(b.report).toEqual(a.report)
      } finally { rmSync(dir, { recursive: true, force: true }) }
    })

    it('攻击者预写无 nonce 的伪造 clean 条目 → 被忽略并重扫（反缓存投毒）', () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-nonce-attack-'))
      try {
        // 攻击者同用户可读被扫描文件内容，能算出与 vet 相同的 cacheKey（key 不含 nonce，
        // 校验在条目内容：vet 读取时要求 parsed.nonce === 请求 nonce）
        const content = readFileSync(secretFixture, 'utf8')
        const key = cacheKey([{ path: secretFixture, content }], undefined, { runtime: 'host' })
        const forged = { report: { engine: ENGINE_VERSION, sourceCount: 1, findings: [], staticScore: 100, verdict: 'clean' } }
        require('node:fs').writeFileSync(join(dir, key + '.json'), JSON.stringify(forged))
        const res = scan({ kind: 'files', files: [secretFixture], cacheDir: dir, cacheNonce: 'nonce-A' })
        expect(res.report!.verdict).toBe('suspicious')
        expect(res.report!.findings.length).toBeGreaterThan(0)
      } finally { rmSync(dir, { recursive: true, force: true }) }
    })

    it('同内容不同 nonce：不命中对方条目，最终条目为后写入的 nonce', () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-nonce2-'))
      try {
        const reqA: ScanRequest = { kind: 'files', files: [secretFixture], cacheDir: dir, cacheNonce: 'A' }
        const reqB: ScanRequest = { kind: 'files', files: [secretFixture], cacheDir: dir, cacheNonce: 'B' }
        const a = scan(reqA)
        const b = scan(reqB)
        expect(b.report).toEqual(a.report)
        // key 相同（含内容哈希），final 条目是 B 的 nonce（A 条目被 B 扫描视为无效重扫后覆盖）
        const entries = readdirSync(dir)
        expect(entries.length).toBe(1)
        if (entries[0] !== undefined) {
          const raw = JSON.parse(readFileSync(join(dir, entries[0]), 'utf8')) as { nonce?: string }
          expect(raw.nonce).toBe('B')
        }
      } finally { rmSync(dir, { recursive: true, force: true }) }
    })
  })

  describe('存储目录 env 快照', () => {
    it('模块加载后恶意改 env 无效；setter 可覆盖与复位', () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-snap-'))
      try {
        setCapabilitiesDirForTest(dir)
        process.env.DSH_PLUGIN_VET_BASELINE_DIR = '/tmp/attacker-controlled'
        expect(capabilitiesPath()).toBe(join(dir, 'capabilities.json'))
        setCapabilitiesDirForTest(undefined)
        expect(capabilitiesPath()).not.toContain('attacker-controlled')
        expect(capabilitiesPath()).toBe(join(homedir(), '.dsh', 'vet', 'capabilities.json'))
      } finally {
        delete process.env.DSH_PLUGIN_VET_BASELINE_DIR
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })
})