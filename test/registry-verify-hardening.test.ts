import { describe, expect, it, vi } from 'vitest'
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { hashPackTarball, verifyAgainstRegistry } from '../lib/guards/registry-verify.js'

const execFileAsync = promisify(execFile)

/** 三轮审查回归：registry 对账解包与 tarball 来源加固。 */
describe('registry-verify 加固（三轮审查）', () => {
  it('良性 tarball 哈希不受成员预检影响', async () => {
    const stage = mkdtempSync(join(tmpdir(), 'vet-benign-'))
    try {
      mkdirSync(join(stage, 'package'), { recursive: true })
      writeFileSync(join(stage, 'package', 'index.js'), 'module.exports = {}')
      writeFileSync(join(stage, 'package', 'package.json'), '{"name":"benign","version":"1.0.0"}')
      await execFileAsync('tar', ['-czf', join(stage, 'b.tgz'), '-C', stage, 'package'])
      const buf = await import('node:fs').then(fs => fs.readFileSync(join(stage, 'b.tgz')))
      const hash = await hashPackTarball(buf)
      expect(hash).not.toBeNull()
      expect(hash).toMatch(/^[0-9a-f]{64}$/)
    } finally {
      rmSync(stage, { recursive: true, force: true })
    }
  })

  it.skipIf(process.platform === 'win32')("含 '../' 成员的恶意 tarball 被拒且不落盘到临时目录之外", async () => {
    const stage = mkdtempSync(join(tmpdir(), 'vet-evil-stage-'))
    const payloadDir = mkdtempSync(join(tmpdir(), 'vet-evil-payload-'))
    writeFileSync(join(payloadDir, 'marker.txt'), 'traversal')
    try {
      // GNU tar --transform 给所有成员名加 ../../ 前缀 → 构造字面 '../' 成员
      await execFileAsync('tar', [
        '-czf', join(stage, 'evil.tgz'), '-C', payloadDir,
        '--transform', 's|^|../../|', 'marker.txt',
      ])
      const buf = await import('node:fs').then(fs => fs.readFileSync(join(stage, 'evil.tgz')))
      const hash = await hashPackTarball(buf)
      expect(hash).toBeNull()
    } finally {
      rmSync(stage, { recursive: true, force: true })
      rmSync(payloadDir, { recursive: true, force: true })
    }
  })

  it("含反斜杠成员的 tarball 被拒（Windows bsdtar 路径分隔符转换面，四轮补口）", async () => {
    const stage = mkdtempSync(join(tmpdir(), 'vet-bslash-stage-'))
    const payloadDir = mkdtempSync(join(tmpdir(), 'vet-bslash-payload-'))
    try {
      // Linux 文件名允许字面反斜杠：'..\\..\\pwned.txt' 原样入档。GNU tar -tzf 列出字面名，
      // 预检按 includes('\\') 拒绝；Windows bsdtar 提取时会把 \\ 转成路径分隔符越界。
      writeFileSync(join(payloadDir, '..\\..\\pwned.txt'), 'traversal')
      await execFileAsync('tar', ['-czf', join(stage, 'evil.tgz'), '-C', payloadDir, '..\\..\\pwned.txt'])
      const buf = await import('node:fs').then(fs => fs.readFileSync(join(stage, 'evil.tgz')))
      const hash = await hashPackTarball(buf)
      expect(hash).toBeNull()
    } finally {
      rmSync(stage, { recursive: true, force: true })
      rmSync(payloadDir, { recursive: true, force: true })
    }
  })

  it('dist.tarball 主机越界 → unavailable，且不发起第二次 fetch', async () => {
    let calls = 0
    vi.stubGlobal('fetch', async () => {
      calls++
      return new Response(JSON.stringify({ dist: { tarball: 'https://evil.example/x.tgz' } }), { status: 200 })
    })
    try {
      const r = await verifyAgainstRegistry('@vet-test/hostile-tarball', '1.0.0', 2000)
      expect(r.status).toBe('unavailable')
      if (r.status === 'unavailable') expect(r.detail).toContain('主机越界')
      expect(calls).toBe(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })
})