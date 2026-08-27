import { describe, expect, it, vi } from 'vitest'
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { hashPackTarball, verifyAgainstRegistry } from '../lib/guards/registry-verify.js'

const execFileAsync = promisify(execFile)

/** 手工构造含指定成员名的 ustar tarball（gzip）——macOS BSD tar 无 GNU --transform，
 * 跨平台同一构造；GNU/BSD tar -tvzf 均按字面列出成员名。 */
function makeMemberTgz(memberName: string, content: string): Buffer {
  const name = Buffer.from(memberName, 'utf8')
  const data = Buffer.from(content, 'utf8')
  const header = Buffer.alloc(512)
  name.copy(header, 0, 0, Math.min(name.length, 100))
  header.write('0000644\0', 100, 'ascii')
  header.write('0000000\0', 108, 'ascii')
  header.write('0000000\0', 116, 'ascii')
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 'ascii')
  header.write('00000000000\0', 136, 'ascii')
  header.fill(' ', 148, 156) // chksum 占位（空格）
  header.write('0', 156, 'ascii') // 普通文件
  header.write('ustar\0', 257, 'ascii')
  header.write('00', 263, 'ascii')
  let sum = 0
  for (let i = 0; i < 512; i++) sum += header[i]
  header.write(sum.toString(8).padStart(6, '0'), 148, 'ascii')
  header[154] = 0
  header[155] = 0x20
  const pad = data.length % 512 === 0 ? 0 : 512 - (data.length % 512)
  return gzipSync(Buffer.concat([header, data, Buffer.alloc(pad), Buffer.alloc(1024)]))
}

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
    try {
      // 手工构造字面 '../' 成员（../../marker.txt）——GNU --transform 是 Linux 专属，
      // macOS BSD tar 不支持；ustar 手工构造跨平台同一语义。
      const buf = makeMemberTgz('../../marker.txt', 'traversal')
      const hash = await hashPackTarball(buf)
      expect(hash).toBeNull()
    } finally {
      // 无临时目录需要清理（手工构造，未落盘）
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
      const body = JSON.stringify({ dist: { tarball: 'https://evil.example/x.tgz' } })
      return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
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