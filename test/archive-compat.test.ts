import { describe, expect, it, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { hasAuditRecord, setArchiveDirForTest, archiveDir } from '../lib/audit/archive.js'

/** 升级兼容：老格式（-yyyyMMddHHmmss.md 无中间 -）档案也能匹配，避免升级后 audit-required 误报。 */
describe('hasAuditRecord 新旧时间戳格式兼容（0.2.1）', () => {
  const dirs: string[] = []

  function tmpArchiveDir(): string {
    const d = mkdtempSync(join(tmpdir(), 'vet-arch-'))
    dirs.push(d)
    setArchiveDirForTest(d)
    return d
  }

  afterEach(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true })
    dirs.length = 0
  })

  it('新格式 -yyyyMMdd-HHmmss.md（带 -）匹配', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'deepseek-ai-dsh-client-connection-0.1.0-rc.8-20260821-073129.md'), '# record')
    expect(hasAuditRecord('@deepseek-ai/dsh-client-connection', '0.1.0-rc.8')).toBe(true)
  })

  it('旧格式 -yyyyMMddHHmmss.md（无 -）也匹配（升级兼容）', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'deepseek-ai-dsh-client-connection-0.1.0-rc.8-20260821073129.md'), '# record')
    expect(hasAuditRecord('@deepseek-ai/dsh-client-connection', '0.1.0-rc.8')).toBe(true)
  })

  it('本地文件路径插件：路径转义后匹配', () => {
    const d = tmpArchiveDir()
    // /home/me/.dsh/profiles/web/lan-uuid-polyfill.mjs → -home-me-.dsh-profiles-web-lan-uuid-polyfill.mjs
    writeFileSync(join(d, '-home-me-.dsh-profiles-web-lan-uuid-polyfill.mjs-1.0.0-20260821-073129.md'), '# record')
    expect(hasAuditRecord('/home/me/.dsh/profiles/web/lan-uuid-polyfill.mjs', '1.0.0')).toBe(true)
  })

  it('无版本时宽松匹配（版本段以数字开头）', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'deepseek-ai-dsh-client-connection-0.1.0-rc.8-20260821-073129.md'), '# record')
    expect(hasAuditRecord('@deepseek-ai/dsh-client-connection')).toBe(true)
  })

  it('M1 反前缀伪造：lodash-foo-… 不命中 lodash', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'lodash-foo-1.0.0-20260821-073129.md'), '# record')
    expect(hasAuditRecord('lodash', '1.0.0')).toBe(false)
  })

  it('错误命名（缺 scope 前缀）不匹配', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'dsh-client-connection-0.1.0-rc.8-20260821-073129.md'), '# record')
    expect(hasAuditRecord('@deepseek-ai/dsh-client-connection', '0.1.0-rc.8')).toBe(false)
  })
})

describe('round-22：宽松匹配防伪加固（digit 后缀包名不再冒认）', () => {
  const dirs: string[] = []

  function tmpArchiveDir(): string {
    const d = mkdtempSync(join(tmpdir(), 'vet-arch22-'))
    dirs.push(d)
    setArchiveDirForTest(d)
    return d
  }

  afterEach(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true })
    dirs.length = 0
  })

  it('aws-sdk-2 的档案不冒认 aws-sdk（旧规则「数字开头」误判：rest="2-3.1.0"）', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'aws-sdk-2-3.1.0-20260821-073129.md'), '# record')
    expect(hasAuditRecord('aws-sdk-2')).toBe(true) // 自己的档案照常命中
    expect(hasAuditRecord('aws-sdk')).toBe(false)  // digit 后缀兄弟包不得冒认（伪审计通过）
  })

  it('宽松模式仍需数字版本段：非数字前缀（lodash-foo-…）不命中', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'lodash-foo-1.0.0-20260821-073129.md'), '# record')
    expect(hasAuditRecord('lodash')).toBe(false)
  })

  it('预发布版本（1.0.0-beta.1，- 在数字段后）宽松命中不受影响', () => {
    const d = tmpArchiveDir()
    writeFileSync(join(d, 'deepseek-ai-dsh-client-connection-0.1.0-rc.8-20260821-073129.md'), '# record')
    expect(hasAuditRecord('@deepseek-ai/dsh-client-connection')).toBe(true)
  })
})
