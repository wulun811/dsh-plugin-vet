import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { patchModule, isStackTraceTampered, DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { confirmBlock, resetConfirmBlock, setCredentialHomeForTest } from '../lib/guard/confirm-block.js'
import type { HookAlarm } from '../lib/guard/runtime-hooks.js'

describe('0.1.16 加固——归因链防篡改（C4）', () => {
  let fakeHome: string
  const originalPrepare = Error.prepareStackTrace
  const originalLimit = Error.stackTraceLimit

  beforeEach(() => {
    fakeHome = mkdtempSync(join(tmpdir(), 'vet-home-'))
    // C3（review）：凭据清单基准 = 快照，测试经 setCredentialHomeForTest 覆写（改 env 已无效）
    setCredentialHomeForTest(fakeHome)
    resetConfirmBlock()
  })
  afterEach(() => {
    Error.prepareStackTrace = originalPrepare
    Error.stackTraceLimit = originalLimit
    setCredentialHomeForTest(undefined)
    resetConfirmBlock()
    rmSync(fakeHome, { recursive: true, force: true })
  })

  function makeMod(op: string) {
    const mod: Record<string, unknown> = {}
    mod[op] = function () { return 'OK' }
    return mod
  }

  it('isStackTraceTampered：默认 false；替换 prepareStackTrace / 压 stackTraceLimit → true；恢复 → false', () => {
    expect(isStackTraceTampered()).toBe(false)
    Error.prepareStackTrace = () => 'file:///proc/self/fd/999/node_modules/@deepseek-ai/evil/index.js:1:1'
    expect(isStackTraceTampered()).toBe(true)
    Error.prepareStackTrace = originalPrepare
    expect(isStackTraceTampered()).toBe(false)
    Error.stackTraceLimit = 0
    expect(isStackTraceTampered()).toBe(true)
    Error.stackTraceLimit = originalLimit
    expect(isStackTraceTampered()).toBe(false)
  })

  it('归因被篡改 + 敏感读 → 原报警照发 + 独立 attribution-tampered red', () => {
    const mod = makeMod('readFileSync')
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sink.push(a), () => new Map())
    try {
      Error.stackTraceLimit = 0
      mod.readFileSync('/home/u/.ssh/id_rsa')
      const kinds = sink.map(a => a.kind)
      expect(kinds).toContain('fs-read')
      expect(kinds).toContain('attribution-tampered')
      const tampered = sink.find(a => a.kind === 'attribution-tampered')!
      expect(tampered.severity).toBe('red')
      const fsRead = sink.find(a => a.kind === 'fs-read')!
      expect(fsRead.pluginHint).toBeUndefined() // 归因不可信：不取栈
    } finally { disp() }
  })

  it('S3：mid-loop 抛错（只读属性）→ 已包装操作回滚，无半包装残留（装配失败可清理）', () => {
    const unlink = (): string => 'u'
    const mod: Record<string, unknown> = {
      unlink, // DESTROY_OPS 先于 WRITE_OPS 处理 → unlink 会先被包装成功
      writeFileSync: () => 'w',
    }
    Object.defineProperty(mod, 'writeFileSync', { value: mod.writeFileSync, writable: false })
    expect(() => patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, () => {}, () => new Map())).toThrow(TypeError)
    // 已成功的 unlink 包装必须被回滚：函数身份 == 原始函数（否则残留包装且调用方拿不到 disposer）
    expect(mod.unlink).toBe(unlink)
    expect((mod.unlink as () => string)()).toBe('u')
    // 只读属性原样（回滚对它的赋值同样失败但不抛）
    expect((mod.writeFileSync as () => string)()).toBe('w')
  })

  it('归因被篡改 + 族2 凭据本体删除 → 照样拦截（哨兵身份）', () => {
    confirmBlock.setMode('block')
    const mod = makeMod('unlinkSync')
    const sink: HookAlarm[] = []
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sink.push(a), () => new Map(), () => {})
    try {
      Error.stackTraceLimit = 0
      const credPath = join(fakeHome, '.ssh', 'id_rsa')
      let threw: string | undefined
      try { mod.unlinkSync(credPath) } catch (e) { threw = String(e) }
      expect(threw).toBeDefined()
      expect(threw).toContain('vet 拦截（N7）')
      expect(sink.some(a => a.kind === 'n7-block')).toBe(true)
    } finally { disp() }
  })

  it('归因未被篡改：无 attribution-tampered 报警，归因正常', () => {
    const mod = makeMod('readFileSync')
    const sink: HookAlarm[] = []
    const roots = new Map<string, string>([[__dirname, 'fake-pkg']])
    const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, (a) => sink.push(a), () => roots)
    try {
      mod.readFileSync('/home/u/.ssh/id_rsa')
      expect(sink.some(a => a.kind === 'attribution-tampered')).toBe(false)
      const fr = sink.find(a => a.kind === 'fs-read')!
      expect(fr.pluginHint).toBe('fake-pkg')
    } finally { disp() }
  })
})