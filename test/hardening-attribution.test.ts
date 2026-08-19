import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { patchModule, isStackTraceTampered, DEFAULT_HOOK_CONFIG } from '../lib/guard/runtime-hooks.js'
import { confirmBlock, resetConfirmBlock } from '../lib/guard/confirm-block.js'
import type { HookAlarm } from '../lib/guard/runtime-hooks.js'

describe('0.1.16 加固——归因链防篡改（C4）', () => {
  let fakeHome: string
  const originalPrepare = Error.prepareStackTrace
  const originalLimit = Error.stackTraceLimit

  beforeEach(() => {
    fakeHome = mkdtempSync(join(tmpdir(), 'vet-home-'))
    process.env.HOME = fakeHome
    resetConfirmBlock()
  })
  afterEach(() => {
    Error.prepareStackTrace = originalPrepare
    Error.stackTraceLimit = originalLimit
    delete process.env.HOME
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