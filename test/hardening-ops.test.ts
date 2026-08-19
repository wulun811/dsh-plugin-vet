import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { patchModule, DEFAULT_HOOK_CONFIG, isSensitivePath } from '../lib/guard/runtime-hooks.js'
import { isSensitiveFsPath, saveCapabilities, loadCapabilities, consumeCapabilitiesTamper, setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { saveBaseline, loadBaseline, consumeBaselineTamper, setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { pidCmdlineIsVetSidecar, safeKillSidecar } from '../lib/guard/runtime-guard.js'
import { installInternalPluginGuard } from '../lib/guards/internal-plugin.js'
import { VetStatus } from '../lib/guard/status.js'
import { scan } from '../lib/scanner-bin/engine.js'
import type { HookAlarm } from '../lib/guard/runtime-hooks.js'
import type { ScanRequest } from '../lib/scanner-bin/protocol.js'

const manifestV = () => ({ hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false })

class FakeCtx {
  handlers = new Map<string, Function[]>()
  logger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }
  baseUrl?: string
  effect = (fn: () => unknown): (() => void) => { fn(); return () => {} }
  on(event: string, handler: Function): void {
    const list = this.handlers.get(event) ?? []
    list.push(handler)
    this.handlers.set(event, list)
  }
}

describe('0.1.16 加固——T2 操作面 / store 自检 / 段级匹配 / 侧车 PID / ESM 盲区（M5 M7 M8 M9 C2）', () => {
  describe('M5 T2 操作面扩充', () => {
    it('symlink/链接类操作进包装面：敏感首参 → fs-write', () => {
      const mod: Record<string, unknown> = { symlinkSync: () => 'OK' }
      const sink: HookAlarm[] = []
      const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
      try {
        mod.symlinkSync('/home/u/.ssh/id_rsa', '/tmp/x')
        expect(sink.some(a => a.kind === 'fs-write')).toBe(true)
        // 非敏感落点不报
        sink.length = 0
        mod.symlinkSync('/tmp/y', '/tmp/z')
        expect(sink).toEqual([])
      } finally { disp() }
    })
    it('chmod 放宽凭据文件权限 → fs-write', () => {
      const mod: Record<string, unknown> = { chmodSync: () => 'OK' }
      const sink: HookAlarm[] = []
      const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
      try {
        mod.chmodSync('/home/u/.ssh/id_rsa', 0o644)
        expect(sink.some(a => a.kind === 'fs-write')).toBe(true)
        sink.length = 0
        mod.chmodSync('/tmp/plain', 0o644)
        expect(sink).toEqual([])
      } finally { disp() }
    })
    it('mkdir 落位 /etc/cron.d → N7 族3 persistence-write', () => {
      const mod: Record<string, unknown> = { mkdirSync: () => 'OK' }
      const sink: HookAlarm[] = []
      const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
      try {
        mod.mkdirSync('/etc/cron.d/evil', { recursive: true })
        expect(sink.some(a => a.kind === 'persistence-write')).toBe(true)
      } finally { disp() }
    })
    it('lstat 敏感路径 → fs-probe（符号链接侦察面补齐）', () => {
      const mod: Record<string, unknown> = { lstatSync: () => 'OK' }
      const sink: HookAlarm[] = []
      const disp = patchModule(mod, 'fs', DEFAULT_HOOK_CONFIG, a => sink.push(a), () => new Map())
      try {
        mod.lstatSync('/home/u/.ssh')
        expect(sink.some(a => a.kind === 'fs-probe')).toBe(true)
      } finally { disp() }
    })
  })

  describe('M8 isSensitiveFsPath 段级匹配', () => {
    it('整段命中仍敏感', () => {
      expect(isSensitiveFsPath('~/.aws/credentials')).toBe(true)
      expect(isSensitiveFsPath('/home/u/.ssh/id_rsa')).toBe(true)
      expect(isSensitiveFsPath('/etc/passwd')).toBe(true)
    })
    it('宽泛子串不再误抬（旧实现子串命中全部 true）', () => {
      expect(isSensitiveFsPath('/app/my-credentials-manager/src/main.ts')).toBe(false)
      expect(isSensitiveFsPath('/var/log/application-credentials-rotation.log')).toBe(false)
      // shadow-utils 属段前缀命中（shadow-），与 T2 keyword 边界语义一致——记为已知轻微过报
      expect(isSensitiveFsPath('/home/user/shadow-utils/bin')).toBe(true)
    })
    it('边界命中保留：credentials-file（前缀段）与 foo.vault（后缀段）', () => {
      expect(isSensitiveFsPath('/app/credentials-file')).toBe(true)
      expect(isSensitiveFsPath('/home/x/foo.vault')).toBe(true)
    })
  })

  describe('M7 store 篡改自检', () => {
    let dir: string
    beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vet-tamper-')); setCapabilitiesDirForTest(dir); setBaselineDirForTest(dir) })
    afterEach(() => { setCapabilitiesDirForTest(undefined); setBaselineDirForTest(undefined); rmSync(dir, { recursive: true, force: true }) })
    it('自写后读取 → 无篡改；外部改写 → consumeCapabilitiesTamper true（一次性）', () => {
      saveCapabilities({ records: { a: { name: 'a', version: '1', recordedAt: 1, capabilities: manifestV() } } })
      loadCapabilities()
      expect(consumeCapabilitiesTamper()).toBe(false)
      writeFileSync(join(dir, 'capabilities.json'), JSON.stringify({ records: { evil: { name: 'evil', version: '9', recordedAt: 2, capabilities: manifestV() } } }))
      loadCapabilities()
      expect(consumeCapabilitiesTamper()).toBe(true)
      expect(consumeCapabilitiesTamper()).toBe(false)
    })
    it('baseline 同款自检', () => {
      saveBaseline({ records: { 'x@1': { name: 'x', version: '1', hash: 'h', recordedAt: 1 } } })
      loadBaseline()
      expect(consumeBaselineTamper()).toBe(false)
      writeFileSync(join(dir, 'baseline.json'), JSON.stringify({ records: { 'evil@9': { name: 'evil', version: '9', hash: 'evil', recordedAt: 9 } } }))
      loadBaseline()
      expect(consumeBaselineTamper()).toBe(true)
    })
  })

  describe('M9 侧车 PID 身份校验', () => {
    it.skipIf(process.platform === 'win32')('cmdline 含 vet-sidecar 才杀；非侧车进程拒绝终止（PID 复用保护）', () => {
      const sidecar = spawn(process.execPath, ['--vet-sidecar'], { stdio: 'ignore' })
      const pid1 = sidecar.pid!
      expect(pidCmdlineIsVetSidecar(pid1)).toBe(true)
      const killed = safeKillSidecar(pid1)
      expect(killed).toBe(true)
      const innocent = spawn(process.execPath, ['-e', 'setInterval(()=>{},1e9)'], { stdio: 'ignore' })
      const pid2 = innocent.pid!
      expect(pidCmdlineIsVetSidecar(pid2)).toBe(false)
      expect(safeKillSidecar(pid2)).toBe(false)
      innocent.kill()
    })
  })

  describe('C2 ESM 具名导入盲区标记 + 接线', () => {
    it('具名/命名空间导入内建危险模块 → capabilities.esmNamedBuiltins = true', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-esm-'))
      try {
        writeFileSync(join(dir, 'a.js'), "import { readFileSync } from 'node:fs'; import * as http from 'node:http'; readFileSync('/x')")
        const res = scan({ kind: 'files', files: [join(dir, 'a.js')] } as ScanRequest)
        expect(res.report!.capabilities?.esmNamedBuiltins).toBe(true)
        writeFileSync(join(dir, 'b.js'), "import fs from 'fs'; fs.readFileSync('/x')")
        const res2 = scan({ kind: 'files', files: [join(dir, 'b.js')] } as ScanRequest)
        expect(res2.report!.capabilities?.esmNamedBuiltins).toBe(false)
      } finally { rmSync(dir, { recursive: true, force: true }) }
    })
    it('internal/plugin 接线：runtimeGuard watch + esmNamedBuiltins → yellow esm-guard-coverage', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-esm-profile-'))
      const pkg = join(profile, 'node_modules', '@esm-test', 'pkg')
      mkdirSync(pkg, { recursive: true })
      writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@esm-test/pkg', version: '1.0.0', main: 'index.js' }))
      writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; export default 1")
      try {
        const ctx = new FakeCtx()
        ctx.baseUrl = profile
        const status = new VetStatus()
        installInternalPluginGuard(ctx as never, {
          mode: 'report', autoScan: true, scannerTimeoutMs: 15_000, rules: {}, denyOn: 'critical',
          allowlist: [], requireAudit: false, runtimeGuard: 'watch', runtimeIntervalMs: 2000,
          runtimeMemLimitMb: 2048, runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256,
          runtimeGrowthWindowMs: 600_000, osvCheck: false, honeypot: { enabled: false, dir: '' },
          contentBaseline: true, networkEgress: false, transitiveDeps: false, confirmBlock: 'block',
          confirmBlockFamily3: 'alarm', confirmBlockFamily4: 'alarm',
        } as never, status)
        const h = ctx.handlers.get('internal/plugin')![0]
        await h({ uid: 1, state: 0, dispose: vi.fn(async () => {}), entry: { options: { name: '@esm-test/pkg' } } })
        const alarms = status.snapshot().alarms
        expect(alarms.some(a => a.kind === 'esm-guard-coverage')).toBe(true)
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })
  })
})