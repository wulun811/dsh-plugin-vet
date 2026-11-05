import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { patchModule, DEFAULT_HOOK_CONFIG, isSensitivePath } from '../lib/guard/runtime-hooks.js'
import { isSensitiveFsPath, saveCapabilities, loadCapabilities, consumeCapabilitiesTamper, setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { saveBaseline, loadBaseline, consumeBaselineTamper, setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { brandVetHook, registerHookTarget, resetHookRegistry } from '../lib/guard/runtime-heartbeat.js'
import { setOfficialCatalogDirForTest, setCatalogAutoRefresh, refreshOfficialCatalogFromRegistry } from '../lib/guards/official-catalog.js'
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
    it('自写后读取 → 无篡改；外部改写 → consumeCapabilitiesTamper 返回证据（一次性）', () => {
      saveCapabilities({ records: { a: { name: 'a', version: '1', recordedAt: 1, capabilities: manifestV() } } })
      loadCapabilities()
      expect(consumeCapabilitiesTamper()).toBeNull()
      writeFileSync(join(dir, 'capabilities.json'), JSON.stringify({ records: { evil: { name: 'evil', version: '9', recordedAt: 2, capabilities: manifestV() } } }))
      loadCapabilities()
      // 0.3.15：返回证据对象（file + 改写方 writer 戳）而非 boolean；无戳 = 进程内篡改形态
      expect(consumeCapabilitiesTamper()).toMatchObject({ file: join(dir, 'capabilities.json'), foreign: null })
      expect(consumeCapabilitiesTamper()).toBeNull()
    })
    it('baseline 同款自检', () => {
      saveBaseline({ records: { 'x@1': { name: 'x', version: '1', hash: 'h', recordedAt: 1 } } })
      loadBaseline()
      expect(consumeBaselineTamper()).toBeNull()
      writeFileSync(join(dir, 'baseline.json'), JSON.stringify({ records: { 'evil@9': { name: 'evil', version: '9', hash: 'evil', recordedAt: 9 } } }))
      loadBaseline()
      expect(consumeBaselineTamper()).toMatchObject({ file: join(dir, 'baseline.json'), foreign: null })
    })
  })

  describe('M9 侧车 PID 身份校验', () => {
    it.skipIf(process.platform === 'win32')('cmdline 含 vet-sidecar 才杀；非侧车进程拒绝终止（PID 复用保护）', () => {
      // round-18 review（根因修复）：旧夹具 spawn(node, ['-e', script, '--vet-sidecar']) 里
      // flag 位于 -e 脚本之后 → 被 node 当**自身选项**解析 → bad option exit(9)，子进程从不存活；
      // 用例此前能过纯属僵尸窗口竞态（同步测试阻塞 libuv reaper，/proc/<pid>/cmdline 残读），
      // 全量并行下实测 flake。生产形态（runtime-guard.ts:304）是 [sidecarPath, '--vet-sidecar']
      // ——脚本路径在前、flag 是脚本 argv，选项解析器不碰。夹具与生产同构才是真验证。
      // 夹具目录/文件刻意不含 "vet-sidecar" 连续子串——innocent 的 cmdline 必须干净。
      const dir = mkdtempSync(join(tmpdir(), 'm9-fixture-'))
      const script = join(dir, 'keepalive.js')
      writeFileSync(script, 'setInterval(() => {}, 1e9)')
      const sidecar = spawn(process.execPath, [script, '--vet-sidecar'], { stdio: 'ignore' })
      const pid1 = sidecar.pid!
      let innocent: ReturnType<typeof spawn> | undefined
      // exec 完成前 /proc/<pid>/cmdline 尚无标记（并行负载下窗口可达数百 ms），轮询等待就绪
      // （同 QA-8 抖动吸收，预算 10s；就绪即出，正常路径 <100ms）。
      const deadline = Date.now() + 10_000
      const nap = new Int32Array(new SharedArrayBuffer(4))
      try {
        while (Date.now() < deadline && !pidCmdlineIsVetSidecar(pid1)) Atomics.wait(nap, 0, 0, 25)
        expect(pidCmdlineIsVetSidecar(pid1)).toBe(true)
        expect(safeKillSidecar(pid1)).toBe(true)
        innocent = spawn(process.execPath, [script], { stdio: 'ignore' })
        const pid2 = innocent.pid!
        expect(pidCmdlineIsVetSidecar(pid2)).toBe(false)
        expect(safeKillSidecar(pid2)).toBe(false)
      } finally {
        try { process.kill(pid1) } catch { /* 已随断言通过被杀或已退出（ESRCH） */ }
        try { innocent?.kill() } catch { /* 同上 */ }
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })

  describe('C2 ESM 具名导入盲区：从黄牌改成覆盖面行（0.5.3）', () => {
    // round-20 review（测试写穿真实环境）：internal/plugin 接线用例会触发
    // recordScanSummary/recordVersionScan 写盘——不隔离 caps/summaries 就会把
    // @esm-test/pkg 写进真实 ~/.dsh/vet/（用户环境残留之一）。与 plugin.test.ts 同纪律。
    let sandbox: string
    beforeEach(() => {
      sandbox = mkdtempSync(join(tmpdir(), 'vet-esm-iso-'))
      setCapabilitiesDirForTest(join(sandbox, 'caps'))
      setSummariesDirForTest(join(sandbox, 'summaries'))
      // 覆盖面里只把 partial 挂到**钩子真的在看**的面；测试进程没有装配运行时守卫，
      // 就手工登记一个完整的 child_process 钩子，模拟「运行时守卫在 watch」的真实状态。
      const execSync = (): void => {}
      brandVetHook(execSync)
      registerHookTarget('child_process', { execSync }, ['execSync'])
    })
    afterEach(() => {
      setCapabilitiesDirForTest(undefined)
      setSummariesDirForTest(undefined)
      resetHookRegistry()
      rmSync(sandbox, { recursive: true, force: true })
    })
    it('具名/命名空间导入内建危险模块 → capabilities.esmNamedBuiltins + 具体模块', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'vet-esm-'))
      try {
        writeFileSync(join(dir, 'a.js'), "import { readFileSync } from 'node:fs'; import * as http from 'node:http'; readFileSync('/x')")
        const res = scan({ kind: 'files', files: [join(dir, 'a.js')] } as ScanRequest)
        expect(res.report!.capabilities?.esmNamedBuiltins).toBe(true)
        // 0.5.3：布尔之外还要给出命中的模块——覆盖面靠它决定哪个执行面 partial
        expect(res.report!.capabilities?.esmNamedBuiltinModules).toEqual(['fs', 'http'])
        writeFileSync(join(dir, 'b.js'), "import fs from 'fs'; fs.readFileSync('/x')")
        const res2 = scan({ kind: 'files', files: [join(dir, 'b.js')] } as ScanRequest)
        expect(res2.report!.capabilities?.esmNamedBuiltins).toBe(false)
        // 默认导入不算盲区：它引用的是可被钩子 patch 的对象本身，模块清单也不该有它
        expect(res2.report!.capabilities?.esmNamedBuiltinModules ?? []).toEqual([])
      } finally { rmSync(dir, { recursive: true, force: true }) }
    })
    it('internal/plugin 接线：runtimeGuard watch + ESM 具名导入 → runtime_spawn partial，不再是黄牌', async () => {
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
        const snap = status.snapshot()
        // 黄牌退场：这条事实现在是这个主体运行时面上的 partial
        expect(snap.alarms.some(a => a.kind === 'esm-guard-coverage')).toBe(false)
        const spawn = snap.coverage.find(c => c.surface === 'runtime_spawn')!
        expect(spawn.result).toBe('partial')
        expect(spawn.reasons.join(',')).toContain('esm-named-import:child_process')
        // 只有真的被具名导入的那个面被标；fs 那一面没有钩子注册 → unknown，不许顺手标 partial
        expect(snap.coverage.find(c => c.surface === 'runtime_fs')!.result).toBe('unknown')
        // networkEgress:false → 明确不看，不是「没看过」
        expect(snap.coverage.find(c => c.surface === 'runtime_net')!.result).toBe('unsupported')
        expect(snap.coverage.find(c => c.surface === 'runtime_net')!.reasons).toContain('network-egress-off')
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })
  })

  describe('0.5.4：deny 同步路径的 OSV 是「明确没问」，不是「问了没答」', () => {
    let sandbox: string
    beforeEach(() => {
      sandbox = mkdtempSync(join(tmpdir(), 'vet-osv-deny-iso-'))
      setCapabilitiesDirForTest(join(sandbox, 'caps'))
      setSummariesDirForTest(join(sandbox, 'summaries'))
    })
    afterEach(() => {
      setCapabilitiesDirForTest(undefined)
      setSummariesDirForTest(undefined)
      rmSync(sandbox, { recursive: true, force: true })
    })
    it('mode=deny 不发网络请求 → intel_osv/deps_direct 都是 excluded osv-not-run-sync', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-osv-deny-profile-'))
      const pkg = join(profile, 'node_modules', '@osv-test', 'pkg')
      mkdirSync(pkg, { recursive: true })
      writeFileSync(join(pkg, 'package.json'), JSON.stringify({
        name: '@osv-test/pkg', version: '1.0.0', main: 'index.js', dependencies: { zod: '4.4.3' },
      }))
      writeFileSync(join(pkg, 'index.js'), 'module.exports = 1\n')
      try {
        const ctx = new FakeCtx()
        ctx.baseUrl = profile
        const status = new VetStatus()
        installInternalPluginGuard(ctx as never, {
          mode: 'deny', autoScan: true, scannerTimeoutMs: 15_000, rules: {}, denyOn: 'critical',
          allowlist: [], requireAudit: false, runtimeGuard: 'off', runtimeIntervalMs: 2000,
          runtimeMemLimitMb: 2048, runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256,
          runtimeGrowthWindowMs: 600_000, osvCheck: true, honeypot: { enabled: false, dir: '' },
          contentBaseline: true, networkEgress: true, transitiveDeps: false, confirmBlock: 'block',
          confirmBlockFamily3: 'alarm', confirmBlockFamily4: 'alarm',
        } as never, status)
        const h = ctx.handlers.get('internal/plugin')![0]
        await h({ uid: 1, state: 0, dispose: vi.fn(async () => {}), entry: { options: { name: '@osv-test/pkg' } } })
        const snap = status.snapshot()
        // P2-7：deny 的同步路径刻意不做网络查询——那是「明确没问」，与「问了没回报」不是一个事实。
        // 旧实现把两者混成同一格 partial + osv-outcome-not-reported，等于说错了原因。
        for (const surface of ['intel_osv', 'deps_direct'] as const) {
          const row = snap.coverage.find((c) => c.surface === surface)!
          expect(row.result, surface).toBe('excluded')
          expect(row.reasons, surface).toContain('osv-not-run-sync')
          expect(row.reasons, surface).not.toContain('osv-outcome-not-reported')
        }
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })
  })

  describe('C2 边界的呈现分级：官方内容锚 acknowledged、未验证与三方未承认（0.5.3）', () => {
    // 官方包 first-seen 判定需写基线 → 隔离 baseline 目录
    let sandbox: string
    beforeEach(async () => {
      sandbox = mkdtempSync(join(tmpdir(), 'vet-c2-iso-'))
      setCapabilitiesDirForTest(join(sandbox, 'caps'))
      setSummariesDirForTest(join(sandbox, 'summaries'))
      setBaselineDirForTest(join(sandbox, 'baseline'))
      // 覆盖面只把 partial 挂到钩子真的在看的面上——模拟运行时守卫已装配（见上组用例说明）
      const execSync = (): void => {}
      brandVetHook(execSync)
      registerHookTarget('child_process', { execSync }, ['execSync'])
      // 0.3.5（M2）：夹具官方名（official-esm-a/b）不在种子目录 → 先以注入 fetch 并入覆盖层
      // 视为目录内官方；随后关闭自动核对并 stub 全局出网（首见验证走 verifyAgainstRegistry，
      // 测试环境禁止真实 fetch）。
      setOfficialCatalogDirForTest(join(sandbox, 'ocat'))
      await refreshOfficialCatalogFromRegistry(async () => {
        const body = JSON.stringify({ objects: ['@deepseek-ai/official-esm-a', '@deepseek-ai/official-esm-b'].map(n => ({ package: { name: n } })) })
        return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } })
      })
      setCatalogAutoRefresh(false)
      vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('test: no network') }))
    })
    afterEach(() => {
      setCapabilitiesDirForTest(undefined)
      setSummariesDirForTest(undefined)
      setBaselineDirForTest(undefined)
      resetHookRegistry()
      setOfficialCatalogDirForTest(undefined)
      setCatalogAutoRefresh(true)
      vi.unstubAllGlobals()
      rmSync(sandbox, { recursive: true, force: true })
    })
    const CFG = {
      mode: 'report', autoScan: true, scannerTimeoutMs: 15_000, rules: {}, denyOn: 'critical',
      allowlist: [], requireAudit: false, runtimeGuard: 'watch', runtimeIntervalMs: 2000,
      runtimeMemLimitMb: 2048, runtimeForkBurstN: 5, runtimeFdLimit: 512, runtimeGrowthMb: 256,
      runtimeGrowthWindowMs: 600_000, osvCheck: false, honeypot: { enabled: false, dir: '' },
      contentBaseline: true, networkEgress: false, transitiveDeps: false, confirmBlock: 'block',
      confirmBlockFamily3: 'alarm', confirmBlockFamily4: 'alarm', acknowledgedPackageHashes: {},
    }
    const mkOfficial = (profile: string, name: string): string => {
      const pkg = join(profile, 'node_modules', name.replace('/', '/'))
      mkdirSync(pkg, { recursive: true })
      writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name, version: '1.0.0', main: 'index.js' }))
      writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; export default 1")
      return pkg
    }
    const fire = async (profile: string, entryName: string, withStatus?: VetStatus): Promise<VetStatus> => {
      const ctx = new FakeCtx()
      ctx.baseUrl = profile
      const status = withStatus ?? new VetStatus()
      installInternalPluginGuard(ctx as never, CFG as never, status)
      const h = ctx.handlers.get('internal/plugin')![0]
      await h({ uid: 1, state: 0, dispose: vi.fn(async () => {}), entry: { options: { name: entryName } } })
      return status
    }

    it('官方包（first-seen）C2 边界 → 覆盖面 partial + acknowledged，不出警报、不抬盾牌', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-c2-official-'))
      try {
        mkOfficial(profile, '@deepseek-ai/official-esm-a')
        mkOfficial(profile, '@deepseek-ai/official-esm-b')
        const status = new VetStatus()
        await fire(profile, '@deepseek-ai/official-esm-a', status)
        await fire(profile, '@deepseek-ai/official-esm-b', status)
        const snap = status.snapshot()
        // 0.5.3：不再有 esm-guard-coverage 行——它现在就是覆盖面里的一行 runtime_spawn
        expect(snap.alarms.filter(a => a.kind === 'esm-guard-coverage').length).toBe(0)
        expect(snap.alarmCount).toBe(0)
        expect(snap.level).toBe('green')
        const spawn = snap.coverage.find(c => c.surface === 'runtime_spawn')!
        expect(spawn.result).toBe('partial')
        expect(spawn.reasons.join(',')).toContain('esm-named-import:child_process')
        expect(spawn.acknowledged).toBe(true) // 官方内容锚 = 已知架构边界，不是新风险
        expect(spawn.subject).toBeDefined() // 多主体聚合必须写清这行出自谁
        expect(snap.coverageSubjects).toBe(2)
        expect(snap.coverageSubject).toBeUndefined() // 多主体时不许拿一个包的名字冒充全体
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })

    it('三方包 C2 边界 → 未承认的 partial；重扫照旧（状态不是事件，不需要去重机制）', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-c2-p3-'))
      const pkg = join(profile, 'node_modules', '@vet-p3', 'pkg')
      mkdirSync(pkg, { recursive: true })
      writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@vet-p3/pkg', version: '1.0.0', main: 'index.js' }))
      writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; export default 1")
      try {
        const s1 = await fire(profile, '@vet-p3/pkg')
        const snap1 = s1.snapshot()
        const row1 = snap1.coverage.find(c => c.surface === 'runtime_spawn')!
        expect(row1.result).toBe('partial')
        expect(row1.acknowledged).toBeUndefined() // 三方未审计 = 没被承认为架构边界
        expect(row1.subject).toBe('@vet-p3/pkg')
        expect(snap1.coverageSubject).toBe('@vet-p3/pkg') // 单主体：写明是谁的九行
        expect(snap1.coverageSubjects).toBeUndefined()
        expect(snap1.alarms.filter(a => a.kind === 'esm-guard-coverage').length).toBe(0)
        // 同版本同能力重扫 → 结论照旧。旧实现靠 known-boundaries 落盘做「不重报」，
        // 现在没有可重报的东西：一行状态每次都在，本来就不打扰人。
        const s2 = await fire(profile, '@vet-p3/pkg')
        const row2 = s2.snapshot().coverage.find(c => c.surface === 'runtime_spawn')!
        expect(row2.result).toBe('partial')
        expect(row2.acknowledged).toBeUndefined()
        // 能力变化（多一个第三方具名导入）→ 仍不是警报；唯一的变化源是覆盖面本身
        writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; import { helper } from 'some-dep'; export default 1")
        const s3 = await fire(profile, '@vet-p3/pkg')
        expect(s3.snapshot().alarms.filter(a => a.kind === 'esm-guard-coverage').length).toBe(0)
        expect(s3.snapshot().coverage.find(c => c.surface === 'runtime_spawn')!.result).toBe('partial')
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })

    it('官方名但内容未验证（mismatch 未确认）→ 不享信任呈现：partial 但未承认', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-c2-mismatch-'))
      try {
        mkOfficial(profile, '@deepseek-ai/mismatch-esm')
        // 先手预植基线：同一版本不同 hash → classifyOfficial 判 mismatch（未登记 ack）→ 非 exempt
        const first = await fire(profile, '@deepseek-ai/mismatch-esm')
        // 改内容 → 与基线不一致 → mismatch（report 模式异步对账 registry 会失败，红警路径）
        const pkg = join(profile, 'node_modules', '@deepseek-ai', 'mismatch-esm')
        writeFileSync(join(pkg, 'index.js'), "import { execSync, readFileSync } from 'node:child_process'; export default 1")
        const second = await fire(profile, '@deepseek-ai/mismatch-esm')
        void first
        const spawn = second.snapshot().coverage.find(c => c.surface === 'runtime_spawn')!
        expect(spawn.result).toBe('partial')
        // 身份未核实就享「已知边界」待遇，等于用名字换信任——这一档必须保持未承认
        expect(spawn.acknowledged).toBeUndefined()
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })
  })
})