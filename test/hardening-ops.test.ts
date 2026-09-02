import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { patchModule, DEFAULT_HOOK_CONFIG, isSensitivePath } from '../lib/guard/runtime-hooks.js'
import { isSensitiveFsPath, saveCapabilities, loadCapabilities, consumeCapabilitiesTamper, setCapabilitiesDirForTest } from '../lib/guard/version-diff.js'
import { setSummariesDirForTest } from '../lib/guard/scan-summaries.js'
import { saveBaseline, loadBaseline, consumeBaselineTamper, setBaselineDirForTest } from '../lib/guards/content-baseline.js'
import { setKnownBoundariesDirForTest } from '../lib/guard/known-boundaries.js'
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

  describe('C2 ESM 具名导入盲区标记 + 接线', () => {
    // round-20 review（测试写穿真实环境）：internal/plugin 接线用例会触发
    // recordScanSummary/recordVersionScan 写盘——不隔离 caps/summaries 就会把
    // @esm-test/pkg 写进真实 ~/.dsh/vet/（用户环境残留之一）。与 plugin.test.ts 同纪律。
    let sandbox: string
    beforeEach(() => {
      sandbox = mkdtempSync(join(tmpdir(), 'vet-esm-iso-'))
      setCapabilitiesDirForTest(join(sandbox, 'caps'))
      setSummariesDirForTest(join(sandbox, 'summaries'))
      // 0.3.3（P3）：known-boundaries 同样落 ~/.dsh/vet/——不隔离则 @esm-test/pkg
      // 记录跨进程残留（二次运行 isKnownBoundary=true → 不报警 → 接线断言失败）
      setKnownBoundariesDirForTest(join(sandbox, 'known'))
    })
    afterEach(() => {
      setCapabilitiesDirForTest(undefined)
      setSummariesDirForTest(undefined)
      setKnownBoundariesDirForTest(undefined)
      rmSync(sandbox, { recursive: true, force: true })
    })
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

  describe('0.3.3 官方信任锚级联 + 三方持久化去重（P1/P2/P3，警报疲劳反馈）', () => {
    // 官方包 first-seen 判定需写基线 → 隔离 baseline 与 known-boundaries 目录
    let sandbox: string
    beforeEach(async () => {
      sandbox = mkdtempSync(join(tmpdir(), 'vet-c2-iso-'))
      setCapabilitiesDirForTest(join(sandbox, 'caps'))
      setSummariesDirForTest(join(sandbox, 'summaries'))
      setBaselineDirForTest(join(sandbox, 'baseline'))
      setKnownBoundariesDirForTest(join(sandbox, 'known'))
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
      setKnownBoundariesDirForTest(undefined)
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

    it('官方包（first-seen）C2 边界 → info 观察而非黄色：跨包折叠一条、count 累计、不计入 alarmCount', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-c2-official-'))
      try {
        mkOfficial(profile, '@deepseek-ai/official-esm-a')
        mkOfficial(profile, '@deepseek-ai/official-esm-b')
        // 同一 guard 实例连续扫描两个官方包 → 同 mergeKey 折叠为一条并累计 count
        const status = new VetStatus()
        await fire(profile, '@deepseek-ai/official-esm-a', status)
        await fire(profile, '@deepseek-ai/official-esm-b', status)
        const snap = status.snapshot()
        const c2 = snap.alarms.filter(a => a.kind === 'esm-guard-coverage')
        expect(c2.length).toBe(1)
        expect(c2[0].severity).toBe('info')
        expect(c2[0].count).toBe(2) // 折叠计数：2 个官方包同一边界
        expect(c2[0].target).toBe('@deepseek-ai/official-esm-b') // 保留最近一个 target
        expect(snap.alarmCount).toBe(0) // info 不进警报计价
        expect(snap.level).toBe('green') // 不抬盾牌（无行为警报）
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })

    it('三方包 C2 边界 → 维持 yellow；同版本同能力重扫不重报（P3），能力差分变化重新报警', async () => {
      const profile = mkdtempSync(join(tmpdir(), 'vet-c2-p3-'))
      const pkg = join(profile, 'node_modules', '@vet-p3', 'pkg')
      mkdirSync(pkg, { recursive: true })
      writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@vet-p3/pkg', version: '1.0.0', main: 'index.js' }))
      writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; export default 1")
      try {
        // 第一次扫描 → yellow（新边界）
        const s1 = await fire(profile, '@vet-p3/pkg')
        const snap1 = s1.snapshot()
        const c2a = snap1.alarms.filter(a => a.kind === 'esm-guard-coverage')
        expect(c2a.length).toBe(1)
        expect(c2a[0].severity).toBe('yellow')
        expect(snap1.alarmCount).toBe(1)
        // 第二次扫描（同版本同能力，模拟重启复扫）→ 状态化去重：不重报
        const s2 = await fire(profile, '@vet-p3/pkg')
        const snap2 = s2.snapshot()
        expect(snap2.alarms.filter(a => a.kind === 'esm-guard-coverage').length).toBe(0)
        expect(snap2.alarmCount).toBe(0)
        // 能力差分变化（新增非内建具名导入 → capabilitiesHash 变；builtin 的 esmNamedBuiltins
        // 形态不变）→ 重新报警——「唯一有信息量的场景」照常新警
        writeFileSync(join(pkg, 'index.js'), "import { execSync } from 'node:child_process'; import { helper } from 'some-dep'; export default 1")
        const s3 = await fire(profile, '@vet-p3/pkg')
        const c2c = s3.snapshot().alarms.filter(a => a.kind === 'esm-guard-coverage')
        expect(c2c.length).toBe(1)
        expect(c2c[0].severity).toBe('yellow')
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })

    it('官方名但内容未验证（mismatch 未确认）→ 不享信任呈现：C2 仍按 yellow（检测层未关闭）', async () => {
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
        const snap = second.snapshot()
        // mismatch 未确认 → 不走 info 聚合；esmNamedBuiltins 命中仍按 yellow 报警（保守呈现）
        const c2 = snap.alarms.filter(a => a.kind === 'esm-guard-coverage')
        expect(c2.some(a => a.severity === 'yellow')).toBe(true)
      } finally { rmSync(profile, { recursive: true, force: true }) }
    })
  })
})