import { describe, expect, it } from 'vitest'
import { VetStatus } from '../src/guard/status.js'
import { analyzeSample, detectGrowth, type ProcSample, type RssSample, type WatchConfig } from '../src/guard/runtime-watch.js'
import {
  classifyOp, isSensitivePath, patchModule, pluginFromStack, DEFAULT_HOOK_CONFIG,
} from '../src/guard/runtime-hooks.js'
import { readHostMetrics } from '../src/guard/metrics.js'
import { ensureHoneypot, DEFAULT_HONEYPOT_DIR } from '../src/guard/honeypot.js'
import { registerStatusRouteOnce, writeRuntimeGuardConfig, readPatchRuntimeGuard } from '../src/guard/status-route.js'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const CFG: WatchConfig = { intervalMs: 2000, memLimitMb: 1024, forkBurstN: 5, fdLimit: 512, growthMb: 256, growthWindowMs: 600_000 }

function sample(partial: Partial<ProcSample>): ProcSample {
  return { rssKb: 512 * 1024, childCount: 0, fdCount: 10, at: Date.now(), ...partial }
}

describe('VetStatus（盾牌聚合器）', () => {
  it('green 初始态', () => {
    const s = new VetStatus()
    const snap = s.snapshot()
    expect(snap.level).toBe('green')
    expect(snap.alarmCount).toBe(0)
  })

  it('yellow 报警 → yellow；同 id 窗口内去重', () => {
    const s = new VetStatus({ dedupeWindowMs: 60_000 })
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: Date.now() }
    expect(s.record(alarm)).toBe('new')
    expect(s.record({ ...alarm, at: Date.now() + 1000 })).toBe('deduped')
    expect(s.snapshot().level).toBe('yellow')
    expect(s.snapshot().alarmCount).toBe(1)
  })

  it('red 报警压过 yellow → red', () => {
    const s = new VetStatus()
    s.record({ id: 'a', severity: 'yellow', source: 't2', kind: 'fs-write', message: 'y', at: Date.now() })
    s.record({ id: 'b', severity: 'red', source: 't1', kind: 'mem', message: 'r', at: Date.now() })
    expect(s.snapshot().level).toBe('red')
  })

  it('窗口外的同 id 重新报警', () => {
    const s = new VetStatus({ dedupeWindowMs: 10 })
    const alarm = { id: 't1:fd:512', severity: 'yellow' as const, source: 't1' as const, kind: 'fd', message: 'x', at: Date.now() - 1000 }
    expect(s.record(alarm)).toBe('new')
    expect(s.record({ ...alarm, at: Date.now() })).toBe('new')
    expect(s.snapshot().alarmCount).toBe(2)
  })

  it('alarmMax 环形截断', () => {
    const s = new VetStatus({ alarmMax: 3, dedupeWindowMs: 0 })
    for (let i = 0; i < 5; i++) {
      s.record({ id: `a${i}`, severity: 'yellow', source: 't2', kind: 'fs-write', message: `m${i}`, at: Date.now() + i })
    }
    expect(s.snapshot().alarmCount).toBe(3)
    expect(s.snapshot().alarms[0].id).toBe('a4')
  })

  it('noteScan suspicious → yellow 抬升', () => {
    const s = new VetStatus()
    expect(s.snapshot().level).toBe('green')
    s.noteScan({ pluginName: 'evil', verdict: 'suspicious', staticScore: 40, at: Date.now() })
    expect(s.snapshot().level).toBe('yellow')
    s.noteScan({ pluginName: 'good', verdict: 'clean', staticScore: 100, at: Date.now() })
    expect(s.snapshot().level).toBe('green')
  })
})

describe('analyzeSample（T1 差分判定）', () => {
  it('内存超限 → red', () => {
    const alarms = analyzeSample(null, sample({ rssKb: 2048 * 1024 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'mem' })
  })

  it('fork 突增 → red（prev 为 null 不误报）', () => {
    expect(analyzeSample(null, sample({ childCount: 20 }), CFG)).toHaveLength(0)
    const alarms = analyzeSample(sample({ childCount: 1 }), sample({ childCount: 20 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'red', kind: 'fork' })
  })

  it('fd 超限 → yellow', () => {
    const alarms = analyzeSample(null, sample({ fdCount: 600 }), CFG)
    expect(alarms).toHaveLength(1)
    expect(alarms[0]).toMatchObject({ severity: 'yellow', kind: 'fd' })
  })

  it('稳态无报警', () => {
    expect(analyzeSample(sample({}), sample({}), CFG)).toHaveLength(0)
  })
})

describe('detectGrowth（持续膨胀/疑似泄漏检测）', () => {
  const gcfg = { growthMb: 256, growthWindowMs: 600_000 }
  const s = (rssMb: number, at: number): RssSample => ({ rssKb: rssMb * 1024, at })

  it('窗口内净增长 < 阈值 → 不报警', () => {
    const samples = [s(200, 0), s(300, 60_000), s(400, 120_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('净增长越过 1 倍 → yellow growth，倍数更新', () => {
    const samples = [s(200, 0), s(300, 60_000), s(500, 120_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.alarms).toHaveLength(1)
    expect(r.alarms[0]).toMatchObject({ severity: 'yellow', kind: 'growth' })
    expect(r.alarms[0].message).toContain('持续膨胀')
    expect(r.multiples).toBe(1)
  })

  it('同倍数不重复报警（去重）', () => {
    const r = detectGrowth([s(200, 0), s(500, 120_000)], gcfg, 1)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(1)
  })

  it('回落归零重置倍数', () => {
    const r = detectGrowth([s(500, 0), s(200, 120_000)], gcfg, 2)
    expect(r.alarms).toHaveLength(0)
    expect(r.multiples).toBe(0)
  })

  it('窗口外的旧样本不参与（起点取窗口内）', () => {
    const samples = [s(900, 0), s(300, 700_000), s(600, 720_000)]
    const r = detectGrowth(samples, gcfg, 0)
    expect(r.multiples).toBe(1)
  })
})

describe('isSensitivePath / classifyOp（T2 分类）', () => {
  it('敏感路径判定', () => {
    expect(isSensitivePath('/etc/passwd', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etc', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/etcetera/foo', DEFAULT_HOOK_CONFIG)).toBe(false)
    expect(isSensitivePath('/home/user/.ssh/id_rsa', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/.env.local', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/user/project/src/index.ts', DEFAULT_HOOK_CONFIG)).toBe(false)
  })

  it('敏感路径删除 → red fs-destroy', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rmSync', args: ['/etc/hosts'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red', kind: 'fs-destroy' })
  })

  it('敏感路径写入 → yellow fs-write', () => {
    const alarm = classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/.npmrc', 'x'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-write' })
  })

  it('敏感路径读取 → yellow fs-read', () => {
    const alarm = classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/user/.ssh/id_ed25519'] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'yellow', kind: 'fs-read' })
  })

  it('普通路径写入不报警', () => {
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/home/user/a.txt', 'x'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('库名含 token 子串不误报（js-tokens 回归）', () => {
    // 旧规则：sensitiveSegments 子串匹配把合法库名 js-tokens 当敏感词
    expect(isSensitivePath('/home/chen/.npm-global/lib/node_modules/@deepseek-ai/dsh/node_modules/js-tokens/index.js', DEFAULT_HOOK_CONFIG)).toBe(false)
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/chen/.npm-global/lib/node_modules/@deepseek-ai/dsh/node_modules/js-tokens/index.js'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    // 沙箱清理临时文件（文件名带 js-tokens）也不该触发 fs-destroy
    expect(classifyOp({ module: 'fs', op: 'rmdir', args: ['/home/chen/1q/plugin-vet/scripts/._probe-js-tokens.mjs.4152567.abc.tmpdir'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('凭据语义路径仍报警（精度不丢）', () => {
    expect(isSensitivePath('/app/secrets.prod.yaml', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/creds/credentials.json', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/server.key', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/prod.env', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.aws/credentials', DEFAULT_HOOK_CONFIG)).toBe(true)
  })

  it('含 shell/下载关键词的子进程 → yellow spawn', () => {
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['curl http://x'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'yellow', kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['/bin/sh', ['-c', 'rm -rf /tmp/x']] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['wget', ['https://x/y']] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'spawn' })
  })

  it('常规子进程（git/node/pnpm）不报警', () => {
    expect(classifyOp({ module: 'child_process', op: 'spawn', args: ['git', ['status']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'execFile', args: ['node', ['server.js']] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(classifyOp({ module: 'child_process', op: 'exec', args: ['npm run build'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('读取系统根下普通文件不报警；写删仍报（read/mutate 分档）', () => {
    expect(isSensitivePath('/usr/lib/node_modules/foo/index.js', DEFAULT_HOOK_CONFIG, 'read')).toBe(false)
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/usr/lib/node_modules/foo/index.js'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
    expect(isSensitivePath('/usr/lib/node_modules/foo/index.js', DEFAULT_HOOK_CONFIG, 'mutate')).toBe(true)
    expect(classifyOp({ module: 'fs', op: 'writeFile', args: ['/usr/lib/node_modules/foo/index.js', 'x'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // /etc/passwd 由精确段名覆盖，读取仍报（枚举目标不漏）
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-read' })
    // 新增敏感名：.netrc / .pgpass / .gitconfig
    expect(isSensitivePath('/home/u/.netrc', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.pgpass', DEFAULT_HOOK_CONFIG)).toBe(true)
    expect(isSensitivePath('/home/u/.gitconfig', DEFAULT_HOOK_CONFIG)).toBe(true)
  })

  it('对象参数取 path', () => {
    const alarm = classifyOp({ module: 'fs', op: 'rm', args: [{ path: '/etc/passwd', recursive: true }] }, DEFAULT_HOOK_CONFIG)
    expect(alarm).toMatchObject({ severity: 'red' })
  })

  it('createWriteStream 写敏感路径 → yellow fs-write（D29 补漏：流式写入此前漏报）', () => {
    expect(classifyOp({ module: 'fs', op: 'createWriteStream', args: ['/home/user/.ssh/authorized_keys'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ severity: 'yellow', kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'createWriteStream', args: ['/home/user/log.txt'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })

  it('open 带写 flags → fs-write；只读 flags → fs-read（D29 补漏）', () => {
    expect(classifyOp({ module: 'fs', op: 'open', args: ['/etc/hosts', 'w'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'openSync', args: ['/home/u/.env', 'a+'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    expect(classifyOp({ module: 'fs', op: 'open', args: ['/etc/passwd', 'r'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-read' })
  })

  it('cp/rename 双向：src 敏感（拷密钥出局）或 dest 敏感（覆盖系统文件）都报（D29 补漏）', () => {
    // src 敏感：把 .env 拷出去
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/home/u/.env', '/tmp/stolen'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // dest 敏感：把恶意文件覆盖成 /etc/hosts
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/evil', '/etc/hosts'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // rename 落位系统路径
    expect(classifyOp({ module: 'fs', op: 'rename', args: ['/tmp/evil', '/etc/passwd'] }, DEFAULT_HOOK_CONFIG)).toMatchObject({ kind: 'fs-write' })
    // 普通 cp 不报
    expect(classifyOp({ module: 'fs', op: 'cpSync', args: ['/tmp/a.txt', '/tmp/b.txt'] }, DEFAULT_HOOK_CONFIG)).toBeNull()
  })
})

describe('pluginFromStack（栈归因）', () => {
  it('file:// 帧命中插件根 → 包名', () => {
    const roots = new Map([['/app/node_modules/evil-plugin/lib', 'evil-plugin']])
    const stack = 'Error\n    at wrapper (/app/node_modules/evil-plugin/lib/index.js:10:5)\n    at Object.<anonymous> (/app/main.js:1:1)'
    expect(pluginFromStack(stack, roots)).toBe('evil-plugin')
  })

  it('裸路径帧命中 → 包名；未命中 → undefined', () => {
    const roots = new Map([['/x/lib', '@scope/pkg']])
    expect(pluginFromStack('Error\n    at foo (/x/lib/a.js:1:1)', roots)).toBe('@scope/pkg')
    expect(pluginFromStack('Error\n    at foo (/other/b.js:1:1)', roots)).toBeUndefined()
  })

  it('空映射 / 空栈 → undefined', () => {
    expect(pluginFromStack(undefined, new Map())).toBeUndefined()
    expect(pluginFromStack('Error', new Map([['/x', 'x']]))).toBeUndefined()
  })
})

describe('patchModule（包装 + 恢复）', () => {
  it('危险操作报警、普通操作直通、disposer 恢复', () => {
    const calls: string[] = []
    const fake = {
      writeFile: (p: string) => { calls.push(`write:${p}`) },
      readFile: (p: string) => { calls.push(`read:${p}`) },
    }
    const alarms: string[] = []
    const dispose = patchModule(
      fake as unknown as Record<string, unknown>,
      'fs',
      DEFAULT_HOOK_CONFIG,
      a => { alarms.push(a.kind) },
      () => new Map(),
    )
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/home/user/.env')
    ;(fake as unknown as { readFile: (p: string) => void }).readFile('/home/user/a.txt')
    expect(alarms).toEqual(['fs-write'])
    expect(calls).toEqual(['write:/home/user/.env', 'read:/home/user/a.txt'])

    dispose()
    const restored = fake as unknown as Record<string, unknown>
    expect(restored.writeFile).toBeTypeOf('function')
    // 恢复后调用不再报警
    ;(fake as unknown as { writeFile: (p: string) => void }).writeFile('/etc/x')
    expect(alarms).toEqual(['fs-write'])
  })

  it('fs.promises 独立对象也被包装（Promise 调用同样报警）', async () => {
    const fakePromises = {
      readFile: async (p: string) => Buffer.from('x'),
      writeFile: async (p: string) => { },
    }
    const alarms: string[] = []
    const dispose = patchModule(
      fakePromises as unknown as Record<string, unknown>,
      'fs',
      DEFAULT_HOOK_CONFIG,
      a => { alarms.push(a.kind) },
      () => new Map(),
    )
    await (fakePromises as unknown as { readFile(p: string): Promise<Buffer> }).readFile('/home/user/.ssh/id_rsa')
    expect(alarms).toEqual(['fs-read'])
    await (fakePromises as unknown as { writeFile(p: string): Promise<void> }).writeFile('/home/user/.env')
    expect(alarms).toEqual(['fs-read', 'fs-write'])
    dispose()
  })
})

describe('readHostMetrics（宿主实时指标）', () => {
  it('Linux 下返回完整形状且字段在界内', () => {
    const m = readHostMetrics()
    expect(m.rssMb).toBeGreaterThanOrEqual(0)
    expect(m.cpuPct).toBeGreaterThanOrEqual(0)
    expect(m.ioReadMb).toBeGreaterThanOrEqual(0)
    expect(m.ioWriteMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpRssMb).toBeGreaterThanOrEqual(0)
    expect(m.mcpCount).toBeGreaterThanOrEqual(0)
    expect(m.vetRssMb).toBeGreaterThanOrEqual(0)
    expect(m.vetCount).toBeGreaterThanOrEqual(0)
    expect(m.childCount).toBeGreaterThanOrEqual(-1)
    expect(m.fdCount).toBeGreaterThanOrEqual(-1)
    expect(m.at).toBeGreaterThan(0)
  })
})

describe('writeRuntimeGuardConfig（profile 配置写入）', () => {
  const mkCtx = (baseUrl: string): { baseUrl: string; logger?: undefined } => ({ baseUrl })

  it('enable 写入条目 + 重复 enable 幂等 + disable 移除', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n  config:\n    watch: false\n')

    const ctx = mkCtx(dir)
    const r1 = writeRuntimeGuardConfig(ctx, true)
    expect(r1.ok).toBe(true)
    const content1 = readFileSync(patch, 'utf8')
    expect(content1).toContain('- id: plugin-vet')
    expect(content1).toContain('runtimeGuard: watch')

    const r2 = writeRuntimeGuardConfig(ctx, true) // 重复开启：重写而不是叠加，仍只有一条
    expect(r2.ok).toBe(true)
    const content2 = readFileSync(patch, 'utf8')
    expect(content2.match(/- id: plugin-vet/g)?.length).toBe(1)

    const r3 = writeRuntimeGuardConfig(ctx, false)
    expect(r3.ok).toBe(true)
    const content3 = readFileSync(patch, 'utf8')
    expect(content3).not.toContain('plugin-vet')
    expect(content3).toContain('- id: settings')

    rmSync(dir, { recursive: true, force: true })
  })

  it('旧形态包名条目（含引号）会被重写/移除（自愈）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n- id: "@jieai/dsh-plugin-vet"\n  config:\n    runtimeGuard: watch\n')

    const r1 = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r1.ok).toBe(true)
    const content1 = readFileSync(patch, 'utf8')
    expect(content1).toContain('- id: plugin-vet')
    expect(content1).not.toContain('@jieai/dsh-plugin-vet')

    const r2 = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r2.ok).toBe(true)
    const content2 = readFileSync(patch, 'utf8')
    expect(content2).not.toContain('plugin-vet')
    expect(content2).not.toContain('@jieai/dsh-plugin-vet')
    expect(content2).toContain('- id: settings')

    rmSync(dir, { recursive: true, force: true })
  })

  it('vet 条目 config 含嵌套列表也能完整剥离（D29：缩进边界）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: settings\n  config:\n    watch: false\n- id: plugin-vet\n  config:\n    runtimeGuard: watch\n    allowlist:\n      - foo\n      - bar\n- id: other\n  config:\n    x: 1\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content).not.toContain('plugin-vet')
    expect(content).not.toContain('allowlist')
    expect(content).toContain('- id: settings')
    expect(content).toContain('- id: other')
    expect(content).toContain('x: 1')
    rmSync(dir, { recursive: true, force: true })
  })

  it('未配置时 disable 返回 ok', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })

  it('baseUrl 为 file: URL 时正常读写（DSH web profile 实际形态）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    writeFileSync(join(dir, 'cordis.patch.yml'), '- id: settings\n')
    const r = writeRuntimeGuardConfig(mkCtx('file:' + dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('runtimeGuard: watch')
    const r2 = writeRuntimeGuardConfig(mkCtx('file:' + dir), false)
    expect(r2.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).not.toContain('plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 enable 直接新建', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r.ok).toBe(true)
    expect(readFileSync(join(dir, 'cordis.patch.yml'), 'utf8')).toContain('- id: plugin-vet')
    rmSync(dir, { recursive: true, force: true })
  })

  it('H1：disable 后文件只剩 vet 条目 → 写 []（DSH boot 契约，空文件会抛错）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    runtimeGuard: watch\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content.trim()).toBe('[]')

    rmSync(dir, { recursive: true, force: true })
  })

  it('H2：开启守卫保留已有 config 的非 runtimeGuard 键（deny/allowlist 不被冲掉）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    mode: deny\n    allowlist:\n      - foo\n')

    const r = writeRuntimeGuardConfig(mkCtx(dir), true)
    expect(r.ok).toBe(true)
    const content = readFileSync(patch, 'utf8')
    expect(content).toContain('mode: deny')
    expect(content).toContain('allowlist')
    expect(content).toContain('runtimeGuard: watch')

    rmSync(dir, { recursive: true, force: true })
  })

  it('M5：readPatchRuntimeGuard 读文件级实际状态（watch/off）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const patch = join(dir, 'cordis.patch.yml')
    expect(readPatchRuntimeGuard(mkCtx(dir))).toBe('off')
    writeFileSync(patch, '- id: plugin-vet\n  config:\n    runtimeGuard: watch\n')
    expect(readPatchRuntimeGuard(mkCtx(dir))).toBe('watch')
    rmSync(dir, { recursive: true, force: true })
  })

  it('patch 文件不存在时 disable 视为未开启', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-guard-test-'))
    const r = writeRuntimeGuardConfig(mkCtx(dir), false)
    expect(r.ok).toBe(true)
    rmSync(dir, { recursive: true, force: true })
  })
})

describe('registerStatusRouteOnce（webServer 就绪重试）', () => {
  it('webServer 未就绪 → false，不注册', () => {
    const routes: unknown[] = []
    const ctx = {
      baseUrl: '/tmp',
      get: () => undefined,
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'off' } as never, new VetStatus())
    expect(ok).toBe(false)
    expect(routes).toHaveLength(0)
  })

  it('webServer 就绪 → true，注册 /vet 前缀路由', () => {
    let handler: unknown
    const routes: unknown[] = []
    const ws = { register: (r: unknown) => { routes.push(r); return () => {} } }
    const ctx = {
      baseUrl: '/tmp',
      get: (name: string) => (name === 'webServer' ? ws : undefined),
      effect: (fn: () => unknown) => { fn() },
    } as never
    const ok = registerStatusRouteOnce(ctx as never, { runtimeGuard: 'watch' } as never, new VetStatus())
    expect(ok).toBe(true)
    expect(routes).toHaveLength(1)
    expect((routes[0] as { path: string }).path).toBe('/vet')
  })
})

describe('ensureHoneypot（蜜罐播种）', () => {
  it('创建诱饵文件集，内容/文件名无蜜罐关键词（反蜜罐）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-hp-data-'))
    const root = ensureHoneypot(dir)
    expect(root).toBe(dir)
    const names = ['id_rsa.pem', 'id_rsa.pub', '.env', 'credentials.json', '.npmrc', '.netrc', 'aws-credentials']
    for (const n of names) {
      expect(readFileSync(join(dir, n), 'utf8').length).toBeGreaterThan(10)
    }
    // 反蜜罐：文件名/内容都不该出现 honeypot/vet/decoy/fake 关键词
    for (const n of names) {
      expect(n).not.toMatch(/honeypot|vet|decoy|fake/i)
      expect(readFileSync(join(dir, n), 'utf8')).not.toMatch(/honeypot|vet[-_]|decoy|fake/i)
    }
    // RSA 诱饵是真实格式
    expect(readFileSync(join(dir, 'id_rsa.pem'), 'utf8')).toContain('BEGIN PRIVATE KEY')
    rmSync(dir, { recursive: true, force: true })
  })

  it('幂等：已存在诱饵不重写；被删诱饵自动重建', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-honeypot-'))
    ensureHoneypot(dir)
    const before = readFileSync(join(dir, '.env'), 'utf8')
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.env'), 'utf8')).toBe(before)
    // 用户预置文件不被覆盖
    writeFileSync(join(dir, '.env'), 'REAL=value')
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.env'), 'utf8')).toBe('REAL=value')
    // 被删诱饵重建（自愈）
    rmSync(join(dir, '.npmrc'))
    ensureHoneypot(dir)
    expect(readFileSync(join(dir, '.npmrc'), 'utf8').length).toBeGreaterThan(10)
    rmSync(dir, { recursive: true, force: true })
  })

  it('默认目录位于 ~/.dsh 下且无蜜罐关键词', () => {
    expect(DEFAULT_HONEYPOT_DIR).toContain('.dsh')
    expect(DEFAULT_HONEYPOT_DIR).toContain('.local')
    expect(DEFAULT_HONEYPOT_DIR).not.toMatch(/honeypot|vet|decoy|fake/i)
  })
})

describe('蜜罐报警（classifyOp）', () => {
  const mkCfg = (roots: string[]): typeof DEFAULT_HOOK_CONFIG => ({ ...DEFAULT_HOOK_CONFIG, honeypotRoots: roots })

  it('触碰诱饵路径 → 独立 honeypot 报警（读黄/删红）', () => {
    const dir = mkdtempSync(join(process.cwd(), '.tmp-honeypot-'))
    ensureHoneypot(dir)
    const cfg = mkCfg([dir])
    const read = classifyOp({ module: 'fs', op: 'readFileSync', args: [join(dir, '.env')] }, cfg)
    expect(read).toMatchObject({ kind: 'honeypot', severity: 'yellow' })
    const del = classifyOp({ module: 'fs', op: 'rmSync', args: [join(dir, 'credentials.json')] }, cfg)
    expect(del).toMatchObject({ kind: 'honeypot', severity: 'red' })
    const write = classifyOp({ module: 'fs', op: 'writeFile', args: [join(dir, '.npmrc'), 'x'] }, cfg)
    expect(write).toMatchObject({ kind: 'honeypot', severity: 'yellow' })
    rmSync(dir, { recursive: true, force: true })
  })

  it('未启用蜜罐（空蜜罐根）不产生 honeypot 报警；普通敏感路径仍按原规则', () => {
    const cfg = mkCfg([])
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/home/user/.ssh/id_rsa'] }, cfg)).toMatchObject({ kind: 'fs-read' })
    expect(classifyOp({ module: 'fs', op: 'readFileSync', args: ['/tmp/whatever/index.js'] }, cfg)).toBeNull()
  })
})
describe('sidecar 单例锁（D30 修漏：配置热重载重复 apply 不再叠加哨兵）', () => {
  // spawn 子进程需要真实可执行 JS：用编译产物（npm test = build + vitest；源码是 .ts 不能直接跑）
  const watchPath = fileURLToPath(new URL('../lib/guard/runtime-watch.js', import.meta.url))
  const args = [watchPath, '--vet-sidecar', '2000', '2048', '5', '512', '256', '600000']

  it('同宿主重复 spawn → 后者立即退出（exit 0），前者存活', async () => {
    const first = spawn(process.execPath, args, { stdio: 'ignore' })
    // 等第一个完成 exec（cmdline 可读）再 spawn 第二个，避免 /proc 竞态
    // 等 first 进入稳态（单例锁已通过、setInterval 已建立）再 spawn second——
    // 模拟生产时序：热重载时旧哨兵早已运行，新 spawn 的哨兵晚到 → 新自杀、旧存活。
    // 不能只等 exec：first 和 second 若几乎同时 exec 完，各自扫描都能看到对方 → 两个都自杀（测试竞态）。
    await new Promise((resolve) => setTimeout(resolve, 1000))
    const second = spawn(process.execPath, args, { stdio: 'ignore' })
    const code = await new Promise<number | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), 5000)
      second.on('exit', (c) => { clearTimeout(timer); resolve(c) })
    })
    expect(code).toBe(0) // 后者自杀退出
    // 前者还活着
    expect(first.exitCode).toBeNull()
    first.kill()
  })
})