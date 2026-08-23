import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { extractTelemetryFields, diffTelemetry, snapshotTelemetryFields, installConfigDiff, homePatchPath } from '../lib/guard/config-diff.js'

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

function sha16(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 16)
}

function fakeStatus() {
  const records: { id: string; severity: string; kind: string; message: string }[] = []
  return {
    records,
    record: (r: { id: string; severity: string; kind: string; message: string }) => { records.push(r) },
  } as never
}

describe('Phase 3.2 遥测配置敏感化（G-3，round-13；round-15 适配 DSH 0.1.1-rc.2 row/home 层）', () => {
  let dir: string | undefined
  // 测试隔离：home 层固定为空临时目录（真实 ~/.dsh 不参与单测）；结束后还原
  const realHome = process.env.DSH_HOME
  beforeEach(() => { process.env.DSH_HOME = mkdtempSync(join(tmpdir(), 'vet-cd-home-')) })
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined
    const envHome = process.env.DSH_HOME
    if (envHome !== undefined) rmSync(envHome, { recursive: true, force: true })
    if (realHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = realHome
  })

  it('extractTelemetryFields：块状 + 深层键', () => {
    const f = extractTelemetryFields('telemetry:\n  exporter:\n    url: https://collect.example.com/v1\n    mode: FULL\nother: 1\n')
    expect(f.urlHash).toBeDefined()
    expect(f.urlHash!.length).toBe(16)
    expect(f.mode).toBe('FULL')
  })

  it('extractTelemetryFields：单行 flow 形态', () => {
    const f = extractTelemetryFields('telemetry: { enabled: true, exporter: { url: "https://x.example.com", mode: REDACTED } }\n')
    expect(f.urlHash).toBeDefined()
    expect(f.mode).toBe('REDACTED')
  })

  it('extractTelemetryFields：无 telemetry 块 → 空对象', () => {
    expect(extractTelemetryFields('a: 1\nb: 2\n')).toEqual({})
  })

  it('round-15：新 row 形态（session-telemetry-otel 块状 config）→ url/mode 提取', () => {
    const f = extractTelemetryFields(
      '- id: settings\n  config:\n    watch: false\n' +
      '- id: session-telemetry-otel\n  config:\n    mode: FULL\n    exporter:\n      url: "https://otel.example.com/v1/logs"\n' +
      '- id: plugin-vet\n  config:\n    requireAudit: true\n')
    expect(f.urlHash).toBeDefined()
    expect(f.urlHash!.length).toBe(16)
    expect(f.mode).toBe('FULL')
  })

  it('round-15：新 row 形态（config 单行 flow）→ url/mode 提取', () => {
    const f = extractTelemetryFields('- id: session-telemetry-otel\n  config: { mode: REDACTED, exporter: { url: "https://t.example.com" } }\n')
    expect(f.urlHash).toBeDefined()
    expect(f.mode).toBe('REDACTED')
  })

  it('round-15：telemetry row 禁用形态（disabled）→ 空对象', () => {
    expect(extractTelemetryFields('- id: session-telemetry-otel\n  disabled: true\n')).toEqual({})
  })

  it('round-15：非 telemetry row（settings/skills/webserver 含 !!js）→ 空对象', () => {
    expect(extractTelemetryFields(
      '- id: settings\n  config:\n    watch: false\n' +
      '- id: skill-filesystem\n  config:\n    watch: true\n' +
      '- id: webserver\n  config:\n    port: !!js ctx.webStartup.port ?? 3456\n' +
      '- id: insert-x\n  value: 1\n')).toEqual({})
  })

  it('round-15：home 层 $DSH_HOME/cordis.patch.yml 被读取且覆盖 profile 层', () => {
    dir = mkdtempSync(join(tmpdir(), 'vet-cd3-'))
    writeFileSync(join(dir, 'cordis.patch.yml'),
      '- id: session-telemetry-otel\n  config:\n    mode: FULL\n    exporter:\n      url: "https://profile.example.com"\n')
    writeFileSync(join(process.env.DSH_HOME!, 'cordis.patch.yml'),
      '- id: session-telemetry-otel\n  config:\n    mode: REDACTED\n    exporter:\n      url: "https://home.example.com"\n')
    const f = snapshotTelemetryFields(dir)
    expect(f).not.toBeNull()
    expect(f!.mode).toBe('REDACTED') // home 层优先（boot 应用序 profile → home）
    expect(f!.urlHash).not.toBe(sha16('https://profile.example.com'))
    expect(f!.urlHash).toBe(sha16('https://home.example.com'))
  })

  it('round-15：旧式 telemetry: 块仍兼容提取', () => {
    const f = extractTelemetryFields('telemetry:\n  exporter:\n    url: https://legacy.example.com\n    mode: FULL\n')
    expect(f.urlHash).toBe(sha16('https://legacy.example.com'))
    expect(f.mode).toBe('FULL')
  })

  it('diffTelemetry：冷启动（null）不报；url/mode 变化报对应字段', () => {
    const base = { urlHash: 'aaaa', mode: 'REDACTED' }
    expect(diffTelemetry(null, base)).toEqual([])
    expect(diffTelemetry(base, { ...base, urlHash: 'bbbb' })).toEqual(['exporter.url'])
    expect(diffTelemetry(base, { ...base, mode: 'FULL' })).toEqual(['exporter.mode'])
    expect(diffTelemetry(base, base)).toEqual([])
  })

  it('snapshotTelemetryFields：profile 目录读取 cordis.patch.yml；缺失 → null', () => {
    dir = mkdtempSync(join(tmpdir(), 'vet-cd-'))
    expect(snapshotTelemetryFields(dir)).toBeNull()
    writeFileSync(join(dir, 'cordis.patch.yml'), 'telemetry:\n  exporter:\n    url: https://c.example.com\n    mode: FULL\n')
    const f = snapshotTelemetryFields(dir)
    expect(f).not.toBeNull()
    expect(f!.mode).toBe('FULL')
  })

  it('installConfigDiff：冷启动无报警；url 变化 → yellow 记录；配置消失 → 静默', async () => {
    dir = mkdtempSync(join(tmpdir(), 'vet-cd2-'))
    const patch = join(dir, 'cordis.patch.yml')
    writeFileSync(patch, 'telemetry:\n  exporter:\n    url: https://a.example.com\n    mode: REDACTED\n')
    const status = fakeStatus()
    const disposer = installConfigDiff({ baseUrl: dir }, { telemetryDiff: true } as never, status, { intervalMs: 10, runNow: true })
    try {
      expect(status.records.length).toBe(0) // 冷启动只记录基线
      await sleep(30)
      expect(status.records.length).toBe(0) // 未变不报
      writeFileSync(patch, 'telemetry:\n  exporter:\n    url: https://evil.example.com\n    mode: FULL\n')
      await sleep(30)
      const changes = status.records.filter((r: { kind: string }) => r.kind === 'telemetry-config-change')
      expect(changes.length).toBe(2)
      // 隐私：message 含哈希前缀，不含完整 URL
      for (const c of changes) {
        expect(c.message).not.toContain('evil.example.com')
        expect(c.severity).toBe('yellow')
      }
      writeFileSync(patch, 'no telemetry at all\n')
      await sleep(30)
      const afterRemove = status.records.filter((r: { kind: string }) => r.kind === 'telemetry-config-change')
      expect(afterRemove.length).toBe(2) // 配置消失不新增报警
    } finally {
      disposer()
    }
  })

  it('installConfigDiff：telemetryDiff=false 不装；profileDir 缺失静默跳过', () => {
    const status = fakeStatus()
    const d1 = installConfigDiff({ baseUrl: dir }, { telemetryDiff: false } as never, status, { intervalMs: 10 })
    expect(d1).not.toBeUndefined()
    d1()
    const d2 = installConfigDiff({}, { telemetryDiff: true } as never, status, { intervalMs: 10 })
    d2() // 无 profileDir → noop disposer
  })

  it('round-15 复查：homePatchPath 与 launcher resolveDshHome 对齐（trim + ~ 展开）', () => {
    const real = process.env.DSH_HOME
    try {
      process.env.DSH_HOME = '   '
      expect(homePatchPath()).toBe(join(homedir(), '.dsh', 'cordis.patch.yml')) // 空白串=未设置 → ~/.dsh
      process.env.DSH_HOME = '~/my-dsh'
      expect(homePatchPath()).toBe(join(homedir(), 'my-dsh', 'cordis.patch.yml')) // ~ 展开
      process.env.DSH_HOME = '/tmp/vet-cd-abs'
      expect(homePatchPath()).toBe(join('/tmp/vet-cd-abs', 'cordis.patch.yml'))
    } finally {
      // 还原 beforeEach 注入的隔离值（afterEach 负责清理与还原环境）
      if (real === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = real
    }
  })
})