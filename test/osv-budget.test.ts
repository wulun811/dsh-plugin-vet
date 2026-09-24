import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scanWithOsv } from '../lib/scanner-bin/engine.js'
import type { ScanRequest } from '../lib/scanner-bin/protocol.js'

/**
 * P2-10：OSV 网络相位必须在宿主 kill 超时前结束——否则子进程被 SIGKILL → 扫描失败
 * （deny 模式 fail-closed 误拦合法包 / report 误报 scan-fail）。
 * 这组测试验证 scanWithOsv 的 OSV 总预算约束：逐查询超时按剩余预算动态收窄，超预算提前
 * break，整体耗时不超过预算。
 */

/** 慢速 fetch 实现：尊重 AbortSignal，被 abort 时 reject（模拟 OSV 服务端慢/超时）。 */
function slowFetch(delayMs: number): { impl: typeof fetch; calls: () => number } {
  let n = 0
  const impl = (async (_url: string, init?: { signal?: AbortSignal }) => {
    n++
    const signal = init?.signal
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(resolve, delayMs)
      signal?.addEventListener('abort', () => { clearTimeout(t); reject(new Error('aborted')) })
    })
    return {
      ok: true,
      json: async () => ({ vulns: [{ id: 'OSV-' + n, aliases: [], summary: 'vuln' }] }),
    } as unknown as Awaited<ReturnType<typeof fetch>>
  }) as unknown as typeof fetch
  return { impl, calls: () => n }
}

function makePkg(dir: string, depCount: number): string[] {
  const deps: Record<string, string> = {}
  for (let i = 0; i < depCount; i++) deps['dep-' + i] = '1.0.0' // 精确版本，参与 OSV
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0', dependencies: deps }))
  writeFileSync(join(dir, 'index.js'), 'module.exports = 1\n')
  return [join(dir, 'package.json'), join(dir, 'index.js')]
}

describe('OSV budget bounding (P2-10)', () => {
  it('OSV total time bounded by osvBudgetMs — no host-kill scan-failure', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    const files = makePkg(dir, 10) // 9 targets (pkg + 8 deps，directDepsOf 上限 8)
    const { impl, calls } = slowFetch(300) // 每查若不被 abort 将耗时 300ms
    const req: ScanRequest = { kind: 'files', files, osv: true, timeoutMs: 60_000 }
    const t0 = Date.now()
    const res = await scanWithOsv(req, { fetchImpl: impl, osvBudgetMs: 200 })
    const dt = Date.now() - t0
    rmSync(dir, { recursive: true, force: true })

    expect(res.ok).toBe(true)
    expect(res.report).toBeDefined()
    // 无预算时 9 × 300ms ≈ 2.7s；有 200ms 预算应远小于此
    expect(dt).toBeLessThan(2500)
    // 预算触发提前 break：并非全部 9 个目标都被查询
    expect(calls()).toBeLessThan(9)
  })

  it('large budget still queries all targets and returns findings', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    const files = makePkg(dir, 10) // 9 targets
    const { impl, calls } = slowFetch(5) // 快，但确认全量路径仍工作
    const req: ScanRequest = { kind: 'files', files, osv: true, timeoutMs: 60_000 }
    const res = await scanWithOsv(req, { fetchImpl: impl, osvBudgetMs: 5000 })
    rmSync(dir, { recursive: true, force: true })

    expect(res.ok).toBe(true)
    expect(calls()).toBe(9) // pkg + 8 deps（directDepsOf 上限 8）
    const osvFindings = res.report!.findings.filter(f => f.rule === 'OSV')
    expect(osvFindings.length).toBe(9)
  })

  it('osv disabled → no network calls, static-only ok', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    const files = makePkg(dir, 10)
    const { impl, calls } = slowFetch(300)
    const req: ScanRequest = { kind: 'files', files, osv: false, timeoutMs: 60_000 }
    const res = await scanWithOsv(req, { fetchImpl: impl, osvBudgetMs: 200 })
    rmSync(dir, { recursive: true, force: true })

    expect(res.ok).toBe(true)
    expect(calls()).toBe(0) // osv!==true 不触发 OSV 查询
  })

  // 0.3.14（用户实测回归：@deepseek-ai/dsh-mcp-client 重启首扫报
  // 「scanner timeout after 15000ms」scan-fail 黄牌）：P2-10 的预算算术默认 fetch 会响应
  // AbortSignal——DNS 卡在 threadpool / 代理吞连接 / 半开 socket 时 await 永不 settle，
  // 引擎挂死到宿主 kill。硬护栏（withHardTimeout）必须让引擎无论底层是否响应 abort 都在预算内返回。
  it('回归：fetch 永不 settle（abort 不生效）→ 硬护栏仍在预算内返回静态报告，不挂死', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    const files = makePkg(dir, 3)
    const neverSettles = (() => new Promise(() => {})) as unknown as typeof fetch
    const req: ScanRequest = { kind: 'files', files, osv: true, timeoutMs: 60_000 }
    const t0 = Date.now()
    const res = await scanWithOsv(req, { fetchImpl: neverSettles, osvBudgetMs: 300 })
    const dt = Date.now() - t0
    rmSync(dir, { recursive: true, force: true })

    expect(res.ok).toBe(true)
    expect(res.report).toBeDefined()
    expect(res.report!.verdict).toBe('clean') // 静态结果照常给出（OSV 静默降级）
    expect(dt).toBeLessThan(3000) // 旧行为：25s+ 不返回 → 宿主 SIGKILL → 整个扫描丢失
  })

  it('余量不足（宿主超时太小）→ 整段跳过 OSV：零网络调用，静态报告照常返回', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-osv-'))
    const files = makePkg(dir, 3)
    const { impl, calls } = slowFetch(5)
    const req: ScanRequest = { kind: 'files', files, osv: true, timeoutMs: 2000 }
    const t0 = Date.now()
    const res = await scanWithOsv(req, { fetchImpl: impl })
    const dt = Date.now() - t0
    rmSync(dir, { recursive: true, force: true })

    expect(res.ok).toBe(true)
    expect(calls()).toBe(0) // 余量 < OSV_MIN_BUDGET_MS → 不冒险贴 kill 线
    expect(dt).toBeLessThan(2000)
  })
})
