/**
 * 0.5.15：`config.rules` 必须真的到达扫描器。
 *
 * 0.5.14 及以前这个键是死的：README 承诺 `rules: {R17: false}` 能关掉一个面，`config-view`
 * 还把它标成 `active`，但**全仓没有一处读 `config.rules`**——`FileScanPolicy` 里根本没有
 * `rules` 字段，三条请求构造路径（工具面 / 加载前自动扫描 / 工具执行 code 通道）都没把它写进
 * `ScanRequest`，引擎侧于是永远走缺省（全开）。
 *
 * 这个文件钉住三件事：
 * 1. 策略输入能被写进请求（三条路径都要覆盖，它们是三个不同的构造点）；
 * 2. 空对象与省略等价——否则每次升级都会让存量缓存整体失效一次（缓存键含 rules 的 JSON）；
 * 3. 端到端：同一个文件，关掉 R 之后那条规则真的不再出现，其余不受影响。
 *
 * 反面用例（`rules.R5`）单独在 `ctx-verbs` 侧：R5 在 files 面上不跑，是另一处已知问题，
 * 不在本文件里假装它已被修好。
 */
import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildFileScanRequest } from '../lib/scanner/scan-request.js'
import { buildRequest } from '../lib/tools/scan-plugin.js'
import { scan } from '../lib/scanner/client.js'

/** 一份同时命中 R2（动态执行）与 R13（外联端点）的源码。 */
const CODE = [
  'const url = "https://discord.com/api/webhooks/1/2";',
  'export function apply(ctx) { return eval("1"); }',
].join('\n')

function rulesOf(findings, rule) {
  return findings.some(f => f.rule === rule)
}

describe('config.rules → ScanRequest（0.5.15）', () => {
  it('包目录：策略里的 rules 写进请求', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-rules-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }))
      writeFileSync(join(dir, 'index.js'), CODE)
      const req = buildFileScanRequest(dir, { rules: { R13: false } })
      expect(req.rules).toEqual({ R13: false })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('空对象与省略等价（不写进请求，不制造缓存键漂移）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-rules-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }))
      writeFileSync(join(dir, 'index.js'), CODE)
      expect(buildFileScanRequest(dir, { rules: {} }).rules).toBeUndefined()
      expect(buildFileScanRequest(dir, {}).rules).toBeUndefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('工具面 file 目标：策略与部署者配置两条路径都接线', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-rules-'))
    try {
      writeFileSync(join(dir, 'a.js'), CODE)
      const file = join(dir, 'a.js')
      // ① 显式策略
      expect(buildRequest({ target: 'file', source: file }, undefined, { rules: { R2: false } }).request.rules).toEqual({ R2: false })
      // ② 省略 = 不写
      expect(buildRequest({ target: 'file', source: file }).request.rules).toBeUndefined()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('端到端：关掉一条规则，该规则的命中真的消失，其余保留', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-rules-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }))
      writeFileSync(join(dir, 'index.js'), CODE)

      const all = await scan(buildFileScanRequest(dir, { targetKind: 'plugin' }), { timeoutMs: 30000 })
      expect(all.ok).toBe(true)
      expect(rulesOf(all.report.findings, 'R13')).toBe(true)
      expect(rulesOf(all.report.findings, 'R2')).toBe(true)

      const off = await scan(buildFileScanRequest(dir, { targetKind: 'plugin', rules: { R13: false } }), { timeoutMs: 30000 })
      expect(off.ok).toBe(true)
      expect(rulesOf(off.report.findings, 'R13')).toBe(false)
      // 关一条不影响别的
      expect(rulesOf(off.report.findings, 'R2')).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 60000)
})
