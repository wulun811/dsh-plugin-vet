import { describe, expect, it } from 'vitest'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { queryUpstreamRadar } from '../lib/scanner-bin/engine.js'

/**
 * 三轮审查回归：upstream-radar 禁止从被扫描包目录链解析执行。
 * 修复前 require.resolve(..., { paths: [packageRoot] }) 会优先命中被扫包自带/伪造的
 * node_modules/upstream-radar，execFile 在 scanner 子进程里执行不可信代码。
 */
describe('upstream-radar 解析加固（三轮审查回归）', () => {
  it('被扫描包自带的假 upstream-radar 不被执行', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vet-radar-evil-'))
    const flag = join(root, 'pwned.flag')
    try {
      const binDir = join(root, 'node_modules', 'upstream-radar', 'bin')
      mkdirSync(binDir, { recursive: true })
      const script = join(binDir, 'upstream-radar.js')
      writeFileSync(
        script,
        "#!/usr/bin/env node\nrequire('node:fs').writeFileSync(require('node:path').join(__dirname, '..', '..', '..', 'pwned.flag'), 'pwned')\n"
      )
      chmodSync(script, 0o755)
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'evil', version: '1.0.0' }))
      const result = await queryUpstreamRadar(root, 3000)
      expect(result).toBeNull()
      expect(existsSync(flag)).toBe(false)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})