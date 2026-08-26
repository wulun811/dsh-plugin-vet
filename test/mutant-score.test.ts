import { describe, expect, it } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * 变异语料击杀率门禁（阶段 B）：
 * - 恶意 mutants 必须全杀（kill 100%）——survivor 必须补规则或从语料除名（带理由）
 * - 良性 controls 必须 0 误杀（precision 反项）
 * - 评测失败（scan 异常）按 fail-closed 处理
 * 语料权威登记表：test/mutants.manifest.json；评测面与 plugins-matrix 同一引擎入口。
 */
describe('mutant-score 击杀率门禁', () => {
  it('--gate：恶意全杀 + 良基全净 + 无评测失败', () => {
    const res = spawnSync(process.execPath, ['scripts/mutant-score.mjs', '--gate'], {
      cwd: ROOT, encoding: 'utf8', timeout: 120_000,
    })
    expect(res.status).toBe(0)
    expect(res.stdout).toMatch(/击杀率: \d+\/\d+ \(100%\)/)
    expect(res.stdout).toMatch(/良性对照组 retained: 0\/\d+/)
    expect(res.stdout).toMatch(/mutant gate OK/)
  })

  it('manifest 语料文件全部存在（防登记幽灵条目）', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'test', 'mutants.manifest.json'), 'utf8'))
    const refs = [
      ...(manifest.mutants ?? []).flatMap(m => m.refs ?? []),
      ...(manifest.controls ?? []).flatMap(c => c.refs ?? []),
    ]
    expect(refs.length).toBeGreaterThan(0)
    for (const ref of refs) {
      expect(existsSync(join(ROOT, ref)), `语料缺失: ${ref}`).toBe(true)
    }
  })
})