import { describe, expect, it, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setDismissedFileForTest, persistentlyDismiss } from '../lib/guard/dismissed-alerts.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const dirs: string[] = []
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'vet-round6-'))
  dirs.push(d)
  return d
}
afterEach(() => {
  for (const d of dirs) {
    try { rmSync(d, { recursive: true, force: true }) } catch { /* 忽略 */ }
  }
  dirs.length = 0
})

/**
 * round-6 review 回归：
 * 1. dismissed-alerts 原子写 rename 失败时清理 tmp 残件（旧实现在 ~/.dsh/vet 留永久垃圾）
 * 2. mutant-score 对畸形 manifest fail-closed（结构非法 exit 2 / 单条评测失败进清单 exit 1）
 */
describe('review round-6', () => {
  it('dismissed 原子写：rename 失败不残留 .tmp.* 文件', () => {
    const dir = tmp()
    // 目标路径是一个目录 → writeFileSync(tmp) 成功、renameSync(tmp → 目录) 必失败（EISDIR）
    const blocked = join(dir, 'blocked')
    mkdirSync(blocked)
    setDismissedFileForTest(blocked)
    persistentlyDismiss('alarm-1', 'round6-tmp-residue')
    const residue = readdirSync(dir).filter(n => n.includes('.tmp.'))
    expect(residue).toEqual([])
    setDismissedFileForTest(join(dir, 'dismissed.json'))
  })

  it('mutant-score：manifest 结构非法 → exit 2（fail-closed，不产出误导报告）', () => {
    const dir = tmp()
    const bad = join(dir, 'bad.manifest.json')
    writeFileSync(bad, JSON.stringify({ mutants: [{ id: '', refs: [] }] }), 'utf8')
    const res = spawnSync(process.execPath, ['scripts/mutant-score.mjs', '--gate'], {
      cwd: ROOT,
      env: { ...process.env, VET_MUTANT_MANIFEST: bad },
      encoding: 'utf8',
      timeout: 60_000,
    })
    expect(res.status).toBe(2)
    expect(res.stderr).toMatch(/manifest 结构非法/)
  })

  it('mutant-score：语料缺失的单条评测失败 → 进 errors 清单且 gate exit 1（不崩脚本）', () => {
    const dir = tmp()
    const missing = join(dir, 'missing.manifest.json')
    writeFileSync(missing, JSON.stringify({
      $comment: '单条条目合法但语料文件不存在',
      mutants: [{
        id: 'MX99', name: '幽灵语料', evasion: 'probe', layer: 'static',
        kind: 'files', refs: [join(dir, 'no-such.fixture.js')],
        expect: { rules: ['R1'] }, origin: 'test',
      }],
      controls: [],
    }), 'utf8')
    const res = spawnSync(process.execPath, ['scripts/mutant-score.mjs', '--gate', '--json', join(dir, 'out.json')], {
      cwd: ROOT,
      env: { ...process.env, VET_MUTANT_MANIFEST: missing },
      encoding: 'utf8',
      timeout: 60_000,
    })
    expect(res.status).toBe(1)
    expect(res.stdout).toMatch(/评测失败 MX99/)
    expect(res.stdout).toMatch(/语料文件不存在/)
    expect(res.stdout).not.toMatch(/ReferenceError|TypeError|at /)
  })

  it('权威 manifest 的全部 refs 在磁盘上存在（幽灵条目防护延续）', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'test', 'mutants.manifest.json'), 'utf8'))
    const refs = [
      ...(manifest.mutants ?? []).flatMap((m: { refs?: string[] }) => m.refs ?? []),
      ...(manifest.controls ?? []).flatMap((c: { refs?: string[] }) => c.refs ?? []),
    ]
    for (const ref of refs) expect(existsSync(join(ROOT, ref)), `语料缺失: ${ref}`).toBe(true)
  })
})
