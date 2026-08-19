import { describe, expect, it, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'

/**
 * #6（代码审查修复）：缓存 key 阶段不再整读超过 PRE_FILE_SIZE_LIMIT（8MB）的文件——
 * 旧实现 cacheKey 对全部文件 readOrDefault，大文件在散列阶段被全量读入（内存峰值），
 * 而扫描循环里本就用 stat 先行 R8-skip。回归：超限文件扫描正常、出 R8 skipping、无异常。
 */

describe('#6 R8-skip 先于缓存散列（大文件不整读）', () => {
  let dir: string | undefined
  afterEach(() => { if (dir) { rmSync(dir, { recursive: true, force: true }); dir = undefined } })

  it('>8MB 文件 → R8 skip，扫描正常完成', () => {
    dir = mkdtempSync(join(tmpdir(), 'vet-bigfile-'))
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'big-pkg', version: '1.0.0' }))
    // 9MB 翻过 PRE_FILE_SIZE_LIMIT（8MB）
    writeFileSync(join(dir, 'huge.js'), 'x'.repeat(9 * 1024 * 1024))

    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'huge.js')] })
    expect(res.ok).toBe(true)
    const skip = res.report!.findings.find(f => f.rule === 'R8' && f.file === 'huge.js')
    expect(skip).toBeDefined()
  })

  it('边界恰好 ≤8MB 的文件仍正常扫描（不误 skip）', () => {
    dir = mkdtempSync(join(tmpdir(), 'vet-bigfile-'))
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'small-pkg', version: '1.0.0' }))
    writeFileSync(join(dir, 'ok.js'), 'const x = 1;' + ' //pad'.repeat(2000))
    const res = scan({ kind: 'files', files: [join(dir, 'package.json'), join(dir, 'ok.js')] })
    expect(res.ok).toBe(true)
    const skip = res.report!.findings.find(f => f.rule === 'R8' && f.file === 'ok.js')
    expect(skip).toBeUndefined()
  })
})
