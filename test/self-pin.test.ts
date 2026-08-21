import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { hashScanFiles, pinStateFor, type SelfPins } from '../lib/report/self-pin.js'

function tmpTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-pin-'))
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel)
    writeFileSync(p, content)
  }
  return dir
}

describe('hashScanFiles', () => {
  it('确定性：同内容同顺序 → 同 hash；文件顺序无关', () => {
    const dir = tmpTree({ 'a.ts': 'x', 'b.ts': 'y' })
    const f1 = [join(dir, 'a.ts'), join(dir, 'b.ts')]
    const f2 = [join(dir, 'b.ts'), join(dir, 'a.ts')]
    expect(hashScanFiles(f1, dir)).toBe(hashScanFiles(f2, dir))
    rmSync(dir, { recursive: true, force: true })
  })
  it('内容变化 → hash 变化', () => {
    const dir = tmpTree({ 'a.ts': 'x' })
    const h1 = hashScanFiles([join(dir, 'a.ts')], dir)
    writeFileSync(join(dir, 'a.ts'), 'y')
    const h2 = hashScanFiles([join(dir, 'a.ts')], dir)
    expect(h1).not.toBe(h2)
    rmSync(dir, { recursive: true, force: true })
  })
  it('仅排序相对路径参与（绝对路径前缀不影响）', () => {
    const d1 = tmpTree({ 'a.ts': 'z' })
    const d2 = tmpTree({ 'a.ts': 'z' })
    expect(hashScanFiles([join(d1, 'a.ts')], d1)).toBe(hashScanFiles([join(d2, 'a.ts')], d2))
    rmSync(d1, { recursive: true, force: true })
    rmSync(d2, { recursive: true, force: true })
  })
})

describe('pinStateFor', () => {
  const pins: SelfPins = { '0.1.20': 'sha256:AAA' }
  it('版本缺 pin → unpinned', () => {
    expect(pinStateFor(pins, '0.1.21', 'sha256:AAA')).toBe('unpinned')
    expect(pinStateFor(undefined, '0.1.20', 'sha256:AAA')).toBe('unpinned')
    expect(pinStateFor(pins, undefined, 'sha256:AAA')).toBe('unpinned')
  })
  it('字节一致 → pinned-match（升级后同版自扫不误报）', () => {
    expect(pinStateFor(pins, '0.1.20', 'sha256:AAA')).toBe('pinned-match')
  })
  it('字节不符 → dev-tree（本地改码/被篡改）', () => {
    expect(pinStateFor(pins, '0.1.20', 'sha256:BBB')).toBe('dev-tree')
  })
})
