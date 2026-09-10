import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { hashScanFiles, pinStateFor, type SelfPins } from '../lib/report/self-pin.js'
import { listShippedFiles } from '../lib/report/self-scope.js'

/** 符号链接能力探针：Windows 无开发者模式/非管理员时 symlinkSync 抛 EPERM——
 * 该环境无法物化符号链接场景，跳过对应用例（CI 特权 runner 与 POSIX 照常执行）。 */
const canSymlink = ((): boolean => {
  const d = mkdtempSync(join(tmpdir(), 'vet-symprobe-'))
  try {
    symlinkSync(join(d, 'a'), join(d, 'b'))
    return true
  } catch {
    return false
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
})()

function tmpTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-pin-'))
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel)
    mkdirSync(join(p, '..'), { recursive: true })
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

describe('pinStateFor（round-16：any-pin 匹配 + 升级窗口）', () => {
  const pins: SelfPins = { '0.3.0': 'sha256:AAA', '0.3.1': 'sha256:BBB' }
  it('字节 == 本版 pin → pinned-match（常规）', () => {
    expect(pinStateFor(pins, '0.3.1', 'sha256:BBB')).toBe('pinned-match')
  })
  it('字节 == 任一其他版本 pin → pinned-match（升级窗口：宿主进程版本滞后/交错更新，字节是被审计发布物）', () => {
    // 宿主还报 0.3.0、磁盘已是 0.3.1 字节（pin 表先行写入）——不再「两个 vet 互不认」
    expect(pinStateFor(pins, '0.3.0', 'sha256:BBB')).toBe('pinned-match')
    // 版本未知但字节匹配某已发布 pin（表里只有旧版条目、磁盘已是新版字节）
    expect(pinStateFor(pins, undefined, 'sha256:BBB')).toBe('pinned-match')
    expect(pinStateFor(pins, '9.9.9', 'sha256:AAA')).toBe('pinned-match')
  })
  it('本版有 pin 但字节不符任何 pin → dev-tree（本地改码/未构建/被篡改）', () => {
    expect(pinStateFor(pins, '0.3.1', 'sha256:CCC')).toBe('dev-tree')
  })
  it('版本无条目且字节无匹配 → unpinned', () => {
    expect(pinStateFor(pins, '9.9.9', 'sha256:CCC')).toBe('unpinned')
    expect(pinStateFor(pins, undefined, 'sha256:CCC')).toBe('unpinned')
    expect(pinStateFor(undefined, '0.3.1', 'sha256:BBB')).toBe('unpinned')
  })
})

describe('listShippedFiles（round-16：发布物范围，生产安装可 pinned-match）', () => {
  it('白名单：lib/ + 根级清单 + docs/ARCHITECTURE.md 进面；docs/ 其他文件不进面（QA-6）；src/ 与 vet-self-pins.json 不进面', () => {
    const dir = tmpTree({
      'lib/index.js': 'a',
      'lib/scanner/x.js': 'b',
      'package.json': '{}',
      'README.md': 'x',
      'docs/ARCHITECTURE.md': 'y',
      // round-16（QA-6）：docs/ 前缀收窄为 ARCHITECTURE.md——local/ 与 MUTANT-QA.md
      // 不进 tarball（files 白名单仅 ARCHITECTURE.md），旧前缀会让钉扎范围 ⊋ 发布物
      'docs/local/design.html': 'd',
      'docs/MUTANT-QA.md': 'm',
      'src/report/self-pin.ts': 'z',
      'vet-self-pins.json': '{}',
      'cordis.patch.yml': 'p',
    })
    try {
      const rels = listShippedFiles(dir).map(f => f.slice(dir.length + 1).split('\\').join('/')).sort()
      expect(rels).toEqual([
        'README.md',
        'cordis.patch.yml',
        'docs/ARCHITECTURE.md',
        'lib/index.js',
        'lib/scanner/x.js',
        'package.json',
      ])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  it('vet-self-pins.json 自引用排除：改动它不改变 hash（钉扎表不可哈希自身）', () => {
    const dir = tmpTree({ 'lib/index.js': 'a', 'package.json': '{}' })
    try {
      const h1 = hashScanFiles(listShippedFiles(dir), dir)
      writeFileSync(join(dir, 'vet-self-pins.json'), '{ "pins": { "x": "y" } }')
      expect(hashScanFiles(listShippedFiles(dir), dir)).toBe(h1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  it('未构建的裸源码树（无 lib/）→ 集合只有根级文件；与发布物 hash 不一致（dev-tree 的诚实来源）', () => {
    const dir = tmpTree({ 'src/foo.ts': 'x', 'package.json': '{}', 'README.md': 'r' })
    try {
      const rels = listShippedFiles(dir).map(f => f.slice(dir.length + 1)).sort()
      expect(rels).toEqual(['README.md', 'package.json'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
  it.skipIf(!canSymlink)('符号链接不进面（与 listSourceFiles walk 纪律一致）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-pin-link-'))
    const target = tmpTree({ 'evil.js': 'x' })
    try {
      writeFileSync(join(dir, 'package.json'), '{}')
      symlinkSync(join(target, 'evil.js'), join(dir, 'lib-evil.js'))
      const rels = listShippedFiles(dir).map(f => f.slice(dir.length + 1))
      expect(rels).toEqual(['package.json'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
      rmSync(target, { recursive: true, force: true })
    }
  })
})