import { describe, expect, it, afterEach } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { resolvePkgRoot, resolveVetFile } from '../lib/pkg-root.js'

/**
 * 0.1.16 C1 回归：main 切到打包版 lib/index.bundle.js 后，固定 `..` 级数定位包根
 * 在 bundle 形态失效（lib/ 上两级越出包根 → AUDIT_PROTOCOL.md ENOENT → 重启启动失败）。
 * resolvePkgRoot/resolveVetFile 改为向上搜索 package.json + 候选目录存在性，
 * 且支持注入 base（模拟任意产物形态的模块位置）。本测试在临时目录构造两种形态验证。
 */

const roots: string[] = []

/** 建一个临时包：根含 package.json，按 rel 相对路径写占位文件。 */
function makePkg(reals: string[] = []): { root: string } {
  const root = mkdtempSync(join(tmpdir(), 'vet-pkgroot-'))
  roots.push(root)
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fixture-pkg', version: '1.0.0' }))
  for (const rel of reals) {
    const parent = join(root, ...rel.split('/').slice(0, -1))
    if (parent !== root) mkdirSync(parent, { recursive: true })
    writeFileSync(join(root, rel), 'fixture')
  }
  return { root }
}

afterEach(() => {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true })
})

describe('pkg-root：bundle / 逐文件双形态包根定位（0.1.16 C1 回归）', () => {
  it('逐文件形态 lib/skills/audit-protocol.js → 包根', () => {
    const { root } = makePkg(['lib/skills/audit-protocol.js', 'AUDIT_PROTOCOL.md'])
    const base = join(root, 'lib', 'skills', 'audit-protocol.js')
    expect(resolvePkgRoot(base)).toBe(root)
    // 消费方 loadAuditProtocolContent：包根下 AUDIT_PROTOCOL.md 必须可达
    expect(existsSync(join(resolvePkgRoot(base), 'AUDIT_PROTOCOL.md'))).toBe(true)
  })

  it('bundle 形态 lib/index.bundle.js → 包根（旧实现多上一级越出包根 → 回归点）', () => {
    const { root } = makePkg(['lib/index.bundle.js', 'AUDIT_PROTOCOL.md'])
    const base = join(root, 'lib', 'index.bundle.js')
    // 旧行为 join(dirname(base), '..', '..') 会落到 root 的父目录（包外）——必须指回包根
    expect(resolvePkgRoot(base)).toBe(root)
    expect(resolvePkgRoot(base)).not.toBe(join(dirname(base), '..', '..'))
    expect(existsSync(join(resolvePkgRoot(base), 'AUDIT_PROTOCOL.md'))).toBe(true)
  })

  it('resolveVetFile：lib/ 产物优先（bundle 形态）', () => {
    const { root } = makePkg(['lib/index.bundle.js', 'lib/scanner-bin/index.js', 'scanner-bin/index.js'])
    const base = join(root, 'lib', 'index.bundle.js')
    expect(resolveVetFile('scanner-bin/index.js', base)).toBe(join(root, 'lib', 'scanner-bin/index.js'))
    expect(resolveVetFile('guard/runtime-watch.js', base)).toBe(join(root, 'lib', 'guard/runtime-watch.js'))
  })

  it('resolveVetFile：lib 缺失时回退包根目录候选', () => {
    const { root } = makePkg(['lib/index.bundle.js', 'scanner-bin/index.js'])
    const base = join(root, 'lib', 'index.bundle.js')
    expect(resolveVetFile('scanner-bin/index.js', base)).toBe(join(root, 'scanner-bin/index.js'))
  })

  it('resolveVetFile：lib/根均缺失时回退 src 源码候选', () => {
    const { root } = makePkg(['lib/index.bundle.js', 'src/scanner-bin/index.js'])
    const base = join(root, 'lib', 'index.bundle.js')
    expect(resolveVetFile('scanner-bin/index.js', base)).toBe(join(root, 'src', 'scanner-bin/index.js'))
  })

  it('resolveVetFile：全部候选缺失 → 回退 lib/ 布局（不抛错）', () => {
    const { root } = makePkg(['lib/index.bundle.js'])
    const base = join(root, 'lib', 'index.bundle.js')
    expect(resolveVetFile('scanner-bin/index.js', base)).toBe(join(root, 'lib', 'scanner-bin/index.js'))
  })

  it('默认（无 base）：从真实产物位置解析到 plugin-vet 包根', () => {
    const root = resolvePkgRoot()
    expect(existsSync(join(root, 'package.json'))).toBe(true)
    expect(root).toContain('plugin-vet')
    // 真实产物一致性：scanner-bin 入口与哨兵 sidecar 均能按 resolveVetFile 落位
    expect(existsSync(resolveVetFile('scanner-bin/index.js'))).toBe(true)
    expect(existsSync(resolveVetFile('guard/runtime-watch.js'))).toBe(true)
  })
})
