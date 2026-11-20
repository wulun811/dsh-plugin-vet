/**
 * round-23 全量审查的回归（0.5.30）。
 *
 * 每一条都对应一个**被复现的**真缺陷；测试断言的是「缺陷形状不再成立」，
 * 不是实现细节。命名带场景，方便将来谁改坏了能一眼看出坏的是哪一类。
 */
import { describe, expect, it } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan } from '../lib/scanner-bin/engine.js'
import { buildRequest } from '../lib/tools/scan-plugin.js'
import { pluginFromStack } from '../lib/guard/runtime-attrib.js'
import { parseSource, walk } from '../lib/scanner-bin/ast.js'
import { readSmallRegularFile } from '../lib/guard/fs-read.js'
import {
  decideBlock, resetConfirmBlock, setCredentialHomeForTest,
} from '../lib/guard/confirm-block.js'
import { setDismissedFileForTest, persistentlyDismiss, isPersistentlyDismissed } from '../lib/guard/dismissed-alerts.js'

const tmpPkg = (files: Record<string, string>): string => {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r23-'))
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name)
    mkdirSync(dirname(p), { recursive: true })
    writeFileSync(p, content)
  }
  return dir
}

const scanPkg = (files: Record<string, string>) => {
  const dir = tmpPkg({
    'package.json': JSON.stringify({ name: 'p', version: '1.0.0', main: 'index.js', dependencies: { '@deepseek-ai/cordis': '^4.0.1' } }),
    ...files,
  })
  try {
    const { request } = buildRequest({ target: 'package', packagePath: dir })
    return scan(request)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('round-23 · 扫描器不再被输入打死（ReDoS / 递归 / 展开）', () => {
  it('深表达式遍历不再爆栈（显式栈）', () => {
    // 递归 walk 在 ~2000 层抛 RangeError；抛点在规则执行之前 → 该文件所有规则跳过、
    // verdict 仍是 clean。4KB 输入即可关掉整个判定面。直接测遍历本身（快且精确）。
    const code = 'const x = ' + Array.from({ length: 3000 }, () => 'a').join(' + ') + '\n'
    const sf = parseSource(code, 'deep.js', 'js')
    let visited = 0
    expect(() => walk(sf, () => { visited++ })).not.toThrow()
    expect(visited).toBeGreaterThan(3000)
  })

  it('超长 fromCharCode 实参不崩、不吞掉其余规则', () => {
    const flood = 'const junk = String.fromCharCode(' + '0,'.repeat(250000) + '0)\n'
      + 'const c = (()=>{}).constructor; c("return process")()\n'
    const res = scanPkg({ 'index.js': flood })
    expect(res.report?.findings.some(f => f.rule === 'R1')).toBe(true)
  })

  it('端点形状判定是线性的（36 字节不再回溯 26 秒）', () => {
    const bomb = 'const u = "169.254.169.254' + 'a'.repeat(20) + '!"\n'
    const started = Date.now()
    const res = scanPkg({ 'index.js': bomb })
    const elapsed = Date.now() - started
    expect(res.ok).toBe(true)
    // 旧正则在 n=20 时纯正则就 5s、引擎内 26.8s；线性实现是毫秒级。阈值给足机器差异余量。
    expect(elapsed).toBeLessThan(5000)
  })
})

describe('round-23 · 规则面补漏', () => {
  it("R11 认 `require('fs').promises.rm` 形态", () => {
    const res = scanPkg({ 'index.js': "require('fs').promises.rm('/etc/passwd')\n" })
    const r11 = res.report?.findings.find(f => f.rule === 'R11')
    expect(r11?.severity, '同一语义的第五种写法此前整体漏检').toBe('high')
  })

  it('R12 认 exports 数组与顶层条件糖（不再谎报「无包入口」）', () => {
    for (const exportsField of [["./index.mjs"], { import: './index.mjs' }]) {
      const dir = tmpPkg({
        'package.json': JSON.stringify({ name: 'p', version: '1.0.0', exports: exportsField }),
        'index.mjs': 'export function apply() {}\n',
      })
      try {
        const { request } = buildRequest({ target: 'package', packagePath: dir })
        const res = scan(request)
        const r12 = res.report?.findings.filter(f => f.rule === 'R12' && f.severity === 'medium')
        expect(r12 ?? []).toHaveLength(0)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    }
  })

})

describe('round-23 · 归因与拦截的坐标系', () => {
  it('ESM 栈帧的百分号编码被解码（目录名带空格/中文也能归因）', () => {
    const roots = new Map<string, string>([['/tmp/dir with space', 'evil-plugin'], ['/tmp/中文插件', 'cn-plugin']])
    expect(pluginFromStack('    at boom (file:///tmp/dir%20with%20space/mod.mjs:1:33)', roots)).toBe('evil-plugin')
    expect(pluginFromStack('    at boom (file:///tmp/%E4%B8%AD%E6%96%87%E6%8F%92%E4%BB%B6/mod.mjs:1:33)', roots)).toBe('cn-plugin')
  })

  it('相对路径拼写不能绕过 N7 族 2 凭据拦截', () => {
    const home = mkdtempSync(join(tmpdir(), 'vet-r23-home-'))
    const cwd = process.cwd()
    try {
      mkdirSync(join(home, '.ssh'), { recursive: true })
      writeFileSync(join(home, '.ssh', 'id_rsa'), 'secret')
      setCredentialHomeForTest(home)
      resetConfirmBlock()
      process.chdir(home)
      // chdir 之后 `.ssh/id_rsa` 与绝对路径是同一个文件——判定必须在同一坐标系里
      expect(decideBlock('evil', 'rmSync', ['.ssh/id_rsa'])?.family).toBe(2)
      expect(decideBlock('evil', 'unlink', [join('.ssh', 'id_rsa')])?.family).toBe(2)
    } finally {
      process.chdir(cwd)
      setCredentialHomeForTest(undefined)
      resetConfirmBlock()
      rmSync(home, { recursive: true, force: true })
    }
  })
})

describe('round-24 · 自报元数据不能自我降级', () => {
  const scanWith = (pkg: Record<string, unknown>, files: Record<string, string>) => {
    const dir = tmpPkg({
      'package.json': JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { '@deepseek-ai/cordis': '^4.0.1' }, ...pkg }),
      ...files,
    })
    try {
      const { request } = buildRequest({ target: 'package', packagePath: dir })
      return scan(request)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  it('把 bin 指向自己的插件入口不再换来降级（R3/R2 保持）', () => {
    const body = "export function apply(ctx){ process.exit(1); require('child_process').exec('id') }"
    const plain = scanWith({ main: 'index.js' }, { 'index.js': body })
    const withBin = scanWith({ main: 'index.js', bin: { evil: 'index.js' } }, { 'index.js': body })
    expect(withBin.report?.verdict, '℗ bin 自报不能把入口判成 CLI 脚本').toBe(plain.report?.verdict)
    expect(withBin.report?.verdict).not.toBe('clean')
  })

  it('scripts 指向入口同样不降级', () => {
    const body = "export function apply(ctx){ process.exit(1) }"
    const res = scanWith({ main: 'index.js', scripts: { build: 'node ./index.js' } }, { 'index.js': body })
    const r3 = res.report?.findings.find(f => f.rule === 'R3')
    expect(r3?.severity).toBe('critical')
  })

  it('入口 import 的 test/ 载荷不再按「测试文件」降级', () => {
    const res = scanWith({ main: 'index.js' }, {
      'index.js': "import './test/payload.js'\nexport function apply(){}\n",
      'test/payload.js': 'process.exit(1)\n',
    })
    const r3 = res.report?.findings.find(f => f.rule === 'R3')
    expect(r3?.severity, '路径不是可达性的证据').toBe('critical')
  })
})

describe('round-24 · 差分基线不被容量清理淘汰', () => {
  it('包的最新一条记录不会被别人的新版本挤掉（旧实现会）', async () => {
    const { pruneCapabilities } = await import('../lib/guard/version-diff.js')
    const store: { records: Record<string, unknown> } = { records: {} }
    // pkgA 有 10 个版本且都很新；pkgB 只有一个很旧的版本。
    // 旧实现按全局时间保留最新 N 条 → pkgB 整个消失，下次加载只能冷启动。
    for (let i = 0; i < 10; i++) {
      store.records[`pkgA@1.0.${i}`] = { name: 'pkgA', version: `1.0.${i}`, recordedAt: 100 + i, capabilities: {} }
    }
    store.records['pkgB@0.1.0'] = { name: 'pkgB', version: '0.1.0', recordedAt: 1, capabilities: {} }
    pruneCapabilities(store as never, 8)
    const keys = Object.keys(store.records)
    expect(keys).toContain('pkgB@0.1.0')
    expect(keys).toHaveLength(8)
    // 被淘汰的是 pkgA 最旧的三个版本
    expect(keys).toContain('pkgA@1.0.9')
    expect(keys).not.toContain('pkgA@1.0.0')
  })
})

describe('round-23 · 持久化读取（FIFO / 坏条目）', () => {
  it('FIFO 按「读不到」处理，不阻塞', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r23-fifo-'))
    const fifo = join(dir, 'f')
    const made = spawnSync('mkfifo', [fifo])
    try {
      if (made.status !== 0) return // 平台无 mkfifo（Windows）→ 跳过
      const started = Date.now()
      expect(readSmallRegularFile(fifo, 1024)).toBeNull()
      expect(Date.now() - started).toBeLessThan(1000)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('忽略库里混入 null 条目时 prune 不抛（旧实现 TypeError 逃出 http 监听器 → 进程退出）', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r23-dismiss-'))
    const file = join(dir, 'dismissed-alerts.json')
    const dismissed: Record<string, unknown> = { broken: null }
    for (let i = 0; i < 205; i++) dismissed[`k${i}`] = { dismissedAt: i }
    writeFileSync(file, JSON.stringify({ dismissed }))
    try {
      setDismissedFileForTest(file)
      expect(() => persistentlyDismiss('fresh-id')).not.toThrow()
      expect(isPersistentlyDismissed('fresh-id')).toBe(true)
    } finally {
      setDismissedFileForTest(join(tmpdir(), 'vet-r23-unused.json'))
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('round-25 · 复杂度与静默降级', () => {
  it('R3 解构成员：k 个成员不再走 k 遍全文件 AST', () => {
    const members = Array.from({ length: 2000 }, (_, i) => `m${i}`).join(', ')
    const body = `const { ${members} } = process\nm0()\nexport function apply(){}\n`
    const started = Date.now()
    const res = scanPkg({ 'index.js': body })
    const elapsed = Date.now() - started
    const r3 = res.report?.findings.filter(f => f.rule === 'R3')
    expect(r3?.length).toBeGreaterThan(0)
    expect(elapsed, 'k×n 遍历（199KB 实测 42s）已改为单次遍历').toBeLessThan(10000)
  })

  it('R9 alternation 两两比较按次数计预算（40000 分支不再跑 14 秒）', () => {
    const branches = Array.from({ length: 40000 }, (_, i) => String.fromCharCode(0x4e00 + i)).join('|')
    const body = `const re = /(${branches})+/g\nexport function apply(){ return re }\n`
    const started = Date.now()
    const res = scanPkg({ 'index.js': body })
    expect(res.ok).toBe(true)
    expect(Date.now() - started, '分支两两比较是 O(b²)，必须计入预算').toBeLessThan(10000)
  })

  it('cacheKey 接受生成器：与物化数组得到同一个键', async () => {
    const { cacheKey } = await import('../lib/scanner-bin/cache.js')
    const files = [{ path: '/a.js', content: 'const a = 1' }, { path: '/b.js', content: 'const b = 2' }]
    const fromArray = cacheKey(files, undefined, {})
    const fromGenerator = cacheKey(
      (function* () { for (const f of files) yield f })(),
      undefined,
      {},
    )
    expect(fromGenerator).toBe(fromArray)
  })

  it('哈希预算超限 → 「未验成」，不再谎报 ok', async () => {
    const { checkThirdPartyBaseline } = await import('../lib/guards/internal-plugin.js')
    const { VetConfigSchema } = await import('../lib/config.js')
    const dir = mkdtempSync(join(tmpdir(), 'vet-r25-big-'))
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'big', version: '1.0.0' }))
      // 超过单文件上限（DEFAULT_HASH_OPTIONS.maxSizeBytes = 50MB）→ computePackageHash 返回 null
      writeFileSync(join(dir, 'huge.bin'), Buffer.alloc(51 * 1024 * 1024))
      const cfg = VetConfigSchema({ thirdPartyBaseline: true })
      expect(checkThirdPartyBaseline('big', dir, '1.0.0', cfg as never)).toBe('unverifiable')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('round-26 · 网络观测的两处空洞', () => {
  it('new net.Socket() 的第一次写入补一条观测（此前整条通道静默）', async () => {
    const { patchNetSocketPrototype } = await import('../lib/guard/runtime-patch.js')
    const { DEFAULT_HOOK_CONFIG } = await import('../lib/guard/runtime-ops.js')
    const alarms: Array<{ kind: string; message: string }> = []
    const ledger: number[] = []
    const canaries: string[] = []
    const fakeProto: Record<string, unknown> = { write: () => 'ok' }
    const fakeNet = { Socket: { prototype: fakeProto } }
    patchNetSocketPrototype(
      fakeNet as never,
      DEFAULT_HOOK_CONFIG,
      (a: never) => { alarms.push(a as never) },
      () => new Map<string, string>(),
      (evt) => { ledger.push(evt.bytes) },
      (_hint, text) => { canaries.push(text) },
    )
    const socket = Object.create(fakeProto) as Record<string, unknown> & { write: (c: unknown) => unknown }
    socket.remoteAddress = 'webhook.site'
    socket.remotePort = 443
    socket.write('secret')
    expect(alarms.some(a => a.kind === 'net-egress' || a.message.includes('new net.Socket'))).toBe(true)
    expect(canaries.some(t => t.includes('webhook.site'))).toBe(true)
    // 只观测一次（同一 socket 的后续写入不再重复立报警）
    socket.write('again')
    expect(alarms).toHaveLength(1)
  })
})

describe('round-27 · 子进程读取面与线程子进程计数', () => {
  it('exec(cat ~/.ssh/id_rsa) 不再零报警；普通路径不报', async () => {
    const { classifyOp } = await import('../lib/guard/runtime-classify.js')
    const { DEFAULT_HOOK_CONFIG } = await import('../lib/guard/runtime-ops.js')
    const read = classifyOp({ module: 'child_process', op: 'exec', args: ['cat ~/.ssh/id_rsa'] }, DEFAULT_HOOK_CONFIG)
    expect(read?.kind).toBe('spawn')
    expect(read?.message).toContain('敏感路径')
    const plain = classifyOp({ module: 'child_process', op: 'exec', args: ['cat /tmp/notes.txt'] }, DEFAULT_HOOK_CONFIG)
    expect(plain).toBeNull()
    const interp = classifyOp(
      { module: 'child_process', op: 'spawn', args: ['node', ['-e', "require('fs').readFileSync('/home/u/.dsh/.credentials.yaml')"]] },
      DEFAULT_HOOK_CONFIG,
    )
    expect(interp?.kind).toBe('spawn')
  })
})
