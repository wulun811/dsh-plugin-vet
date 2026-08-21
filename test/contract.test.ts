import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  validateContract, patternMatchPath, patternMatchHost, patternMatchCommand,
  fsWithinScope, netWithinScope, spawnWithinScope, envWithinScope,
  contractPriority, setContractsDirForTest, loadContract,
  type ContractScope, type ContractScopeFs, type ContractScopeNet, type ContractScopeSpawn,
} from '../lib/guard/contract.js'

const SCOPE: ContractScope = {
  fs: { read: ['/home/u/data/**', '/home/u/notes/vault', '/tmp/<seg>/out'], write: ['/home/u/data/**'], destroy: [] },
  network: { connect: ['registry.example.com', '*.cdn.tools'], ports: [443, 8443] },
  spawn: { commands: ['git', '/usr/bin/gh'] },
  env: ['VET_EXAMPLE'],
}

function valid(json: unknown): string {
  return JSON.stringify({
    schema: 1,
    name: '@scope/demo',
    scope: SCOPE,
    meta: { generator: 'agent' },
    ...(json as object),
  })
}

describe('M1 契约宽松度校验器（validateContract）', () => {
  it('合法最小契约 → ok', () => {
    const v = validateContract(valid({}))
    expect(v.ok).toBe(true)
    expect(v.issues.filter(i => i.level === 'reject')).toHaveLength(0)
  })
  it('非法 JSON → reject', () => {
    const v = validateContract('{ not json')
    expect(v.ok).toBe(false)
    expect(v.issues[0].level).toBe('reject')
  })
  it('schema 版本不匹配 → reject', () => {
    const v = validateContract(valid({ schema: 99 }))
    expect(v.ok).toBe(false)
    expect(v.issues.some(i => i.field === 'schema' && i.level === 'reject')).toBe(true)
  })
  it('缺少 name → reject', () => {
    const v = validateContract(valid({ name: '' }))
    expect(v.ok).toBe(false)
    expect(v.issues.some(i => i.field === 'name')).toBe(true)
  })
  it('缺 scope.fs / scope.network / scope.spawn → reject', () => {
    for (const drop of ['fs', 'network', 'spawn'] as const) {
      const s: Record<string, unknown> = { ...SCOPE }
      delete s[drop]
      const v = validateContract(valid({ scope: s }))
      expect(v.ok, drop + ' 段缺失应拒载').toBe(false)
    }
  })
  it('过宽路径模式（** / 裸 * / 空串 / **/x）→ reject', () => {
    for (const bad of ['**', '*', '', '**/x', 'a/**/b']) {
      const v = validateContract(valid({ scope: { ...SCOPE, fs: { ...SCOPE.fs, read: [bad] } } }))
      expect(v.ok, 'pattern=' + JSON.stringify(bad) + ' 应拒载').toBe(false)
      expect(v.issues.some(i => i.field === 'scope.fs.read' && i.level === 'reject')).toBe(true)
    }
  })
  it('单段通配 /tmp/<seg>/out 与目录前缀 /home/u/data/** 可接受', () => {
    const v = validateContract(valid({}))
    expect(v.ok).toBe(true)
  })
  it('不可达路径模式（家目录 ~/ / 根 / 相对 ./）→ reject', () => {
    for (const bad of ['~/data', '/', './data', './', '~/']) {
      const v = validateContract(valid({ scope: { ...SCOPE, fs: { ...SCOPE.fs, read: [bad] } } }))
      expect(v.ok, 'pattern=' + JSON.stringify(bad) + ' 应拒载').toBe(false)
      expect(v.issues.some(i => i.field === 'scope.fs.read' && i.level === 'reject')).toBe(true)
    }
  })
  it('反斜杠路径形态（Windows 转义）按 / 规范化后仍可接受', () => {
    const v = validateContract(valid({ scope: { ...SCOPE, fs: { ...SCOPE.fs, read: ['/home/u/projects/x'] } } }))
    expect(v.ok).toBe(true)
  })
  it('过宽主机（* / 空串 / 非法字符）→ reject；*.example.com 可接受', () => {
    for (const bad of ['*', '', 'evil host!']) {
      const v = validateContract(valid({ scope: { ...SCOPE, network: { connect: [bad] } } }))
      expect(v.ok, 'host=' + JSON.stringify(bad) + ' 应拒载').toBe(false)
    }
    const ok = validateContract(valid({ scope: { ...SCOPE, network: { connect: ['*.example.com'] } } }))
    expect(ok.ok).toBe(true)
  })
  it('非法/过宽命令（* / 空串 / 含空格）→ reject', () => {
    for (const bad of ['*', '', 'rm -rf']) {
      const v = validateContract(valid({ scope: { ...SCOPE, spawn: { commands: [bad] } } }))
      expect(v.ok, 'cmd=' + JSON.stringify(bad) + ' 应拒载').toBe(false)
    }
  })
  it('声明 destroy 面 → warn（非拒载）', () => {
    const v = validateContract(valid({ scope: { ...SCOPE, fs: { ...SCOPE.fs, destroy: ['/home/u/tmp/**'] } } }))
    expect(v.ok).toBe(true)
    expect(v.issues.some(i => i.field === 'scope.fs.destroy' && i.level === 'warn')).toBe(true)
  })
  it('未知 generator → warn（非拒载）', () => {
    const v = validateContract(valid({ meta: { generator: 'random-llm' } }))
    expect(v.ok).toBe(true)
    expect(v.issues.some(i => i.field === 'meta.generator' && i.level === 'warn')).toBe(true)
  })
})

describe('路径/主机/命令模式匹配', () => {
  it('字面路径精确匹配 + 目录前缀 /** 递归 + 反斜杠归一', () => {
    expect(patternMatchPath('/home/u/notes/vault', '/home/u/notes/vault')).toBe(true)
    expect(patternMatchPath('/home/u/data/**', '/home/u/data')).toBe(true)
    expect(patternMatchPath('/home/u/data/**', '/home/u/data/raw/x.json')).toBe(true)
    expect(patternMatchPath('/home/u/data/**', '/home/u/other/x')).toBe(false)
    expect(patternMatchPath('C:\\work\\a', 'C:/work/a')).toBe(true)
  })
  it('单段通配 * 不跨 /', () => {
    const segPattern = (s) => s.replace('<seg>', '*')
    expect(patternMatchPath(segPattern('/tmp/<seg>/out'), '/tmp/abc/out')).toBe(true)
    expect(patternMatchPath(segPattern('/tmp/<seg>/out'), '/tmp/a/b/out')).toBe(false)
  })
  it('裸 * 或含 ** 的模式恒不匹配（宽松守卫双保险）', () => {
    expect(patternMatchPath('*', '/anything')).toBe(false)
    expect(patternMatchPath('**', '/a/b')).toBe(false)
    expect(patternMatchPath('/', '/')).toBe(false) // 根模式归一化后为空串 → 不匹配（宽松守卫）
  })
  it('主机匹配：精确名 / *.suffix 自域与子域 / 大小写不敏感', () => {
    expect(patternMatchHost('registry.example.com', 'registry.example.com')).toBe(true)
    expect(patternMatchHost('*.cdn.tools', 'cdn.tools')).toBe(true)
    expect(patternMatchHost('*.cdn.tools', 'img.cdn.tools')).toBe(true)
    expect(patternMatchHost('*.cdn.tools', 'cdn.tools.evil')).toBe(false)
    expect(patternMatchHost('API.EXAMPLE.COM', 'api.example.com')).toBe(true)
    expect(patternMatchHost('*', 'webhook.site')).toBe(false)
  })
  it('命令匹配：basename / 完整路径 / argv 任一项', () => {
    expect(patternMatchCommand('git', 'git clone x')).toBe(true)
    expect(patternMatchCommand('/usr/bin/gh', 'gh pr list')).toBe(true)
    expect(patternMatchCommand('git', 'sh -c git status')).toBe(true)
    expect(patternMatchCommand('curl', 'wget -q url')).toBe(false)
  })
})

describe('范围判定（fs/network/spawn/env）', () => {
  it('fsWhileWithinScope 读/写/删分面', () => {
    const fs: ContractScopeFs = SCOPE.fs
    expect(fsWithinScope('/home/u/data/x.json', fs, 'read')).toBe(true)
    expect(fsWithinScope('/home/u/data/x.json', fs, 'write')).toBe(true)
    expect(fsWithinScope('/home/u/data/x.json', fs, 'destroy')).toBe(false)
    expect(fsWithinScope('/etc/passwd', fs, 'read')).toBe(false)
  })
  it('netWithinScope 含端口白名单', () => {
    const net: ContractScopeNet = SCOPE.network
    expect(netWithinScope('registry.example.com', 443, net)).toBe(true)
    expect(netWithinScope('registry.example.com', 8080, net)).toBe(false)
    expect(netWithinScope('evil.com', 443, net)).toBe(false)
  })
  it('spawn/env 范围', () => {
    const spawn: ContractScopeSpawn = SCOPE.spawn
    expect(spawnWithinScope('git clone x', spawn)).toBe(true)
    expect(spawnWithinScope('rm -rf /', spawn)).toBe(false)
    expect(envWithinScope('VET_EXAMPLE', SCOPE.env)).toBe(true)
    expect(envWithinScope('HOME', SCOPE.env)).toBe(false)
  })
})

describe('三级优先级（契约承诺 < 运行时观测 < 代码事实）', () => {
  it('代码事实与契约冲突 → code-fact-beats-contract（契约被推翻）', () => {
    expect(contractPriority(true, false, false)).toEqual({ outcome: 'code-fact-beats-contract' })
  })
  it('观测越契约 → observation-beats-contract（记录档黄色信号）', () => {
    expect(contractPriority(false, true, false)).toEqual({ outcome: 'observation-beats-contract', within: false })
  })
  it('观测在契约内 → contract-explains-observation（降噪候选）', () => {
    expect(contractPriority(false, true, true)).toEqual({ outcome: 'contract-explains-observation', within: true })
  })
  it('代码事实在契约内 → 由更高权威事实解释（可降噪）', () => {
    expect(contractPriority(true, false, true)).toEqual({ outcome: 'contract-explains-observation', within: true })
  })
  it('无观测无事实 → ambiguous（契约未落观测面，无事可做）', () => {
    expect(contractPriority(false, false, true)).toEqual({ outcome: 'ambiguous' })
  })
})

describe('契约加载（离线目录 + 测试覆写）', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vet-contract-'))
    setContractsDirForTest(dir)
  })
  afterEach(() => {
    setContractsDirForTest(undefined)
    rmSync(dir, { recursive: true, force: true })
  })
  const readFile = (p: string): string | undefined => {
    try {
      return readFileSync(p, 'utf8')
    } catch {
      return undefined
    }
  }
  it('缺失契约 → no-contract', () => {
    expect(loadContract('@scope/nope', readFile).kind).toBe('no-contract')
  })
  it('损坏/过宽契约 → rejected（并带原因）', () => {
    writeFileSync(join(dir, '@scope_demo.json'), valid({ scope: { ...SCOPE, fs: { read: ['**'] } } }), 'utf8')
    const r = loadContract('@scope/demo', readFile)
    expect(r.kind).toBe('rejected')
    if (r.kind === 'rejected') expect(r.validation.ok).toBe(false)
  })
  it('合法契约 → loaded 并带校验结果', () => {
    writeFileSync(join(dir, '@scope_demo.json'), valid({}), 'utf8')
    const r = loadContract('@scope/demo', readFile)
    expect(r.kind).toBe('loaded')
    if (r.kind === 'loaded') {
      expect(r.contract.name).toBe('@scope/demo')
      expect(r.validation.ok).toBe(true)
    }
  })
})