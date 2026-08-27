import { describe, it, expect } from 'vitest'
import { VetConfigSchema, applyProfile } from '../lib/config.js'
import type { VetConfig } from '../lib/config.js'
import { observationAlarmsFor } from '../lib/guards/internal-plugin.js'

/** 用 schema 解析出带默认值的配置（模拟 cordis 装配后的 resolved config；schemastery schema 可调用）。 */
const parse = (raw: Record<string, unknown>): VetConfig =>
  VetConfigSchema(raw)

describe('VetConfigSchema 默认值（0.3 档位）', () => {
  it('默认 profile=standard、observeLoopback=true、thirdPartyBaseline=false、runtimeGuard=off', () => {
    const cfg = parse({})
    expect(cfg.profile).toBe('standard')
    expect(cfg.observeLoopback).toBe(true)
    expect(cfg.thirdPartyBaseline).toBe(false)
    expect(cfg.runtimeGuard).toBe('off')
    expect(cfg.denyOn).toBe('critical')
    expect(cfg.confirmBlockFamily3).toBe('alarm')
    expect(cfg.confirmBlockFamily4).toBe('alarm')
  })
})

describe('applyProfile（档位预设展开）', () => {
  it('standard 恒等：不改变任何键', () => {
    const cfg = parse({ profile: 'standard' })
    expect(applyProfile(cfg)).toEqual(cfg)
  })

  it('hardened：唤醒 runtimeGuard watch + thirdPartyBaseline + honeypot', () => {
    const cfg = applyProfile(parse({ profile: 'hardened' }))
    expect(cfg.runtimeGuard).toBe('watch')
    expect(cfg.thirdPartyBaseline).toBe(true)
    expect(cfg.honeypot.enabled).toBe(true)
    // 不改 verdict 面：denyOn/requireAudit/confirmBlock 族保持默认
    expect(cfg.denyOn).toBe('critical')
    expect(cfg.requireAudit).toBe(false)
    expect(cfg.confirmBlockFamily3).toBe('alarm')
    expect(cfg.confirmBlockFamily4).toBe('alarm')
  })

  it('paranoid：hardened 全部 + requireAudit + denyOn suspicious + 族 3/4 block', () => {
    const cfg = applyProfile(parse({ profile: 'paranoid' }))
    expect(cfg.runtimeGuard).toBe('watch')
    expect(cfg.thirdPartyBaseline).toBe(true)
    expect(cfg.honeypot.enabled).toBe(true)
    expect(cfg.requireAudit).toBe(true)
    expect(cfg.denyOn).toBe('suspicious')
    expect(cfg.confirmBlockFamily3).toBe('block')
    expect(cfg.confirmBlockFamily4).toBe('block')
  })

  it('显式偏离默认值的键存活（显式 > 预设）', () => {
    // 注：runtimeGuard 的 "显式 off" 与默认值不可区分（bool 二值），这是设计边界——
    // 面板开关写入的 patch 才是表达 "显式 off" 的通道（见下一用例）。
    const cfg = applyProfile(parse({ profile: 'hardened', honeypot: { enabled: false, dir: '/x' } }))
    // honeypot.dir 显式非默认 → 预设不覆盖；其他仍处默认的键照常展开
    expect(cfg.honeypot.enabled).toBe(false)
    expect(cfg.honeypot.dir).toBe('/x')
    expect(cfg.thirdPartyBaseline).toBe(true)
    expect(cfg.runtimeGuard).toBe('watch')
  })

  it('显式键集合（patch 写入语义）优先于预设', () => {
    const cfg = applyProfile(parse({ profile: 'hardened' }), new Set(['runtimeGuard']))
    // patch 显式写了 runtimeGuard（如面板开关写入 off）→ 预设跳过
    expect(cfg.runtimeGuard).toBe('off')
    expect(cfg.thirdPartyBaseline).toBe(true)
    expect(cfg.honeypot.enabled).toBe(true)
  })

  it('0.3 fix（review）：非法档位字符串不崩溃（纯函数防御，脏数据路径恒等返回）', () => {
    // schema 校验会挡住非法档位（上面 parse 直接抛 ValidationError）；applyProfile 是导出
    // 纯函数，绕过 schema 手拼/旧存储的脏数据直接喂进来也不该崩（旧实现 Object.entries(undefined)）
    const dirty = { profile: 'bogus' } as unknown as VetConfig
    expect(() => applyProfile(dirty)).not.toThrow()
    expect(applyProfile(dirty)).toEqual(dirty)
  })

  it('不修改入参（纯函数）', () => {
    const cfg = parse({ profile: 'hardened' })
    const snapshot = JSON.stringify(cfg)
    applyProfile(cfg)
    expect(JSON.stringify(cfg)).toBe(snapshot)
  })
})

describe('observationAlarmsFor（档位观察抬升，verdict 不变）', () => {
  it('无 R17/R18/R19 info 观测 → 空', () => {
    expect(observationAlarmsFor([])).toEqual([])
    expect(observationAlarmsFor([
      { rule: 'R7', severity: 'high', message: 'sk-xx' },
      { rule: 'R13', severity: 'info', message: 'webhook' },
    ])).toEqual([])
  })

  it('R17/R18/R19 的 info 观测按规则聚合为一条黄牌', () => {
    const out = observationAlarmsFor([
      { rule: 'R17', severity: 'info', evidence: '!!js require(fs)' },
      { rule: 'R17', severity: 'info', evidence: '!!js child_process' },
      { rule: 'R19', severity: 'info', evidence: 'dshh' },
    ])
    expect(out).toHaveLength(2)
    const r17 = out.find(a => a.kind === 'r17-observation')
    const r19 = out.find(a => a.kind === 'r19-observation')
    expect(r17?.message).toContain('2 条')
    expect(r17?.message).toContain('!!js require(fs)')
    expect(r19?.message).toContain('1 条')
  })

  it('非 info 严重度不参与（静态层判定原样，只抬升 info 观测）', () => {
    const out = observationAlarmsFor([
      { rule: 'R17', severity: 'high', evidence: '!!js 组合' },
      { rule: 'R18', severity: 'info', evidence: 'AGENTS.md' },
    ])
    expect(out).toHaveLength(1)
    expect(out[0]!.kind).toBe('r18-observation')
  })

  it('kind 命名：r17/r18/r19-observation', () => {
    const out = observationAlarmsFor([
      { rule: 'R17', severity: 'info', message: 'a' },
      { rule: 'R18', severity: 'info', message: 'b' },
      { rule: 'R19', severity: 'info', message: 'c' },
    ])
    expect(out.map(a => a.kind).sort()).toEqual(['r17-observation', 'r18-observation', 'r19-observation'])
  })
})