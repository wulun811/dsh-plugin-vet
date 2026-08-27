import { describe, expect, it, afterEach } from 'vitest'
import { createT2Sink } from '../lib/guard/runtime-sink.js'
import { VetStatus } from '../lib/guard/status.js'
import { markOfficialTrusted, resetOfficialTrustForTest } from '../lib/guard/runtime-attrib.js'

// 运行时拼接出完整 PEM 头尾——避免源码出现完整密钥样序列触发仓库自身的密钥门禁
const PEM = ['-----BEGIN ', 'PRIVATE KEY-----\nAAAA\n-----END ', 'PRIVATE KEY-----'].join('')

describe('recordKeyLeak 归因分级（0.1.21 → 0.2.1 修复）', () => {
  afterEach(() => { resetOfficialTrustForTest() })

  it('无主（宿主自身流量）→ 不报警（宿主对话包含 PEM 格式是正常行为，非外泄）', () => {
    const s = new VetStatus()
    createT2Sink(s).recordKeyLeak('body', 'upload ' + PEM, undefined)
    // 0.2.1 修复：无主警报不报警——宿主对话包含 PEM 格式是正常行为（安全讨论、文档示例等）
    expect(s.snapshot().alarms.length).toBe(0)
  })

  it('归因第三方插件 → red 按外泄处置', () => {
    const s = new VetStatus()
    createT2Sink(s).recordKeyLeak('body', 'upload ' + PEM, 'evil-plugin')
    const a = s.snapshot().alarms.find(x => x.kind === 'n3-key-leak')
    expect(a?.severity).toBe('red')
    expect(a?.message).toContain('按外泄处置')
    expect(a?.pluginHint).toBe('evil-plugin')
  })

  it('内容信任锚官方包归因 → 静默（既有豁免语义不变，判据升级为信任锚）', () => {
    const s = new VetStatus()
    // round-16（SEC-1）：豁免 = 内容信任锚（markOfficialTrusted 模拟基线 match/registry 对账通过）
    markOfficialTrusted('@deepseek-ai/dsh-web-app')
    createT2Sink(s).recordKeyLeak('body', 'upload ' + PEM, '@deepseek-ai/dsh-web-app')
    expect(s.snapshot().alarms.length).toBe(0)
  })

  it('SEC-1：仅名字前缀的官方归因不再静默——伪名包外泄照常报警', () => {
    const s = new VetStatus()
    // 不加 markOfficialTrusted：@deepseek-ai/* 前缀不再是外泄静默判据（伪名 tarball 可伪造前缀）
    createT2Sink(s).recordKeyLeak('body', 'upload ' + PEM, '@deepseek-ai/forged-evil')
    const a = s.snapshot().alarms.find(x => x.kind === 'n3-key-leak')
    expect(a?.severity).toBe('red')
    expect(a?.pluginHint).toBe('@deepseek-ai/forged-evil')
  })
})
