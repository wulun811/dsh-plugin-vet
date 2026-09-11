import { describe, expect, it } from 'vitest'
import corpusData from './fixtures/r13-corpus-64.json'
import { scan } from '../lib/scanner-bin/engine.js'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

/**
 * OSS 注册站（zhousm666/dsh.so）64-hit 语料回归（0.3.11）。
 * 出处：issue 回复 §7 的 JSON breakdown——「Recovered from the exact registry snapshot this
 * issue was filed against (pre-rescan, pre-suppression)」：64 findings / 35 plugins，
 * 53 条 static-v20、11 条 legacy engine:null；与 issue 主体对账：10 × .onion（0 合法地址）、
 * 1 test-file hit、1 redacted webhook template。语料原样落盘于 test/fixtures/r13-corpus-64.json。
 *
 * 本测试接线 v23/v24 引擎的**类别级**回归（语料无源码上下文，逐条只能复刻 shape/evidence
 * 级输入）：
 *  ① flags.onion（10）——全部为非法 label（action.onion / 散文里的 .onion），v23 只认
 *     v2 16 / v3 56 base32 label → 零命中；
 *  ② shape=prose-or-label（17）——整字面量非端点形态 → 零命中；
 *  ③ flags.redacted（1）→ 脱敏占位降 info；
 *  ④ flags.test-file（1）→ 测试/CI 文件降 info（verdict clean）；
 *  ⑤ sourceVerified（9，reporter §2 全部溯源为 deny-list/guard）→ 守卫语境降 info
 *     （prose 那条由②零命中）；
 *  ⑥ 形状级护栏：裸字面量端点（去重 6 个）在纯字面量语境**保持 high**——v23 的纪律是
 *     「字符串本身不是问题，散文/守卫语境才是」，防止过度抑制；尾部带句点的
 *     http://metadata.google.internal. 是形状边界 → 零命中；
 *  ⑦ ⑥ 中每个端点的守卫语境变体 → info（真实世界的安静来自守卫语境，如 dsh-netguard
 *     address.js:213 的 REFUSED_ADDRESSES 冻结表）。
 */

interface CorpusEntry {
  id: string
  package: string | null
  engine: string | null
  basis: string
  file: string
  line: number
  severity: string
  confidence: string
  shape: string
  flags: string[]
  evidence: string
  sourceVerified?: boolean
}

const corpus = corpusData as CorpusEntry[]

function codeRequest(overrides: Partial<ScanRequest>): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string, severity?: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule && (severity === undefined || f.severity === severity))
}

function withTmp(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r13corpus-'))
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content)
  }
  try {
    fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

/** 把任意 evidence 安全地嵌入 JS 字符串字面量。 */
const lit = (evidence: string): string => JSON.stringify(evidence)

describe('0.3.11 R13 64-hit 语料回归（OSS 注册站 §7 交付物）', () => {
  it('语料完整性：64 条 / 35 插件（与 issue 对账）', () => {
    expect(corpus.length).toBe(64)
    expect(new Set(corpus.map(e => e.id)).size).toBe(35)
    expect(corpus.filter(e => e.flags.includes('onion')).length).toBe(10)
    expect(corpus.filter(e => e.flags.includes('test-file')).length).toBe(1)
    expect(corpus.filter(e => e.flags.includes('redacted')).length).toBe(1)
    expect(corpus.filter(e => e.sourceVerified === true).length).toBe(9)
  })

  it('① onion 标记 10 条全零命中（非法 label 不再命中）', () => {
    for (const e of corpus.filter(x => x.flags.includes('onion'))) {
      const res = scan(codeRequest({ code: `const x = ${lit(e.evidence)};` }))
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R13'), `${e.id} ${e.file}:${e.line} evidence=${e.evidence}`).toBeUndefined()
    }
  })

  it('② prose-or-label 17 条全零命中（整字面量非端点形态）', () => {
    for (const e of corpus.filter(x => x.shape === 'prose-or-label')) {
      const res = scan(codeRequest({ code: `const doc = ${lit(e.evidence)};` }))
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R13'), `${e.id} ${e.file}:${e.line} evidence=${e.evidence}`).toBeUndefined()
    }
  })

  it('③ redacted 标记 1 条 → 脱敏占位降 info', () => {
    const e = corpus.find(x => x.flags.includes('redacted'))!
    const res = scan(codeRequest({ code: `const tpl = ${lit(e.evidence)};` }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13, e.evidence).toBeDefined()
    expect(r13!.severity).toBe('info')
    expect(r13!.message).toContain('脱敏占位')
  })

  it('④ test-file 标记 1 条 → 测试/CI 文件降 info，verdict clean', () => {
    const e = corpus.find(x => x.flags.includes('test-file'))!
    withTmp({ [e.file]: `const M = ${lit(e.evidence)}\n` }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, e.file)] })
      expect(res.ok).toBe(true)
      const r13 = findingOf(res.report!, 'R13')
      expect(r13, `${e.id} ${e.file}:${e.line}`).toBeDefined()
      expect(r13!.severity).toBe('info')
      expect(r13!.message).toContain('测试/CI')
      expect(res.report!.verdict).toBe('clean')
    })
  })

  it('⑤ sourceVerified 9 条守卫语境 → info（prose 那条由②零命中）', () => {
    const verified = corpus.filter(x => x.sourceVerified === true)
    expect(verified.length).toBe(9)
    // 守卫形状按 evidence 分簇复刻（reporter §2：5 处位置全部溯源为 deny-list/guard），
    // 并断言命中的 finding evidence 与该条语料对上（不是「存在任意 info」）。
    const cluster = (evidence: string): string => {
      if (evidence === '169.254.169.254/32') {
        return 'export const REFUSED_ADDRESSES = Object.freeze([rule("169.254.169.254/32", "cloud-metadata", true), rule("100.100.100.200/32", "alicloud", true)])\n'
      }
      if (evidence === 'metadata.google.internal') {
        return 'if (host === "metadata.google.internal") throw new Error("cloud metadata not allowed")\n'
      }
      if (evidence === '169.254.169.254' || evidence === '100.100.100.200') {
        return 'const BLOCKED = new Set(["169.254.169.254", "100.100.100.200"]);\nif (BLOCKED.has(host)) throw new Error("denied")\n'
      }
      return '' // prose 形态（cloud metadata (169.254.169.254)）→ ② 已覆盖零命中
    }
    for (const e of verified) {
      const code = cluster(e.evidence)
      if (code === '') {
        const res = scan(codeRequest({ code: `const doc = ${lit(e.evidence)};` }))
        expect(findingOf(res.report!, 'R13'), `${e.id} ${e.file}:${e.line}`).toBeUndefined()
        continue
      }
      const res = scan(codeRequest({ code }))
      expect(res.ok).toBe(true)
      const r13 = res.report!.findings.find(
        f => f.rule === 'R13' && f.severity === 'info' && f.evidence.includes(e.evidence),
      )
      expect(r13, `${e.id} ${e.file}:${e.line} evidence=${e.evidence}`).toBeDefined()
      expect(r13!.message).toContain('拒绝名单')
    }
  })

  it('⑥ 形状级护栏：裸端点字面量保持 high（防过度抑制），尾点 URL 是形状边界 → 零命中', () => {
    const verifiedEvidence = new Set(corpus.filter(x => x.sourceVerified === true).map(x => x.evidence))
    const distinct = [...new Set(
      corpus
        .filter(x => x.shape !== 'prose-or-label' && !x.flags.includes('onion') && !x.flags.includes('test-file') && !x.flags.includes('redacted'))
        .map(x => x.evidence),
    )]
    // 与 sourceVerified 证据同值时其守卫性已由⑤ 验证——此处护栏覆盖语料独有的纯裸字面量
    const bare = distinct.filter(ev => !verifiedEvidence.has(ev))
    expect(bare.sort()).toEqual([
      'discord.com/api/webhooks',
      'hooks.slack.com/services',
      'http://169.254.169.254',
      'http://metadata.google.internal.',
    ].sort())
    for (const ev of bare) {
      const res = scan(codeRequest({ code: `const x = ${lit(ev)};` }))
      expect(res.ok).toBe(true)
      if (ev === 'http://metadata.google.internal.') {
        // 尾部句点 → ENDPOINT_SHAPE 不成立（句子截断痕迹）→ 零命中
        expect(findingOf(res.report!, 'R13'), `trailing-dot boundary: ${ev}`).toBeUndefined()
      } else {
        const r13 = findingOf(res.report!, 'R13', 'high')
        expect(r13, `bare literal must stay high: ${ev}`).toBeDefined()
      }
    }
  })

  it('⑦ 裸端点证据的守卫语境变体 → info（真实世界安静来自守卫语境）', () => {
    const guardShapes: Array<{ name: string; code: string }> = [
      { name: 'metadata.google.internal（deny Set）', code: 'const BLOCKED_HOSTS = new Set(["metadata.google.internal"]); if (BLOCKED_HOSTS.has(host)) throw 1' },
      { name: '169.254.169.254（deny Set）', code: 'const BLOCKED = new Set(["169.254.169.254"]); if (BLOCKED.has(host)) throw 1' },
      { name: '100.100.100.200（deny Set）', code: 'const BLOCKED = new Set(["100.100.100.200"]); if (BLOCKED.has(host)) throw 1' },
      { name: 'discord.com/api/webhooks（policy deny）', code: 'const POLICY_DENY = new Set(["discord.com/api/webhooks", "hooks.slack.com/services"]); if (POLICY_DENY.has(url)) throw 1' },
      { name: 'http://169.254.169.254（比较守卫）', code: 'if (target === "http://169.254.169.254") throw 1' },
    ]
    for (const g of guardShapes) {
      const res = scan(codeRequest({ code: g.code }))
      expect(res.ok).toBe(true)
      const r13 = findingOf(res.report!, 'R13', 'info')
      expect(r13, g.name).toBeDefined()
      expect(r13!.message).toContain('拒绝名单')
    }
  })
})