import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { RULES, executeRules } from '../lib/scanner-bin/rules/index.js'
import { RULE_IDS, ENGINE_VERSION } from '../lib/scanner-bin/protocol.js'
import { parseSource } from '../lib/scanner-bin/ast.js'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

function codeRequest(overrides: Partial<ScanRequest>): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule)
}

function r15sOf(report: { findings: Finding[] }): Finding[] {
  return report.findings.filter(f => f.rule === 'R15')
}

describe('N5 R15 dynamic-string provenance (网络目标动态构造)', () => {
  it('规则已注册：RULES 含 R15，RULE_IDS 含 R15，ENGINE_VERSION 递增为 static-v12（缓存失效）', () => {
    expect(RULES.some(r => r.id === 'R15')).toBe(true)
    expect(RULE_IDS).toContain('R15')
    expect(ENGINE_VERSION).toBe('static-v12')
  })

  it('fetch(动态拼接) → R15 info/heuristic', () => {
    const res = scan(codeRequest({ code: "fetch('https://' + userInput + '.com')" }))
    expect(res.ok).toBe(true)
    const lst = r15sOf(res.report!)
    expect(lst.length).toBe(1)
    expect(lst[0].severity).toBe('info')
    expect(lst[0].confidence).toBe('heuristic')
    expect(lst[0].message).toContain('N5')
    expect(res.report!.verdict).toBe('clean') // info 不进 verdict
  })

  it('fetch(自由标识符，未解析到字面量) → R15（fetch 首参按契约是 URL）', () => {
    const res = scan(codeRequest({ code: 'function go(u) { fetch(u) }' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('fetch(process.env.API_URL) → R15（运行时环境目标，不可静态声明）', () => {
    const res = scan(codeRequest({ code: 'fetch(process.env.API_URL)' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('fetch(模板串含未知替换) → R15', () => {
    const res = scan(codeRequest({ code: 'function go(host: string) { fetch(`https://${host}.x.com/api`) }' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('fetch(任意函数调用结果) → R15（目标不可审计）', () => {
    const res = scan(codeRequest({ code: 'fetch(generateUrl())' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('字面量目标 → 不报（可声明）', () => {
    const res = scan(codeRequest({ code: "fetch('https://api.example.com/v1')" }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('常量标识符（const 初始化字面量）→ 不报（stringyValue 解析到声明）', () => {
    const res = scan(codeRequest({ code: "const API = 'https://api.example.com'; fetch(API)" }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('N2 可解码目标（atob）→ 不报（解码后语义可见，R13 吃语料）', () => {
    const res = scan(codeRequest({ code: "fetch(atob('aHR0cHM6Ly9ldmlsLmNvbS9jb2xsZWN0'))" }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('http.request(options 对象) → 不报（options 表单）', () => {
    const res = scan(codeRequest({ code: "http.request({ hostname: 'x.com', path: '/' }, cb)" }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('http.request(未解析标识符) → 不报（http 表单歧义：可能是 options 对象）', () => {
    const res = scan(codeRequest({ code: 'function go(url: string) { http.request(url, cb) }' }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('http.request(动态拼接) → R15', () => {
    const res = scan(codeRequest({ code: "function go(suffix: string) { http.request('https://' + suffix, cb) }" }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it("require('http').get(动态) → R15（require 属性访问形态）", () => {
    const res = scan(codeRequest({ code: "function go(x: string) { require('http').get(x + '.com') }" }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('net.connect(port, 动态 host) → R15（host 参数按契约是字符串）', () => {
    const res = scan(codeRequest({ code: 'function go(host: string) { net.connect(443, host) }' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('net.connect(仅端口) → 跳过（无目标参数）', () => {
    const res = scan(codeRequest({ code: 'net.connect(443)' }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('new WebSocket(动态变量) → R15', () => {
    const res = scan(codeRequest({ code: 'function go(u: string) { const ws = new WebSocket(u) }' }))
    expect(r15sOf(res.report!).length).toBe(1)
  })

  it('同文件多个动态 sink → 每个调用点一条（不去重合并）', () => {
    const res = scan(codeRequest({ code: "function a(u: string) { fetch(u) }; function b(v: string) { fetch('https://x.com/' + v) }; fetch('https://ok.com')" }))
    expect(r15sOf(res.report!).length).toBe(2)
  })

  it('rules: R15:false 可关闭', () => {
    const res = scan(codeRequest({ code: "fetch('https://' + userInput)", rules: { R15: false } }))
    expect(res.ok).toBe(true)
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('无网络 sink → 零 R15（无单例误报）', () => {
    const res = scan(codeRequest({ code: 'export const add = (a: number, b: number) => a + b' }))
    expect(r15sOf(res.report!)).toEqual([])
  })

  it('executeRules 直接调用（RuleContext 注入）同样生效', () => {
    const sf = parseSource("fetch('https://' + x)", 't.js', 'js')
    const findings = executeRules(sf, { request: codeRequest({}), runtime: 'host' })
    expect(findings.filter(f => f.rule === 'R15').length).toBe(1)
  })
})
