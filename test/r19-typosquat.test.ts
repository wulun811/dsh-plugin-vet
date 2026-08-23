import { afterEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../lib/scanner-bin/engine.js'
import { runTyposquat, isTyposquatOf } from '../lib/scanner-bin/rules/typosquat.js'

function writePkg(name: string, deps: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'vet-r19-'))
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, dependencies: deps }, null, 2))
  return dir
}

function r19sOf(report: { findings: { rule: string }[] }) {
  return report.findings.filter(f => f.rule === 'R19')
}

describe('R19 typosquat 观测（P4/G-9，round-13）', () => {
  let dirs: string[] = []
  afterEach(() => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }) } catch {} } dirs = [] })

  it('isTyposquatOf 单元：编辑距离 ≤1 / 同形 / 精确匹配不算', () => {
    expect(isTyposquatOf('dshh', 'dsh')).toBe(true)
    expect(isTyposquatOf('dsh-base', 'dsh-bases')).toBe(true)
    expect(isTyposquatOf('d5h', 'dsh')).toBe(true) // 同形 5≈s
    expect(isTyposquatOf('dsh_tool_bash', 'dsh-tool-bash')).toBe(true) // 同形 -≈_
    expect(isTyposquatOf('dsh', 'dsh')).toBe(false)
    expect(isTyposquatOf('dsh-tool-subagent', 'dsh-tool-subagent')).toBe(false)
    expect(isTyposquatOf('completely-unrelated', 'dsh')).toBe(false)
  })

  it('依赖含仿冒名 → R19 info，verdict clean（永不进 verdict）', () => {
    const dir = writePkg('legit-plugin', { '@deepseek-ai/dshh': '^1.0.0' })
    dirs.push(dir)
    const pkg = join(dir, 'package.json')
    const res = scan({ kind: 'files', files: [pkg] })
    expect(res.ok).toBe(true)
    const rs = r19sOf(res.report!)
    expect(rs.length).toBeGreaterThan(0)
    expect(rs[0].severity).toBe('info')
    expect(rs[0].message).toContain('dshh')
    expect(res.report!.verdict).toBe('clean')
  })

  it('自身 name 仿冒同样提示；精确官方依赖不提示', () => {
    const dir1 = writePkg('dsh-toolsx', {})
    dirs.push(dir1)
    const res1 = scan({ kind: 'files', files: [join(dir1, 'package.json')] })
    expect(r19sOf(res1.report!).some(f => f.message.includes('dsh-toolsx'))).toBe(true)
    const dir2 = writePkg('legit', { '@deepseek-ai/dsh-tool-bash': '^1.0.0' })
    dirs.push(dir2)
    const res2 = scan({ kind: 'files', files: [join(dir2, 'package.json')] })
    expect(r19sOf(res2.report!).length).toBe(0)
  })

  it('rules.R19=false 关闭；坏 JSON 不炸', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vet-r19b-'))
    dirs.push(dir)
    const pkg = join(dir, 'package.json')
    writeFileSync(pkg, JSON.stringify({ name: 'x', dependencies: { '@deepseek-ai/dshh': '1' } }))
    const off = scan({ kind: 'files', files: [pkg], rules: { R19: false } })
    expect(r19sOf(off.report!).length).toBe(0)
    writeFileSync(pkg, '{ bad json')
    const bad = scan({ kind: 'files', files: [pkg] })
    expect(bad.ok).toBe(true)
    expect(r19sOf(bad.report!).length).toBe(0)
  })

  it('round-15：npm-public 新官方名在名单中；精确名不报、仿冒名报', () => {
    expect(isTyposquatOf('dsh-agant', 'dsh-agent')).toBe(true)
    expect(isTyposquatOf('dsh-subagant', 'dsh-subagent')).toBe(true)
    const pkg = JSON.stringify({ name: 'p', dependencies: { '@deepseek-ai/dsh-agent': '1', '@deepseek-ai/dsh-agentx': '1' } })
    const rs = runTyposquat(pkg, 'package.json')
    expect(rs.length).toBe(1)
    expect(rs[0].message).toContain('dsh-agentx')
  })

  it('round-15 复查：+5 官方名（telemetry row 包/短名/接口面）；精确名不报、仿冒名报', () => {
    expect(isTyposquatOf('dsh-session-telemetry-0tel', 'dsh-session-telemetry-otel')).toBe(true)
    expect(isTyposquatOf('dsh-session-telemetry-ote1', 'dsh-session-telemetry-otel')).toBe(true)
    expect(isTyposquatOf('dsh-goa1', 'dsh-goal')).toBe(true)
    expect(isTyposquatOf('dsh-headles', 'dsh-headless')).toBe(true)
    expect(isTyposquatOf('dsh-mcp-clien', 'dsh-mcp-client')).toBe(true)
    expect(isTyposquatOf('dsh-session-telemetry-otel', 'dsh-session-telemetry-otel')).toBe(false)
    expect(isTyposquatOf('dsh-session-telemetry', 'dsh-session-telemetry-otel')).toBe(false) // 长度差>1 不误判
    const pkg = JSON.stringify({
      name: 'p',
      dependencies: {
        '@deepseek-ai/dsh-session-telemetry-otel': '1', // 精确官方名 → 不报
        '@deepseek-ai/dsh-session-telemetry-0tel': '1', // 0≈o 同形 → 报
      },
    })
    const rs = runTyposquat(pkg, 'package.json')
    expect(rs.length).toBe(1)
    expect(rs[0].message).toContain('0tel')
  })

  it('runTyposquat 单元：精确官方名不报，仿冒名报一条', () => {
    const pkg = JSON.stringify({ name: 'p', dependencies: { '@deepseek-ai/dsh': '1', '@deepseek-ai/dshh': '1' } })
    const rs = runTyposquat(pkg, 'package.json')
    expect(rs.length).toBe(1)
    expect(rs[0].message).toContain('dshh')
    expect(rs[0].message).not.toContain('@deepseek-ai/dsh"') // 精确名自身不出现为候选
  })
})