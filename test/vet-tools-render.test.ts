import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { recordScan, setCapabilitiesDirForTest, type CapabilityManifest } from '../lib/guard/version-diff.js'
import { createVetLabelTool } from '../lib/tools/vet-label.js'
import { createVetDiffTool } from '../lib/tools/vet-diff.js'

/**
 * 三轮审查回归（DSH.SO 反馈 bug）：单条版本记录时 vet_label 渲染崩溃。
 * 根因：execute 对 null 字段整键省略 → render 收到 undefined，`!== null` 判断穿透，
 * 读 .from 抛 “Cannot read properties of undefined (reading 'from')”。
 * vet_diff 为同款隐患，一并覆盖。
 */
describe('vet_label / vet_diff 单记录渲染边界（三轮审查回归）', () => {
  let testDir: string

  const manifest = (o: Partial<CapabilityManifest> = {}): CapabilityManifest => ({
    hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false, ...o,
  })

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'vet-render-'))
    setCapabilitiesDirForTest(testDir)
  })

  afterEach(() => {
    setCapabilitiesDirForTest(undefined)
    rmSync(testDir, { recursive: true, force: true })
  })

  it('vet_label：仅一条版本记录 → execute+render 全程不抛错，无升级差分行', async () => {
    recordScan('@x/single', '1.0.0', manifest({ hosts: ['api.example.com'], hasNetwork: true }))
    const tool = createVetLabelTool()
    const args = { package: '@x/single' }
    const value = await tool.execute(args) as Record<string, unknown>
    expect(value.diffSummary).toBeUndefined() // 键被省略——正是触发渲染崩溃的形状
    const rendered = tool.output.render(args as never, value as never) as { type: string; text: string }[]
    expect(rendered[0]!.text).not.toContain('最近升级')
    expect(rendered[0]!.text).toContain('api.example.com')
  })

  it('vet_diff：仅一条版本记录 → 同款边界不抛错', async () => {
    recordScan('@x/single2', '2.0.0', manifest({ spawnCmds: ['git'] }))
    const tool = createVetDiffTool()
    const args = { package: '@x/single2' }
    const value = await tool.execute(args) as Record<string, unknown>
    expect(value.diff).toBeUndefined()
    const rendered = tool.output.render(args as never, value as never) as { type: string; text: string }[]
    expect(rendered[0]!.text).not.toContain('行为差分')
    expect(rendered[0]!.text).toContain('2.0.0')
  })

  it('多版本记录 → 升级差分照常渲染（防修过界）', async () => {
    recordScan('@x/multi', '1.0.0', manifest({ hosts: ['old.example.com'] }))
    recordScan('@x/multi', '1.1.0', manifest({ hosts: ['old.example.com', 'new.example.com'], hasExec: true }))
    const tool = createVetLabelTool()
    const args = { package: '@x/multi' }
    const value = await tool.execute(args) as Record<string, unknown>
    const rendered = tool.output.render(args as never, value as never) as { type: string; text: string }[]
    expect(rendered[0]!.text).toContain('最近升级 1.0.0 → 1.1.0')
    expect(rendered[0]!.text).toContain('执行能力')
  })

  // 四轮审查回归：loadCapabilities 对单条记录零结构校验，残缺存储（手改/半写/旧版升级遗留）
  // 可让 renderLabel 收到 undefined manifest（execute 键省略同款穿透）或缺数组字段的对象。
  it('四轮回归：残缺存储——单条记录缺 capabilities → manifest 穿透为 undefined，渲染不崩', async () => {
    writeFileSync(join(testDir, 'capabilities.json'), JSON.stringify({
      records: { r1: { name: '@x/corrupt', version: '9.9.9', recordedAt: Date.now() } },
    }))
    const tool = createVetLabelTool()
    const args = { package: '@x/corrupt' }
    const value = await tool.execute(args) as Record<string, unknown>
    expect(value.present).toBe(true)
    expect(value.manifest).toBeUndefined() // 与用户上报崩溃完全相同的形状
    const rendered = tool.output.render(args as never, value as never) as { type: string; text: string }[]
    expect(rendered[0]!.text).toContain('vet label @x/corrupt')
    expect(rendered[0]!.text).not.toContain('undefined')
  })

  it('四轮回归：manifest 缺数组字段 → 各段按空渲染不崩、能力布尔照常展示', async () => {
    writeFileSync(join(testDir, 'capabilities.json'), JSON.stringify({
      records: { r2: { name: '@x/partial', version: '8.8.8', recordedAt: Date.now(), capabilities: { hasNetwork: true } } },
    }))
    const tool = createVetLabelTool()
    const args = { package: '@x/partial' }
    const value = await tool.execute(args) as Record<string, unknown>
    expect(value.manifest).toBeDefined()
    const rendered = tool.output.render(args as never, value as never) as { type: string; text: string }[]
    expect(rendered[0]!.text).toContain('网络')
    expect(rendered[0]!.text).not.toContain('undefined')
  })
})