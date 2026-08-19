import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'

const bundlePath = join(dirname(import.meta.dirname), 'lib', 'index.bundle.js')

describe('0.1.16 C1 发布 bundle（内部状态闭包封闭）', () => {
  it('bundle 存在且宿主形态正确（name/apply/Config/inject）', async () => {
    expect(existsSync(bundlePath)).toBe(true)
    const mod = await import(bundlePath) as Record<string, unknown>
    expect(mod.name).toBe('plugin-vet')
    expect(typeof mod.apply).toBe('function')
    expect(typeof mod.Config).toBe('function')
    expect(mod.inject).toEqual(['tools', 'skills'])
  })
  it('bundle 不导出 guard 内部状态（setRootIndexing/withVetSelfIo/confirmBlock/canaryStore 等）', async () => {
    const mod = await import(bundlePath) as Record<string, unknown>
    const leaky = Object.keys(mod).filter(k => /setRootIndexing|withVetSelfIo|confirmBlock|canaryStore|capabilityDiff|isStackTraceTampered/i.test(k))
    expect(leaky).toEqual([])
  })
})