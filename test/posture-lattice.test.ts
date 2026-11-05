import { describe, expect, it } from 'vitest'
import {
  POSTURE_SURFACES,
  postureEntry,
  postureOf,
  postureSeverity,
  postureSummary,
  type PostureInput,
} from '../lib/domain/posture.js'
import { derivePosture, type PostureObservations } from '../lib/guard/posture.js'

/**
 * 0.5.2 步骤 7 之一：姿态的 96 格真值表。
 *
 * 六面 × 四输入二值（desired / supported / installed / healthy）= 6 × 16 = 96。
 * 这里把九个里的六个面**逐一**跑一遍 16 种组合——格子本身不看面，但「有没有哪个面偷偷
 * 开了特例」只能这样证。判定函数与输入来源分开（domain 纯格运算 / guard 取观测），
 * 也是为了让这张表能被穷举，而不用造一整个配置对象才验一格。
 */

const bits = (n: number): [boolean, boolean, boolean, boolean] => [
  (n & 1) !== 0,
  (n & 2) !== 0,
  (n & 4) !== 0,
  (n & 8) !== 0,
]

const EXPECTED: Record<number, string> = {
  // 位序：bit0=desired bit1=supported bit2=installed bit3=healthy
  0b0000: 'off', 0b0001: 'unsupported', 0b0010: 'off', 0b0011: 'degraded',
  0b0100: 'off', 0b0101: 'unsupported', 0b0110: 'off', 0b0111: 'degraded',
  0b1000: 'off', 0b1001: 'unsupported', 0b1010: 'off', 0b1011: 'degraded',
  0b1100: 'off', 0b1101: 'unsupported', 0b1110: 'off', 0b1111: 'enforced',
}

describe('格运算：6 面 × 16 = 96 格', () => {
  it('六个面 × 16 种输入组合，逐格给出定义内的结果', () => {
    let cells = 0
    for (const surface of POSTURE_SURFACES) {
      for (let n = 0; n < 16; n++) {
        const [desired, supported, installed, healthy] = bits(n)
        const input: PostureInput = { desired, supported, installed, healthy }
        const entry = postureEntry(surface, input)
        expect(entry.effective, `${surface} ${n.toString(2)}`).toBe(EXPECTED[n])
        cells += 1
      }
    }
    expect(cells).toBe(96)
    expect(POSTURE_SURFACES).toHaveLength(6)
  })

  it('不和稀泥：desired 为真而没生效时，结果绝不是 enforced', () => {
    for (let n = 0; n < 16; n++) {
      const [desired, supported, installed, healthy] = bits(n)
      if (!desired) continue
      const all = supported && installed && healthy
      expect(postureOf({ desired, supported, installed, healthy })).toBe(all ? 'enforced' : EXPECTED[n])
      if (!all) expect(postureOf({ desired, supported, installed, healthy })).not.toBe('enforced')
    }
  })

  it('desired=false 一律 off——「关着」不是「失败」', () => {
    for (let n = 0; n < 16; n++) {
      const [, supported, installed, healthy] = bits(n)
      expect(postureOf({ desired: false, supported, installed, healthy })).toBe('off')
    }
  })

  it('unsupported 与 degraded 必须分开（本版本没有 vs 有但没生效）', () => {
    expect(postureOf({ desired: true, supported: false, installed: false, healthy: false })).toBe('unsupported')
    expect(postureOf({ desired: true, supported: true, installed: false, healthy: true })).toBe('degraded')
  })

  it('关掉的开关即便观测不到也是 off（没有「不知道」可言）', () => {
    expect(postureOf({ desired: false, supported: true, installed: null, healthy: null })).toBe('off')
    expect(postureOf({ desired: false, supported: false, installed: null, healthy: false })).toBe('off')
  })

  it('观测不到（null）→ unknown，不拿 false 代替', () => {
    expect(postureOf({ desired: true, supported: true, installed: null, healthy: true })).toBe('unknown')
    expect(postureOf({ desired: true, supported: true, installed: true, healthy: null })).toBe('unknown')
  })
})

describe('gap 与严重度：只说「想要但没得到」', () => {
  it('enforced / off 不算 gap，其余算', () => {
    expect(postureSeverity(postureEntry('runtime_fs', { desired: true, supported: true, installed: true, healthy: true }))).toBeUndefined()
    expect(postureSeverity(postureEntry('runtime_fs', { desired: false, supported: true, installed: true, healthy: true }))).toBeUndefined()
    expect(postureSeverity(postureEntry('runtime_fs', { desired: true, supported: true, installed: false, healthy: true }))).toBe('yellow')
    expect(postureSeverity(postureEntry('runtime_fs', { desired: true, supported: false, installed: true, healthy: true }))).toBe('info')
  })

  it('gap 文案指出具体是哪一路塌了', () => {
    expect(postureEntry('runtime_fs', { desired: true, supported: true, installed: false, healthy: true }).gap).toContain('not installed')
    expect(postureEntry('runtime_fs', { desired: true, supported: true, installed: true, healthy: false }).gap).toContain('unhealthy')
    expect(postureEntry('runtime_fs', { desired: true, supported: false, installed: true, healthy: true }).gap).toContain('not supported')
  })

  it('summary 数得清「生效了几个」与「差在哪」', () => {
    const entries = [
      postureEntry('runtime_fs', { desired: true, supported: true, installed: true, healthy: true }),
      postureEntry('runtime_net', { desired: true, supported: true, installed: false, healthy: true }),
    ]
    const summary = postureSummary(entries)
    expect(summary.enforced).toBe(1)
    expect(summary.gaps).toHaveLength(1)
  })
})

describe('derivePosture：从观测到六行', () => {
  const obs = (over: Partial<PostureObservations> = {}): PostureObservations => ({
    autoScan: true,
    requireAudit: false,
    runtimeGuard: 'watch',
    confirmBlock: 'block',
    hookChecks: [
      { module: 'fs', op: 'writeFile', intact: true },
      { module: 'child_process', op: 'spawn', intact: true },
    ],
    archiveDirReadable: true,
    lastScanOk: true,
    ...over,
  })

  it('守卫关闭 → 三个运行时面与 N7 都是 off（不是 failure——用户没要求）', () => {
    const entries = derivePosture(obs({ runtimeGuard: 'off' }))
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn', 'confirm_block'] as const) {
      const e = entries.find((x) => x.surface === surface)!
      expect(e.effective, surface).toBe('off')
      expect(postureSeverity(e), surface).toBeUndefined()
    }
  })

  it('守卫开着但 net 没钩子 → runtime_net 是 degraded（配置了没装上）', () => {
    const entries = derivePosture(obs())
    const net = entries.find((x) => x.surface === 'runtime_net')!
    expect(net.effective).toBe('degraded')
    expect(net.gap).toContain('not installed')
    // fs 有钩子且完好 → enforced
    expect(entries.find((x) => x.surface === 'runtime_fs')!.effective).toBe('enforced')
  })

  it('钩子被剥离 → 对应面 degraded，N7 跟着塌（拦截点就在 fs 包装里）', () => {
    const entries = derivePosture(obs({ hookChecks: [{ module: 'fs', op: 'writeFile', intact: false }] }))
    expect(entries.find((x) => x.surface === 'runtime_fs')!.effective).toBe('degraded')
    expect(entries.find((x) => x.surface === 'confirm_block')!.effective).toBe('degraded')
  })

  it('requireAudit 打开但档案目录读不到 → audit_gate degraded（那是故障不是保护）', () => {
    const entries = derivePosture(obs({ requireAudit: true, archiveDirReadable: false }))
    const gate = entries.find((x) => x.surface === 'audit_gate')!
    expect(gate.effective).toBe('degraded')
    expect(gate.gap).toContain('not installed')
  })

  it('还没扫过（lastScanOk=undefined）→ preload_scan unknown，不是 enforced', () => {
    const entries = derivePosture(obs({ lastScanOk: undefined }))
    expect(entries.find((x) => x.surface === 'preload_scan')!.effective).toBe('unknown')
  })
})
