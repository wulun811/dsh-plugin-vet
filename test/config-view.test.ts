/**
 * 生效配置视图（`src/config-view.ts`）的单元测试。
 *
 * 这一层最容易出的错不是崩溃，是**说反**：把一个"设了但没用"的键说成在用（用户以为
 * 防护开着），或者把一个在用的键说成没用（用户白折腾一遍）。所以每个用例都同时断言
 * 状态与 `because`——只断言"有一条记录"是不够的。
 */
import { describe, it, expect } from 'vitest'
import { VET_CONFIG_DEFAULTS, applyProfile, type VetConfig } from '../lib/config.js'
import { effectiveConfigView } from '../lib/config-view.js'

function cfg(over: Partial<VetConfig> = {}): VetConfig {
  return { ...(VET_CONFIG_DEFAULTS as unknown as VetConfig), ...over }
}

function reading(c: VetConfig, key: string) {
  return effectiveConfigView(c).keys.find((k) => k.key === key)
}

describe('默认配置：什么都没动，就什么都不用解释', () => {
  it('standard 默认值下 changed = 0', () => {
    const view = effectiveConfigView(cfg())
    expect(view.keys).toEqual([])
    expect(view.counts).toEqual({ changed: 0, active: 0, inert: 0, partial: 0 })
    expect(view.profile).toBe('standard')
  })

  it('空对象字典不算「动过」（rules: {} 与默认等价）', () => {
    expect(reading(cfg({ rules: {} }), 'rules')).toBeUndefined()
    expect(reading(cfg({ rules: { R18: false } }), 'rules')?.status).toBe('active')
  })
})

describe('被 runtimeGuard 支配的一批键', () => {
  it('守卫 off：蜜罐与 T1 阈值都不生效，且指名支配者', () => {
    const c = cfg({
      runtimeGuard: 'off', honeypot: { enabled: true, dir: '' },
      runtimeMemLimitMb: 8192, runtimeWarmupMs: 60_000, runtimeMemSustainMs: 5_000,
    })
    for (const key of ['honeypot.enabled', 'runtimeMemLimitMb', 'runtimeWarmupMs', 'runtimeMemSustainMs']) {
      const r = reading(c, key)
      expect(r?.status, key).toBe('inert')
      expect(r?.because, key).toBe('runtimeGuard')
    }
  })

  it('守卫 watch：同一批键变成 active', () => {
    const c = cfg({
      runtimeGuard: 'watch', honeypot: { enabled: true, dir: '' },
      runtimeMemLimitMb: 8192, runtimeWarmupMs: 60_000, runtimeMemSustainMs: 5_000,
    })
    for (const key of ['honeypot.enabled', 'runtimeMemLimitMb', 'runtimeWarmupMs', 'runtimeMemSustainMs']) {
      expect(reading(c, key)?.status, key).toBe('active')
    }
  })

  it('networkEgress / observeLoopback 同样只在 watch 下有意义', () => {
    const off = cfg({ runtimeGuard: 'off', networkEgress: false, observeLoopback: false })
    expect(reading(off, 'networkEgress')?.status).toBe('inert')
    expect(reading(off, 'observeLoopback')?.status).toBe('inert')
    const watch = cfg({ runtimeGuard: 'watch', networkEgress: false, observeLoopback: false })
    expect(reading(watch, 'networkEgress')?.status).toBe('active')
    expect(reading(watch, 'observeLoopback')?.status).toBe('active')
  })

  it('runtimeGuard 自己不会被自己支配（白名单不是前缀匹配）', () => {
    expect(reading(cfg({ runtimeGuard: 'watch' }), 'runtimeGuard')?.status).toBe('active')
  })
})

describe('更具体的支配排在更前面', () => {
  it('蜜罐没开时，诱饵目录的原因是 honeypot.enabled 而不是 runtimeGuard', () => {
    const c = cfg({ runtimeGuard: 'off', honeypot: { enabled: false, dir: '/tmp/lures' } })
    const r = reading(c, 'honeypot.dir')
    expect(r?.status).toBe('inert')
    expect(r?.because).toBe('honeypot.enabled')
  })

  it('蜜罐开了、守卫没开：这时原因是 runtimeGuard', () => {
    const c = cfg({ runtimeGuard: 'off', honeypot: { enabled: true, dir: '/tmp/lures' } })
    expect(reading(c, 'honeypot.dir')?.because).toBe('runtimeGuard')
  })

  it('契约目录同理：contract.enabled=false 时目录不被读取', () => {
    const c = cfg({ contract: { enabled: false, dir: '/tmp/contracts' } })
    expect(reading(c, 'contract.dir')).toMatchObject({ status: 'inert', because: 'contract.enabled' })
  })
})

describe('被 mode 支配：没有拦截判定，就没有门槛', () => {
  it('report 模式下 denyOn 不生效', () => {
    expect(reading(cfg({ mode: 'report', denyOn: 'suspicious' }), 'denyOn')).toMatchObject({
      status: 'inert',
      because: 'mode',
    })
  })

  it('deny 模式下同一项在用', () => {
    expect(reading(cfg({ mode: 'deny', denyOn: 'suspicious' }), 'denyOn')?.status).toBe('active')
  })
})

/**
 * 0.5.18：`domainProjection` 是「设了但看不出区别」的典型。
 *
 * 实测依据（真实打包产物 + 真宿主，两种模式各起一次）：`shadow` 与 `active` 在面板上
 * 产出逐字段相同的告警，因为投影与旧字面量目前等价。所以把它标成 `active`（在用）会让
 * 用户以为切换做了什么——而这正是这个视图存在要防的那种「说反」。
 *
 * 0.5.18 后半段：默认值已从 `shadow` 切到 `active`。于是「没动过的键不解释」这条规则
 * 让 active 不再出现，要验证提示文案就得从非默认值那一侧进（shadow / legacy）。
 */
describe('domainProjection：生效的层级是实现路径，不是可观察输出', () => {
  it('默认值不出现（没动过的键不解释）', () => {
    // 默认现在是 active；显式写成默认值与不写无法区分，都不该占一行解释。
    expect(reading(cfg({}), 'domainProjection')).toBeUndefined()
    expect(reading(cfg({ domainProjection: VET_CONFIG_DEFAULTS.domainProjection }), 'domainProjection')).toBeUndefined()
  })

  it('显式选 shadow 报 partial，并说清「面板上看不出差别」', () => {
    const r = reading(cfg({ domainProjection: 'shadow' }), 'domainProjection')
    expect(r?.status).toBe('partial')
    expect(r?.because).toBe('domainProjection')
    // 这句是重点：不许让用户以为选了就有新行为
    expect(r?.note).toContain('看不出差别')
    expect(r?.note).toContain('等价')
  })

  it('legacy 同样报 partial，说明它跳过投影', () => {
    const r = reading(cfg({ domainProjection: 'legacy' }), 'domainProjection')
    expect(r?.status).toBe('partial')
    expect(r?.note).toContain('跳过投影')
  })
})

/**
 * 0.5.19（F19）：审计门槛已经从 `autoScan` 下面搬走了，两个基线还没有——它们都要在
 * 加载期走包目录树算哈希。这个依赖在配置文件里看不出来，所以必须由这一层说出来。
 */
describe('autoScan 仍然支配的两个基线（0.5.19）', () => {
  it('autoScan:false + 三方基线开着 → inert，并指名支配者是 autoScan', () => {
    const r = reading(cfg({ autoScan: false, thirdPartyBaseline: true }), 'thirdPartyBaseline')
    expect(r?.status).toBe('inert')
    expect(r?.because).toBe('autoScan')
    // 这句话必须顺带把「审计门槛不受影响」说出来：它正是这一版修掉的那件事，
    // 而用户看到 autoScan:false 时最可能担心的就是「那还要不要审」。
    expect(r?.note).toContain('requireAudit')
  })

  it('用户自己把基线关掉：不能说成「被 autoScan 关掉」', () => {
    // contentBaseline 默认 true，显式写成 false 才是「动过」；这时原因是他自己的开关，
    // 不是 autoScan——把那个也说成 autoScan 就是在编理由。
    const r = reading(cfg({ autoScan: false, contentBaseline: false }), 'contentBaseline')
    expect(r?.status).toBe('active')
    expect(r?.because).toBeUndefined()
  })

  it('autoScan 开着时基线照常在用', () => {
    const r = reading(cfg({ autoScan: true, thirdPartyBaseline: true }), 'thirdPartyBaseline')
    expect(r?.status).toBe('active')
  })
})

describe('部分生效：显式覆写与主开关的关系要写下来，而不是留给人猜', () => {
  it('confirmBlock=off + 族 3 显式 block：报 partial 并说明覆写仍然生效', () => {
    const r = reading(cfg({ confirmBlock: 'off', confirmBlockFamily3: 'block' }), 'confirmBlockFamily3')
    expect(r?.status).toBe('partial')
    expect(r?.because).toBe('confirmBlock')
    expect(r?.note).toContain('仍然会拦')
  })

  it('confirmBlock=block + 族 3 显式 block：就是 active', () => {
    expect(reading(cfg({ confirmBlock: 'block', confirmBlockFamily3: 'block' }), 'confirmBlockFamily3')?.status).toBe('active')
  })
})

describe('视图本身的纪律', () => {
  it('只列叶子键：动 honeypot.enabled 不会冒出一整块 honeypot', () => {
    const view = effectiveConfigView(cfg({ runtimeGuard: 'watch', honeypot: { enabled: true, dir: '' } }))
    expect(view.keys.map((k) => k.key)).toEqual(['runtimeGuard', 'honeypot.enabled'])
  })

  it('计数自洽：changed = active + inert + partial，且每条非 active 都有原因与人话', () => {
    const view = effectiveConfigView(cfg({
      runtimeGuard: 'off',
      mode: 'report',
      denyOn: 'suspicious',
      honeypot: { enabled: true, dir: '' },
      confirmBlock: 'off',
      confirmBlockFamily3: 'block',
      transitiveDeps: true,
    }))
    const { changed, active, inert, partial } = view.counts
    expect(changed).toBe(view.keys.length)
    expect(active + inert + partial).toBe(changed)
    expect(active).toBeGreaterThan(0)
    expect(inert).toBeGreaterThan(0)
    expect(partial).toBeGreaterThan(0)
    for (const k of view.keys) {
      if (k.status === 'active') continue
      expect(k.because, k.key).toBeTruthy()
      expect(k.note, k.key).toBeTruthy()
    }
  })

  it('paranoid 档展开后：只有 denyOn 悬空，因为档位**不**替你打开 deny 模式', () => {
    const view = effectiveConfigView(applyProfile(cfg({ profile: 'paranoid' })))
    expect(view.profile).toBe('paranoid')
    expect(view.keys.length).toBeGreaterThan(5)
    // 这一条是这个视图存在的最好理由：档位把 denyOn 收严到 suspicious，但 mode 仍是 report
    // （deny 必须由部署者显式开），于是那半个档位当前什么都不做。不显示出来，用户会以为
    // 「我选了 paranoid，所以 suspicious 就会被拦」。
    expect(view.keys.filter((k) => k.status === 'inert')).toEqual([
      expect.objectContaining({ key: 'denyOn', because: 'mode' }),
    ])
  })

  it('paranoid + 显式 mode=deny：所有键都在用', () => {
    const view = effectiveConfigView(applyProfile(cfg({ profile: 'paranoid', mode: 'deny' })))
    expect(view.counts.inert).toBe(0)
    expect(view.counts.active).toBe(view.counts.changed)
  })

  it('纯函数：不改入参', () => {
    const input = cfg({ runtimeGuard: 'off', honeypot: { enabled: true, dir: '' } })
    const before = JSON.stringify(input)
    effectiveConfigView(input)
    expect(JSON.stringify(input)).toBe(before)
  })
})
