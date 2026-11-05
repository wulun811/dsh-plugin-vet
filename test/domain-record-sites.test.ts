import { afterEach, describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { VetStatus, type VetAlarm } from '../lib/guard/status.js'
import { createT2Sink } from '../lib/guard/runtime-sink.js'
import { domainProjectionStats, emitAlarm, resetDomainProjectionStats } from '../lib/guard/alarm-emit.js'
import { HOST_SUBJECT, SELF_SUBJECT } from '../lib/domain/types.js'
import { npmSubject } from '../lib/domain/project.js'

/**
 * 0.5.6 的验收单：**每一个**报警落点都走同一个漏斗（`emitAlarm` → 注册表 + 投影器）。
 *
 * 这一轮之前的账：`internal-plugin` 的 22 个落点已经投影，另外 15 个（runtime-sink 8 /
 * runtime-guard 6 / config-diff 1）仍在自己拼 8 个字段。拼出来的形状必须与注册表推出来的
 * 逐字段相等，否则「形状只定义一次」就是空话。
 *
 * 三层证据：
 * 1. **结构**：`src` 里除了漏斗自己，没有谁再直接 `status.record(`——它防的是「下一个人
 *    顺手又加一处」，这是静态断言，随代码增长一直有效。0.5.8 起连扫描结论那条派生路径也
 *    走了漏斗（`VetStatus.noteScan` → `emitAlarm`），所以这条检查不再有白名单。
 * 2. **被测试覆盖不到的落点**（哨兵缺失/接管、心跳、遥测配置差分）：把落点用的
 *    (旧字面量, 事实) 这一对搬进来跑一遍投影。它证明的是「这一对等价」，不是「线上那条
 *    路径用的就是这一对」——后者靠 `emitAlarm` 的签名（事实是必填参数）与代码审查。
 * 3. **T2 的 8 个落点**：真的驱动 sink（不是搬字面量），三种模式各产一份快照，逐字段相等。
 *    严格模式（`VET_DOMAIN_SHADOW_STRICT=1`）下，任何一个落点投影不等价都会在这里抛。
 */

// 用「现在」：status.record/snapshot 会按 TTL 过期，固定在过去的时间戳会被直接丢掉
const AT = Date.now()
const PEM = ['-----BEGIN ', 'PRIVATE KEY-----\nAAAA\n-----END ', 'PRIVATE KEY-----'].join('')

// 事实侧只有「主体 + 事实层来源」两个分量会进形状；四种组合各写一次，落点对照表按它们分组。
const SELF_SENTINEL = { subject: SELF_SUBJECT, source: 'sentinel' } as const
const HOST_SENTINEL = { subject: HOST_SUBJECT, source: 'sentinel' } as const
const SELF_HOOK = { subject: SELF_SUBJECT, source: 'runtime_hook' } as const
const HOST_SCAN = { subject: HOST_SUBJECT, source: 'local_scan' } as const

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...sourceFiles(full))
    else if (entry.name.endsWith('.ts')) out.push(full)
  }
  return out
}

describe('0.5.6：报警只有一个落账口', () => {
  it('src 里只有漏斗自己调用 status.record', () => {
    const root = join(import.meta.dirname, '..', 'src')
    const files = sourceFiles(root)
    // 防空洞：文件列表为空时下面的断言会「通过」
    expect(files.length).toBeGreaterThan(60)
    const offenders: string[] = []
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, index) => {
        // 漏斗自己（legacy / active / shadow 三条出口）
        if (/\bstatus\.record\(/.test(line) && !file.endsWith(join('guard', 'alarm-emit.ts'))) {
          offenders.push(`${file.slice(root.length + 1)}:${index + 1}`)
        }
      })
    }
    expect(offenders).toEqual([])
  })
})

describe('0.5.6：测试覆盖不到的落点，投影与旧字面量逐字段相等', () => {
  interface Case {
    readonly name: string
    readonly legacy: VetAlarm
    readonly facts: { subject: typeof HOST_SUBJECT | typeof SELF_SUBJECT; source: 'sentinel' | 'runtime_hook' | 'local_scan' }
  }

  // 字面量逐字抄自落点（runtime-guard 的 T1 装配 / 心跳，config-diff 的遥测差分）。
  // 事实侧是这一轮新增的那一句：主体是「谁」，来源是事实层的 TrustOrigin（不是通道名）。
  const cases: readonly Case[] = [
    {
      name: 'vet-self-broken（哨兵文件缺失）',
      legacy: {
        id: 'vet-self-broken:sidecar-missing',
        severity: 'red',
        source: 't1',
        kind: 'vet-self-broken',
        message: 'vet 哨兵文件缺失：/x/guard/runtime-watch.js——T1 运行时监控无法启动。可能原因：安装损坏/文件被误删。建议重装 vet 插件',
        at: AT,
      },
      facts: SELF_SENTINEL,
    },
    {
      name: 'T1 资源观测（mem，透传哨兵形状）',
      legacy: { id: 't1:mem', severity: 'red', source: 't1', kind: 'mem', message: '宿主内存超限', target: 'VmRSS=2200MB', at: AT },
      facts: HOST_SENTINEL,
    },
    {
      name: 'T1 资源观测（growth，快增）',
      legacy: { id: 't1:growth', severity: 'yellow', source: 't1', kind: 'growth', message: '宿主内存快速增长', target: 'growth=300MB', at: AT },
      facts: HOST_SENTINEL,
    },
    {
      name: 'sentinel（启动失败）',
      legacy: {
        id: 't1:spawn-fail',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵启动失败，运行时内存/子进程/fd 监控未生效',
        at: AT,
      },
      facts: SELF_SENTINEL,
    },
    {
      name: 'sentinel（意外退出）',
      legacy: {
        id: 't1:sentinel-down',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵意外退出，运行时内存/子进程/fd 监控中断',
        at: AT,
      },
      facts: SELF_SENTINEL,
    },
    {
      name: 'sentinel（被接管）',
      legacy: {
        id: 't1:sentinel-taken-over',
        severity: 'yellow',
        source: 't1',
        kind: 'sentinel',
        message: 'T1 哨兵被其他实例接管，本实例监控通道失效（如重复安装 vet，建议只保留一份）',
        at: AT,
      },
      facts: SELF_SENTINEL,
    },
    {
      name: 'hook-heartbeat（T2 包装被剥离）',
      legacy: {
        id: 't2:hook-heartbeat',
        severity: 'yellow',
        source: 't2',
        kind: 'hook-heartbeat',
        message: '钩子完整性心跳失败：T2 包装被剥离/替换（fs.unlink）——运行时观测降级，疑似插件篡改内置模块',
        target: 'fs.unlink',
        at: AT,
      },
      facts: SELF_HOOK,
    },
    {
      name: 'telemetry-config-change（遥测导出被改写）',
      legacy: {
        id: 'telemetry-config-change:exporter.url',
        severity: 'yellow',
        source: 'scan',
        kind: 'telemetry-config-change',
        message: '遥测配置变化：telemetry exporter.url 与上次观测不同（url 哈希前缀 abc123）——热重载 15s 生效，需重启校验 exporter 端点（G-3 形态）',
        target: 'exporter.url',
        at: AT,
      },
      facts: HOST_SCAN,
    },
  ]

  for (const item of cases) {
    it(`${item.name}：投影结果与旧字面量相等`, () => {
      resetDomainProjectionStats()
      const status = new VetStatus()
      emitAlarm(status, item.legacy, item.facts, 'shadow')
      // shadow 下差异只计数——这里断言计数为 0（严格模式已经会直接抛）
      expect(domainProjectionStats()).toEqual({ mismatches: 0 })
      const alarms = status.snapshot().alarms
      expect(alarms).toHaveLength(1)
      expect(alarms[0]).toEqual({ ...item.legacy, count: 1 })
    })
  }

  afterEach(() => {
    resetDomainProjectionStats()
  })
})

describe('0.5.6：T2 的 8 个落点在三种投影模式下产出同一批报警', () => {
  /** 真的驱动 sink：归因/无主、n3、官方家务探针、金丝雀、密钥外泄各一条。 */
  function alarmsOf(mode: 'legacy' | 'shadow' | 'active'): VetAlarm[] {
    const status = new VetStatus()
    const t2 = createT2Sink(status, undefined, mode)
    const plugin = '@acme/recordsite'
    t2.sink({ severity: 'yellow', kind: 'fs-read', message: '读配置', target: '/home/u/.config/x.json', pluginHint: plugin })
    t2.sink({ severity: 'red', kind: 'fs-destroy', message: '删数据', target: '/home/u/data', pluginHint: plugin })
    // 无主观测：主体是宿主，不应产生 pluginHint
    t2.sink({ severity: 'yellow', kind: 'fs-probe', message: '无主探测', target: '/home/u/.dsh/settings.yaml' })
    // n3 关联签名：合并键是 t2:<code>:<主体名>
    t2.sink({ severity: 'red', kind: 'n3-ransom', message: '勒索签名', target: '/home/u/docs', pluginHint: plugin })
    // 官方家务探针：自己的码 + literal 合并键（跨包聚合为一条）
    t2.sink({ severity: 'yellow', kind: 'fs-probe', message: '探测 settings.yaml.lock', target: '/home/u/.dsh/settings.yaml.lock', pluginHint: '@deepseek-ai/dsh-settings-file', officialHousekeeping: true })
    t2.recordCanary('url', 'CANARY-7f3a', plugin)
    // 无主金丝雀：合并键主体段是空串（旧字面量本来就是 `${plugin ?? ''}`）
    t2.recordCanary('body', 'CANARY-7f3a', undefined)
    t2.recordKeyLeak('url', PEM, plugin)
    return status.snapshot().alarms
  }

  /** 时间与计数不在投影的比对范围内（R10：时间戳是唯一白名单）。 */
  const normalize = (alarms: readonly VetAlarm[]): unknown[] =>
    alarms.map(({ at: _at, count: _count, ...rest }) => rest)

  it('shadow / active 与 legacy 逐字段相同', () => {
    const legacy = alarmsOf('legacy')
    // 防空洞：三条路径都得真的产出东西
    expect(legacy.length).toBeGreaterThanOrEqual(8)
    expect(normalize(alarmsOf('shadow'))).toEqual(normalize(legacy))
    expect(normalize(alarmsOf('active'))).toEqual(normalize(legacy))
  })

  it('官方家务探针用的自己的码，不再借用底层探针码', () => {
    const kinds = alarmsOf('active').map((a) => a.kind)
    expect(kinds).toContain('official-housekeeping-probe')
    // 同一批里那条无主 fs-probe 仍然是 fs-probe（两条路径没有混）
    expect(kinds.filter((k) => k === 'fs-probe')).toHaveLength(1)
  })

  it('无主观测不产生 pluginHint（错误归因比没有归因更糟）', () => {
    const unattributed = alarmsOf('active').filter((a) => a.id === 't2:fs-probe:/home/u/.dsh/settings.yaml:')
    expect(unattributed).toHaveLength(1)
    expect(unattributed[0].pluginHint).toBeUndefined()
  })
})

describe('0.5.8：扫描结论（noteScan）也走漏斗', () => {
  const echo = {
    pluginName: '@acme/recordsite',
    verdict: 'suspicious',
    staticScore: 41,
    at: Date.now(),
    rules: ['R6', 'R8'],
  }

  function alarmsOf(mode: 'legacy' | 'shadow' | 'active'): VetAlarm[] {
    const status = new VetStatus()
    status.noteScan(echo, mode)
    return status.snapshot().alarms
  }

  const normalize = (alarms: readonly VetAlarm[]): unknown[] =>
    alarms.map(({ at: _at, count: _count, ...rest }) => rest)

  it('shadow / active 与 legacy 逐字段相同', () => {
    const legacy = alarmsOf('legacy')
    expect(legacy).toHaveLength(1)
    expect(normalize(alarmsOf('shadow'))).toEqual(normalize(legacy))
    expect(normalize(alarmsOf('active'))).toEqual(normalize(legacy))
  })

  it('形状仍是「证据即身份」：mergeKey 来自证据 id，aggregate 行也不例外', () => {
    const status = new VetStatus()
    // 聚合行（多个官方包共用一条公告）：id 不含包名，pluginHint 仍是刷新它的那个包
    status.noteScan({
      pluginName: '@deepseek-ai/dsh-agent-loop',
      verdict: 'suspicious',
      staticScore: 0,
      at: Date.now(),
      official: true,
      aggregate: true,
      osvDependency: 'zod@4.4.3',
      osvIds: ['GHSA-mrhx-c7xc-m3w5'],
    }, 'shadow')
    const [row] = status.snapshot().alarms
    expect(row.kind).toBe('scan-verdict')
    expect(row.id.startsWith('scan-verdict:agg:osv:')).toBe(true)
    expect(row.pluginHint).toBe('@deepseek-ai/dsh-agent-loop')
  })
})

describe('0.5.6：T2 主体映射（npm 主体 / 宿主）', () => {
  it('npmSubject 只用于「有归因」的观测；无主走宿主主体', () => {
    // 这两条是 T2 的主体判定，直接钉住，避免以后有人把无主行也挂到 npm 主体上
    expect(npmSubject('@acme/recordsite').name).toBe('@acme/recordsite')
    expect(HOST_SUBJECT.kind).toBe('other')
    expect(SELF_SUBJECT.subjectId).toBe('vet-self')
  })
})
