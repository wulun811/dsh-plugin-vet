import { afterEach, describe, expect, it, vi } from 'vitest'
import { aggregateCoverage, emptyCoverage, resultOf, summarizeCoverage, withUnknownDefaults, coverageEntry } from '../lib/domain/coverage.js'
import { coverageForScan } from '../lib/guard/coverage.js'
import { brandVetHook, registerHookTarget, resetHookRegistry } from '../lib/guard/runtime-heartbeat.js'
import { VetStatus } from '../lib/guard/status.js'
import { SURFACES } from '../lib/domain/types.js'
import type { CoverageInputs } from '../lib/guard/coverage.js'

/**
 * 不变式 2：**读不到/被排除的执行面，不得被表述成已扫描 clean**。
 *
 * 这条不变式只有在「没表态 = unknown」被强制成结构事实之后才成立。所以这里测的重点
 * 不是某个函数返回值，而是：**九行永远齐、缺的那一行不是 covered、关掉的能力不是 covered**。
 */

const base = (over: Partial<CoverageInputs> = {}): CoverageInputs => ({
  osvEnabled: true,
  transitiveDeps: false,
  runtimeGuard: 'off',
  scanFailed: false,
  sourceCount: 12,
  observedAt: 1_700_000_000_000,
  ...over,
})

afterEach(() => {
  resetHookRegistry()
})

describe('九行齐：没表过态就是 unknown', () => {
  it('空输入补齐九行，全部 unknown，顺序与 SURFACES 一致', () => {
    const entries = emptyCoverage(1)
    expect(entries).toHaveLength(SURFACES.length)
    expect(entries.map((e) => e.surface)).toEqual([...SURFACES])
    expect(entries.every((e) => e.result === 'unknown')).toBe(true)
    expect(entries[0].reasons).toEqual(['not-reported'])
  })

  it('只报一个面时，其余八个仍是 unknown（不许被顺手写成 covered）', () => {
    const entries = withUnknownDefaults([coverageEntry('file_tree', 'covered', [], 1)], 1)
    expect(resultOf(entries, 'file_tree')!.result).toBe('covered')
    for (const surface of SURFACES) {
      if (surface === 'file_tree') continue
      expect(resultOf(entries, surface)!.result, `${surface} 被默认成了非 unknown`).toBe('unknown')
    }
  })

  it('同一面两条结论取最差（两个采集点不一致本身就是不确定）', () => {
    const entries = withUnknownDefaults([
      coverageEntry('file_tree', 'covered', [], 1),
      coverageEntry('file_tree', 'failed', ['x'], 1),
    ])
    expect(resultOf(entries, 'file_tree')!.result).toBe('failed')
    expect(entries.filter((e) => e.surface === 'file_tree')).toHaveLength(1)
  })

  it('summarizeCoverage 的计数与九行一致', () => {
    const entries = emptyCoverage(1)
    const summary = summarizeCoverage(entries)
    expect(Object.values(summary).reduce((a, b) => a + b, 0)).toBe(SURFACES.length)
    expect(summary.unknown).toBe(SURFACES.length)
  })
})

describe('扫描面：关掉的能力不是 covered', () => {
  it('OSV 关闭 → intel_osv 与 deps_direct 都是 excluded（最容易被写反的一条）', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ osvEnabled: false })), 1)
    expect(resultOf(entries, 'intel_osv')!.result).toBe('excluded')
    expect(resultOf(entries, 'intel_osv')!.reasons).toContain('osv-disabled')
    expect(resultOf(entries, 'deps_direct')!.result).toBe('excluded')
  })

  it('transitiveDeps 关闭 → deps_transitive 是 excluded', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ transitiveDeps: false })), 1)
    expect(resultOf(entries, 'deps_transitive')!.result).toBe('excluded')
    const on = withUnknownDefaults(coverageForScan(base({ transitiveDeps: true })), 1)
    expect(resultOf(on, 'deps_transitive')!.result).toBe('covered')
  })

  it('扫描器失败 → file_tree failed，不是 partial/covered', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ scanFailed: true })), 1)
    expect(resultOf(entries, 'file_tree')!.result).toBe('failed')
    expect(resultOf(entries, 'file_tree')!.reasons).toContain('scanner-error')
  })

  it('没有任何源码文件 → file_tree partial（看过了但什么也没判）', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ sourceCount: 0 })), 1)
    expect(resultOf(entries, 'file_tree')!.result).toBe('partial')
    expect(resultOf(entries, 'file_tree')!.reasons).toContain('no-source-files')
  })

  it('扫描器跳过文件（R8）→ file_tree partial，而不是「都看了」', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ sourceCount: 40, skippedFiles: 3 })), 1)
    expect(resultOf(entries, 'file_tree')!.result).toBe('partial')
    expect(resultOf(entries, 'file_tree')!.reasons.join(',')).toContain('scan-skipped:3')
  })

  it('OSV 开着但没有「问到了」的证据 → intel_osv partial（问了 ≠ 问到了）', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ osvEnabled: true })), 1)
    expect(resultOf(entries, 'intel_osv')!.result).toBe('partial')
    expect(resultOf(entries, 'intel_osv')!.reasons).toContain('osv-outcome-not-reported')
    // deps_direct 说的是「递给了 OSV」，这一步确实做了
    expect(resultOf(entries, 'deps_direct')!.result).toBe('covered')
  })

  it('registry 对账不在扫描收尾路径上 → intel_registry unknown（诚实缺口）', () => {
    const entries = withUnknownDefaults(coverageForScan(base()), 1)
    expect(resultOf(entries, 'intel_registry')!.result).toBe('unknown')
  })
})

describe('0.5.4：OSV 统计把「问了」与「问到了」分开', () => {
  const withOsv = (osv: CoverageInputs['osv']): CoverageInputs => base({ osv })

  it('全问全答 → intel_osv covered（之前只能一直 partial）', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: 3, attempted: 3, answered: 3 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('covered')
    expect(resultOf(rows, 'deps_direct')!.result).toBe('covered')
  })

  it('问了 3 条只答 2 条 → partial，理由带「1/3」而不是含糊的「问了不等于问到了」', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: 3, attempted: 3, answered: 2 }))
    const row = resultOf(rows, 'intel_osv')!
    expect(row.result).toBe('partial')
    expect(row.reasons).toContain('osv-unanswered:1/3')
    // 「问了」这一面确实问全了：deps_direct 不该跟着降档
    expect(resultOf(rows, 'deps_direct')!.result).toBe('covered')
  })

  it('有目标没发出去（预算/条数上限）→ 两个面都 partial，理由带未发出条数', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: 5, attempted: 2, answered: 2 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('partial')
    expect(resultOf(rows, 'intel_osv')!.reasons).toContain('osv-unqueried:3')
    expect(resultOf(rows, 'deps_direct')!.result).toBe('partial')
    expect(resultOf(rows, 'deps_direct')!.reasons).toContain('osv-unqueried:3')
  })

  it('一条都没问出去 → unknown（没有证据，不是「部分证据」）', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: 4, attempted: 0, answered: 0 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('unknown')
    expect(resultOf(rows, 'intel_osv')!.reasons).toContain('osv-budget-exhausted')
    expect(resultOf(rows, 'deps_direct')!.result).toBe('unknown')
  })

  it('余量不足整段跳过 → unknown，不是 covered（跳过不等于没问题）', () => {
    const rows = coverageForScan(withOsv({ phase: 'skipped', targets: 0, attempted: 0, answered: 0 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('unknown')
    expect(resultOf(rows, 'intel_osv')!.reasons).toContain('osv-budget-exhausted')
  })

  it('相位被预算掐断 → partial + osv-phase-overran；条数是断点前的事实', () => {
    const rows = coverageForScan(withOsv({ phase: 'overran', targets: 4, attempted: 1, answered: 0 }))
    const row = resultOf(rows, 'intel_osv')!
    expect(row.result).toBe('partial')
    expect(row.reasons).toContain('osv-phase-overran')
    expect(row.reasons).toContain('osv-unanswered:1/1')
  })

  it('相位在读完 manifest 之前就被掐断 → 不是「没有可查的目标」', () => {
    const rows = coverageForScan(withOsv({ phase: 'overran', targets: 0, attempted: 0, answered: 0 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('unknown')
    expect(resultOf(rows, 'intel_osv')!.reasons).not.toContain('osv-no-target')
  })

  it('没有可查询目标 → excluded（这一面这次不在场，不是 covered）', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: 0, attempted: 0, answered: 0 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('excluded')
    expect(resultOf(rows, 'intel_osv')!.reasons).toContain('osv-no-target')
  })

  it('deny 的同步路径 → excluded osv-not-run-sync（没问 ≠ 问了没答）', () => {
    const rows = coverageForScan(base({ osvSkipped: 'sync-mode' }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('excluded')
    expect(resultOf(rows, 'intel_osv')!.reasons).toContain('osv-not-run-sync')
    expect(resultOf(rows, 'deps_direct')!.result).toBe('excluded')
  })

  it('计数不是有限数 → 整份退回「没回报」，不产生 NaN 理由', () => {
    const rows = coverageForScan(withOsv({ phase: 'ran', targets: Number.NaN, attempted: 1, answered: 1 }))
    expect(resultOf(rows, 'intel_osv')!.result).toBe('partial')
    expect(resultOf(rows, 'intel_osv')!.reasons).toEqual(['osv-outcome-not-reported'])
  })

  it('聚合：一个主体全问全答、另一个只答了一半 → 取最差（不许用干净的盖住脏的）', () => {
    const clean = coverageForScan(withOsv({ phase: 'ran', targets: 2, attempted: 2, answered: 2 }))
    const dirty = coverageForScan(withOsv({ phase: 'ran', targets: 2, attempted: 2, answered: 1 }))
    const rows = aggregateCoverage(
      [
        { subject: 'pkg-clean', entries: withUnknownDefaults(clean, 1) },
        { subject: 'pkg-dirty', entries: withUnknownDefaults(dirty, 1) },
      ],
      2,
    )
    const osv = rows.find((r) => r.surface === 'intel_osv')!
    expect(osv.result).toBe('partial')
    expect(osv.reasons).toContain('osv-unanswered:1/2')
    expect(osv.subject).toBe('pkg-dirty') // 最差的那一行归谁，要说得出来
  })
})

describe('运行时面：从钩子事实推，不从配置猜', () => {
  it('runtimeGuard=off → 四个运行时面 unsupported，一个 covered 都没有', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ runtimeGuard: 'off' })), 1)
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn', 'runtime_hook_health'] as const) {
      expect(resultOf(entries, surface)!.result, surface).toBe('unsupported')
      expect(resultOf(entries, surface)!.reasons).toContain('runtime-guard-off')
    }
  })

  it('守卫开着但一个钩子都没注册 → 四个运行时面全 unknown（不是 covered）', () => {
    const entries = withUnknownDefaults(coverageForScan(base({ runtimeGuard: 'watch' })), 1)
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn', 'runtime_hook_health'] as const) {
      expect(resultOf(entries, surface)!.result, surface).toBe('unknown')
    }
  })

  it('注册了 fs 钩子且完整 → runtime_fs covered + hook_health covered；其余仍 unknown', () => {
    const readFile = (): void => {}
    brandVetHook(readFile)
    registerHookTarget('fs', { readFile }, ['readFile'])
    const entries = withUnknownDefaults(coverageForScan(base({ runtimeGuard: 'watch' })), 1)
    expect(resultOf(entries, 'runtime_fs')!.result).toBe('covered')
    expect(resultOf(entries, 'runtime_hook_health')!.result).toBe('covered')
    expect(resultOf(entries, 'runtime_net')!.result).toBe('unknown')
  })

  it('钩子被剥离 → runtime_fs failed + hook_health failed（取消一次装配就得看见）', () => {
    const readFile = (): void => {}
    brandVetHook(readFile)
    const mod: Record<string, unknown> = { readFile }
    registerHookTarget('fs', mod, ['readFile'])
    mod.readFile = (): void => {}
    const entries = withUnknownDefaults(coverageForScan(base({ runtimeGuard: 'watch' })), 1)
    expect(resultOf(entries, 'runtime_fs')!.result).toBe('failed')
    expect(resultOf(entries, 'runtime_fs')!.reasons.join(',')).toContain('hook-stripped')
    expect(resultOf(entries, 'runtime_hook_health')!.result).toBe('failed')
  })
})

describe('VetStatus：coverage 永远九行', () => {
  it('未设置时是九行 unknown，不是空数组', () => {
    const coverage = new VetStatus().snapshot().coverage
    expect(coverage).toHaveLength(SURFACES.length)
    expect(coverage.every((e) => e.result === 'unknown')).toBe(true)
  })

  it('setCoverage 带上主体，快照里能看出这九行说的是谁', () => {
    const status = new VetStatus()
    status.setCoverage([coverageEntry('file_tree', 'covered', [], 1)], '@acme/plugin')
    expect(status.snapshot().coverageSubject).toBe('@acme/plugin')
  })

  it('setCoverage 只报一个面，快照仍是九行', () => {
    const status = new VetStatus()
    status.setCoverage([coverageEntry('runtime_net', 'unsupported', ['no-hook'], 1)])
    const coverage = status.snapshot().coverage
    expect(coverage).toHaveLength(SURFACES.length)
    expect(resultOf(coverage, 'runtime_net')!.result).toBe('unsupported')
    expect(resultOf(coverage, 'file_tree')!.result).toBe('unknown')
  })
})

describe('scan_plugin 报告：单次扫描也要说清哪些面没看', () => {
  it('tool 上下文只回答静态面，运行时面留白成 unknown（不是 unsupported）', () => {
    const entries = withUnknownDefaults(
      coverageForScan({ ...base({ osvEnabled: true }), scope: 'tool' }),
      1,
    )
    expect(entries).toHaveLength(SURFACES.length)
    expect(resultOf(entries, 'file_tree')!.result).toBe('covered')
    expect(resultOf(entries, 'intel_osv')!.result).toBe('partial')
    // 单次扫描不对运行时防线表态
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn', 'runtime_hook_health'] as const) {
      expect(resultOf(entries, surface)!.result, surface).toBe('unknown')
      expect(resultOf(entries, surface)!.reasons).toEqual(['not-reported'])
    }
    // 传递依赖雷达不在这条路径上
    expect(resultOf(entries, 'deps_transitive')!.result).toBe('unknown')
  })

  it('tool 上下文同样不许把跳过文件说成已覆盖', () => {
    const entries = withUnknownDefaults(
      coverageForScan({ ...base({ sourceCount: 30, skippedFiles: 2 }), scope: 'tool' }),
      1,
    )
    expect(resultOf(entries, 'file_tree')!.result).toBe('partial')
  })
})

describe('0.5.3：C2 边界改成覆盖面行（不是漏了，是换了表达）', () => {
  const hookFs = (): void => {
    const readFile = (): void => {}
    brandVetHook(readFile)
    registerHookTarget('fs', { readFile }, ['readFile'])
  }
  const hookSpawn = (): void => {
    const execSync = (): void => {}
    brandVetHook(execSync)
    registerHookTarget('child_process', { execSync }, ['execSync'])
  }
  const hookNet = (): void => {
    for (const mod of ['http', 'https', 'net', 'http2', 'tls'] as const) {
      const request = (): void => {}
      brandVetHook(request)
      registerHookTarget(mod, { request }, ['request'])
    }
  }

  it('只知道「有盲区」不知道是哪个模块 → 三个运行时面全 partial（不确定就少说好话）', () => {
    hookFs(); hookSpawn(); hookNet()
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true })),
      1,
    )
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn'] as const) {
      expect(resultOf(entries, surface)!.result, surface).toBe('partial')
      expect(resultOf(entries, surface)!.reasons, surface).toContain('esm-named-import')
    }
  })

  it('知道是哪个模块 → 只标对得上的面（child_process 不该连带 fs 一起标）', () => {
    hookFs(); hookSpawn(); hookNet()
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['child_process'] })),
      1,
    )
    expect(resultOf(entries, 'runtime_spawn')!.result).toBe('partial')
    expect(resultOf(entries, 'runtime_spawn')!.reasons).toContain('esm-named-import:child_process')
    expect(resultOf(entries, 'runtime_fs')!.result).toBe('covered')
    expect(resultOf(entries, 'runtime_net')!.result).toBe('covered')
  })

  it('命中的模块不归任何执行面管（vm/worker_threads）→ 不标：那不是 ESM 造成的盲区', () => {
    hookFs(); hookSpawn(); hookNet()
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['vm', 'worker_threads'] })),
      1,
    )
    for (const surface of ['runtime_fs', 'runtime_net', 'runtime_spawn'] as const) {
      expect(resultOf(entries, surface)!.result, surface).toBe('covered')
    }
  })

  it('钩子没注册 → 不挂 partial（unknown 不该被一条 partial 抬成「看了大部分」）', () => {
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['fs'] })),
      1,
    )
    expect(resultOf(entries, 'runtime_fs')!.result).toBe('unknown')
  })

  it('networkEgress 关掉 → runtime_net unsupported，且 ESM 行不往这一面挂', () => {
    hookNet()
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', networkEgress: false, esmNamedBuiltins: true, esmNamedModules: ['http'] })),
      1,
    )
    expect(resultOf(entries, 'runtime_net')!.result).toBe('unsupported')
    expect(resultOf(entries, 'runtime_net')!.reasons).toContain('network-egress-off')
  })

  it('官方内容锚 → 行标 acknowledged；未验证 → 不标', () => {
    hookSpawn()
    const trusted = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['child_process'], esmAcknowledged: true })),
      1,
    )
    expect(resultOf(trusted, 'runtime_spawn')!.acknowledged).toBe(true)
    const plain = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['child_process'] })),
      1,
    )
    expect(resultOf(plain, 'runtime_spawn')!.acknowledged).toBeUndefined()
  })

  it('钩子被剥离 + ESM：结论取 failed，但两条理由都得留着（都为真，一条都不能丢）', () => {
    const readFile = (): void => {}
    brandVetHook(readFile)
    const mod: Record<string, unknown> = { readFile }
    registerHookTarget('fs', mod, ['readFile'])
    mod.readFile = (): void => {}
    const entries = withUnknownDefaults(
      coverageForScan(base({ runtimeGuard: 'watch', esmNamedBuiltins: true, esmNamedModules: ['fs'] })),
      1,
    )
    const fsRow = resultOf(entries, 'runtime_fs')!
    expect(fsRow.result).toBe('failed')
    expect(fsRow.reasons.join(',')).toContain('hook-stripped')
    // hook 被剥离时这一面已经不是 covered，ESM 行不挂（见上一条用例），理由只有剥离
    expect(fsRow.reasons.join(',')).not.toContain('esm-named-import')
  })
})

describe('0.5.3：每主体一份 + 跨主体取最差', () => {
  const subj = (name: string, entries: Parameters<typeof withUnknownDefaults>[0]) => ({
    subject: name,
    entries: withUnknownDefaults(entries, 1),
  })

  it('一个包的文件树没看完，整个装机的 file_tree 就不是 covered', () => {
    const rows = aggregateCoverage([
      subj('@a/one', [coverageEntry('file_tree', 'covered', [], 1)]),
      subj('@a/two', [coverageEntry('file_tree', 'partial', ['scan-skipped:2'], 1)]),
    ], 1)
    const fileTree = rows.find((r) => r.surface === 'file_tree')!
    expect(fileTree.result).toBe('partial')
    expect(fileTree.subject).toBe('@a/two') // 最差那行来自谁，必须写清
  })

  it('聚合结果与遍历顺序无关（同档时按主体名定序，不按扫描顺序）', () => {
    const one = subj('@a/one', [coverageEntry('file_tree', 'partial', ['x'], 5)])
    const two = subj('@a/two', [coverageEntry('file_tree', 'partial', ['y'], 5)])
    const forward = aggregateCoverage([one, two], 1).find((r) => r.surface === 'file_tree')!
    const backward = aggregateCoverage([two, one], 1).find((r) => r.surface === 'file_tree')!
    expect(forward.subject).toBe(backward.subject)
  })

  it('同档时未承认的优先：已承认的边界不许让另一个未承认的缺口隐身', () => {
    const rows = aggregateCoverage([
      subj('@a/official', [{ ...coverageEntry('runtime_spawn', 'partial', ['esm-named-import'], 9), acknowledged: true }]),
      subj('@a/third', [coverageEntry('runtime_spawn', 'partial', ['esm-named-import'], 1)]),
    ], 1)
    const spawn = rows.find((r) => r.surface === 'runtime_spawn')!
    expect(spawn.subject).toBe('@a/third')
    expect(spawn.acknowledged).toBeUndefined()
  })

  it('一个主体都没报过的面仍是 unknown（不是 covered）', () => {
    const rows = aggregateCoverage([subj('@a/one', [coverageEntry('file_tree', 'covered', [], 1)])], 1)
    expect(rows.find((r) => r.surface === 'intel_osv')!.result).toBe('unknown')
    expect(rows).toHaveLength(SURFACES.length)
  })

  it('VetStatus：两个包各自一份，快照给聚合 + 个数，不冒充某一个', () => {
    const status = new VetStatus()
    status.setCoverage([coverageEntry('file_tree', 'covered', [], Date.now())], '@a/one')
    status.setCoverage([coverageEntry('file_tree', 'partial', ['scan-skipped:1'], Date.now())], '@a/two')
    const snap = status.snapshot()
    expect(snap.coverageSubject).toBeUndefined()
    expect(snap.coverageSubjects).toBe(2)
    expect(resultOf(snap.coverage, 'file_tree')!.result).toBe('partial')
    expect(resultOf(snap.coverage, 'file_tree')!.subject).toBe('@a/two')
  })

  it('VetStatus：同一个包重扫覆盖前一份，不堆成两份', () => {
    const status = new VetStatus()
    status.setCoverage([coverageEntry('file_tree', 'partial', ['scan-skipped:1'], Date.now())], '@a/one')
    status.setCoverage([coverageEntry('file_tree', 'covered', [], Date.now())], '@a/one')
    const snap = status.snapshot()
    expect(snap.coverageSubject).toBe('@a/one') // 单主体：写明是谁
    expect(snap.coverageSubjects).toBeUndefined()
    expect(resultOf(snap.coverage, 'file_tree')!.result).toBe('covered')
  })

  it('VetStatus：超龄的覆盖面退回 unknown（一周前的扫描不能说现在的事）', () => {
    vi.useFakeTimers()
    try {
      const status = new VetStatus({ alarmTtlMs: 1000 })
      status.setCoverage([coverageEntry('file_tree', 'covered', [], Date.now())], '@a/one')
      vi.advanceTimersByTime(2000)
      const snap = status.snapshot()
      expect(snap.coverage.every((e) => e.result === 'unknown')).toBe(true)
      expect(snap.coverageSubject).toBeUndefined()
    } finally {
      vi.useRealTimers()
    }
  })
})
