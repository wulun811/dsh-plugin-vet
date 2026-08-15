/**
 * 运行时守卫装配（D22）：runtimeGuard: 'watch' 时启用 T1 哨兵（子进程 /proc 监视）
 * + T2 钩子（进程内包装 fs/child_process）。
 * alarm-only：所有报警进 VetStatus；绝不自动拦截/杀进程（PLAN §2.1 D21）。
 */
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import cp from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import type { VetConfig } from '../config.js'
import { VetStatus, type VetAlarm } from './status.js'
import type { WatchAlarm } from './runtime-watch.js'
import { DEFAULT_HOOK_CONFIG, patchModule, type HookAlarm } from './runtime-hooks.js'
import { resolvePackageRoot } from '../scanner/package-sources.js'
import { PACKAGE_NAME } from '../invariant.js'

/** T1 哨兵是否已启动（invariant 断言用）。 */
export let sidecarSpawned = false

/** 官方包信任（能力授权）：T2 对官方归因的 spawn 降噪（报警留给第三方）。 */
function isOfficial(name: string): boolean {
  return name.startsWith('@deepseek-ai/') || name === PACKAGE_NAME
}

interface LoaderLike {
  entries(): { options: { name: string } }[]
}

/**
 * 安装运行时守卫（T1 + T2）。
 * @returns disposer：恢复钩子并终止哨兵（HMR/卸载安全）。
 */
export function installRuntimeGuard(ctx: Context, config: VetConfig, status: VetStatus): () => void {
  if (config.runtimeGuard !== 'watch') return () => {}
  const disposers: (() => void)[] = []

  // ── T1 哨兵 ─────────────────────────────────────────────
  const watchArgs = [
    String(config.runtimeIntervalMs),
    String(config.runtimeMemLimitMb),
    String(config.runtimeForkBurstN),
    String(config.runtimeFdLimit),
    String(config.runtimeGrowthMb),
    String(config.runtimeGrowthWindowMs),
  ]
  const sidecarPath = fileURLToPath(new URL('../guard/runtime-watch.js', import.meta.url))
  const child = spawn(process.execPath, [sidecarPath, '--vet-sidecar', ...watchArgs], {
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  sidecarSpawned = true
  let sidecarAlive = true
  child.stdout?.setEncoding('utf8')
  child.stdout?.on('data', (chunk: string) => {
    for (const line of chunk.split('\n')) {
      const trimmed = line.trim()
      if (trimmed === '') continue
      try {
        const a = JSON.parse(trimmed) as WatchAlarm
        status.record({ ...a, source: 't1' })
      } catch {
        ctx.logger.warn(`vet: 哨兵输出无法解析: ${trimmed.slice(0, 120)}`)
      }
    }
  })
  child.on('exit', (code) => {
    sidecarAlive = false
    ctx.logger.warn(`vet: T1 哨兵退出（code=${code ?? 'null'}）`)
  })
  disposers.push(() => {
    if (sidecarAlive) child.kill()
  })

  // ── T2 钩子 ─────────────────────────────────────────────
  const rootIndex = (): Map<string, string> => {
    const map = new Map<string, string>()
    let loader: LoaderLike | undefined
    try {
      loader = (ctx as Context & { loader?: LoaderLike }).loader
    } catch {
      loader = undefined
    }
    const names: string[] = []
    if (loader !== undefined) {
      for (const entry of loader.entries()) names.push(entry.options.name)
    }
    for (const name of names) {
      const root = resolvePackageRoot(name)
      if (root !== undefined) map.set(root, name)
    }
    return map
  }
  const sink = (alarm: HookAlarm): void => {
    // 官方归因的 spawn 降噪（官方能力授权）；第三方与无归因才报警
    if (alarm.kind === 'spawn' && alarm.pluginHint !== undefined && isOfficial(alarm.pluginHint)) return
    const entry: VetAlarm = {
      id: `t2:${alarm.kind}:${alarm.target ?? ''}`,
      severity: alarm.severity,
      source: 't2',
      kind: alarm.kind,
      message: alarm.message,
      target: alarm.target,
      pluginHint: alarm.pluginHint,
      at: Date.now(),
    }
    status.record(entry)
  }
  const hookCfg = { ...DEFAULT_HOOK_CONFIG }
  disposers.push(patchModule(fs as unknown as Record<string, unknown>, 'fs', hookCfg, sink, rootIndex))
  // fs.promises 是独立对象（require('fs').promises / node:fs/promises 同一对象），同步包装不覆盖 → 必须单独包装（D26 审核补漏）
  const promisesMod = (fs as unknown as { promises?: Record<string, unknown> }).promises
  if (promisesMod !== undefined) {
    disposers.push(patchModule(promisesMod, 'fs', hookCfg, sink, rootIndex))
  }
  disposers.push(patchModule(cp as unknown as Record<string, unknown>, 'child_process', hookCfg, sink, rootIndex))

  return () => {
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // 恢复/终止失败不阻断卸载
      }
    }
  }
}
