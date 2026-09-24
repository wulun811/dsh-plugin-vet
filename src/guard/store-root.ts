/**
 * vet 存储根目录解析（唯一真源，0.3.15）。
 *
 * 解析优先级（模块加载时定值——进程内插件此后改 env/HOME 无法重定向 vet 自己的状态，
 * 与既有 C3「homedir 快照」纪律一致）：
 *   1. setStoreRootForTest() 显式覆盖（测试用，优先级最高；既有 setXDirForTest 仍各自生效）
 *   2. DSH_PLUGIN_VET_STORE_DIR（部署期迁移口子：把 vet 状态放到别处）
 *   3. 测试运行时（VITEST / NODE_ENV=test）→ 进程私有临时目录
 *   4. ~/.dsh/vet
 *
 * 第 3 条是 2026-09-24 实测事故的修复：0.3.14 及以前，任何**忘记** setXDirForTest 的测试
 * 都会写进用户真实存储（实测 vitest 把 6 条夹具记录写进 ~/.dsh/vet/capabilities.json、
 * 8 条写进 scan-summaries.json，另有 stats/forensics/完整性金丝雀），随后被 M7 自检如实
 * 报成 vet-store-tamper 黄牌——「逐测试纪律」挡不住漏网（0.3.3/round-4 已补过两轮同类
 * 隔离，仍在 plugin.test.ts / runtime-guard.test.ts / review-round4.test.ts /
 * review-fixes.test.ts 复发）。改为默认 fail-closed：测试运行时的默认根目录**永远不是**
 * 真实家目录，显式覆盖照旧优先。
 *
 * 生产语义未变：homedir 在模块加载时快照，运行期改 $HOME/env 不会移动存储。
 * @module dsh-plugin-vet/store-root
 */
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

/** 存储根迁移口子（部署期显式声明；未设 = ~/.dsh/vet）。 */
export const VET_STORE_DIR_ENV = 'DSH_PLUGIN_VET_STORE_DIR'

export interface StoreRootInputs {
  env?: Record<string, string | undefined>
  home?: string
  isTestRuntime?: boolean
}

/** 是否测试运行时：vitest 注入 VITEST；vitest/jest 亦会设 NODE_ENV=test。 */
export function isTestRuntime(env: Record<string, string | undefined> = process.env): boolean {
  return env.VITEST !== undefined || env.NODE_ENV === 'test'
}

/** 测试运行时的私有存储根：按 pid 稳定（同进程内所有模块共用一份，绝不落真实家目录）。
 * 不注册退出清理——vitest 线程池下同 pid 多 worker 共享该目录，先退出的 worker 删目录
 * 会影响仍在跑的用例；临时目录本身由 OS 回收。 */
export function testStoreRoot(): string {
  return join(tmpdir(), 'dsh-plugin-vet-test-store-' + String(process.pid))
}

/** 纯解析（可测）：给定环境算出默认存储根。 */
export function resolveStoreRoot(inputs: StoreRootInputs = {}): string {
  const env = inputs.env ?? process.env
  const explicit = env[VET_STORE_DIR_ENV]
  if (explicit !== undefined && explicit.trim() !== '') return explicit.trim()
  const test = inputs.isTestRuntime ?? isTestRuntime(env)
  if (test) return testStoreRoot()
  return join(inputs.home ?? homedir(), '.dsh', 'vet')
}

/** 模块加载时快照（生产语义：运行期改 env/HOME 无效）。 */
const SNAPSHOT_ROOT = resolveStoreRoot()

let storeRootOverride: string | undefined

/** vet 存储根目录：capabilities/baseline/stats/scan-summaries/known-boundaries/
 * official-catalog/forensics/contracts/audits/dismissed-alerts 全在其下。 */
export function vetStoreRoot(): string {
  return storeRootOverride ?? SNAPSHOT_ROOT
}

/** 测试专用：覆盖存储根（生产路径不调用；各模块自己的 setXDirForTest 优先级更高）。 */
export function setStoreRootForTest(dir?: string): void {
  storeRootOverride = dir
}

/** vet 完整性金丝雀根（生产 = ~/.dsh）：由存储根派生，测试运行时随之落临时目录，
 * 不把 vet-integrity-* 写进真实家目录。 */
export function vetIntegrityRoot(): string {
  return dirname(vetStoreRoot())
}
