/**
 * 钩子完整性心跳（P0-2 #2）
 * P0-4 结构债拆分自 runtime-hooks.ts（T2 包装品牌；只观测不拦截）
 */
// ── P0-2 #2（0.1.21）：钩子完整性心跳 ──────────────────────────────────────
// 目标：让「T2 包装被剥离/替换」（插件改写 require.cache 后的模块导出、或直接覆盖导出）可被确定性观测。
//
// **0.5.15 修：品牌从「函数上一个 Symbol 属性」改为「按函数身份的 WeakSet」。**
//
// 旧实现（0.1.21–0.5.14）注释写的是「闭包私有的 Symbol 品牌无法被复制/伪造，是唯一可靠的
// 可析出标记」。这个判断是错的：`Symbol()` 只是不打进全局注册表，函数上的 symbol 属性
// **可枚举**——`Object.getOwnPropertySymbols(fn)` 就能抄走，贴到自己的假函数上，
// `isVetHook(fake)` 随即返回 true（已实测复现）。攻击者因此可以把 vet 的包装整个换成自己的
// 函数、让心跳报 55/55 完好，而面板永久绿——「可析出标记」变成了「可伪造标记」。
//
// WeakSet 按**对象身份**判定：没有可抄走的属性面，复制属性不会让另一个函数变成同一个对象。
// 这是唯一能把「这个函数是我们造的」与「这个函数长得像我们造的」区分开的机制。
const hookBrandSet = new WeakSet<(...a: unknown[]) => unknown>()

/** 给一个 vet 包装函数打品牌（patchModule/patchNetworkModule 内部 + runtime-guard 的手工包装共用）。 */
export function brandVetHook(fn: (...a: unknown[]) => unknown): void {
  hookBrandSet.add(fn)
}

/** 判断一个函数是否为 vet 钩子包装（按函数身份，不看属性）。 */
export function isVetHook(fn: unknown): boolean {
  return typeof fn === 'function' && hookBrandSet.has(fn as (...a: unknown[]) => unknown)
}

/** 钩子注册表：patchModule / patchNetworkModule / registerHookTarget 登记的目标（模块名 → 实际导出的 mod 对象），
 * 供心跳在任意时刻复查「当前导出是否仍带品牌」。以 mod 对象身份去重，多次安装共享登记、ops 取并集。 */
interface HookTarget {
  label: string
  mod: Record<string, unknown>
  ops: Set<string>
}
const hookTargets: HookTarget[] = []

/** 登记一个钩子目标（patchModule/patchNetworkModule 内部调用；dgram/fetch 由 runtime-guard 手动登记）。 */
export function registerHookTarget(label: string, mod: Record<string, unknown>, ops: Iterable<string>): void {
  let target = hookTargets.find(t => t.mod === mod)
  if (target === undefined) {
    target = { label, mod, ops: new Set() }
    hookTargets.push(target)
  }
  for (const op of ops) target.ops.add(op)
}

/** 单测辅助：清空钩子注册表（生产路径不调用）。 */
export function resetHookRegistry(): void {
  hookTargets.length = 0
}

export interface HookHeartbeatResult {
  ok: boolean
  /** 逐个 (module, op) 的完整性检查（含完好的，供状态/测试展示）。 */
  checks: { module: string; op: string; intact: boolean }[]
}

/** 钩子完整性心跳：复查全部已登记目标，「当前导出仍带品牌」即完好；
 * 被剥离/替换（未标记）→ 该项失守，ok=false。只观测不拦截（alarm-only）。 */
export function hookHeartbeat(): HookHeartbeatResult {
  const checks: HookHeartbeatResult['checks'] = []
  let ok = true
  for (const target of hookTargets) {
    for (const op of [...target.ops].sort()) {
      let intact = false
      try {
        intact = isVetHook(target.mod[op])
      } catch {
        intact = false
      }
      if (!intact) ok = false
      checks.push({ module: target.label, op, intact })
    }
  }
  return { ok, checks }
}
