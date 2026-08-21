/**
 * 钩子完整性心跳（P0-2 #2）
 * P0-4 结构债拆分自 runtime-hooks.ts（T2 包装品牌：本模块闭包私有 Symbol，不可复制/伪造；只观测不拦截）
 */
// ── P0-2 #2（0.1.21）：钩子完整性心跳 ──────────────────────────────────────
// 目标：让「T2 包装被剥离/替换」（插件改写 require.cache 后的模块导出、或直接覆盖导出）可被确定性观测。
// 标记选型（ROADMAP #2 的意图落地）：本模块闭包私有的 Symbol 品牌，而非「源码注入哨兵串 + toString() 比对」——
// toString 哨兵是源码可复制的（攻击者把包装器源码拷走再造外观一致的函数即可绕过），闭包私有、
// 非配置/非可写/非可枚举的 Symbol 品牌无法被复制/伪造，是唯一可靠的「可析出标记」。
const HOOK_BRAND = Symbol('vet-hook-brand')

/** 给一个 vet 包装函数打品牌（patchModule/patchNetworkModule 内部 + runtime-guard 的手工包装共用）。 */
export function brandVetHook(fn: (...a: unknown[]) => unknown): void {
  try {
    Object.defineProperty(fn, HOOK_BRAND, { value: true, writable: false, configurable: false, enumerable: false })
  } catch {
    // 无法打标（冻结函数等极端场景）：该包装对心跳视为未标记——心跳宁可报「疑似剥离」也不漏报
  }
}

/** 判断一个函数是否为 vet 钩子包装（带品牌标记）。 */
export function isVetHook(fn: unknown): boolean {
  return typeof fn === 'function' && (fn as unknown as Record<symbol, unknown>)[HOOK_BRAND] === true
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
