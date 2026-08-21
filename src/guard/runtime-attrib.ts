/**
 * T2 归因
 * P0-4 结构债拆分自 runtime-hooks.ts（pluginFromStack：栈 → 插件包名；isOfficial：官方包信任降噪）
 */
/** 从错误栈提取插件包名：栈帧路径 → 已知插件根目录（root→包名映射）最长前缀匹配。 */
export function pluginFromStack(stack: string | undefined, roots: Map<string, string>): string | undefined {
  if (stack === undefined || roots.size === 0) return undefined
  for (const frame of stack.split('\n')) {
    const m = /\((.+?):\d+:\d+\)/.exec(frame) ?? /at (.+?):\d+:\d+/.exec(frame)
    if (m === null) continue
    let path = m[1].replace(/\\/g, '/')
    if (path.startsWith('file://')) path = path.slice('file://'.length).replace(/\\/g, '/')
    let best: { len: number; name: string } | undefined
    for (const [root, name] of roots) {
      const normRoot = root.replace(/\\/g, '/')
      // M4：要求路径边界——/node_modules/foo 不能匹配 /node_modules/foobar/index.js
      if ((path === normRoot || path.startsWith(normRoot + '/'))
        && (best === undefined || normRoot.length > best.len)) {
        best = { len: normRoot.length, name }
      }
    }
    if (best !== undefined) return best.name
  }
  return undefined
}
// ── 网络出口观测（P1 特性）─────────────────────────────────────

/** 官方包信任（能力授权）：网络出口观测对官方归因的报警降噪。
 * P2-5 修复：统一导出，runtime-guard.ts 复用（避免包名变更时一处遗漏）。
 */
export function isOfficial(name: string): boolean {
  return name.startsWith('@deepseek-ai/') || name === '@jieai/dsh-plugin-vet'
}
