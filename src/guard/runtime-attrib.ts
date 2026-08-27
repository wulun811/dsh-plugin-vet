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

/**
 * round-16（SEC-1）：官方信任锚（内容验证）——运行时防线抑制的真值从「名字前缀」
 * 升级为「内容验证过的官方包」。任何包都可以把 package.json 的 name 写成
 * @deepseek-ai/*（本地 tarball/文件装机理不校验发布身份），名称级 isOfficial 只凭
 * 前缀就为伪造者关掉 T2 报警 / N7 拦截 / 密钥外泄 / 金丝雀 / N3 台账全部运行时防线
 * ——纯字符串检查的运行时失明是最大的单点盲区。isOfficial 仍保留用于纯展示/
 * 降噪走廊（audit-summary 聚合、observeLoopback 回环观测、名称级去噪），防线上
 * 的抑制一律改用 isOfficialTrusted。
 * trusted 集合只由两类内容验证路径写入：
 * - classifyOfficial reason==='match'（内容哈希与历史基线一致，internal-plugin.ts）；
 * - registry-verify resolved（本机字节 == 官方 registry tarball，registry-verify.ts）。
 * first-seen（无历史基线可对照，TOFU 窗口）刻意不写入——首见官方包照常观测/报警
 * （round-16 决策 1 同款：TOFU 窗口是伪造 tarball 可乘的唯一入口，扫描与运行时
 * 防线都不该在窗口内失明）。'@jieai/dsh-plugin-vet' 本体恒在锚内（bundle/符号链接
 * 形态无法做内容哈希时仍是 vet 自身，身份级豁免）。
 */
const officialTrusted = new Set<string>()

/** 登记内容验证通过的官方包（仅 @deepseek-ai/ 前缀可入锚；vet 本体由 isOfficialTrusted 恒真兜底）。 */
export function markOfficialTrusted(name: string): void {
  if (name.startsWith('@deepseek-ai/')) officialTrusted.add(name)
}

/** 内容信任锚判据：锚内包（内容验证过）或 vet 本体。 */
export function isOfficialTrusted(name: string): boolean {
  return officialTrusted.has(name) || name === '@jieai/dsh-plugin-vet'
}

/** 单测辅助：清空信任锚（生产不调用）。 */
export function resetOfficialTrustForTest(): void {
  officialTrusted.clear()
}
