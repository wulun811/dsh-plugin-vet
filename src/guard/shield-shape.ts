/**
 * 盾牌快照线格式的**最小形状谓词**（round-21，安全信号完整性）。
 *
 * 背景：客户端 Shield 轮询 `/vet/status.json` 后直接 `JSON.parse(...) as ShieldSnapshotWire`
 * 落状态——而该路由存在**合法返回可解析非快照 JSON** 的路径（SEC-6 跨源 403 信封
 * `{ok:false,note}`、宿主错误信封等）。形状不符的对象一旦覆盖旧快照，渲染层所有 `??`
 * 缺省回退会把「数据拿不到」画成**假全绿 0 报警**——对安全插件这是最坏的静默形态。
 *
 * 本谓词与 DOM 零耦合：服务端编译进 lib/（单测回归护栏），客户端经 esbuild 打进
 * lib/client.js 共用同一份判定（单源防漂移——与 darwin-sysinfo 同纪律）。
 */

/** status-route 200 快照的判别字段：level 为字符串 + alarms 为数组（渲染层的两个硬依赖）。 */
export function isShieldSnapshotShape(parsed: unknown): boolean {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false
  const p = parsed as { level?: unknown; alarms?: unknown }
  return typeof p.level === 'string' && Array.isArray(p.alarms)
}
