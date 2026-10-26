import { existsSync, readFileSync, renameSync, mkdirSync, unlinkSync } from 'node:fs'
import { writeTmpExclusive } from './path-utils.js'
import { dirname, join } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'
import { vetStoreRoot } from './store-root.js'

/**
 * 持久化忽略警报存储（0.2.1 新增）：用户点击"忽略"后，警报 ID 写入此存储，
 * 后续即使重新触发也不再生成新警报。存储文件：~/.dsh/vet/dismissed-alerts.json
 * 
 * 与 VetStatus.dismissedIds 的区别：
 * - dismissedIds：内存 Set，session 级，DSH 重启后丢失
 * - dismissedAlerts：持久化 JSON，跨 session 生效，直到用户手动恢复
 * 
 * 0.2.2（二轮审查 #2/#3 修复）：isPersistentlyDismissed 是 VetStatus.record 的收口热路径
 * （每次 T2 报警都查），原实现每次同步 readFileSync 读盘——报警风暴时叠加大量同步 I/O。
 * 现在缓存已加载集合到内存 Set（O(1) 查询），写操作（dismiss/restore）同步更新缓存；
 * 仅测试覆盖路径（setDismissedFileForTest）显式清缓存。外部进程改写文件（几乎不发生）在
 * 下次 dismiss/restore 写盘时以磁盘为准融合（loadDismissed 每次写前重读）。
 */

/** 0.3.15：默认路径由 store-root 解析（测试运行时默认落进程私有临时目录）。 */
let DISMISSED_FILE: string = join(vetStoreRoot(), 'dismissed-alerts.json')

/** 内存缓存：已加载的忽略 id 集合（热路径 O(1) 查询，避免每次 record 都同步读盘）。 */
let cachedIds: Set<string> | undefined

/** 测试专用：覆盖存储路径（并清缓存——缓存只服务本文件的路径）。 */
export function setDismissedFileForTest(file: string): void {
  DISMISSED_FILE = file
  cachedIds = undefined
}

/** 存储结构：{ dismissed: { [alertId]: { dismissedAt: number, reason?: string } } } */
interface DismissedStore {
  dismissed: Record<string, { dismissedAt: number; reason?: string }>
}

/**
 * 0.4.1：`scan-verdict` 的 id 加了**类别结构位**（`agg:` / `plugin:` / `tool:`，见
 * guard/scan-verdict.ts 的命名空间说明）。旧格式的聚合行是
 * `scan-verdict:osv:<公告>:<依赖>:<结论>`，加了结构位后变成
 * `scan-verdict:agg:osv:…`——**字符串不再相等**，于是已忽略的 CVE 在升级后重新冒出来，
 * 用户被迫对同一条公告再点一次「忽略」（实测：同一 zod 公告在存储里留下新旧两把键）。
 *
 * 迁移必须保守，只改写**结构上无歧义**的旧聚合行：
 * - 5 段及以上、且第二段是 `osv` → 插入 `agg` 段。
 * - 3 段的 `scan-verdict:<name>:<digest>`（旧对象行）**不改写**：旧格式不区分 plugin/tool，
 *   猜成 plugin 会把「工具执行结果被忽略」变成「同名插件的红牌被预批准」——这正是本轮
 *   修掉的别名 bug 的反向版本。宁可不迁移（让用户重新忽略一次），也不做有损猜测。
 */
export function migrateLegacyScanVerdictId(id: string): string {
  const parts = id.split(':')
  if (parts.length >= 5 && parts[0] === 'scan-verdict' && parts[1] === 'osv') {
    return `scan-verdict:agg:${parts.slice(1).join(':')}`
  }
  return id
}

/**
 * 迁移整张忽略表：旧键改写成新键，**同一条目两条键都存时按 dismissedAt 取较晚的一条**
 * （reason 有值就保留）。纯函数、不写盘——迁移结果随下一次 dismiss/restore 的既存写入
 * 自然落盘（loadDismissed 每次写前重读，所以不需要额外的写路径）。
 */
function migrateLegacyDismissals(
  dismissed: Record<string, { dismissedAt: number; reason?: string }>,
): Record<string, { dismissedAt: number; reason?: string }> {
  type Entry = { dismissedAt: number; reason?: string }
  const isEntry = (v: unknown): v is Entry => v !== null && typeof v === 'object'
  const out: Record<string, Entry> = {}
  for (const [id, entry] of Object.entries(dismissed) as Array<[string, unknown]>) {
    const next = migrateLegacyScanVerdictId(id)
    const prev = out[next]
    // 盘上数据不可信（外部手改/截断残留）：非对象条目原样带过，绝不让规格外的值在迁移里
    // 抛异常——那会被外层 catch 吞成「空存储」，用户全部忽略一起失效。
    if (!isEntry(entry)) {
      if (prev === undefined) out[next] = entry as unknown as Entry
      continue
    }
    if (!isEntry(prev)) {
      out[next] = entry
      continue
    }
    const prevAt = Number.isFinite(prev.dismissedAt) ? prev.dismissedAt : -Infinity
    const nextAt = Number.isFinite(entry.dismissedAt) ? entry.dismissedAt : -Infinity
    const [later, earlier] = nextAt > prevAt ? [entry, prev] : [prev, entry]
    out[next] = earlier.reason !== undefined && later.reason === undefined
      ? { dismissedAt: later.dismissedAt, reason: earlier.reason }
      : later
  }
  return out
}

/** 加载持久化忽略列表（写路径用：写前重读盘，以磁盘为准防外部改写竞态；不触碰缓存）。 */
function loadDismissed(): DismissedStore {
  return withVetSelfIo(() => {
    try {
      if (!existsSync(DISMISSED_FILE)) {
        return { dismissed: {} }
      }
      const content = readFileSync(DISMISSED_FILE, 'utf8')
      const parsed = JSON.parse(content)
      if (parsed && typeof parsed === 'object' && parsed.dismissed && typeof parsed.dismissed === 'object') {
        const store = parsed as DismissedStore
        // 旧 id 迁移（纯内存，不在此写盘）：0.3.x 里点过的「忽略」在 0.4.x 继续有效。
        // 迁移结果随下一次 dismiss/restore 的既存写入自然落盘。
        return { dismissed: migrateLegacyDismissals(store.dismissed) }
      }
      return { dismissed: {} }
    } catch {
      return { dismissed: {} }
    }
  })
}

/**
 * 保存持久化忽略列表（目录以 DISMISSED_FILE 的 dirname 为准——#3：#2 起测试会
 * 把存储文件指到任意路径，硬编码 ~/.dsh/vet 会让测试建错目录甚至写错位置）。
 * round-5 review（A#9/B-A11）：与 stats/baseline/capabilities 同款原子写（tmp + rename）
 * + 文件 0600——旧实现直写：崩溃窗口可留下截断 JSON，loadDismissed 解析失败返回空，
 * 用户全部忽略失效、报警复活。返回是否写成功（调用方据此决定是否更新内存缓存）。
 */
function saveDismissed(store: DismissedStore): boolean {
  return withVetSelfIo(() => {
    // round-6 review：tmp 路径提升到 try 外——rename 失败时 catch 需要 best-effort 清理残件
    // （同 pid 下次写会覆盖同名 tmp，但进程重启换 pid 后旧 tmp 在 ~/.dsh/vet 下永久残留）。
    const tmp = DISMISSED_FILE + '.tmp.' + process.pid
    try {
      const dir = dirname(DISMISSED_FILE)
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
      }
      writeTmpExclusive(tmp, JSON.stringify(store, null, 2), 0o600)
      renameSync(tmp, DISMISSED_FILE)
      return true
    } catch (error) {
      try {
        unlinkSync(tmp)
      } catch {
        // tmp 未落盘（writeFileSync 就失败）或已被清理——无残件可清
      }
      // 静默失败：持久化失败不影响运行（调用方缓存不更新——重启后以磁盘为准是一致的）
      console.error('[vet] 保存忽略列表失败:', error)
      return false
    }
  })
}

/** 检查某警报是否已被用户持久化忽略（热路径：内存缓存 O(1)，不读盘）。
 * 首次调用时惰性加载一次盘上数据。 */
export function isPersistentlyDismissed(alertId: string): boolean {
  if (cachedIds === undefined) {
    cachedIds = new Set(Object.keys(loadDismissed().dismissed))
  }
  return cachedIds.has(alertId)
}

/** 持久化忽略某警报（用户点击"忽略"时调用）；写盘成功后才更新内存缓存——
 * 写失败时缓存保持旧态（盘上没有该记录，重启后自然恢复为未忽略，行为一致）。
 * 0.3.9（审查修复）：**容量上限 + LRU 淘汰**——restore 是唯一手动清理途径，此前无回收，
 * 同源页面被 XSS / 官方面板被注入时可无限堆积忽略档案（ids 上限 200，超出按 dismissedAt
 * 淘汰最旧；上限外新忽略照常生效，只丢最旧的已忽略记录）。 */
export const DISMISSED_MAX_KEPT = 200

/** 持久化忽略某警报（用户点击"忽略"时调用）；写盘成功后才更新内存缓存——
 * 写失败时缓存保持旧态（盘上没有该记录，重启后自然恢复为未忽略，行为一致）。 */
export function persistentlyDismiss(alertId: string, reason?: string): void {
  const store = loadDismissed()
  store.dismissed[alertId] = {
    dismissedAt: Date.now(),
    reason,
  }
  pruneDismissedStore(store)
  if (saveDismissed(store) && cachedIds !== undefined) cachedIds.add(alertId)
}

/** 0.3.9：按 dismissedAt 保留最近 DISMISSED_MAX_KEPT 条（非有限值排最末淘汰，与 capabilities LRU 同款纪律）。 */
function pruneDismissedStore(store: DismissedStore): void {
  const entries = Object.entries(store.dismissed)
  if (entries.length <= DISMISSED_MAX_KEPT) return
  entries.sort((a, b) => {
    const ar = Number.isFinite(a[1].dismissedAt) ? a[1].dismissedAt : -Infinity
    const br = Number.isFinite(b[1].dismissedAt) ? b[1].dismissedAt : -Infinity
    return br - ar
  })
  for (const [key] of entries.slice(DISMISSED_MAX_KEPT)) delete store.dismissed[key]
}

/** 恢复某警报（用户点击"恢复"时调用）；写盘成功后才更新内存缓存。 */
export function restorePersistentDismissal(alertId: string): void {
  const store = loadDismissed()
  delete store.dismissed[alertId]
  if (saveDismissed(store) && cachedIds !== undefined) cachedIds.delete(alertId)
}

/** 获取所有持久化忽略的警报 ID 列表。 */
export function getPersistentDismissedList(): string[] {
  return Object.keys(loadDismissed().dismissed)
}