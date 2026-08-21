import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'

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

let DISMISSED_FILE: string = join(homedir(), '.dsh', 'vet', 'dismissed-alerts.json')

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
        return parsed as DismissedStore
      }
      return { dismissed: {} }
    } catch {
      return { dismissed: {} }
    }
  })
}

/** 保存持久化忽略列表（目录以 DISMISSED_FILE 的 dirname 为准——#3：#2 起测试会
 * 把存储文件指到任意路径，硬编码 ~/.dsh/vet 会让测试建错目录甚至写错位置）。 */
function saveDismissed(store: DismissedStore): void {
  return withVetSelfIo(() => {
    try {
      const dir = dirname(DISMISSED_FILE)
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
      }
      writeFileSync(DISMISSED_FILE, JSON.stringify(store, null, 2), 'utf8')
    } catch (error) {
      // 静默失败：持久化失败不影响运行
      console.error('[vet] 保存忽略列表失败:', error)
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

/** 持久化忽略某警报（用户点击"忽略"时调用）；同步更新内存缓存。 */
export function persistentlyDismiss(alertId: string, reason?: string): void {
  const store = loadDismissed()
  store.dismissed[alertId] = {
    dismissedAt: Date.now(),
    reason,
  }
  saveDismissed(store)
  if (cachedIds !== undefined) cachedIds.add(alertId)
}

/** 恢复某警报（用户点击"恢复"时调用）；同步更新内存缓存。 */
export function restorePersistentDismissal(alertId: string): void {
  const store = loadDismissed()
  delete store.dismissed[alertId]
  saveDismissed(store)
  if (cachedIds !== undefined) cachedIds.delete(alertId)
}

/** 获取所有持久化忽略的警报 ID 列表。 */
export function getPersistentDismissedList(): string[] {
  return Object.keys(loadDismissed().dismissed)
}