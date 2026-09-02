/**
 * M1 官方包目录（0.3.5，用户警报疲劳第七轮反馈）：
 *
 * 信任模型反转为「官方全集 + 官方哈希」——之前是「机器本地 TOFU 基线」：每个 @deepseek-ai/*
 * 名字先在 TOFU 窗口里被当成「可能是假冒」逐条报警，等第二次加载哈希 match 才入内容信任锚，
 * 导致官方插件自己的家务（锁探针/会话分片探针）在窗口期刷黄警（用户机实测三条）。
 *
 * 新模型：全量官方目录（种子来自 dsh-src/packages，运行时用 registry scope 枚举在线刷新）是
 * 名字的真值。判定方（internal-plugin 的 classifyOfficial）由此一分为三：
 * - 名字 ∈ 目录 且 哈希与官方 registry 一致 → 真官方，首见即可入内容信任锚（TOFU 窗口合上）；
 * - 名字 ∈ 目录 但 哈希不一致 → 黄牌观察（非红——误报比漏报更消耗信任，用户决策）；
 * - 名字 ∉ 目录（"多出来的那个"）→ 黄牌观察（冒充官方，或官方新包尚未纳入目录），不拦不入锚，
 *   触发一次有界的 registry 核对，确认真官方后自动纳入目录覆盖层并重评。
 *
 * 目录不是机器本地的自证，而是可独立对账的集合：种子随发行物更新（重跑
 * scripts/gen-official-catalog-seed.mjs），覆盖层落盘 ~/.dsh/vet/official-catalog.json（C3 快照
 * 纪律 + 原子写），registry 核对在线兜底。任何一层读不到都 fail-open 回退种子/纯前缀旧行为，
 * 绝不把「目录缺失」当成「目录为空」去误判。
 *
 * @module dsh-plugin-vet/official-catalog
 */
import { existsSync, readFileSync, statSync, renameSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { writeTmpExclusive } from '../guard/path-utils.js'
import { OFFICIAL_CATALOG_SEED } from './official-catalog-seed.js'

/** C3 同款纪律：默认目录在模块加载时定值（进程内插件改 $HOME 无法重定向存储）。 */
const SNAPSHOT_DEFAULT_DIR = join(homedir(), '.dsh', 'vet')

let catalogDirOverride: string | undefined

/** 存储文件路径：~/.dsh/vet/official-catalog.json（测试可用 setOfficialCatalogDirForTest 覆盖）。 */
export function officialCatalogPath(): string {
  const dir = catalogDirOverride ?? SNAPSHOT_DEFAULT_DIR
  return join(dir, 'official-catalog.json')
}

/** 测试专用：覆盖存储目录（生产路径不调用）。 */
export function setOfficialCatalogDirForTest(dir?: string): void {
  catalogDirOverride = dir
  catalogCache = undefined
}

/**
 * 归一化包名（@scope/name/subpath → @scope/name；name/subpath → name；本地路径原样返回）。
 * 与 internal-plugin.extractPackageName 语义一致——此处独立实现避免目录模块反向依赖 guards。
 */
export function normalizePackageName(raw: string): string {
  if (raw === '') return raw
  if (raw.startsWith('@')) {
    const parts = raw.split('/')
    return parts.length >= 3 ? parts.slice(0, 2).join('/') : raw
  }
  if (raw.includes('/')) {
    if (raw.startsWith('/') || raw.startsWith('./')) return raw
    return raw.split('/')[0]
  }
  return raw
}

interface CatalogOverlay {
  names: string[]
  refreshedAt: number
}

/** 覆盖层 + 缓存（seed ∪ 覆盖层）。加载失败 fail-open 回退种子。 */
let catalogCache: Set<string> | undefined

/** 覆盖层文件大小上限（0.3.5 审查加固：防被撑大后每次插件加载整读拖慢；超限 fail-open 回种子）。 */
const OVERLAY_MAX_BYTES = 8 * 1024 * 1024

function loadOverlay(): CatalogOverlay | null {
  try {
    const path = officialCatalogPath()
    if (!existsSync(path)) return null
    if (statSync(path).size > OVERLAY_MAX_BYTES) return null
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<CatalogOverlay>
    if (Array.isArray(parsed.names) && parsed.names.length >= 0) {
      return { names: parsed.names.filter(n => typeof n === 'string'), refreshedAt: parsed.refreshedAt ?? 0 }
    }
    return null
  } catch {
    return null
  }
}

/** 构建并缓存目录集合（seed ∪ 覆盖层）。任何失败回退种子（fail-open）。 */
function catalogSet(): Set<string> {
  if (catalogCache === undefined) {
    const set = new Set(OFFICIAL_CATALOG_SEED)
    const overlay = loadOverlay()
    if (overlay !== null) for (const n of overlay.names) set.add(n)
    catalogCache = set
  }
  return catalogCache
}

/** 目录成员判定：名字是否在官方全集内（归一化后比对；大小写敏感——npm 包名大小写敏感）。 */
export function isOfficialPackageName(name: string): boolean {
  const norm = normalizePackageName(name)
  return catalogSet().has(norm)
}

const REGISTRY_SCOPES_PAGE_SIZE = 250
/**
 * 0.3.5 审查加固（分页）：search 接口单页 size=250 按热度排序，实测 @deepseek-ai scope
 * 231 个官方包散布在前 4 页（首页 250 条里仅 201 个官方名，其余是 scope 搜索噪声）——
 * 单页枚举会漏掉尾部真官方包（"自动核对并入目录"对它们永不生效，黄牌永续）。分页上限
 * 4 页（1000 槽位）、每页 content-length 8MB 上限不变、页间解析失败即停（fail-open）。
 */
const REGISTRY_SCOPES_URL_BASE = 'https://registry.npmjs.org/-/v1/search?text=scope:@deepseek-ai'
const REGISTRY_SCOPES_MAX_PAGES = 4
const REGISTRY_PAGE_LIMIT_BYTES = 8 * 1024 * 1024
const REFRESH_TIMEOUT_MS = 15_000

/** 测试钩子：关闭目录的自动在线核对（测试环境禁止真实出网；默认为开）。 */
let catalogAutoRefresh = true
export function setCatalogAutoRefresh(enabled: boolean): void {
  catalogAutoRefresh = enabled
}

/**
 * 在线核对官方全集（registry scope 枚举）并合并落盘覆盖层。
 * 只在「目录外出现 @deepseek-ai/* 名」时惰性触发（不在启动时出网）；deny 模式调用方自行
 * 不调（P2-7：同步路径零网络）。有界：分页上限 × 每页 content-length 上限 + 超时；失败
 * fail-open 返回当前目录集合（调用方维持观察，不误伤）。本函数单飞：进程内并发触发只跑一次。
 * @param fetchImpl 测试注入（默认全局 fetch）。
 * @returns 合并后的目录集合（含本次 discovered 的官方包名）。
 */
let refreshInflight: Promise<Set<string>> | undefined
export async function refreshOfficialCatalogFromRegistry(fetchImpl: typeof fetch = fetch): Promise<Set<string>> {
  if (!catalogAutoRefresh) return catalogSet()
  if (refreshInflight !== undefined) return refreshInflight
  refreshInflight = (async () => {
    try {
      const merged = new Set(catalogSet())
      let discoveredOnThisRun = 0
      // 分页枚举：首页能命中大部分（按热度排序），但尾部官方包可能压到后续页——
      // 逐页取到「不足整页」（搜索已穷尽）或页数上限为止；页内解析失败即停（fail-open）。
      for (let from = 0; from < REGISTRY_SCOPES_MAX_PAGES * REGISTRY_SCOPES_PAGE_SIZE; from += REGISTRY_SCOPES_PAGE_SIZE) {
        const url = `${REGISTRY_SCOPES_URL_BASE}&size=${REGISTRY_SCOPES_PAGE_SIZE}&from=${from}`
        const res = await fetchImpl(url, { signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS), redirect: 'error' })
        if (!res.ok) break
        const cl = res.headers.get('content-length')
        if (cl !== null && Number.parseInt(cl, 10) > REGISTRY_PAGE_LIMIT_BYTES) break
        const data = await res.json() as { objects?: Array<{ package?: { name?: unknown } }> }
        const objects = data.objects ?? []
        let pageAdded = 0
        for (const obj of objects) {
          const n = obj?.package?.name
          if (typeof n === 'string' && n.startsWith('@deepseek-ai/') && !merged.has(n)) {
            merged.add(n)
            pageAdded += 1
          }
        }
        if (pageAdded > 0) discoveredOnThisRun += pageAdded
        if (objects.length < REGISTRY_SCOPES_PAGE_SIZE) break // 搜索已穷尽：不足整页即末页
      }
      if (discoveredOnThisRun === 0) return catalogSet()
      catalogCache = merged
      persistOverlay([...merged])
      return merged
    } catch {
      return catalogSet() // fail-open：网络/解析失败维持现状
    } finally {
      refreshInflight = undefined
    }
  })()
  return refreshInflight
}

/** 原子写覆盖层（tmp+rename，0600；失败静默——下次核对重写）。 */
function persistOverlay(names: string[]): void {
  try {
    const path = officialCatalogPath()
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const tmp = path + '.tmp.' + process.pid
    writeTmpExclusive(tmp, JSON.stringify({ names, refreshedAt: Date.now() } as CatalogOverlay, null, 2), 0o600)
    renameSync(tmp, path)
  } catch {
    // fail-open：落盘失败只影响下次核对前的覆盖层记忆，不影响本次判定与种子兜底
  }
}