/**
 * 自动更新适配提示（0.4.1）——两层设计。
 *
 * ## 要解决的问题
 * 用户装了 vet 之后，DSH 升级了，用户不会知道新版 vet 是否已适配；vet 也不会主动说。
 * 于是要么用户带着未复验的组合跑，要么每次 DSH 发版都无差别弹提示（警报疲劳）。
 *
 * ## 闸门（关键设计）
 * 提示的触发条件**不是「DSH 出新版了」**，而是「**registry 上那个最新 vet 自己声明的
 * 已复验范围，是否覆盖你正在跑的 DSH**」。这样天然满足两条纪律：
 *   - 我们还没发适配版 → 绝不谎称有适配版（在线层不弹升级、也不改措辞）；
 *   - 已发适配版但用户没升 → 才提示「新版已适配，可升级」。
 * 范围真值取 package.json 的 `dshCompat.tested`，**刻意不用 peerDependencies**（见 dsh-compat.ts）。
 *
 * ## 两层
 * - 离线层（零网络，永远在）：本机 DSH 版本 ∉ 本版 `dshCompat.tested` → yellow「超出已复验范围」。
 *   这是价值最高的一半：拿不到网络也有安全网。
 * - 在线层（节流，fail-quiet）：查 registry 上 latest 的 `dshCompat.tested`；若它覆盖本机 DSH
 *   且比本机 vet 新 → 「新版已适配，可升级」。任何失败一律静默，绝不制造虚假紧迫感。
 *
 * ## 出网纪律（与 official-catalog.ts 同款）
 * 仅 `registry.npmjs.org`（已在 DECLARED_HOSTS），单飞、超时、content-length 上限、
 * `redirect: 'error'`、origin 钉死（防被诱导取任意 URL）。
 * **deny 模式不出网**（P2-7 同款约束：同步路径零网络）。
 *
 * ## 不做什么（边界，不夸大）
 * 绝不自动升级：那要求 vet 有写自身安装目录 + spawn npm 的能力，对一个安全插件是巨大的新增
 * 攻击面；且实测安装形态常为符号链接（本机即 `profiles/web/node_modules/@jieai/dsh-plugin-vet
 * -> ~/1q/plugin-vet`），"一键升级"在该形态下无意义。本模块只**显示**事实与可复制的命令。
 * @module dsh-plugin-vet/update-check
 */
import { readFileSync, renameSync, mkdirSync, existsSync, lstatSync, openSync, readSync, closeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { satisfiesRange, compareSemver, parseSemver } from './dsh-compat.js'
import { vetStoreRoot } from './store-root.js'
import { resolvePkgRoot } from '../pkg-root.js'
import { withVetSelfIo } from './runtime-denoise.js'
import { writeTmpExclusive } from './path-utils.js'

/** 在线层的结论状态。`unknown` = 还没查到/查失败（不弹任何升级提示）。 */
export type UpdateStatus = 'up-to-date' | 'update-available' | 'unknown'

/** 离线兼容层结论。`unknown` = 读不到本机 DSH 版本或本版没声明范围（fail-open，不报警）。 */
export type CompatStatus = 'ok' | 'out-of-range' | 'unknown'

/** 盾牌消费的完整更新视图。字段全部可选语义可降级，旧后端无此字段时客户端整块隐藏。 */
export interface UpdateView {
  /** 本机运行中的 DSH 版本（读不到 = ''）。 */
  dshVersion: string
  /** 本版 vet 自己声明的已复验 DSH 范围（未声明 = ''）。 */
  testedRange: string
  /** 离线兼容层结论。 */
  compat: CompatStatus
  /** 在线层结论。 */
  status: UpdateStatus
  /** 本机 vet 版本。 */
  currentVersion: string
  /** registry 上最新 vet 版本（未查到 = ''）。 */
  latestVersion: string
  /** latest 声明的已复验范围（未查到 = ''）。 */
  latestTestedRange: string
  /** 上次成功检查的时间戳（0 = 从未）。 */
  checkedAt: number
}

/** 落盘结构（~/.dsh/vet/update-check.json）：节流状态 + 最近一次在线结论。 */
interface Persisted {
  lastCheckedAt: number
  latestVersion: string
  latestTestedRange: string
}

const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000
const FETCH_TIMEOUT_MS = 15_000
const MAX_BODY_BYTES = 256 * 1024
const REGISTRY_ORIGIN = 'https://registry.npmjs.org'

const SNAPSHOT_DEFAULT_DIR = vetStoreRoot()
let dirOverride: string | undefined

/** 内部状态：进程内缓存，避免每次 5s 轮询都读文件。 */
let persisted: Persisted | undefined
let inflight: Promise<void> | undefined
let autoCheck = true

/** 测试钩子：关闭在线复核（测试禁止真实出网）。 */
export function setUpdateAutoCheck(enabled: boolean): void {
  autoCheck = enabled
}

/** 测试专用：覆盖存储目录（并清空内存缓存）。 */
export function setUpdateCheckDirForTest(dir?: string): void {
  dirOverride = dir
  persisted = undefined
  inflight = undefined
}

/** 测试专用：直接注入「上一次的远端结论」，避免出网。 */
export function seedRemoteForTest(latestVersion: string, latestTestedRange: string): void {
  const p = loadPersisted()
  p.latestVersion = latestVersion
  p.latestTestedRange = latestTestedRange
  p.lastCheckedAt = Date.now()
  persisted = p
}

export function updateCheckPath(): string {
  return join(dirOverride ?? SNAPSHOT_DEFAULT_DIR, 'update-check.json')
}

/** 读取本版 vet 自己声明的字段（version + dshCompat.tested）。fail-open → ''。 */
function readOwnManifest(): { version: string; tested: string } {
  try {
    const raw = JSON.parse(readFileSync(join(resolvePkgRoot(), 'package.json'), 'utf8')) as {
      version?: unknown
      dshCompat?: { tested?: unknown }
    }
    return {
      version: typeof raw.version === 'string' ? raw.version : '',
      tested: typeof raw.dshCompat?.tested === 'string' ? raw.dshCompat.tested : '',
    }
  } catch {
    return { version: '', tested: '' }
  }
}

/**
 * 探测本机运行中的 DSH 版本。
 *
 * 锚点顺序（按可靠性；任一命中即返回，全失败 → ''）：
 *   1. `baseDir`（调用方传入的 profile 目录，即 ctx.baseUrl）——最稳：dsh loader 就用它解析模块，
 *      实测 `createRequire('<profile>/node_modules/...')` 能解析到宿主 @deepseek-ai/dsh；
 *   2. `process.argv[1]`（DSH 的 bin 入口）——真实宿主下就是 `.../bin/dsh`，实测可解析；
 *   3. 从 argv[1] 所在目录逐级上溯找 package.json（bin 入口被包装/重定向时的兜底）；
 *   4. vet 自身位置（开发态 vet 被链接进 profile 时的回退）。
 * 读不到一律返回 ''（fail-open：绝不当成「超出范围」去误报）。
 *
 * 锚点用目录下的 package.json 作 createRequire 的父路径——createRequire 只用它确定解析起点，
 * 文件本身无需存在（profile 目录下就通常没有 package.json），而 package.json 是真实随包发布的
 * 文件，不用虚构的探针文件名（那会误触发 check-pack-integrity 的「根目录文件必须入包」规则）。
 */
export function detectDshVersion(baseDir?: string): string {
  const tryResolveFrom = (dir: string): string => {
    try {
      const rq = createRequire(join(dir, 'package.json'))
      const p = rq.resolve('@deepseek-ai/dsh/package.json')
      const parsed = JSON.parse(readFileSync(p, 'utf8')) as { version?: unknown }
      if (typeof parsed.version === 'string' && parsed.version !== '') return parsed.version
    } catch {
      // 该锚点不可用，试下一个
    }
    return ''
  }

  // 1. profile 目录（调用方给的最可靠锚点）
  if (typeof baseDir === 'string' && baseDir !== '') {
    // file: URL 必须走 fileURLToPath：手工截掉 file:// 在 Windows 上会留下 `/C:/…`
    // （盘符前多一个斜杠），createRequire 解析不到宿主；POSIX 上 `file:/home/…` 单斜杠
    // 形态也截不掉。与 status-route.resolveProfileDir 同一纪律。
    let b = baseDir
    if (b.startsWith('file:')) {
      try {
        b = fileURLToPath(b)
      } catch {
        // 非法 URL：退回字面量，由下面的解析失败路径兜底（fail-open）
      }
    }
    const v = tryResolveFrom(b)
    if (v !== '') return v
  }

  const argv1 = process.argv[1]
  if (typeof argv1 === 'string' && argv1 !== '') {
    // 2. argv[1] 自身（bin 入口）
    const fromArgv = tryResolveFrom(dirname(argv1))
    if (fromArgv !== '') return fromArgv
    // 3. argv[1] 所在目录逐级上溯（bin 被包装/重定向时的兜底）
    let dir = dirname(argv1)
    for (let depth = 0; depth < 6; depth += 1) {
      if (existsSync(join(dir, 'package.json'))) {
        try {
          const parsed = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: unknown; version?: unknown }
          if (parsed.name === '@deepseek-ai/dsh' && typeof parsed.version === 'string') return parsed.version
        } catch {
          // 坏的 package.json：继续上溯
        }
      }
      const parent = dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  }

  // 4. vet 自身位置（开发态回退）
  return tryResolveFrom(resolvePkgRoot())
}

/** 离线兼容层：本机 DSH 是否落在本版声明范围内。读不到信息 → 'unknown'（不报警）。 */
export function compatStatus(dshVersion: string, testedRange: string): CompatStatus {
  if (dshVersion === '' || testedRange === '') return 'unknown'
  // 「解析不了」≠「超出范围」。读不出版本号的宿主（日期版本、nightly 构建）说「不知道」，
  // 否则会弹一张假的兼容性告警——与「离线层不可能误报」的承诺相反。
  if (parseSemver(dshVersion) === null) return 'unknown'
  return satisfiesRange(dshVersion, testedRange) ? 'ok' : 'out-of-range'
}

/**
 * 只读**普通文件**且限长：`lstat`（不跟随符号链接）+ 大小上限 + 有界 `read`。
 * 反例（审查实测）：`update-check.json` 被换成指向 FIFO 的符号链接时，同步读会永久阻塞，
 * 而它就在 /vet/status.json 的同步路径上——整个 DSH web 事件循环冻住；指向大文件则是无界读。
 * 写侧早已用 'wx' 防同名 tmp 预埋，读侧此前完全没有对应防护。
 */
function readSmallRegularFile(path: string, maxBytes: number): string | null {
  try {
    const st = lstatSync(path)
    if (!st.isFile() || st.size > maxBytes) return null
    const fd = openSync(path, 'r')
    try {
      const buf = Buffer.alloc(Math.min(st.size, maxBytes))
      const n = readSync(fd, buf, 0, buf.length, 0)
      return buf.subarray(0, n).toString('utf8')
    } finally {
      closeSync(fd)
    }
  } catch {
    return null
  }
}

function loadPersisted(): Persisted {
  if (persisted !== undefined) return persisted
  const empty: Persisted = { lastCheckedAt: 0, latestVersion: '', latestTestedRange: '' }
  const loaded = withVetSelfIo(() => {
    try {
      const p = updateCheckPath()
      const text = readSmallRegularFile(p, 64 * 1024)
      if (text === null) return empty
      const parsed = JSON.parse(text) as Partial<Persisted>
      return {
        lastCheckedAt: typeof parsed.lastCheckedAt === 'number' ? parsed.lastCheckedAt : 0,
        latestVersion: typeof parsed.latestVersion === 'string' ? parsed.latestVersion : '',
        latestTestedRange: typeof parsed.latestTestedRange === 'string' ? parsed.latestTestedRange : '',
      }
    } catch {
      return empty
    }
  })
  persisted = loaded
  return loaded
}

/** 原子写（排他 tmp + rename，0600；失败静默——下次检查重写）。
 * 用 writeTmpExclusive 而非裸 writeFileSync：tmp 名含固定 pid，同用户恶意进程可预植
 * `update-check.json.tmp.<pid> → 目标` 的符号链接，裸写（默认 flag 'w' 跟随链接）会以
 * JSON 原文盲写穿链接毁掉目标。排他创建（flag 'wx'）遇到预置物即 EEXIST 并重写，与
 * scan-summaries/stats/version-diff 等全部 store 写入者同一纪律（0.3.9 SEC-5 先例）。 */
function savePersisted(next: Persisted): void {
  persisted = next
  withVetSelfIo(() => {
    try {
      const p = updateCheckPath()
      mkdirSync(dirname(p), { recursive: true, mode: 0o700 })
      const tmp = p + '.tmp.' + process.pid
      writeTmpExclusive(tmp, JSON.stringify(next, null, 2), 0o600)
      renameSync(tmp, p)
    } catch {
      // fail-open：落盘失败只影响节流记忆，不影响本次判定
    }
  })
}

/** 出网取远端结论；任何失败 → null（fail-quiet，调用方维持 unknown）。 */
async function fetchRemote(fetchImpl: typeof fetch): Promise<{ version: string; tested: string } | null> {
  try {
    // 用 packument 的 latest 字段（单请求、体积小）；origin 钉死防被诱导取任意 URL。
    const url = `${REGISTRY_ORIGIN}/${encodeURIComponent('@jieai/dsh-plugin-vet')}/latest`
    const target = new URL(url)
    if (target.origin !== new URL(REGISTRY_ORIGIN).origin) return null
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: 'error' })
    if (!res.ok) return null
    const cl = res.headers.get('content-length')
    if (cl !== null && Number.parseInt(cl, 10) > MAX_BODY_BYTES) return null
    const text = await res.text()
    if (text.length > MAX_BODY_BYTES) return null
    const parsed = JSON.parse(text) as { version?: unknown; dshCompat?: { tested?: unknown } }
    const version = typeof parsed.version === 'string' ? parsed.version : ''
    if (version === '') return null
    return { version, tested: typeof parsed.dshCompat?.tested === 'string' ? parsed.dshCompat.tested : '' }
  } catch {
    return null
  }
}

/**
 * 有界触发一次在线复核（节流 24h + 单飞）。**不 await 也不抛**——由 5s 轮询的同步路径调用，
 * 后台自行落定。任何失败静默，视图维持 unknown（不弹升级提示）。
 * @param fetchImpl 测试注入（默认全局 fetch）。
 * @returns 本次派发的 Promise（调用方可忽略；测试用来 await 落定）；被节流/单飞拦下 → undefined。
 */
export function maybeCheckForUpdate(fetchImpl: typeof fetch = fetch): Promise<void> | undefined {
  if (!autoCheck) return undefined
  const p = loadPersisted()
  // lastCheckedAt 在未来（时钟回拨 / 快照恢复 / 同步来的记录）不能当作「刚查过」——否则在线层
  // 会静默停摆到那个日期，卡片永远停在 unknown。负的 elapsed 一律视为该重新查。
  const elapsed = Date.now() - p.lastCheckedAt
  if (elapsed >= 0 && elapsed < CHECK_INTERVAL_MS) return undefined
  if (inflight !== undefined) return undefined
  inflight = (async () => {
    try {
      const remote = await fetchRemote(fetchImpl)
      if (remote === null) {
        // 失败不写远端结论（保留旧值），但推进尝试时间——否则每 5s 轮询都打一次网络。
        // 净效果：失败后 24h 内不再重试，视图维持上次（或 unknown）结论，fail-quiet。
        savePersisted({ ...loadPersisted(), lastCheckedAt: Date.now() })
        return
      }
      savePersisted({ lastCheckedAt: Date.now(), latestVersion: remote.version, latestTestedRange: remote.tested })
    } catch {
      // fail-quiet
    } finally {
      inflight = undefined
    }
  })()
  return inflight
}

/** 组装盾牌视图（纯读 + 触发一次有界在线复核）。 */
export function getUpdateView(baseDir?: string): UpdateView {
  const own = readOwnManifest()
  const dshVersion = detectDshVersion(baseDir)
  const p = loadPersisted()
  const compat = compatStatus(dshVersion, own.tested)
  // 在线结论：远端必须「真的比本机新」且「声明覆盖本机 DSH」，才叫 update-available。
  // 远端声明为空（旧版本没这个字段）→ 无法证明适配 → 不提示（不谎报）。
  let status: UpdateStatus = 'unknown'
  if (p.latestVersion !== '' && own.version !== '') {
    // 用三态比较而不是 isNewer 的布尔：版本号读不出来时不能把「不知道」说成「已是最新」。
    const cmp = compareSemver(p.latestVersion, own.version)
    if (cmp === null) {
      status = 'unknown'
    } else if (cmp <= 0) {
      status = 'up-to-date'
    } else if (p.latestTestedRange !== '' && dshVersion !== '' && satisfiesRange(dshVersion, p.latestTestedRange)) {
      status = 'update-available'
    } else {
      status = 'unknown' // 有新版但没声明适配（或读不到本机 DSH）→ 静默
    }
  }
  return {
    dshVersion,
    testedRange: own.tested,
    compat,
    status,
    currentVersion: own.version,
    latestVersion: p.latestVersion,
    latestTestedRange: p.latestTestedRange,
    checkedAt: p.lastCheckedAt,
  }
}
