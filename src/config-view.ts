/**
 * 生效配置视图（0.5.12，施工图 §0.5.2 的「不删键 + `effectiveConfig` 推导」）。
 *
 * 为什么需要一层推导，而不是把配置原样丢给用户看：这份配置里有相当一部分键**只在别的键
 * 打开时才有意义**——`honeypot.enabled=true` 配 `runtimeGuard=off` 是个空动作，
 * `denyOn=suspicious` 配 `mode=report` 是个空门槛。它们在配置文件里看着都"设好了"，
 * 而用户能看到的唯一反馈通常是一句运行时日志，或者什么都没有。
 *
 * 于是这一层只回答一个问题：**你动过的那些键，现在到底有没有在用？**
 *
 * 三条设计纪律：
 * 1. **只推导，不修复**。它不改值、不删键、不打印告警；`applyProfile` 已经在别处做过了，
 *    这里的入参必须是**档位展开之后**的生效值（`index.ts` 那个 `cfg`）。
 * 2. **只给事实，不给分数**。三个状态（在用 / 没在用 / 部分在用）各自带一句为什么，
 *    不做「配置健康度 78 分」——那正是这类面板最容易变成噪音的地方。
 * 3. **不猜环境**。`transitiveDeps` 需要机器上装了 `upstream-radar`，这属于运行时环境，
 *    不是配置能推的；这里不装作知道（它会显示为"在用"，缺 CLI 的事实由扫描结果自己说）。
 */
import { VET_CONFIG_DEFAULTS, type VetConfig, type VetProfile } from './config.js'

/** 一个被动过的键当前的实际处境。 */
export type ConfigKeyStatus = 'active' | 'inert' | 'partial'

/**
 * `active`  = 当前确实在影响行为；
 * `inert`   = 当前完全不影响行为（被另一个键支配）；
 * `partial` = 影响一部分，且"另一部分为什么不生效"值得写下来。
 */
export interface ConfigKeyReading {
  /** 叶子键（点分）：`honeypot.enabled`，不是 `honeypot`。 */
  readonly key: string
  readonly status: ConfigKeyStatus
  /** `status !== 'active'` 时：支配它的那个键。 */
  readonly because?: string
  /** `status !== 'active'` 时：一句人话。面板/文档直接复用，不各写一套。 */
  readonly note?: string
}

export interface EffectiveConfigView {
  readonly profile: VetProfile
  /** 只列**被动过**的键（与 schema 默认值不同），按扁平化顺序稳定排列。 */
  readonly keys: readonly ConfigKeyReading[]
  readonly counts: {
    readonly changed: number
    readonly active: number
    readonly inert: number
    readonly partial: number
  }
}

/**
 * 运行时守卫（T1/T2）没开时这一批键都无处生效。
 *
 * 列成白名单而不是 `startsWith('runtime')`：`runtimeGuard` 自己也是 runtime 开头，
 * 而它是**支配者**，不能因为自己被自己支配。
 */
const RUNTIME_GUARD_KEYS: ReadonlySet<string> = new Set([
  'runtimeIntervalMs',
  'runtimeMemLimitMb',
  'runtimeForkBurstN',
  'runtimeFdLimit',
  'runtimeGrowthMb',
  'runtimeGrowthWindowMs',
  // 0.5.22：暖机与内存持续判定同样只在 T1 哨兵存在时才有意义
  'runtimeWarmupMs',
  'runtimeMemSustainMs',
  'networkEgress',
  'observeLoopback',
  'honeypot.enabled',
  'honeypot.dir',
])

/** 这两个键是**字典**，不是对象结构：整体当一个叶子，不按内部键展开。 */
const OPAQUE_KEYS: ReadonlySet<string> = new Set(['rules', 'acknowledgedPackageHashes'])

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** 把配置摊平成 `[叶子键, 值]`。数组与两个字典键整体算一个叶子。 */
function flatten(value: unknown, prefix = ''): Array<[string, unknown]> {
  if (!isPlainRecord(value) || OPAQUE_KEYS.has(prefix)) return [[prefix, value]]
  const out: Array<[string, unknown]> = []
  for (const [key, child] of Object.entries(value)) {
    const path = prefix === '' ? key : `${prefix}.${key}`
    if (isPlainRecord(child) && !OPAQUE_KEYS.has(path)) out.push(...flatten(child, path))
    else out.push([path, child])
  }
  return out
}

/** 结构相等（够用即可：只用于「与默认值是否相同」，不承担通用深比较的职责）。 */
function sameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => sameValue(item, b[i]))
  }
  if (isPlainRecord(a) && isPlainRecord(b)) {
    const ak = Object.keys(a)
    const bk = Object.keys(b)
    return ak.length === bk.length && ak.every((k) => k in b && sameValue(a[k], b[k]))
  }
  return a === b
}

/**
 * 这个键当前为什么没用（或只有一部分在用）。
 *
 * 顺序有意义：越具体的支配关系排在越前面——`honeypot.dir` 先问「蜜罐开了吗」，
 * 再问「守卫开了吗」。反过来的话，一个既没开守卫又没开蜜罐的配置会被解释成
 * 「守卫没开，所以蜜罐不生效」，而用户真正的错处是压根没开蜜罐。
 */
function statusOf(key: string, cfg: VetConfig): Omit<ConfigKeyReading, 'key'> | undefined {
  if (key === 'honeypot.dir' && cfg.honeypot.enabled !== true) {
    return { status: 'inert', because: 'honeypot.enabled', note: '蜜罐未开启，诱饵目录不会被使用' }
  }
  if (key === 'contract.dir' && cfg.contract.enabled !== true) {
    return { status: 'inert', because: 'contract.enabled', note: '契约对账未开启，契约目录不会被读取' }
  }
  if (RUNTIME_GUARD_KEYS.has(key) && cfg.runtimeGuard !== 'watch') {
    return {
      status: 'inert',
      because: 'runtimeGuard',
      note: '运行时守卫为 off：T1 哨兵与 T2 钩子都没有装配，这一项没有可作用的对象',
    }
  }
  if ((key === 'confirmBlockFamily3' || key === 'confirmBlockFamily4') && cfg.confirmBlock === 'off') {
    return {
      status: 'partial',
      because: 'confirmBlock',
      note: 'confirmBlock=off 关掉的是族 1/2 的确认拦截；族 3/4 的显式 block 是覆写，仍然会拦',
    }
  }
  if (key === 'denyOn' && cfg.mode !== 'deny') {
    return { status: 'inert', because: 'mode', note: 'report 模式下没有任何拦截判定，这个门槛用不上' }
  }
  /**
   * 0.5.19（F19 的同一条根因）：这两个基线仍然挂在 `autoScan` 上——它们都要在加载期
   * 走包目录树算哈希，而 `autoScan: false` 的语义正是「加载时别走树」。审计门槛已经从
   * 这个开关下面搬走了（它只读一个目录），这两个没有。
   *
   * 不写这一条，用户只能靠读源码或读 CHANGELOG 才知道自己的基线压根没在跑：`hardened`/
   * `paranoid` 档会把 `thirdPartyBaseline` 展开成 true，而那正是一个「改过的键」。
   *
   * 只在这一项**是开着的**时候说「被 autoScan 关掉」——用户自己把它设成 false 是另一个
   * 原因，把那个也说成 autoScan 就是在编理由。
   */
  if (!cfg.autoScan
    && ((key === 'contentBaseline' && cfg.contentBaseline) || (key === 'thirdPartyBaseline' && cfg.thirdPartyBaseline))) {
    return {
      status: 'inert',
      because: 'autoScan',
      note: 'autoScan 关闭时加载路径不算哈希：这一项在加载期没有可作用的对象（审计门槛 requireAudit 不受影响）',
    }
  }
  /**
   * 0.5.18：`domainProjection` 是「设了但看不出区别」的典型，必须主动说明。
   *
   * 实测（0.5.18，真实打包产物 + 真宿主，两种模式各起一次）：`shadow` 与 `active` 在面板
   * 上产出**逐字段相同**的告警行，因为投影与旧字面量目前等价——这正是切换的验收结论。
   * 所以 0.5.18 把默认值从 `shadow` 切到了 `active`，而用户能观察到的差别仍然是零。
   *
   * 标成 `active` 不算撒谎（它确实在生效，只是生效结果与 shadow 相同），但那句「在用」
   * 会让人以为切换做了什么。这里给 `partial`：它影响的是**实现路径**而非可观察输出，
   * 一旦某处投影与字面量不等价，两者才会分开——那正是这个键存在的理由。
   */
  if (key === 'domainProjection') {
    if (cfg.domainProjection === 'legacy') {
      return {
        status: 'partial',
        because: 'domainProjection',
        note: 'legacy 跳过投影：告警形状完全按采集点写的字面量输出，注册表与投影器不参与。面板上看到的与前面几版一致',
      }
    }
    return {
      status: 'partial',
      because: 'domainProjection',
      note: '投影与旧字面量目前等价（切换的验收结论），所以 active 与 shadow 在面板上看不出差别；两者的区别只在出现不等价时才现形——那时 active 输出投影结果、shadow 仍输出字面量并记一次差异',
    }
  }
  return undefined
}

/**
 * 生效配置视图。
 *
 * @param cfg **档位展开之后**的配置（`applyProfile` 的结果）。传原始配置也不会崩，
 *            但档位预设还没展开，推导出来的是「用户写了什么」而不是「实际在跑什么」。
 */
export function effectiveConfigView(cfg: VetConfig): EffectiveConfigView {
  const defaults = new Map(flatten(VET_CONFIG_DEFAULTS))
  const keys: ConfigKeyReading[] = []
  for (const [key, value] of flatten(cfg)) {
    if (sameValue(value, defaults.get(key))) continue
    const reading = statusOf(key, cfg)
    keys.push(reading === undefined ? { key, status: 'active' } : { key, ...reading })
  }
  const count = (status: ConfigKeyStatus): number => keys.filter((k) => k.status === status).length
  return {
    profile: cfg.profile,
    keys,
    counts: {
      changed: keys.length,
      active: count('active'),
      inert: count('inert'),
      partial: count('partial'),
    },
  }
}
