/**
 * 「版本与适配」卡的展示决策（0.4.1）。
 *
 * 背景（用户 2026-10-13 反馈）：「版本与适配」卡在**安静态**（已复验支持 / 已是最新，无新消息）
 * 下一直占着主面板，但它每次说的都是同一句话——常驻仪表是给**会变的量**用的，这条信息是一次
 * 性通知。故安静态只在「第一次看到」之后展示 20 分钟，随后收起；**真消息不受此限**。
 *
 * 分层：
 * - 本模块是**纯判定**（零 DOM、零 node API）——服务端 tsconfig（lib 只有 ES2022，无 DOM）与
 *   客户端 tsconfig（有 DOM）都要能编译它，且要能被单测直接驱动；与 `guard/shield-shape.ts`
 *   同款单源纪律。
 * - **存储与渲染**在客户端（`client/Shield.tsx`）：本模块不碰 localStorage。
 *
 * 什么算「真消息」（永不收起，且一出现就重新计时）：
 * - `compat === 'out-of-range'`：正在跑的 DSH 超出本版已复验范围 → 兼容性未验证，用户要知道；
 * - `status === 'update-available'`：registry 上确有更新版**且**它声明覆盖本机 DSH → 可升级。
 *
 * 其余（`compat` ok/unknown 且 `status` up-to-date/unknown）都是「无新消息」，按 20 分钟窗口收起。
 * @module dsh-plugin-vet/update-card
 */

/** 安静态展示窗口：从「第一次看到这条消息」起算 20 分钟。 */
export const UPDATE_CARD_TTL_MS = 20 * 60 * 1000

/**
 * 判定所需的字段（结构化子集）。
 * 刻意**不**导入 client/types.ts 的 `VetUpdateWire`：本模块要被服务端 tsconfig 编译，而
 * `src/client/**` 被 tsconfig.src 排除。客户端那个接口在结构上兼容本接口。
 */
export interface UpdateCardInput {
  /** 离线兼容层结论。 */
  compat: 'ok' | 'out-of-range' | 'unknown'
  /** 在线层结论。 */
  status: 'up-to-date' | 'update-available' | 'unknown'
  /** 本机运行中的 DSH 版本（读不到 = ''）。 */
  dshVersion: string
  /** 本机 vet 版本。 */
  currentVersion: string
  /** 本版声明的已复验 DSH 范围（未声明 = ''）。 */
  testedRange: string
  /** registry 上最新 vet 版本（未查到 = ''）。 */
  latestVersion: string
}

/** 客户端持久化的「已见」记录：哪条消息、第一次看到的时间。 */
export interface UpdateSeen {
  sig: string
  at: number
}

/** 是否为「真消息」——是则永不收起（见模块头）。 */
export function isUpdateNews(u: UpdateCardInput): boolean {
  return u.compat === 'out-of-range' || u.status === 'update-available'
}

/**
 * 消息指纹：**描述这条消息说的是什么**，而不是渲染细节。指纹变化 = 出现了一条新消息 →
 * 展示窗口从此刻重新起算。
 *
 * 刻意**不含** `latestVersion` / `latestTestedRange`：那两个字段每次在线复核都可能变
 * （registry 发了新版但没声明 `dshCompat`），若纳入指纹，则每次 registry 抖动都会把安静态
 * 卡片重新弹 20 分钟——而卡片内容一字未变。安静态说的是「已复验支持 DSH x / VET y」，
 * 故指纹取 compat + status + 两个版本号。
 *
 * 分隔符 '|' 与各字段的取值域不冲突：compat/status 是固定枚举，dshVersion/currentVersion 是
 * 三段版本号（`[\d.rc-]`），都不含 '|'，故不会出现「不同消息拼出同一指纹」。
 */
export function updateCardSignature(u: UpdateCardInput): string {
  return [u.compat, u.status, u.dshVersion, u.currentVersion].join('|')
}

/**
 * 从原始存储值解析「已见」记录——**所有**形式的损坏都归一为 null（= 当作首次看到，展示）。
 * 与客户端 `readUpdateSeen` 同规则；放在这里是为了让单测覆盖损坏面，而不是只测 happy path。
 * 判据：非对象/数组、sig 非字符串、at 非有限数 → null。
 */
export function parseSeen(raw: string | null): UpdateSeen | null {
  if (raw === null) return null
  try {
    const parsed = JSON.parse(raw) as unknown
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    const { sig, at } = parsed as { sig?: unknown; at?: unknown }
    if (typeof sig !== 'string' || typeof at !== 'number' || !Number.isFinite(at)) return null
    return { sig, at }
  } catch {
    return null
  }
}

/**
 * 是否展示卡片。
 * @param seen 客户端记住的「已见」记录（localStorage 读回；不可用/首次 → null）。
 * @param now 当前时间戳（注入以便测试与纯函数化）。
 */
export function shouldShowUpdateCard(u: UpdateCardInput, seen: UpdateSeen | null, now: number): boolean {
  // 真消息：不收起（也不依赖任何存储——存储不可用时真消息照样必须显示）。
  if (isUpdateNews(u)) return true
  // 无记录 / 记录损坏 / 是另一条消息 → 视为「刚刚第一次看到」，从此刻起算窗口。
  if (seen === null || seen.sig !== updateCardSignature(u)) return true
  if (!Number.isFinite(seen.at)) return true
  // 时钟回拨（seen.at 在未来）→ now - at 为负，仍 < TTL → 继续展示，不会误收起。
  return now - seen.at < UPDATE_CARD_TTL_MS
}

/** 卡片视觉档位：决定强调色与图标（'news' 系 = 真消息；'quiet' = 安静态）。
 * 仅本模块内部使用（消费方按 `presentation.tone` 字符串比较即可）。 */
type UpdateCardTone = 'out' | 'available' | 'ok' | 'uptodate' | 'unknown'

/** 卡片语义（i18n key 后缀 + 图标 + 是否强调）。文案仍由客户端查 i18n 表，本模块不含中文。 */
export interface UpdateCardPresentation {
  tone: UpdateCardTone
  /** 标题 i18n key。 */
  labelKey: string
  /** 正文 i18n key（含 `{dsh}`/`{range}`/`{latest}`/`{current}` 占位符）。 */
  noteKey: string
  /** 正文占位符取值（客户端用 replace 填充，t 是纯查表无插值）。 */
  vars: Record<string, string>
  /** 是否强调（真消息 → 描边+强调色）。等价于 `isUpdateNews(u)`，此处随文案一并给出以免调用方二次推导。 */
  accent: boolean
  /** 状态图标（无 i18n，纯符号）。 */
  icon: string
}

/**
 * 单一真源的语义组装：主面板卡片与「关于」次级面板**共用本函数**，防两处渲染漂移。
 * 优先级：超出已复验范围 > 可升级 > 已复验支持 > 已是最新 > 未知。
 */
export function updateCardPresentation(u: UpdateCardInput): UpdateCardPresentation {
  const range = u.testedRange === '' ? 'update.rangeNone' : u.testedRange
  if (u.compat === 'out-of-range') {
    // 两条都成立时（本机 DSH 超出本版范围，且 registry 上有**声明覆盖它**的新版）：出路是升级
    // VET，不是回退 DSH。旧实现先返回「超出范围」，于是卡片只喊回退、连升级命令都不渲染——
    // 恰好是这套功能的起因场景（DSH 升级了，用户在等一个适配的 VET）。
    if (u.status === 'update-available' && u.latestVersion !== '') {
      return {
        tone: 'out', labelKey: 'update.compatOut', noteKey: 'update.noteOutWithUpdate', accent: true, icon: '⚠',
        vars: { dsh: u.dshVersion, range, latest: u.latestVersion },
      }
    }
    return {
      tone: 'out', labelKey: 'update.compatOut', noteKey: 'update.noteOut', accent: true, icon: '⚠',
      vars: { dsh: u.dshVersion, range },
    }
  }
  if (u.status === 'update-available') {
    return {
      tone: 'available', labelKey: 'update.available', noteKey: 'update.noteAvailable', accent: true, icon: '↑',
      vars: { latest: u.latestVersion, dsh: u.dshVersion, current: u.currentVersion },
    }
  }
  if (u.compat === 'ok') {
    return {
      tone: 'ok', labelKey: 'update.compatOk',
      noteKey: u.status === 'up-to-date' ? 'update.noteUpToDate' : 'update.noteUnknown',
      accent: false, icon: '·',
      vars: { current: u.currentVersion, dsh: u.dshVersion, range },
    }
  }
  if (u.status === 'up-to-date') {
    // 诚实口径：走到本分支说明 compat 既不是 'out-of-range'（上面已返回）也不是 'ok'——即
    // **本机 DSH 是否落在已复验范围内无从判断**（读不到运行中的 DSH 版本，或本版没声明范围）。
    // 此时只能说「VET 已是最新」，**不能**说「已复验支持 DSH」——那会把「不知道」说成「已验证」，
    // 且在 dshVersion 为空时渲染出「已复验支持 DSH 。」这种悬空占位。
    return {
      tone: 'uptodate', labelKey: 'update.upToDate', noteKey: 'update.noteUpToDateUnverified',
      accent: false, icon: '·', vars: { current: u.currentVersion, dsh: u.dshVersion, range },
    }
  }
  return {
    tone: 'unknown', labelKey: 'update.compatUnknown', noteKey: 'update.noteUnknown',
    accent: false, icon: '·', vars: { current: u.currentVersion, dsh: u.dshVersion, range },
  }
}
