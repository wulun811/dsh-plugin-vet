/**
 * R12 的 DSH 需求闸门（0.5.24，随 DSH 0.2.2 适配）。
 *
 * 为什么单独成文件：`contract.ts` 判的是「manifest 声明的东西在不在」，本模块判的是
 * 「DSH 会不会**拒绝安装/激活**这个包」——后者要版本比较，而 scanner-bin 与 src 是两个
 * 编译单元（各自 rootDir），不能 import `src/guard/dsh-compat.ts`。判定语义也**故意不同**：
 *
 * - `src/guard/dsh-compat.ts` 回答「这个 DSH 版本是我复验过的吗」：npm 严格语义，预发布
 *   版本只有在同一 M.m.p 内存在带预发布的比较器时才入选（`0.2.2-rc.1` ∉ `^0.2.1-rc.2`）。
 * - 本模块回答「DSH 自己的需求闸门会不会放行」：`dsh-app-boot` 的实现是
 *   `semver.satisfies(runtimeVersion, range, { includePrerelease: true })`——预发布不设闸门，
 *   只比大小（`0.2.2-rc.1` ∈ `^0.2.1-rc.2`）。
 *
 * 两套判定服务两个问题，不能互相替代；混用会让「能跑」和「已复验」互相冒充。
 *
 * 实测（DSH 0.2.2-rc.1 发行物 330 个官方包）：`engines.dsh` 零使用，821 条 dsh peer 全部是
 * 精确版本（`= 0.2.2-rc.1`，由发布工具写入）。所以对第三方插件来说，「按 0.2.1-rc.5 发布、
 * 被 0.2.2 拒绝」是真实且常见的形态——精确版本不接纳任何其他版本。
 *
 * 支持的形式：完整三段 + 比较器（`^ ~ >= > <= < =`、空格分隔的 AND 组、`||`）、**部分版本**
 * （`>=0.2`、`<0.3`、`0.3`——真实插件会这么写，本机安装的
 * `@jiesou/dsh-opencode-zen-free-provider` 就是 `>=0.2.0-rc.2 <0.3`）、**x-range**
 * （`1.x` / `1.2.x`，semver 里与 `1` / `1.2` 同义）以及 `~>`（semver 接受，等价 `~`）。
 * 部分版本在 includePrerelease 下两端都补 `-0`（`>=0.3` 是 `>=0.3.0-0`，`0.3.0-rc.1` 落在
 * 里面），规则照 semver 的编译结果，与 semver@7 做过逐格差分。
 *
 * 判不了的写法一律**不报**（`undefined`）：连字符范围（`1.2.3 - 2.0.0`）这类合法但本模块未
 * 实现的形式，宁可沉默也不谎报「会被拒绝」。反过来，**能确证非法**的写法（dist-tag 形态的
 * `latest`、逗号分隔）要报：semver 拒绝解析，而 DSH 的 `satisfies` 对解析失败返回 false
 * （semver 内部 catch）——结论就是「不满足」，不是「不知道」。注意空 `||` 段**不是**非法：
 * semver 把空组当 `*`，`1.0.0 ||` 恒满足。
 *
 * 0.5.26 发布前自查修正了三处与 DSH 实现不一致的判定：
 * - 部分版本 caret（`^1.2`）曾按 x-range 的边界展开成 `<1.3.0-0`，而 npm caret 锁 major
 *   （`<2.0.0-0`）——`1.9.3` 会被谎报成「不接纳」；
 * - `engines.dsh` 存在时 DSH **根本不读 peerDependencies**，此前非字符串 peer 仍会报 high；
 * - `engines`/`peerDependencies` 本身形态非法（非对象）时 DSH 直接抛错，此前静默。
 *
 * 0.5.27 再压一轮：补 x-range 与 `~>`（此前对 `0.2.x` 静默，正是「按上一版发布」的常见写法）；
 * 任一 OR 组能确证非法时整段判为不满足——DSH 解析的是整个 range，`>=0.2 || workspace:^`
 * 在它眼里是 false，此前我们在第一组 true 时提前收工。
 * @module dsh-plugin-vet/dsh-requirement
 */
import type { Finding } from '../protocol.js'

/** 解析后的版本号（与 npm semver 的三段 + 预发布一致）。 */
export interface VersionParts {
  major: number
  minor: number
  patch: number
  pre: string[]
}

const VERSION_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

/** 解析版本号；非法 → null（调用方 fail-open）。 */
export function parseVersion(raw: string): VersionParts | null {
  const m = VERSION_RE.exec(raw.trim())
  if (m === null) return null
  const major = Number(m[1])
  const minor = Number(m[2])
  const patch = Number(m[3])
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) return null
  return { major, minor, patch, pre: m[4] === undefined ? [] : m[4].split('.') }
}

/** 预发布段比较（数字按数值、数字 < 字母、正式版 > 预发布）。 */
function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0
  if (a.length === 0) return 1
  if (b.length === 0) return -1
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const x = a[i]
    const y = b[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const d = Number(x) - Number(y)
      if (d !== 0) return d < 0 ? -1 : 1
      continue
    }
    if (xn) return -1
    if (yn) return 1
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

/** 比较两个已解析版本；a<b → -1，a>b → 1。 */
export function compareVersions(a: VersionParts, b: VersionParts): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1
  return comparePre(a.pre, b.pre)
}

type Op = '>=' | '>' | '<=' | '<' | '='

interface Comparator {
  op: Op
  v: VersionParts
}

/**
 * x-range 归一化（0.5.27）：semver 把 `1.x` / `1.X` / `1.*` 编译成与 `1` 相同的边界，
 * `1.2.x` 与 `1.2` 同理；去掉 `x` 段后交给部分版本展开，两者共用同一套边界规则。
 *
 * 非法形态（`1.x.3`、`x.2.3`、`1.x-rc.1`）不归一化 → 上层判不了 → 不报。唯一反直觉的合法
 * 形态：补丁位 x-range 允许被忽略的后缀（`1.2.x-rc.1` 在 semver 里合法且后缀不参与判定）；
 * 主/次位 x-range 带后缀则非法——按 semver 的实际行为，不擅自放宽。
 */
function normalizeXRange(t: string): string | null {
  const m = /^(\d+)(?:\.(x|X|\*|\d+))?(?:\.(x|X|\*|\d+))?(?:[-+].*)?$/.exec(t)
  if (m === null) return null
  const isX = (seg: string | undefined): boolean => seg === 'x' || seg === 'X' || seg === '*'
  const minor = m[2]
  const patch = m[3]
  if (isX(patch)) {
    // 1.2.x-rc.1 → 1.2；1.x.x → 1
    return minor !== undefined && !isX(minor) ? m[1] + '.' + minor : m[1]
  }
  if (isX(minor)) {
    if (patch !== undefined) return null // 1.x.3 非法
    if (/[-+]/.test(t)) return null // 1.x-rc.1 非法
    return m[1]
  }
  return t // 不是 x-range：原样交给常规解析
}

/**
 * 宽松解析：允许只有 1~2 段的「部分版本」（`0.3` / `1`）与 x-range（`1.2.x`），并返回精度。
 * 真实插件会写 `>=0.2.0-rc.2 <0.3`（本机 `@jiesou/dsh-opencode-zen-free-provider` 就是），
 * 段数不同，语义也不同——`<0.3` 是 `<0.3.0-0`，`<=0.3` 是 `<0.4.0-0`，`>0.3` 是 `>=0.4.0`。
 * 规则照 semver 的 `validRange` 输出，见 test/r12-dsh-requirement.test.ts 的差分表。
 */
function parseLoose(raw: string): { v: VersionParts; precision: 1 | 2 | 3 } | null {
  const t = normalizeXRange(raw.trim().replace(/^v/, ''))
  if (t === null) return null
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(t)
  if (m === null) return null
  const major = Number(m[1])
  const minor = m[2] === undefined ? 0 : Number(m[2])
  const patch = m[3] === undefined ? 0 : Number(m[3])
  if (![major, minor, patch].every(Number.isSafeInteger)) return null
  const precision = m[3] !== undefined ? 3 : m[2] !== undefined ? 2 : 1
  return { v: { major, minor, patch, pre: m[4] === undefined ? [] : m[4].split('.') }, precision }
}

/** 展开一个 token（`^`/`~`/`~>` 展开为上下界）；语法看不懂 → null。 */
function expandToken(token: string): Comparator[] | null {
  const t = token.trim()
  if (t === '' || t === '*' || t === 'x' || t === 'X') return []
  const m = /^(~>|\^|~|>=|<=|>|<|=)?\s*(.+)$/.exec(t)
  if (m === null) return null
  const rawOp = m[1] ?? ''
  // semver 接受 `~>`（Ruby 风格），语义与 `~` 相同
  const op = rawOp === '~>' ? '~' : rawOp
  const rest = m[2]
  // 裸通配符带操作符：`^x`/`~x`/`>=x`/`<=x`/`=x` 都是「任意版本」；`<x`/`>x` 是空集。
  if (rest === '*' || rest === 'x' || rest === 'X') {
    return op === '<' || op === '>'
      ? [{ op: '<', v: { major: 0, minor: 0, patch: 0, pre: ['0'] } }]
      : []
  }
  const parsed = parseLoose(rest)
  if (parsed === null) return null
  const { v, precision } = parsed

  // 部分版本（`1` / `1.2`）：semver 的规则是「补齐到三段 + 按精度取边界」——
  //   >=1.2 → >=1.2.0        <1.2 → <1.2.0-0      <=1.2 → <1.3.0-0     >1.2 → >=1.3.0
  //   1.2（裸）= 1.2.0 的 x-range：>=1.2.0 <1.3.0-0；~ 同「>=下限 + <边界」，^ 见下
  if (precision < 3) {
    // includePrerelease 下 semver 给部分版本的两端都补 `-0`（`validRange('>=0.3')` 在带
    // options 时是 `>=0.3.0-0`）：`0.3.0-rc.1` 因此**落在** `>=0.3` 里，却不在 `>=0.3.0` 里。
    const lower: VersionParts = v.pre.length > 0 ? v : { ...v, pre: ['0'] }
    const boundary: VersionParts = precision === 1
      ? { major: v.major + 1, minor: 0, patch: 0, pre: ['0'] }
      : { major: v.major, minor: v.minor + 1, patch: 0, pre: ['0'] }
    // caret 与 x-range 的边界**不同**：`^1.2` 是 `>=1.2.0-0 <2.0.0-0`（caret 锁 major），
    // 而裸 `1.2` 才是 `>=1.2.0-0 <1.3.0-0`。0.5.25 把两者混用——`1.9.3` 会被判成「不接纳」，
    // 发布前对 semver 逐格差分时抓到（test 的 `^1.2`/`^0.0` 单元格）。
    if (op === '^' && precision === 2 && v.major > 0) {
      return [{ op: '>=', v: lower }, { op: '<', v: { major: v.major + 1, minor: 0, patch: 0, pre: ['0'] } }]
    }
    switch (op) {
      case '>=': return [{ op: '>=', v: lower }]
      case '>': return [{ op: '>=', v: boundary }]
      case '<': return [{ op: '<', v: lower }]
      case '<=': return [{ op: '<', v: boundary }]
      default: // '' | '=' | '^' | '~'
        return [{ op: '>=', v: lower }, { op: '<', v: boundary }]
    }
  }

  if (op === '^') {
    // npm caret：major>0 → 锁 major；major=0 且 minor>0 → 锁 minor；0.0.x → 锁 patch。
    // 上界带 `-0`（semver 的写法，见 `validRange('^0.2.1')` = `>=0.2.1 <0.3.0-0`）：
    // 没有它，`0.3.0-rc.1` 会落在 `<0.3.0` 里——预发布版比正式版小，却属于下一个 minor。
    const upper: VersionParts = v.major > 0
      ? { major: v.major + 1, minor: 0, patch: 0, pre: ['0'] }
      : v.minor > 0
        ? { major: 0, minor: v.minor + 1, patch: 0, pre: ['0'] }
        : { major: 0, minor: 0, patch: v.patch + 1, pre: ['0'] }
    return [{ op: '>=', v }, { op: '<', v: upper }]
  }
  if (op === '~') {
    return [{ op: '>=', v }, { op: '<', v: { major: v.major, minor: v.minor + 1, patch: 0, pre: ['0'] } }]
  }
  return [{ op: op === '' ? '=' : (op as Op), v }]
}

const OPERATORS = new Set(['^', '~', '~>', '>=', '<=', '>', '<', '='])

function testComparator(version: VersionParts, c: Comparator): boolean {
  const cmp = compareVersions(version, c.v)
  switch (c.op) {
    case '>=': return cmp >= 0
    case '>': return cmp > 0
    case '<=': return cmp <= 0
    case '<': return cmp < 0
    case '=': return cmp === 0
  }
}

function allowsGroup(version: VersionParts, raw: string): boolean | undefined {
  const parts = raw.trim().split(/\s+/).filter(Boolean)
  const comparators: Comparator[] = []
  for (let i = 0; i < parts.length; i += 1) {
    let token = parts[i]!
    // `= 0.2.2-rc.1` / `>= 0.2.0`：操作符与版本号之间允许空格（npm 接受，官方发布物就这么写）
    if (OPERATORS.has(token)) {
      const next = parts[i + 1]
      if (next === undefined) return undefined
      token += next
      i += 1
    }
    const expanded = expandToken(token)
    if (expanded === null) return undefined
    comparators.push(...expanded)
  }
  if (comparators.length === 0) return true // `*` / `x`：任何版本都满足
  return comparators.every(c => testComparator(version, c))
}

/**
 * range 是否接纳 version（DSH 侧语义：`includePrerelease: true`，预发布不设闸门）。
 * true/false 是判定；undefined = 判不了（语法不在本子集内），调用方不得据此报警。
 */
export function rangeAllows(version: string, range: string): boolean | undefined {
  const v = parseVersion(version)
  if (v === null) return undefined
  // 空范围：DSH 的 satisfies 要求 range.trim() !== ''，空串判为不满足。本模块不替它下结论
  // （调用方对 engines.dsh 空串另有明确的 high 文案），返回 undefined 交给上层。
  if (range.trim() === '') return undefined
  // 先求值**全部**组再下结论：semver 解析的是整个 range，任一组的语法非法都会让 satisfies
  // 返回 false；若在前面的组 true 时提前返回，`>=0.2 || workspace:^` 会被我们读成「满足」。
  // 组内求不了值（合法但超出子集，如 `1.x`）→ 整体 undefined，不把「不知道」说成结论。
  let hit = false
  for (const group of range.split('||')) {
    const trimmed = group.trim()
    // 能确证非法的组（dist-tag / 逗号 / `workspace:`）：semver 解析整个 range 会失败，
    // DSH 的 `satisfies` 因此返回 false——整段判为「不满足」，而不是「不知道」。
    // 这正是 `>=0.2 || workspace:^` 在 DSH 里的实际结果（第一组满足也没用）。
    if (trimmed !== '' && (obviouslyInvalidRange(trimmed) || /^workspace:/.test(trimmed))) return false
    const allowed = allowsGroup(v, group)
    if (allowed === undefined) return undefined
    if (allowed) hit = true
  }
  // `1.0.0 ||`（尾部空组）在 semver 里是合法的——空组等价 `*`，整体恒满足，因此不能把
  // 空 OR 段当成非法（0.5.26 自查：差分探针曾把它误判成 `obviouslyInvalidRange`）。
  return hit
}

/** DSH 把这三个 peer 范围**精确替换**为当前运行时版本（字符串全等比较），因此恒满足。 */
const WORKSPACE_RUNTIME = new Set(['workspace:^', 'workspace:~', 'workspace:*'])

/**
 * 「能确证非法」的范围：dist-tag 形态（`latest`/`next`/`beta`…）与逗号分隔。
 *
 * 这些不是「本模块求不了值」：semver 拒绝解析，而 DSH 的 `satisfies` 对解析失败**返回
 * false**（`semver.satisfies` 内部 try/catch），所以结论是「不满足」而不是「不知道」。
 * 刻意只收无歧义形态——`1.x`、`1.2.3 - 2.0.0` 这类合法但本模块未实现的形式仍返回
 * undefined，绝不把「我不知道」翻译成「你会被拒绝」。
 *
 * 空 OR 段（`1.0.0 ||`）**不是**非法：semver 把空组当 `*`，整体恒满足。0.5.26 自查的
 * 差分探针先把它收进来，随后被 `validRange('1.0.0 ||')` 打回——假报警就是这样长出来的。
 */
function obviouslyInvalidRange(raw: string): boolean {
  const t = raw.trim()
  if (t === '' || t === 'x' || t === 'X' || t === '*') return false // 合法（空串由调用方处理）
  if (/^[A-Za-z]+$/.test(t)) return true // dist-tag / 单词（x/X 已排除）
  if (t.includes(',')) return true // semver 没有逗号分隔
  return false
}

function summarize(items: string[]): string {
  return items.slice(0, 3).join('、') + (items.length > 3 ? ' 等 ' + items.length + ' 条' : '')
}

/** R12 需求闸门的 finding 集合；空 = 没发现问题（或判不了，见模块注记）。 */
export function requirementFindings(
  pkg: Record<string, unknown>,
  file: string,
  dshVersion?: string,
): Finding[] {
  const found: Finding[] = []
  const high = (message: string, evidence: string): void => {
    found.push({ rule: 'R12', severity: 'high', confidence: 'certain', message, evidence, file })
  }

  // ── engines 自身形态 ───────────────────────────────────────────────────────────
  // dsh-app-boot 的 unmetRequirements 第一句就是 objectOf$1(engines)：非对象（含 null /
  // 数组 / 字符串）直接 throw。这与 dsh 字段存不存在无关——只要写了 engines 就会先撞上。
  const engines = pkg.engines
  const enginesIsObject = typeof engines === 'object' && engines !== null && !Array.isArray(engines)
  if (Object.hasOwn(pkg, 'engines') && !enginesIsObject) {
    high(
      'engines 形态非法（DSH 要求对象）——安装时 DSH 直接抛错，插件无法安装',
      JSON.stringify(engines),
    )
  }

  const hasEngineField = enginesIsObject
    && Object.hasOwn(engines as Record<string, unknown>, 'dsh')
  const engineRange = hasEngineField ? (engines as Record<string, unknown>).dsh : undefined

  if (hasEngineField) {
    if (typeof engineRange !== 'string') {
      // dsh-app-boot 对非字符串直接 throw：这个包永远装不上，且错误信息离用户很远。
      high(
        'engines.dsh 形态非法（DSH 要求字符串）——安装时 DSH 直接抛错，插件无法安装',
        String(engineRange),
      )
    } else if (engineRange.trim() === '') {
      high('engines.dsh 为空范围（DSH 判为不满足）——插件会被拒绝安装/激活', engineRange)
    } else if (/^workspace:/.test(engineRange.trim())) {
      high(
        'engines.dsh 使用 workspace: 协议（DSH 只对 peerDependencies 做 workspace 替换，engines.dsh 判为不满足）——插件会被拒绝安装/激活',
        engineRange,
      )
    } else if (obviouslyInvalidRange(engineRange)) {
      high(
        'engines.dsh=' + engineRange + ' 不是合法的 semver 范围（DSH 判为不满足）——插件会被拒绝安装/激活',
        engineRange,
      )
    } else if (dshVersion !== undefined && dshVersion !== '') {
      const allowed = rangeAllows(dshVersion, engineRange)
      if (allowed === false) {
        high(
          'DSH 需求闸门：engines.dsh=' + engineRange + ' 不接纳本机 DSH ' + dshVersion
          + '——插件会被拒绝安装/激活（更新插件；或按 exact-version 例外显式放行）',
          engineRange,
        )
      }
    }
  }

  // engines.dsh 存在时 DSH **只看它**：unmetRequirements 在这里 return，peerDependencies
  // 连读都不读（其中任何形态错误也不会被触发）。0.5.25 之前无条件检查 peer 的形态，对这类
  // 包是一次假报警——0.5.26 修正为在此提前返回。
  if (hasEngineField) return found

  // ── peerDependencies 自身形态 ──────────────────────────────────────────────────
  const peers = pkg.peerDependencies
  const peersIsObject = typeof peers === 'object' && peers !== null && !Array.isArray(peers)
  if (Object.hasOwn(pkg, 'peerDependencies') && !peersIsObject) {
    high(
      'peerDependencies 形态非法（DSH 要求对象）——安装时 DSH 直接抛错，插件无法安装',
      JSON.stringify(peers),
    )
    return found
  }
  if (!peersIsObject) return found

  // 注意：DSH 的字符串形态检查在**名字过滤之前**——任何 peer（不只 dsh peer）值非字符串
  // 都会 throw；范围语义只对 @deepseek-ai/dsh / dsh-* 生效。
  const allPeers = Object.entries(peers as Record<string, unknown>)
  for (const [name, range] of allPeers) {
    if (typeof range !== 'string') {
      high(
        'peerDependencies[' + JSON.stringify(name) + '] 形态非法（DSH 要求字符串）——安装时 DSH 直接抛错',
        String(range),
      )
    }
  }

  const dshPeers = allPeers.filter(([name]) => name === '@deepseek-ai/dsh' || name.startsWith('@deepseek-ai/dsh-'))

  // 「结构上必不满足」：空串、非精确 workspace:（DSH 只替换三个全等字符串，其余交给 semver
  // 解析失败 → false）、以及能确证非法的范围。与版本无关，宿主版本缺失时照报。
  const shapeUnmet: string[] = []
  for (const [name, range] of dshPeers) {
    if (typeof range !== 'string') continue // 形态问题上面已报
    if (WORKSPACE_RUNTIME.has(range)) continue
    if (/^workspace:/.test(range.trim()) || range.trim() === '' || obviouslyInvalidRange(range)) {
      shapeUnmet.push(name + '@' + JSON.stringify(range))
    }
  }
  if (shapeUnmet.length > 0) {
    high(
      'DSH 需求闸门：dsh peer 的范围不是合法 semver，或不是 DSH 会替换的 workspace 形式（'
      + summarize(shapeUnmet) + '）——DSH 判为不满足，插件会被拒绝安装/激活',
      JSON.stringify(shapeUnmet),
    )
  }

  if (dshVersion !== undefined && dshVersion !== '') {
    const unmet: string[] = []
    for (const [name, range] of dshPeers) {
      if (typeof range !== 'string') continue
      if (WORKSPACE_RUNTIME.has(range)) continue // 恒满足
      // 结构问题上面已报，不再重复算一次
      if (/^workspace:/.test(range.trim()) || range.trim() === '' || obviouslyInvalidRange(range)) continue
      if (rangeAllows(dshVersion, range) === false) unmet.push(name + '@' + range)
    }
    if (unmet.length > 0) {
      high(
        'DSH 需求闸门：dsh peer 不接纳本机 DSH ' + dshVersion + '（' + summarize(unmet)
        + '）——插件会被拒绝安装/激活（更新插件；或按 exact-version 例外显式放行）',
        JSON.stringify(unmet),
      )
    }
  }

  return found
}
