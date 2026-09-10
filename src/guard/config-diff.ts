/**
 * round-13（Phase 3）：遥测配置敏感化（G-3 补强）。
 *
 * 背景（第三方审计报告 G-3）：攻击者在 L1（同用户代码执行）下改写 cordis.patch.yml 的
 * telemetry exporter URL/mode，热重载 15s 内生效，把遥测静默切成 FULL 模式零脱敏外泄到
 * 攻击者端点。写入动作已被 T2 的 install-write 报警覆盖，但"改了什么"的语义缺失。
 *
 * round-15（DSH 0.1.1-rc.2 npm-public 适配）：配置形态从旧式顶层 `telemetry:` 块改为
 * 条目列表（`- id: session-telemetry-otel` + `config:` 块，OTLP exporter 直通任意键）；
 * 新增 home 层补丁（$DSH_HOME/cordis.patch.yml，boot 自动热重载，优先级高于 profile 层）——
 * 两种形态都提取，读取层补全（profile 目录 + 遗留父级 + home 层，后者最后读=覆盖）。
 *
 * 本模块：周期读取上述候选中的 telemetry 配置 url/mode 字段——冷启动只记录基线不报；
 * 主机变化 → yellow（要求重启校验 exporter 端点）。alarm-only，可 dismiss。
 *
 * 隐私纪律：只存 url 的 sha256 前缀 + mode 原值（枚举语义）；配置原文绝不进报警/日志/档案。
 * 纪律（N2/红线）：只做文本级确定性解析，不加载 YAML、不执行任何配置内容；
 * 读取用 withVetSelfIo 直通（vet 自身 IO 不产生无主自报警，P2-2 先例）。
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { withVetSelfIo } from './runtime-hooks.js'
import type { VetConfig } from '../config.js'
import type { VetStatus } from './status.js'

export interface TelemetryFields {
  /** exporter url 的 sha256 前 16 hex（隐私：不存原文）。 */
  urlHash?: string
  /** exporter mode 原值（'FULL'/'REDACTED' 等枚举语义，非密钥）。 */
  mode?: string
}

const CONFIG_CANDIDATES = ['cordis.patch.yml', 'cordis.yml']
const POLL_INTERVAL_MS = 15_000
// round-5 review（B-A20）：键名加词边界——旧正则 `(?:url|mode)\s*:` 在
// 'endpoint-url: xxx' 这类带词根键上从中间截取 'url:' 命中，`m[0]` 截到的是
// 'url' 而非完整键名 → flow 形态中非 url/mode 键被误提取成假 telemetry 变化黄警。
const URL_MODE_RE = /(?<![A-Za-z0-9_.-])(url|mode)\s*:\s*["']?([^"'\s,}]+)/g
const TELEMETRY_ROW_ID_RE = /(?:^|-)(?:session-)?telemetry(?:-|$)/

function sha16(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 16)
}

/** 取 `key:` 之后一行的 YAML 标量值（round-21 review）：先剥外层引号（引号内空格/# 原样保留，
 * 闭合引号之后的 ` # 注释` 忽略），无引号则从首个空白+`#` 处截断行尾注释——与 YAML 语义一致
 * （`#` 仅在前置空白或行首时开注释）。旧实现 `tail.replace(/^["']|["']$/g,'')` 不处理行尾注释：
 * `mode: FULL # prod` 把 ` # prod` 并入值 → 仅加/改注释的无害编辑即触发假「遥测变化」黄警，
 * 且注释原文经 `'mode=' + next.mode` 进入报警，违背本模块「配置原文绝不进报警」隐私纪律。
 * 整行注释（值以 `#` 起）→ 返回 ''（调用方按无值跳过）。 */
function readYamlScalar(tail: string): string {
  let s = tail.trim()
  if (s === '' || s[0] === '#') return ''
  const q = s[0]
  if (q === '"' || q === "'") {
    const end = s.indexOf(q, 1)
    if (end > 0) return s.slice(1, end) // 引号值：取内部，闭合引号后的一切（注释）丢弃
    s = s.slice(1) // 缺闭合引号（截断/畸形）→ 退化为去首引号后按裸值处理
  }
  const c = s.search(/\s#/)
  if (c >= 0) s = s.slice(0, c)
  return s.trim()
}

/** 在含 {…} 的文本段里提取 url:/mode: 键值（flow 形态共用）。 */
function extractUrlModeFlow(out: TelemetryFields, flow: string): void {
  URL_MODE_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = URL_MODE_RE.exec(flow)) !== null) {
    const key = m[1].toLowerCase()
    if (key === 'url') out.urlHash = sha16(m[2])
    else if (key === 'mode') out.mode = m[2]
  }
}

/**
 * 从一段配置文本提取遥测 url/mode（旧式 telemetry: 块 + 新式 row 列表两种形态，
 * 纯文本确定性解析，不加载 YAML、不执行任何内容）。
 */
export function extractTelemetryFields(text: string): TelemetryFields {
  const out: TelemetryFields = {}
  const lines = text.split(/\r?\n/)
  let inTelemetry = false
  let telemetryIndent = -1
  let inTelemetryRow = false
  let rowIndent = -1
  for (const line of lines) {
    // ── 新式 row 形态（0.1.1-rc.2：patch 是 entry 列表，遥测 row id 含 telemetry）──
    // - id: session-telemetry-otel
    //   config:
    //     mode: FULL
    //     exporter:
    //       url: "https://…"   （exporter 为 OTLP 直通 z.any()，取 url/mode 键）
    const rowMatch = /^(\s*-)\s*id:\s*([A-Za-z0-9_.-]+)/.exec(line)
    if (rowMatch !== null) {
      inTelemetryRow = TELEMETRY_ROW_ID_RE.test(rowMatch[2].toLowerCase())
      rowIndent = rowMatch[1].length
      if (inTelemetryRow && line.includes('{')) {
        extractUrlModeFlow(out, line.slice(line.indexOf('{')))
      }
      continue
    }
    if (inTelemetryRow) {
      const keyMatch = /^(\s*)([A-Za-z0-9_.-]+)\s*:/.exec(line)
      if (keyMatch === null) continue
      const indent = keyMatch[1].length
      if (indent <= rowIndent) {
        inTelemetryRow = false // 缩出 row 体（后续行是别的顶层条目/注释）
      } else {
        const key = keyMatch[2].toLowerCase()
        const tail = line.slice(keyMatch[0].length).trim()
        const value = readYamlScalar(tail)
        if (value !== '') { // readYamlScalar 已把纯注释值折成 ''（round-21：旧 value.startsWith('#') 判为死码，删除）
          // round-15 review（过宽键匹配修复）：旧 endsWith('mode'/'url') 会把
          // compatMode / callbackUrl 等无关键误当遥测字段 → 配置里加个无关键就刷
          // 一条假「遥测配置变化」黄灯。只认键名恰为 url/mode，或作为路径末段
          // （exporter.url / exporter.mode）——与行内形态（URL_MODE_RE 精确词边界）一致。
          if (key === 'url' || key.endsWith('.url')) out.urlHash = sha16(value)
          else if (key === 'mode' || key.endsWith('.mode')) out.mode = value
        }
        if (line.includes('{')) extractUrlModeFlow(out, line.slice(line.indexOf('{')))
      }
      continue
    }
    // ── 旧式 telemetry: 块（0.1.0 兼容）──
    if (!inTelemetry && /^\s*telemetry\s*:/.test(line) && line.includes('{')) {
      extractUrlModeFlow(out, line.slice(line.indexOf('{')))
      continue
    }
    const keyMatch = /^(\s*)([A-Za-z0-9_.-]+)\s*:/.exec(line)
    if (keyMatch === null) continue
    const indent = keyMatch[1].length
    const key = keyMatch[2].toLowerCase()
    if (!inTelemetry) {
      if (key === 'telemetry') { inTelemetry = true; telemetryIndent = indent }
      continue
    }
    if (indent <= telemetryIndent) { inTelemetry = false; continue }
    // telemetry 块内：url/mode 键（含 exporter.url / exporter.mode 深层键）
    // round-15 review：与 row 形态同修——精确键/路径末段匹配，不误收 compatMode 等
    const tail = line.slice(keyMatch[0].length).trim()
    const value = readYamlScalar(tail)
    if (value === '') continue
    if (key === 'url' || key.endsWith('.url')) out.urlHash = sha16(value)
    else if (key === 'mode' || key.endsWith('.mode')) out.mode = value
  }
  return out
}

/** home 层补丁路径（与 boot 端 resolveDshHome 语义对齐，round-15 复查：$DSH_HOME trim 后非空才算
 * 设置、支持 ~ 展开；否则默认 ~/.dsh——dsh-home-paths@0.1.1-rc.2 同语义）。 */
export function homePatchPath(): string {
  const env = process.env.DSH_HOME
  let home = env !== undefined && env.trim().length > 0 ? env : join(homedir(), '.dsh')
  if (home === '~') home = homedir()
  else if (home.startsWith('~/') || home.startsWith('~\\')) home = join(homedir(), home.slice(2))
  return join(home, 'cordis.patch.yml')
}

/** 收集候选配置文件文本（profile 目录 + 遗留父级 + home 层；无可读文件 → 空数组）。
 * 顺序即优先级：home 层最后读 = 覆盖（与 boot 的 [profile.patches, homePatches] 应用序一致）。 */
function readCandidateConfigs(profileDir: string): string[] {
  const out: string[] = []
  const candidates = [
    join(profileDir, CONFIG_CANDIDATES[0]),
    join(profileDir, CONFIG_CANDIDATES[1]),
    join(dirname(profileDir), CONFIG_CANDIDATES[0]),
    join(dirname(profileDir), CONFIG_CANDIDATES[1]),
    homePatchPath(), // 0.1.1-rc.2 home 层（$DSH_HOME/cordis.patch.yml）
  ]
  for (const p of candidates) {
    try {
      out.push(readFileSync(p, 'utf8'))
    } catch {
      // 不存在/不可读：跳过
    }
  }
  return out
}

/** 快照 profile 的遥测配置（多文件合并，后者覆盖前者）；无 telemetry url/mode → null。 */
export function snapshotTelemetryFields(profileDir: string): TelemetryFields | null {
  const merged: TelemetryFields = {}
  let found = false
  for (const text of readCandidateConfigs(profileDir)) {
    const fields = extractTelemetryFields(text)
    if (fields.urlHash !== undefined) { merged.urlHash = fields.urlHash; found = true }
    if (fields.mode !== undefined) { merged.mode = fields.mode; found = true }
  }
  return found ? merged : null
}

/** 差分：变化字段列表。任一为 null（无基线/配置消失）→ 空（不报，冷启动/临时不可读静默）。 */
export function diffTelemetry(prev: TelemetryFields | null, next: TelemetryFields | null): string[] {
  if (prev === null || next === null) return []
  const changed: string[] = []
  if (prev.urlHash !== next.urlHash) changed.push('exporter.url')
  if (prev.mode !== next.mode) changed.push('exporter.mode')
  return changed
}

export interface ConfigDiffOptions {
  /** 测试注入：轮询间隔。缺省 15s（G-3 热重载 15s 生效，同尺度可追上）。 */
  intervalMs?: number
  /** 测试注入：profile 目录。缺省 ctx.baseUrl。 */
  profileDir?: string
  /** 测试注入：立即执行一次检查（默认 false，等首个周期）。 */
  runNow?: boolean
}

/**
 * 安装遥测配置敏感化（alarm-only）。返回 disposer（清定时器）。
 * config.telemetryDiff === false 时不装。profile 目录不可得时静默跳过（warn 一次）。
 */
export function installConfigDiff(ctx: { baseUrl?: string; logger?: { warn(m: string): void } }, config: VetConfig, status: VetStatus, opts: ConfigDiffOptions = {}): () => void {
  if (config.telemetryDiff === false) return () => {}
  const profileDir = opts.profileDir ?? ctx.baseUrl
  if (profileDir === undefined || profileDir === '') {
    ctx.logger?.warn('vet: 遥测配置敏感化跳过——无法解析 profile 目录（ctx.baseUrl 缺失）')
    return () => {}
  }
  let prev: TelemetryFields | null = null
  let baselineReady = false
  const check = (): void => {
    const next = withVetSelfIo(() => snapshotTelemetryFields(profileDir))
    if (next === null) {
      // 0.3.9（审查修复）：配置消失/不可读**不重置基线**——此前 prev=null +
      // baselineReady=false，让「删→换」两段式改写（两个 15s 轮询间隙内完成）零信号：
      // 下一轮直接以攻击者新值静默重建基线。保留旧基线：配置恢复后与旧值比对，
      // 真正的 url/mode 更换照常黄警；同值恢复（或用户删配置后被恢复/覆盖）静默。
      return
    }
    if (!baselineReady) {
      prev = next
      baselineReady = true
      return
    }
    for (const field of diffTelemetry(prev, next)) {
      status.record({
        id: 'telemetry-config-change:' + field,
        severity: 'yellow',
        source: 'scan',
        kind: 'telemetry-config-change',
        message: '遥测配置变化：telemetry ' + field + ' 与上次观测不同（' +
          (field === 'exporter.url' ? 'url 哈希前缀 ' + (next.urlHash ?? '').slice(0, 6) : 'mode=' + next.mode) +
          '）——热重载 15s 生效，需重启校验 exporter 端点（G-3 形态）',
        target: field,
        at: Date.now(),
      })
    }
    prev = next
  }
  if (opts.runNow === true) check()
  const timer = setInterval(check, opts.intervalMs ?? POLL_INTERVAL_MS)
  timer.unref?.()
  return () => clearInterval(timer)
}