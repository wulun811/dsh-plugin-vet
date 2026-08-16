/**
 * 盾牌数据通道（D22）：宿主 webServer 注册前缀路由 /vet：
 * - GET  /vet/status.json → { ...盾牌快照, runtimeGuard, metrics（内存/CPU/IO/子进程/fd） }
 * - POST /vet/runtime-guard { enable } → 写入 profile cordis.patch.yml 的 runtimeGuard 配置（重启生效）
 * webServer 是可选服务且可能晚于本插件就绪：注册带轮询重试（插件加载顺序无关）。
 * POST 同源校验（Origin 缺失或不同源 → 403），防止跨站触发。
 */
import type { Context } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync, writeFileSync, renameSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as yaml from 'js-yaml'
import { VetStatus } from './status.js'
import { readHostMetrics } from './metrics.js'
import { withVetSelfIo } from './runtime-hooks.js'
import type { VetConfig } from '../config.js'
import { PLUGIN_ENTRY_ID } from '../invariant.js'

interface WebServerLike {
  register(route: {
    kind: 'exact' | 'prefix'
    path: string
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): () => void
}

/** 最小上下文形状（避免与 cordis Context 的 logger 类型冲突）。 */
interface ContextLike {
  get<T>(name: string, strict?: boolean): T | undefined
  effect(fn: () => unknown, label?: string): unknown
  baseUrl?: string
  logger?: { info(m: string): void; warn(m: string): void; error(m: string): void }
}

const RETRY_MS = 400
const RETRY_MAX = 150

function writeJson(res: ServerResponse, code: number, body: unknown): void {
  // M3：响应可能已被结束（413 后 destroy + 客户端 RST 触发 error 监听再写）——
  // 双写会在事件监听器里抛 ERR_HTTP_HEADERS_SENT → 未捕获 → 宿主进程退出。
  if (res.writableEnded) return
  try {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(JSON.stringify(body))
  } catch {
    // 写入已结束/连接已断：忽略，绝不向上抛
  }
}

/**
 * YAML 写入前校验：用 js-yaml 反序列化验证内容合法，防止拼字符串拼出坏 YAML 导致 DSH 启动崩溃。
 * 任何解析错误直接抛出，调用方捕获后返回用户可读提示（不写入坏文件）。
 */
function validateYaml(content: string): void {
  // js-yaml.load 抛 YAMLException 时带行号/列号，足够定位问题
  yaml.load(content)
}

/**
 * 用对象操作生成 YAML（保证输出合法）：解析现有文件为数组，在数组层面添加/移除 vet 条目，
 * 用 js-yaml.dump() 重新生成。丢失注释但保证不崩溃。
 * 如果现有文件解析失败（已是坏 YAML），备份原文件后写入只含 vet 条目的新文件。
 */
function generateYamlFromObject(existingContent: string, enable: boolean): { content: string; repaired: boolean } {
  let entries: unknown[]
  let repaired = false
  try {
    const parsed = yaml.load(existingContent)
    // cordis.patch.yml 必须是数组（或空/null）
    if (parsed === null || parsed === undefined) {
      entries = []
    } else if (Array.isArray(parsed)) {
      entries = parsed
    } else {
      // 不是数组 → 视为损坏，重置
      entries = []
      repaired = true
    }
  } catch {
    // 解析失败 → 文件已损坏，重置
    entries = []
    repaired = true
  }
  // 移除所有 vet 条目（按 id 判定）
  entries = entries.filter((e: unknown) => {
    if (typeof e !== 'object' || e === null) return true
    const id = (e as Record<string, unknown>).id
    return id !== PLUGIN_ENTRY_ID && id !== '@jieai/dsh-plugin-vet'
  })
  if (enable) {
    // 查找现有 vet 条目的 config（保留非 runtimeGuard 键）
    // 注意：上面已经移除了 vet 条目，这里需要从原始 parsed 里找
    // 重新解析一次（简单起见）
    let existingVetConfig: Record<string, unknown> = {}
    try {
      const parsed = yaml.load(existingContent)
      if (Array.isArray(parsed)) {
        const vetEntry = parsed.find((e: unknown) => {
          if (typeof e !== 'object' || e === null) return false
          const id = (e as Record<string, unknown>).id
          return id === PLUGIN_ENTRY_ID || id === '@jieai/dsh-plugin-vet'
        })
        if (vetEntry && typeof vetEntry === 'object') {
          const config = (vetEntry as Record<string, unknown>).config
          if (config && typeof config === 'object') {
            existingVetConfig = { ...(config as Record<string, unknown>) }
            delete existingVetConfig.runtimeGuard
          }
        }
      }
    } catch {
      // 忽略，用空 config
    }
    // 添加新 vet 条目
    entries.push({
      id: PLUGIN_ENTRY_ID,
      config: {
        ...existingVetConfig,
        runtimeGuard: 'watch',
      },
    })
  }
  // 空数组写 []（DSH boot 契约）
  if (entries.length === 0) {
    return { content: '[]', repaired }
  }
  return { content: yaml.dump(entries, { indent: 2, lineWidth: -1 }), repaired }
}

/**
 * M2：原子写 patch 文件——先写同目录 .tmp，再 rename 覆盖（POSIX 同文件系统 rename 原子）。
 * 崩溃中途不会留下半写的主文件；.bak.latest 是改动前固定快照名（防 Date.now 碰撞/无限堆积）。
 * 写入前强制 YAML 校验：拼错的字符串不会落到磁盘（DSH 启动解析失败会崩溃）。
 */
function atomicWritePatch(patchPath: string, content: string, previousContent: string): void {
  validateYaml(content)
  const tmp = patchPath + '.tmp'
  const backup = patchPath + '.bak.latest'
  try {
    // 改动前快照（固定名，供人工回滚）
    writeFileSync(backup, previousContent, { mode: 0o600 })
  } catch {
    // 快照失败不阻断主写入
  }
  writeFileSync(tmp, content, { mode: 0o600 })
  renameSync(tmp, patchPath)
  // tmp 残留清理（rename 成功后不应存在，防异常残留）
  try {
    rmSync(tmp, { force: true })
  } catch {
    // 无害
  }
}

/** L3：提示语里的配置文件名（不泄露绝对路径）。 */
function profileName(): string {
  return 'cordis.patch.yml'
}

/** 同源校验（POST 用）：Origin 缺失或与 Host 不符 → 拒绝（跨站/无浏览器上下文 POST 防护）。 */
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin
  if (origin === undefined) return false
  const host = req.headers.host
  if (host === undefined) return false
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

/**
 * 在 profile 的 cordis.patch.yml 写入/移除 plugin-vet 的 runtimeGuard 配置。
 * 用户点按钮触发（alarm-only 不冲突：是用户的操作，vet 只按指令写自己的配置）。
 * @returns ok + 给用户的提示语。
 */
/**
 * DSH 的 ctx.baseUrl 可能是 file: URL（如 file:/home/user/.dsh/profiles/web）
 * 或普通目录路径，统一规整成文件系统路径（path.join 不认 URL）。
 */
function resolveProfileDir(baseUrl: string): string {
  if (baseUrl.startsWith('file:')) {
    try {
      return fileURLToPath(baseUrl)
    } catch {
      // 解析失败退回字面量，由后续 IO 报错，避免吞掉真实原因
    }
  }
  return baseUrl
}

/** vet 条目的历史形态：早期误写成了包名 id（DSH 曾自动加引号），统一识别为 vet 条目。 */
const VET_ENTRY_RE = /^-\s*id:\s*(?:["']?@?jieai\/dsh-plugin-vet["']?|plugin-vet)\s*$/

/**
 * vet 条目判定（P2-8 统一规则）：只认顶格条目——VET_ENTRY_RE 锚定行首，缩进的
 * （如嵌在别的插件 insert/group 列表里）不是 vet 顶层条目。strip / extract / read
 * 三处此前规则不一致（后两者用 trim 匹配）→ 缩进嵌套条目被误读/摘不掉；现全部走本函数。
 */
function isVetEntryLine(line: string): boolean {
  return VET_ENTRY_RE.test(line)
}

/** 读 patch 文件里 vet 条目实际配置的 runtimeGuard（'watch' | 'off'）。 */
export function readPatchRuntimeGuard(ctx: ContextLike): 'watch' | 'off' {
  // 先取局部变量再判空：闭包内 TS 对属性访问不保留 narrowing（ctx.baseUrl 可能被外部改写）
  const baseUrl = ctx.baseUrl
  if (baseUrl === undefined) return 'off'
  // P2-6：vet 自读 patch（盾牌 5s 轮询）在 .dsh 敏感段下会自报警——vetSelfIo 直通
  return withVetSelfIo(() => {
    try {
      const content = readFileSync(join(resolveProfileDir(baseUrl), 'cordis.patch.yml'), 'utf8')
      const lines = content.split('\n')
      const start = lines.findIndex(isVetEntryLine)
      if (start === -1) return 'off'
      for (let i = start + 1; i < lines.length; i++) {
        const m = /^\s*runtimeGuard:\s*(\S+)/.exec(lines[i])
        if (m !== null) return m[1] === 'watch' ? 'watch' : 'off'
      }
      return 'off'
    } catch {
      return 'off'
    }
  })
}

export function writeRuntimeGuardConfig(ctx: ContextLike, enable: boolean): { ok: boolean; note: string } {
  if (ctx.baseUrl === undefined) {
    return { ok: false, note: '无法定位 profile 配置目录（ctx.baseUrl 缺失）' }
  }
  const patchPath = join(resolveProfileDir(ctx.baseUrl), 'cordis.patch.yml')
  // P2-6：vet 自写自己的 patch 配置（用户点按钮触发）——vetSelfIo 直通，不自报警
  return withVetSelfIo(() => {
    let content: string
    try {
      content = readFileSync(patchPath, 'utf8')
    } catch (error) {
      if (!enable) return { ok: true, note: '当前未开启' }
      // 首次开启时 cordis.patch.yml 可能还不存在 → 直接新建
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        return { ok: false, note: `无法读取 ${profileName()}` }
      }
      // 文件不存在：用对象操作生成（保证合法）
      const { content: newContent } = generateYamlFromObject('', true)
      try {
        atomicWritePatch(patchPath, newContent, '')
      } catch (writeError) {
        return { ok: false, note: `写入失败：${String(writeError)}` }
      }
      return { ok: true, note: `已写入 ${profileName()}，重启 dsh web 后生效` }
    }
    // 文件存在：用对象操作生成新内容（保证合法，丢失注释但不会崩溃）
    const { content: newContent, repaired } = generateYamlFromObject(content, enable)
    // 检查是否真的需要写入（避免无意义的文件修改）
    if (newContent.trim() === content.trim() && !repaired) {
      return { ok: true, note: enable ? `已写入 ${profileName()}，重启 dsh web 后生效` : '当前未开启' }
    }
    try {
      atomicWritePatch(patchPath, newContent, content)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    if (repaired) {
      return { ok: true, note: `${profileName()} 已损坏并已修复，重启 dsh web 后生效` }
    }
    return { ok: true, note: enable ? `已写入 ${profileName()}，重启 dsh web 后生效` : '已移除 runtimeGuard 配置，重启 dsh web 后生效' }
  })
}

function handleToggle(req: IncomingMessage, res: ServerResponse, ctx: ContextLike): void {
  if (!sameOrigin(req)) {
    writeJson(res, 403, { ok: false, note: '跨源请求被拒绝' })
    return
  }
  const chunks: Buffer[] = []
  let total = 0
  req.on('data', (c: Buffer) => {
    total += c.length
    if (total > 8192) {
      writeJson(res, 413, { ok: false, note: '请求体过大' })
      req.destroy()
      return
    }
    chunks.push(c)
  })
  req.on('end', () => {
    // enable 必须是显式布尔：空 body / 缺字段 / 非布尔 → 400 拒绝，绝不默认当「关闭」误关守卫
    let enable: unknown
    try {
      enable = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').enable
    } catch {
      writeJson(res, 400, { ok: false, note: '请求体不是合法 JSON' })
      return
    }
    if (typeof enable !== 'boolean') {
      writeJson(res, 400, { ok: false, note: '缺少布尔字段 enable' })
      return
    }
    const result = writeRuntimeGuardConfig(ctx, enable)
    writeJson(res, result.ok ? 200 : 500, result)
  })
  req.on('error', () => {
    writeJson(res, 400, { ok: false, note: '请求体读取失败' })
  })
}

/** 单次注册尝试（可测试）：webServer 就绪即注册成功。 */
export function registerStatusRouteOnce(
  ctx: ContextLike,
  config: VetConfig,
  status: VetStatus,
): boolean {
  void config // 状态已改读文件级（M5）；config 保留仅为 API 兼容
  let ws: WebServerLike | undefined
  try {
    ws = ctx.get('webServer')
  } catch {
    return false
  }
  if (ws === undefined) return false
  ctx.effect(
    () => ws!.register({
      kind: 'prefix',
      path: '/vet',
      handler: (req, res) => {
        const pathname = (req.url ?? '').split('?')[0]
        if (req.method === 'POST' && pathname.endsWith('/vet/dismiss')) {
          handleDismiss(req, res, status, false)
          return
        }
        if (req.method === 'POST' && pathname.endsWith('/vet/restore')) {
          handleDismiss(req, res, status, true)
          return
        }
        if (req.method === 'POST' && pathname.endsWith('/vet/runtime-guard')) {
          handleToggle(req, res, ctx)
          return
        }
        if (req.method !== 'GET' || !pathname.endsWith('/vet/status.json')) {
          writeJson(res, 404, { ok: false, note: 'not found' })
          return
        }
        // M5：运行时配置可能在面板外被改（编辑 cordis.patch.yml），返回文件级实际状态而非内存快照
        writeJson(res, 200, { ...status.snapshot(), runtimeGuard: readPatchRuntimeGuard(ctx), metrics: readHostMetrics() })
      },
    }),
    'vet: shield status route',
  )
  return true
}

/** 读取 POST JSON body 的 { id }（统一大小/解析错误处理；超大 body 413 断连）。 */
function readIdBody(req: IncomingMessage, res: ServerResponse, onId: (id: string | undefined) => void): void {
  const chunks: Buffer[] = []
  let total = 0
  req.on('data', (c: Buffer) => {
    total += c.length
    if (total > 8192) {
      writeJson(res, 413, { ok: false, note: '请求体过大' })
      req.destroy()
      return
    }
    chunks.push(c)
  })
  req.on('end', () => {
    let id: unknown
    try {
      id = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').id
    } catch {
      writeJson(res, 400, { ok: false, note: '请求体不是合法 JSON' })
      return
    }
    if (typeof id !== 'string' || id === '') {
      writeJson(res, 400, { ok: false, note: '缺少报警 id' })
      return
    }
    onId(id)
  })
  req.on('error', () => {
    writeJson(res, 400, { ok: false, note: '请求体读取失败' })
  })
}

/**
 * 用户忽略/恢复一条报警：只改 vet 自己的内存聚合（不删记录、不碰插件），
 * 面板下一轮轮询即生效。同源校验与 guard 开关一致（M4）。
 */
function handleDismiss(req: IncomingMessage, res: ServerResponse, status: VetStatus, restore: boolean): void {
  if (!sameOrigin(req)) {
    writeJson(res, 403, { ok: false, note: '跨源请求被拒绝' })
    return
  }
  readIdBody(req, res, (id) => {
    if (id === undefined) return
    if (restore) status.restore(id)
    else status.dismiss(id)
    writeJson(res, 200, { ok: true })
  })
}

/**
 * 安装盾牌状态路由：webServer 可能晚于本插件就绪（fiber 未 ACTIVE 时
 * ctx.get 返回 undefined），轮询重试直到注册成功；超时只告警不阻断。
 */
export function installStatusRoute(ctx: Context, config: VetConfig, status: VetStatus): void {
  const c = ctx as unknown as ContextLike
  if (registerStatusRouteOnce(c, config, status)) return
  const timer = setInterval(() => {
    if (registerStatusRouteOnce(c, config, status)) clearInterval(timer)
  }, RETRY_MS)
  timer.unref?.()
  ctx.effect(() => () => clearInterval(timer), 'vet: status route waiter')
  const timeout = setTimeout(() => {
    if (typeof c.logger?.warn === 'function') {
      c.logger.warn('vet: webServer 60s 内未就绪，盾牌状态路由未注册（非 web profile 属正常）')
    }
  }, RETRY_MS * RETRY_MAX)
  timeout.unref?.()
}