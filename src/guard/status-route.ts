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
import { VetStatus } from './status.js'
import { readHostMetrics } from './metrics.js'
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
 * M2：原子写 patch 文件——先写同目录 .tmp，再 rename 覆盖（POSIX 同文件系统 rename 原子）。
 * 崩溃中途不会留下半写的主文件；.bak.latest 是改动前固定快照名（防 Date.now 碰撞/无限堆积）。
 */
function atomicWritePatch(patchPath: string, content: string, previousContent: string): void {
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
 * 从 patch 行中摘掉所有 vet 条目（含其 config 块），其余行原样保留。
 * 按缩进判定条目边界：config 块（含嵌套列表）都缩进，只有回到顶格（注释/下一个
 * 顶层条目）才结束跳过——避免 vet 配置里的嵌套列表项被误判为新条目。
 */
function stripVetEntries(lines: string[]): string[] {
  const out: string[] = []
  let skipping = false
  for (const line of lines) {
    // M1：只认顶格条目——缩进的 "- id: plugin-vet"（如嵌在别的插件 insert 列表里）
    // 不是 vet 顶层条目，若匹配会吞掉外层条目的尾部并留下真实 vet 条目 → 重复/损坏
    if (line.startsWith('-') && VET_ENTRY_RE.test(line)) {
      skipping = true
      continue
    }
    if (skipping) {
      // 顶格非空行 = 下一个顶层条目或注释 → 结束跳过；缩进行（config/嵌套列表）继续跳过
      if (/^\S/.test(line)) {
        skipping = false
        out.push(line)
      }
      continue
    }
    out.push(line)
  }
  return out
}

/** 提取现有 vet 条目的 config 块（缩进行，含嵌套列表），用于开启守卫时保留非 runtimeGuard 键。 */
function extractVetConfig(content: string): string | undefined {
  const lines = content.split('\n')
  const start = lines.findIndex(l => VET_ENTRY_RE.test(l.trim()))
  if (start === -1) return undefined
  const out: string[] = []
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]
    if (/^\s*config:/.test(line)) {
      // 收集 config 下所有缩进行（比 config: 行多缩进一级）
      const configIndent = line.match(/^\s*/)?.[0].length ?? 0
      for (let j = i + 1; j < lines.length; j++) {
        const sub = lines[j]
        const subIndent = sub.match(/^\s*/)?.[0].length ?? 0
        if (sub.trim() === '' || sub.trim().startsWith('#')) continue
        if (subIndent <= configIndent) break
        out.push(sub)
      }
      break
    }
  }
  return out.join('\n')
}

/** 读 patch 文件里 vet 条目实际配置的 runtimeGuard（'watch' | 'off'）。 */
export function readPatchRuntimeGuard(ctx: ContextLike): 'watch' | 'off' {
  if (ctx.baseUrl === undefined) return 'off'
  try {
    const content = readFileSync(join(resolveProfileDir(ctx.baseUrl), 'cordis.patch.yml'), 'utf8')
    const lines = content.split('\n')
    const start = lines.findIndex(l => VET_ENTRY_RE.test(l.trim()))
    if (start === -1) return 'off'
    for (let i = start + 1; i < lines.length; i++) {
      const m = /^\s*runtimeGuard:\s*(\S+)/.exec(lines[i])
      if (m !== null) return m[1] === 'watch' ? 'watch' : 'off'
    }
    return 'off'
  } catch {
    return 'off'
  }
}

export function writeRuntimeGuardConfig(ctx: ContextLike, enable: boolean): { ok: boolean; note: string } {
  if (ctx.baseUrl === undefined) {
    return { ok: false, note: '无法定位 profile 配置目录（ctx.baseUrl 缺失）' }
  }
  const patchPath = join(resolveProfileDir(ctx.baseUrl), 'cordis.patch.yml')
  let content: string
  try {
    content = readFileSync(patchPath, 'utf8')
  } catch (error) {
    if (!enable) return { ok: true, note: '当前未开启' }
    // 首次开启时 cordis.patch.yml 可能还不存在 → 直接新建
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      return { ok: false, note: `无法读取 ${profileName()}` }
    }
    const entry = `- id: ${PLUGIN_ENTRY_ID}\n  config:\n    runtimeGuard: watch\n`
    try {
      atomicWritePatch(patchPath, entry, '')
    } catch (writeError) {
      return { ok: false, note: `写入失败：${String(writeError)}` }
    }
    return { ok: true, note: `已写入 ${profileName()}，重启 dsh web 后生效` }
  }
  // 先摘掉所有历史 vet 条目（含早期误写的包名 id 形态），再按目标状态重写：幂等且能自愈旧文件。
  const stripped = stripVetEntries(content.split('\n'))
  const changed = stripped.join('\n') !== content
  if (enable) {
    // H2：保留现有 vet 条目 config 里 runtimeGuard 之外的键（mode/allowlist/rules/honeypot 等），
    // 只覆盖 runtimeGuard——避免开启守卫把用户显式配置（如 deny 模式）冲掉。
    const existingVet = content.split('\n').map(l => l.trim()).find(l => VET_ENTRY_RE.test(l))
    const existingBlock = existingVet !== undefined
      ? extractVetConfig(content)
      : undefined
    let entry: string
    if (existingBlock !== undefined && existingBlock.trim() !== '') {
      // 已有 config 块：把 runtimeGuard 键写进它（保留其余键）
      const withoutGuard = existingBlock.replace(/^\s*runtimeGuard:\s*\S+$/m, '').trimEnd()
      entry = `- id: ${PLUGIN_ENTRY_ID}\n  config:\n${withoutGuard}\n    runtimeGuard: watch\n`
    } else {
      entry = `- id: ${PLUGIN_ENTRY_ID}\n  config:\n    runtimeGuard: watch\n`
    }
    try {
      atomicWritePatch(patchPath, stripped.join('\n').trimEnd() + '\n' + entry, content)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    return { ok: true, note: `已写入 ${profileName()}，重启 dsh web 后生效` }
  }
  if (!changed) {
    return { ok: true, note: '当前未开启' }
  }
  try {
    // H1：关闭守卫后若文件只剩注释/空（vet 条目是唯一内容），写 '[]'（DSH boot 契约：
    // 空文件/纯注释文件解析失败，禁用层要写 []）——否则下次启动 profile 加载抛错。
    const rest = stripped.join('\n')
    const hasReal = rest.split('\n').some(l => l.trim() !== '' && !l.trim().startsWith('#'))
    const finalContent = hasReal ? rest : '[]'
    atomicWritePatch(patchPath, finalContent, content)
  } catch (error) {
    return { ok: false, note: `写入失败：${String(error)}` }
  }
  return { ok: true, note: '已移除 runtimeGuard 配置，重启 dsh web 后生效' }
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