/**
 * 盾牌数据通道（D22）：宿主 webServer 注册前缀路由 /vet：
 * - GET  /vet/status.json → { ...盾牌快照, runtimeGuard, metrics（内存/CPU/IO/子进程/fd） }
 * - POST /vet/runtime-guard { enable } → 写入 profile cordis.patch.yml 的 runtimeGuard 配置（重启生效）
 * webServer 是可选服务且可能晚于本插件就绪：注册带轮询重试（插件加载顺序无关）。
 * POST 同源校验（Origin 缺失或不同源 → 403），防止跨站触发。
 */
import type { Context } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync, writeFileSync } from 'node:fs'
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
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}

/** 同源校验：Origin 存在且与 Host 不符 → 拒绝（跨站 POST 防护）。 */
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin
  if (origin === undefined) return true
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

/** 从 patch 行中摘掉所有 vet 条目（含其 config 块），其余行原样保留。 */
function stripVetEntries(lines: string[]): string[] {
  const out: string[] = []
  let skipping = false
  for (const line of lines) {
    if (VET_ENTRY_RE.test(line.trim())) {
      skipping = true
      continue
    }
    if (skipping) {
      const trimmed = line.trim()
      if (trimmed === '' || trimmed.startsWith('- ')) {
        skipping = false
        out.push(line)
      }
      continue
    }
    out.push(line)
  }
  return out
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
      return { ok: false, note: `无法读取 ${patchPath}` }
    }
    const entry = `- id: ${PLUGIN_ENTRY_ID}\n  config:\n    runtimeGuard: watch\n`
    try {
      writeFileSync(patchPath, entry)
    } catch (writeError) {
      return { ok: false, note: `写入失败：${String(writeError)}` }
    }
    return { ok: true, note: `已写入 ${patchPath}，重启 dsh web 后生效` }
  }
  // 先摘掉所有历史 vet 条目（含早期误写的包名 id 形态），再按目标状态重写：幂等且能自愈旧文件。
  const stripped = stripVetEntries(content.split('\n'))
  const changed = stripped.join('\n') !== content
  if (enable) {
    const entry = `- id: ${PLUGIN_ENTRY_ID}\n  config:\n    runtimeGuard: watch\n`
    try {
      writeFileSync(patchPath + '.bak.' + Date.now(), content)
      writeFileSync(patchPath, stripped.join('\n').trimEnd() + '\n' + entry)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    return { ok: true, note: `已写入 ${patchPath}，重启 dsh web 后生效` }
  }
  if (!changed) {
    return { ok: true, note: '当前未开启' }
  }
  try {
    writeFileSync(patchPath + '.bak.' + Date.now(), content)
    writeFileSync(patchPath, stripped.join('\n'))
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
  req.on('data', (c: Buffer) => { chunks.push(c) })
  req.on('end', () => {
    let enable = false
    try {
      enable = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').enable === true
    } catch {
      enable = false
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
        if (req.method === 'POST' && (req.url ?? '').endsWith('/vet/runtime-guard')) {
          handleToggle(req, res, ctx)
          return
        }
        if (req.method !== 'GET' || !(req.url ?? '').endsWith('/vet/status.json')) {
          writeJson(res, 404, { ok: false, note: 'not found' })
          return
        }
        writeJson(res, 200, { ...status.snapshot(), runtimeGuard: config.runtimeGuard, metrics: readHostMetrics() })
      },
    }),
    'vet: shield status route',
  )
  return true
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
