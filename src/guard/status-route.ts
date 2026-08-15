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
import { VetStatus } from './status.js'
import { readHostMetrics } from './metrics.js'
import type { VetConfig } from '../config.js'
import { PACKAGE_NAME } from '../invariant.js'

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
export function writeRuntimeGuardConfig(ctx: ContextLike, enable: boolean): { ok: boolean; note: string } {
  if (ctx.baseUrl === undefined) {
    return { ok: false, note: '无法定位 profile 配置目录（ctx.baseUrl 缺失）' }
  }
  const patchPath = join(ctx.baseUrl, 'cordis.patch.yml')
  let content: string
  try {
    content = readFileSync(patchPath, 'utf8')
  } catch {
    return { ok: false, note: `无法读取 ${patchPath}` }
  }
  const marker = `- id: ${PACKAGE_NAME}`
  if (enable) {
    if (content.includes(marker)) {
      return { ok: false, note: `${patchPath} 已有 plugin-vet 条目，请手动将其 config.runtimeGuard 改为 watch（避免重复叠加）` }
    }
    const entry = `- id: ${PACKAGE_NAME}\n  config:\n    runtimeGuard: watch\n`
    try {
      writeFileSync(patchPath + '.bak.' + Date.now(), content)
      writeFileSync(patchPath, content.trimEnd() + '\n' + entry)
    } catch (error) {
      return { ok: false, note: `写入失败：${String(error)}` }
    }
    return { ok: true, note: `已写入 ${patchPath}，重启 dsh web 后生效` }
  }
  if (!content.includes(marker)) {
    return { ok: true, note: '当前未开启' }
  }
  const lines = content.split('\n')
  const out: string[] = []
  let skipping = false
  for (const line of lines) {
    if (line.trim() === marker) {
      skipping = true
      continue
    }
    if (skipping) {
      const trimmed = line.trim()
      if (trimmed === '' || trimmed.startsWith('- ')) {
        skipping = false
        out.push(line)
      } else {
        continue
      }
    } else {
      out.push(line)
    }
  }
  try {
    writeFileSync(patchPath + '.bak.' + Date.now(), content)
    writeFileSync(patchPath, out.join('\n'))
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
