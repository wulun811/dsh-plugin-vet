/**
 * 盾牌数据通道（D22）：宿主 webServer 注册 /vet/status.json（浏览器 5s 轮询）。
 * webServer 是可选服务（ctx.get 守卫）——非 web profile 自动 no-op，不阻塞加载。
 */
import type { Context } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { VetStatus } from './status.js'

interface WebServerLike {
  register(route: {
    kind: 'exact' | 'prefix'
    path: string
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): () => void
}

/**
 * 注册盾牌状态端点。
 * @param ctx - 插件上下文（webServer 可能不存在）。
 * @param status - 盾牌状态聚合器。
 */
export function installStatusRoute(ctx: Context, status: VetStatus): void {
  let ws: WebServerLike | undefined
  try {
    ws = (ctx as Context & { get<T>(name: string): T | undefined }).get('webServer')
  } catch {
    return
  }
  if (ws === undefined) return
  ctx.effect(
    () => ws!.register({
      kind: 'exact',
      path: '/vet/status.json',
      handler: (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify(status.snapshot()))
      },
    }),
    'vet: shield status route',
  )
}
