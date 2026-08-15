/**
 * vet 浏览器半区（D22）：盾牌状态灯。注册进 ui-conversation 声明的
 * conversation.session.header.actions 孔位（additive 动作区，order 100 靠后）。
 * 数据来自宿主 webServer 的 /vet/status.json（5s 轮询，只读展示）。
 * alarm-only：纯展示，无任何操作。
 * 类型说明：第三方包无法编译期依赖私有 @deepseek-ai/dsh-client-* 包，
 * 这里用最小结构类型镜像浏览器运行时对象（cordis ctx.slots）。
 */
import type { ReactNode } from 'react'
import { Shield } from './Shield.tsx'

interface SlotRegisterSpec {
  name: string
  id: string
  order?: number
  locale?: string
  inject?: Record<string, unknown>
}

interface SlotsLike {
  inject(name: string, register: () => unknown): unknown
  register(spec: SlotRegisterSpec, component: (props: Record<string, unknown>) => ReactNode): unknown
}

interface ClientCtxLike {
  slots: SlotsLike
}

/** 浏览器半区依赖的 cordis 服务：slots（由 dsh-client-ui-slots 提供）。 */
export const inject = ['slots']

export function apply(ctx: ClientCtxLike): void {
  ctx.slots.inject('conversation.session.header.actions', () =>
    ctx.slots.register({ name: 'conversation.session.header.actions', id: 'vet-shield', order: 100 }, Shield),
  )
}
