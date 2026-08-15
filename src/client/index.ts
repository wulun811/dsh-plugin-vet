/**
 * vet 浏览器半区（D22）：盾牌状态灯。注册进 ui-conversation 声明的
 * conversation.session.header.actions 孔位（additive 动作区，order 100 靠后）。
 * 数据来自宿主 webServer 的 /vet/status.json（5s 轮询，只读展示）。
 * alarm-only：纯展示，无任何操作。
 * i18n：向 DSH locale 服务注册 'vet' 命名空间词典（zh/en），槽渲染器把 t 注入盾牌组件，
 * 随页面语言自动切换（D23）。
 * 类型说明：第三方包无法编译期依赖私有 @deepseek-ai/dsh-client-* 包，
 * 这里用最小结构类型镜像浏览器运行时对象（cordis ctx.slots / ctx.locale）。
 */
import type { ReactNode } from 'react'
import { Shield } from './Shield.tsx'
import { NS, zh, en } from './i18n.ts'

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
  /** DSH locale 服务（dsh-client-locale 提供）。 */
  locale?: { register(ns: string, dicts: { zh: Record<string, string>; en: Record<string, string> }): unknown }
  effect?: (fn: () => unknown, label?: string) => unknown
}

/** 浏览器半区依赖的 cordis 服务：slots（dsh-client-ui-slots）+ locale（dsh-client-locale）。 */
export const inject = ['slots', 'locale']

export function apply(ctx: ClientCtxLike): void {
  if (typeof ctx.effect === 'function' && ctx.locale !== undefined) {
    ctx.effect(() => ctx.locale!.register(NS, { zh, en }), 'vet: dictionaries')
  }
  ctx.slots.inject('conversation.session.header.actions', () =>
    ctx.slots.register({ name: 'conversation.session.header.actions', id: 'vet-shield', order: 100, locale: NS }, Shield),
  )
}
