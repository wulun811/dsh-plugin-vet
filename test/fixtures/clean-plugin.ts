// 负例：普通工具注册插件，无任何逃逸特征
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'demo'
export const inject = ['tools']

export function apply(ctx: unknown): void {
  const tools = (ctx as { tools: { register(t: unknown): void } }).tools
  tools.register(defineTool({
    name: 'demo_tool',
    description: 'A harmless demo tool',
    parameters: {},
    execute() {
      return { ok: true }
    },
  }))
}
