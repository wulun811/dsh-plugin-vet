/**
 * 插件自有会话事件：SessionEventMap 可声明合并（dsh-session 约定"plugin-owned events
 * carry no core message"）。事件走 sessionPersistence.append 完整信封 + ignorable: true，
 * 满足 Model-visible ⟺ logged 且不触发 coordinator 未知类型拒读（coordinator.ts:1063）。
 */
declare module '@deepseek-ai/dsh-session' {
  interface SessionEventMap {
    'audit-plugin-vet/request': {
      pluginName: string
      round: number
      inputBytes: number
      provider: string
      model: string
    }
    'audit-plugin-vet/result': {
      pluginName: string
      llmSection: unknown
    }
  }
}
export {}
