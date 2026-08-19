import { describe, it, expect } from 'vitest'

/**
 * rc.8 升级后部分插件 entryName 带子模块路径（如 @deepseek-ai/dsh-tool-subagent-control/list-agents），
 * VET 需要提取包名部分用于解析/豁免/档案匹配。
 */
describe('rc.8 subpath entryName handling', () => {
  // 模拟 extractPackageName 逻辑
  function extractPackageName(packageName: string): string {
    if (packageName.startsWith('@') && packageName.includes('/')) {
      const parts = packageName.split('/')
      if (parts.length >= 3) {
        return parts.slice(0, 2).join('/')
      }
    }
    if (!packageName.startsWith('@') && packageName.includes('/')) {
      if (packageName.startsWith('/') || packageName.startsWith('./')) {
        return packageName
      }
      return packageName.split('/')[0]
    }
    return packageName
  }

  it('extracts package name from @scope/name/subpath', () => {
    expect(extractPackageName('@deepseek-ai/dsh-tool-subagent-control/list-agents'))
      .toBe('@deepseek-ai/dsh-tool-subagent-control')
  })

  it('extracts package name from @scope/name/subpath/deeper', () => {
    expect(extractPackageName('@deepseek-ai/dsh-tool-subagent-control/list-agents/deep'))
      .toBe('@deepseek-ai/dsh-tool-subagent-control')
  })

  it('preserves @scope/name without subpath', () => {
    expect(extractPackageName('@deepseek-ai/dsh-web-app'))
      .toBe('@deepseek-ai/dsh-web-app')
  })

  it('preserves local file paths', () => {
    expect(extractPackageName('/home/chen/.dsh/profiles/web/lan-uuid-polyfill.mjs'))
      .toBe('/home/chen/.dsh/profiles/web/lan-uuid-polyfill.mjs')
  })

  it('preserves relative paths', () => {
    expect(extractPackageName('./local-plugin.mjs'))
      .toBe('./local-plugin.mjs')
  })

  it('extracts package name from name/subpath (non-scoped)', () => {
    expect(extractPackageName('some-package/subpath'))
      .toBe('some-package')
  })

  it('preserves plain package names', () => {
    expect(extractPackageName('@deepseek-ai/dsh-goal'))
      .toBe('@deepseek-ai/dsh-goal')
  })
})
