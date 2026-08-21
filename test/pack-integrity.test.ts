import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'

/**
 * 五轮审查回归：check-pack-integrity 的「lib/** 相对引用闭合」检查曾因正则字面量
 * 误写（\\.{1,2} 在正则字面量中 = 字面反斜杠 + 任意字符，非转义点号）而静默零匹配，
 * 检查完全空转却照印「✓ 全部闭合」，且该脚本此前无任何测试覆盖——0.2.2 的 files
 * 白名单事故今天重演它也拦不住。本测试把脚本本体纳入门禁：正则自检失败或任一
 * 完整性项不过 → 脚本 process.exit(1) → 此处直接红。
 */
describe('check-pack-integrity 发布门禁（五轮审查回归）', () => {
  it('脚本全绿退出（含相对引用提取正则自检）', () => {
    const out = execFileSync('node', ['scripts/check-pack-integrity.mjs'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    expect(out).toContain('完整性检查通过')
    expect(out).toContain('相对引用全部闭合')
    // 0.2.4 回归：裸导入闭包检查必须真实运行并通过（typescript 误删事故即从此盲区穿过）
    expect(out).toContain('裸导入闭包通过')
    expect(out).not.toContain('✗')
  })
})
