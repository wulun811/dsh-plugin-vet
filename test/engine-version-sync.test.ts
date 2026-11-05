/**
 * 引擎标识在两个 tsconfig 里各存一份，必须一致。
 *
 * 为什么会重复：`src` 与 `scanner-bin` 是两个编译单元（各自的 `rootDir`），跨边界 import
 * 会把产物落到 `rootDir` 之外。所以 `src/scanner/protocol.ts` 有 `CURRENT_ENGINE`，
 * `scanner-bin/protocol.ts` 有 `ENGINE_VERSION`。生产代码不该为了消重去动构建布局，
 * 那就让测试来钉。
 *
 * 漂移的具体后果（不是理论）：审计档案的 `rule_set_version` 与 `CURRENT_ENGINE` 比较，
 * 用来判断「这份档案是不是当前规则集产出的」。若 `CURRENT_ENGINE` 是旧值，这条短路永远
 * 不成立——每一条有档案的插件都会掉进影响函数里。那边是 fail-open 的（判不了就放行），
 * 所以不会误拒载，只会**静默失效**：一条本该「没变就是没变」的判断，变成每条记录都要
 * 去翻扫描摘要、还多半判不了。
 */
import { describe, expect, it } from 'vitest'
import { CURRENT_ENGINE } from '../lib/scanner/protocol.js'
import { ENGINE_VERSION } from '../lib/scanner-bin/protocol.js'

describe('引擎标识的两个副本', () => {
  it('src 与 scanner-bin 的常量一致', () => {
    expect(CURRENT_ENGINE).toBe(ENGINE_VERSION)
  })

  it('形如 static-v<数字>（引擎标识是可比较的，不是自由文本）', () => {
    expect(CURRENT_ENGINE).toMatch(/^static-v\d+$/)
  })
})
