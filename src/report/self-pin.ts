/**
 * ② 版本产物钉扎（已审计发布物，按版本发布，不写死单一 hash）。
 *
 * 错误写法是"写死当前版一个 hash"：升级=字节全变=被判陌生人=红字全回，升级即误报。
 * 正确形态是逐版本 pin 表（类似 npm integrity / SLSA provenance）：
 *
 *   vet-self-pins.json  { "pins": { "0.1.20": "sha256:…A", "0.1.21": "sha256:…B" } }
 *
 * 发布管道在 release 时写入本版 hash（scripts/gen-self-pin.mjs），安装/回扫时拿"这版声明的
 * 版本对应 hash"比对"当前扫描集字节 hash"：
 *   - pinned-match：字节 == 被审计发布物 → self-scan 注解生效，可出 Trusted；
 *   - dev-tree     ：版本有 pin 但字节不符（本地改码/未构建）→ 不予信任背书，amber；
 *   - unpinned     ：无此版本记录 → 不予信任背书，amber。
 * 被替换/篡改的 vet 字节不符任何已发布 pin → 一律非 pinned-match → 按陌生人对待、全部照扫。
 * 哈希覆盖扫描器实际看到的扫描集（listSourceFiles：.ts/.js/.mjs/.cjs + shell 脚本 + package.json）。
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { relative, join } from 'node:path'
import { resolvePkgRoot } from '../pkg-root.js'
import type { SelfPinState } from './self-scan.js'

/** 版本 → 扫描集 sha256。缺失版本 = 未钉扎。 */
export type SelfPins = Record<string, string>

/** 扫描集确定性哈希：排序相对路径 + utf8 内容。文件顺序、换行、路径分隔符一律归一，跨机可复现。 */
export function hashScanFiles(files: string[], root: string): string {
  const h = createHash('sha256')
  const entries = files
    .map(f => {
      const rel = relative(root, f).split('\\').join('/')
      let content = ''
      try {
        content = readFileSync(f, 'utf8')
      } catch {
        content = ''
      }
      return { rel, content }
    })
    .sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0))
  for (const e of entries) {
    h.update(e.rel)
    h.update('\u0000')
    h.update(e.content)
    h.update('\u0000')
  }
  return 'sha256:' + h.digest('hex')
}

/** pin 状态判定：pin 表缺本版本 → unpinned；字节不符 → dev-tree；一致 → pinned-match。 */
export function pinStateFor(pins: SelfPins | undefined, version: string | undefined, computed: string): SelfPinState {
  if (version === undefined || pins === undefined) return 'unpinned'
  const pinned = pins[version]
  if (pinned === undefined) return 'unpinned'
  return pinned === computed ? 'pinned-match' : 'dev-tree'
}

/** 读取随包发布的 vet-self-pins.json（缺失/损坏 → undefined，即未钉扎）。 */
export function loadSelfPins(): SelfPins | undefined {
  const root = resolvePkgRoot()
  try {
    const raw = JSON.parse(readFileSync(join(root, 'vet-self-pins.json'), 'utf8')) as { pins?: SelfPins }
    return raw.pins ?? undefined
  } catch {
    return undefined
  }
}
