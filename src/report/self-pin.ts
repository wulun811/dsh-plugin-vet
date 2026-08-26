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
 *   - pinned-match：字节 == 某版被审计发布物 → self-scan 注解生效，可出 Trusted；
 *   - dev-tree     ：本版有 pin 但字节不符任何已发布 pin（本地改码/未构建/被篡改）→ 不予信任背书，amber；
 *   - unpinned     ：无任何版本记录 → 不予信任背书，amber。
 * 被替换/篡改的 vet 字节不符任何已发布 pin → 一律非 pinned-match → 按陌生人对待、全部照扫。
 *
 * round-16 review（决策 2：升级体验优先）：pinned-match 不再要求「版本键 == 当前版本」——
 * 字节匹配**任一**已发布版本的 pin 即视为已知被审计发布物。升级窗口（宿主还是旧版代码、
 * 磁盘已是新版文件、package.json 版本与 pin 表交错更新）里旧进程对新字节的判定由此从
 * dev-tree（互不认）变为 pinned-match——防「两个 vet 互相不认」；安全语义不变：攻击者
 * 换上非审计字节（含仿冒篡改）仍不符任何 pin。降级到旧审计版（字节=某历史 pin）不是
 * 能力升级，无放强面。
 * 哈希覆盖扫描器实际看到的扫描集 = 随包发布的产物（self-scope.listShippedFiles：
 * lib/** + 根级清单 + docs/**，vet-self-pins.json 自引用除外）。
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { relative, join } from 'node:path'
import { resolvePkgRoot } from '../pkg-root.js'
import type { SelfPinState } from './self-scan.js'

/** 版本 → 扫描集 sha256。缺失版本 = 未钉扎。 */
export type SelfPins = Record<string, string>

/** 扫描集确定性哈希：排序相对路径 + utf8 内容。文件顺序、换行、路径分隔符一律归一，跨机可复现。
 * round-5 review（B-A3）：注释承诺「换行归一」但此前只归一路径分隔符——Windows 检出
 * （git core.autocrlf）把源文件挂成 CRLF 时，同一发布字节算出不同 hash，合法安装被误判
 * dev-tree（amber 不背书，pinned-match 永不成立）；现统一折叠 CRLF 并去 BOM。 */
export function hashScanFiles(files: string[], root: string): string {
  const h = createHash('sha256')
  const entries = files
    .map(f => {
      const rel = relative(root, f).split('\\').join('/')
      let content = ''
      try {
        content = readFileSync(f, 'utf8')
          .replace(/\r\n/g, '\n')
          .replace(/^\uFEFF/, '')
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

/** pin 状态判定（round-16 修订：any-pin 匹配）：
 * 1) 字节 == 本版 pin → pinned-match（常规）；
 * 2) 字节 == 任一其他版本 pin → pinned-match（升级窗口：旧宿主进程读新文件，
 *    package.json 版本与 pin 表交错更新的中间态——字节是被审计发布物，可信）；
 * 3) 本版有 pin 但字节不符任何 pin → dev-tree（本地改码/未构建/被篡改）；
 * 4) 其余（版本或 pin 表缺失且字节无匹配）→ unpinned。
 */
export function pinStateFor(pins: SelfPins | undefined, version: string | undefined, computed: string): SelfPinState {
  if (pins === undefined) return 'unpinned'
  if (version !== undefined && pins[version] === computed) return 'pinned-match'
  if (Object.values(pins).some(v => v === computed)) return 'pinned-match'
  if (version !== undefined && pins[version] !== undefined) return 'dev-tree'
  return 'unpinned'
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
