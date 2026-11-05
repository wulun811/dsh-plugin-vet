/**
 * 0.5.23：本机 DSH 与本版声明范围的**当场**对照。
 *
 * 为什么需要这条测试：`dshCompat.tested` 是手工维护的（每轮复验后改），而 DSH 的升级
 * 不在 vet 的发版节奏里——0.2.2-rc.1 装上来的那一刻，vet 还在一本正经地宣布「超出已复验
 * 范围」，面板黄字是 vet 对自己的运行环境感到陌生，不是发现了问题。声明与现实之间没有任何
 * 机制强制同步，只能靠人记得。
 *
 * 这条测试把那份记忆变成红灯：本机装着的 DSH 必须落在本版 `dshCompat.tested` 内，否则
 * 跑测试就失败，提示先复验、再改 package.json。装不到 DSH 的机器（CI/离线）跳过——
 * 这是「不知道」，不是「不兼容」，不能因此变红。
 *
 * 同时守住第二条声明：`peerDependencies` 必须与 tested 同步。DSH 自己判 peer 用
 * includePrerelease（`^0.2.1-rc.2` 也接纳 0.2.2-rc.1），但 npm 安装时用严格 npm 语义，
 * 两者不同步的表现是「插件能跑，安装却报 unmet peer」。
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { satisfiesRange } from '../lib/guard/dsh-compat.js'
import { OFFICIAL_CATALOG_SEED } from '../lib/guards/official-catalog-seed.js'

/** 读本版 package.json 的声明面（tested / peers）。 */
function readManifest(): {
  tested: string
  peers: Record<string, string>
  version: string
} {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    version: string
    dshCompat?: { tested?: string }
    peerDependencies?: Record<string, string>
  }
  return {
    tested: pkg.dshCompat?.tested ?? '',
    peers: pkg.peerDependencies ?? {},
    version: pkg.version,
  }
}

/** 从包根候选读 @deepseek-ai/dsh 版本；不是该包/读不出 → ''。 */
function versionAt(dir: string): string {
  const file = join(dir, 'package.json')
  if (!existsSync(file)) return ''
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { name?: unknown; version?: unknown }
    if (parsed.name === '@deepseek-ai/dsh' && typeof parsed.version === 'string' && parsed.version !== '') {
      return parsed.version
    }
  } catch {
    // 坏 package.json：当作没找到
  }
  return ''
}

/** 沿 PATH 找 `dsh` 可执行文件，realpath 后上溯到包根。找不到 → []。 */
function rootsFromPath(): string[] {
  const out: string[] = []
  const exts = process.platform === 'win32' ? ['.CMD', '.cmd', '.EXE', '.exe', ''] : ['']
  for (const dir of (process.env.PATH ?? '').split(process.platform === 'win32' ? ';' : ':')) {
    if (dir === '') continue
    for (const ext of exts) {
      const bin = join(dir, `dsh${ext}`)
      if (!existsSync(bin)) continue
      try {
        // bin 是 `../lib/node_modules/@deepseek-ai/dsh/lib/bin.js` 这类符号链接：
        // 先解析真实路径，再上溯几级找 package.json（包内任意深度都要能命中）。
        let cursor = dirname(realpathSync(bin))
        for (let depth = 0; depth < 5; depth += 1) {
          out.push(cursor)
          cursor = dirname(cursor)
        }
      } catch {
        // 悬空链接/无权限：继续
      }
    }
  }
  return out
}

/** 解析本机装着的 @deepseek-ai/dsh 包根；找不到 → ''（跳过，不判不兼容）。 */
function detectDshRoot(): string {
  const explicit = process.env.VET_DSH_ROOT
  const candidates: string[] = []
  if (typeof explicit === 'string' && explicit !== '') candidates.push(explicit)
  // PATH 上的 dsh 才是**正在被使用**的那个安装（npm root -g 可能指向另一个 prefix）。
  candidates.push(...rootsFromPath())
  try {
    const globalRoot = execFileSync('npm', ['root', '-g'], { encoding: 'utf8', timeout: 10_000 }).trim()
    if (globalRoot !== '') candidates.push(join(globalRoot, '@deepseek-ai', 'dsh'))
  } catch {
    // npm 不可用：只剩显式/PATH/本仓库锚点
  }
  candidates.push(join(process.cwd(), 'node_modules', '@deepseek-ai', 'dsh'))
  for (const dir of candidates) {
    if (versionAt(dir) !== '') return dir
  }
  return ''
}

const manifest = readManifest()
const dshRoot = detectDshRoot()
const installed = dshRoot === '' ? '' : versionAt(dshRoot)

/** 相邻下一个 minor 的预发布版（`0.2.2-rc.1` → `0.3.0-rc.1`）：范围必须把它挡在外面。 */
function nextMinorOf(version: string): string {
  const m = /^v?(\d+)\.(\d+)\.\d+/.exec(version)
  if (m === null) return ''
  return `${Number(m[1])}.${Number(m[2]) + 1}.0-rc.1`
}

describe('本机 DSH 与 dshCompat.tested 当场对照', () => {
  it('dshCompat.tested 已声明（空范围 = 永不提示，等于没有兼容层）', () => {
    expect(manifest.tested).not.toBe('')
  })

  it.skipIf(installed === '')(
    `本机安装的 DSH（${installed || '未找到'}）落在本版已复验范围内`,
    () => {
      // 失败信息要能直接照做：范围是声明，不是事实；升级 DSH 后先在它上面跑绿全量测试，
      // 再把新版本的 rc 闸门追加进 dshCompat.tested 与 peerDependencies。
      expect(
        satisfiesRange(installed, manifest.tested),
        `本机 DSH ${installed} 不在 ${manifest.version} 的 dshCompat.tested（${manifest.tested}）内：`
        + '先在这个版本上跑一遍全量测试复验，再更新 package.json 的 dshCompat.tested 与 peerDependencies',
      ).toBe(true)
    },
  )

  it.skipIf(installed === '')('范围是上界而不是“向后一直兼容”：下一个 minor 不自动入选', () => {
    const next = nextMinorOf(installed)
    expect(next).not.toBe('')
    // `^0.2.2-rc.1` 覆盖 0.2.2-rc.* 与 0.2.2，不跨到 0.3.0——rc 闸门的语义正是如此。
    expect(satisfiesRange(next, manifest.tested)).toBe(false)
  })

  it.skipIf(installed === '')('peerDependencies 与 tested 同步（否则安装告警与运行判定打架）', () => {
    // DSH 侧判 peer 用 includePrerelease，npm 侧用严格语义；这里按严格语义查——
    // 它才是 `npm install` 打 unmet peer 的那个判定。
    for (const name of ['@deepseek-ai/dsh-llm', '@deepseek-ai/dsh-session', '@deepseek-ai/dsh-tools']) {
      const range = manifest.peers[name]
      expect(range, `peerDependencies 缺 ${name}`).toBeTypeOf('string')
      expect(
        satisfiesRange(installed, range ?? ''),
        `${name} 的 peer 范围（${range}）不接纳本机 DSH ${installed}：安装时会报 unmet peer`,
      ).toBe(true)
    }
  })
})

/**
 * 0.5.23：官方目录种子与本机 DSH 家族的当场对照。
 *
 * 这是 0.2.2-rc.1 升级当天实测到的那张黄牌（`official-not-in-catalog:
 * @deepseek-ai/dsh-tool-executor-ptc`）：官方拆了新包，vet 的种子还是上一版的，
 * 于是「官方新包」被当成「疑似冒充」。种子是随发行物走的静态名单，只能靠重生成同步——
 * 同样是没有机制就会腐烂的声明。
 */
describe('官方目录种子覆盖本机 DSH 家族', () => {
  it.skipIf(dshRoot === '')('家族里每个 @deepseek-ai/* 包名都在种子里', () => {
    const family = join(dshRoot, 'node_modules', '@deepseek-ai')
    expect(existsSync(family), `找不到本机 DSH 家族目录：${family}`).toBe(true)
    const seeded = new Set(OFFICIAL_CATALOG_SEED)
    const missing: string[] = []
    for (const entry of readdirSync(family)) {
      let name: unknown
      try {
        name = (JSON.parse(readFileSync(join(family, entry, 'package.json'), 'utf8')) as { name?: unknown }).name
      } catch {
        continue // 非包目录
      }
      if (typeof name === 'string' && name.startsWith('@deepseek-ai/') && !seeded.has(name)) {
        missing.push(name)
      }
    }
    expect(
      missing,
      '种子缺这些随 DSH 发行的官方包名（重跑 node scripts/gen-official-catalog-seed.mjs）：'
      + missing.join(', '),
    ).toEqual([])
  })
})
