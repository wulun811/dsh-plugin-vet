/**
 * 路径归一化共享原语（round-5 review，B-A12）：
 * confirm-block 与 contract 此前各有一份 normPath 且语义不同——前者只替换反斜杠，
 * 后者额外折叠重复分隔符并去尾部斜杠。「/home/u/.ssh//id_rsa」这类双斜杠等价写法
 * （POSIX 系统调用层会折叠）在 confirm-block 侧不命中凭据精确清单、在 contract 侧
 * 命中——同一概念两处行为不一致，且精确判定面（N7 族 1/2 凭据拦截）存在双斜杠
 * 绕过的理论形态。统一为单源实现，两处共用。
 *
 * round-16（SEC-adjacent）：补 . / .. 点段折叠——`/home/u/.ssh/../.ssh/id_rsa` 是
 * POSIX 系统调用层的等价写法，此前不折叠导致族 2 凭据精确拦截被别名路径绕过
 * （只剩报警）。文本折叠与内核解析在「无符号链接」时一致；符号链接别名属已知
 * 残留边界（逐操作 realpath 成本不可接受，见 contract 同款注释）。
 */
import { writeFileSync, unlinkSync } from 'node:fs'
/** 反斜杠 → 斜杠、折叠重复分隔符、去尾部斜杠（保留根 '/'）、折叠 . / .. 点段。 */
export function normPath(p: string): string {
  const s = p.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/$/, '')
  return foldDotSegments(s)
}

/**
 * macOS 规范前缀折叠（0.4.2，用户反馈 fs-destroy 误报）：macOS 上 /etc、/tmp、/var 都是
 * 指向 /private/* 的符号链接，内核与 realpath 呈现的规范路径因此是 `/private/tmp/…`、
 * `/private/var/…`、`/private/etc/…`。vet 的敏感判定围绕「用户看到的路径」建模（段名 /
 * 关键词 / 系统根前缀），不折叠这一层就等于把整棵 /private 当敏感面：实测 macOS 上 DSH
 * 自身的原子写暂存清理（`/private/tmp/.x.applescript.<pid>.<uuid>.tmpdir`）与
 * workspace-changes 的私有 git index（`/private/var/folders/…/T/dsh-workspace-changes-*`）
 * 每次都被 `private` 关键词命中 → 无主 red fs-destroy 刷屏。
 *
 * 只剥开头的 `/private/` 一段（`/private` 本体保留——它是真实目录，映射到 `/` 会让
 * 「删除 /private」与「删除根」等价）。必须在点段折叠**之后**调用：`/private/tmp/../etc/hosts`
 * 先折成 `/private/etc/hosts`，再剥成 `/etc/hosts` —— 仍是敏感路径（折叠顺序不能洗白）。
 */
export function stripMacPrivatePrefix(p: string): string {
  return p.startsWith('/private/') ? p.slice('/private'.length) : p
}

/**
 * 判定用归一化（0.4.2）：点段折叠 + macOS `/private` 前缀折叠 + macOS 大小写折叠。
 * 平台闸门只在 darwin 生效——`/private` 是 macOS 的规范前缀；Linux/Windows 上没有这层
 * 映射，那里的 `/private/...` 是普通目录，折叠过去只会制造虚假命中。
 *
 * 大小写折叠同样只在 darwin（macOS 默认卷 APFS/HFS+ 大小写不敏感）：`/ETC/hosts` 与
 * `/etc/hosts` 是同一个文件，`sensitiveRoots` 的前缀判定却区分大小写——不折叠就等于留一条
 * 「大写拼写绕过系统根 / N7 族 3」的口子（Linux 上 ext4 区分大小写，/ETC/hosts 根本写不到
 * /etc，折叠反而是虚假命中，故不折叠）。大小写的**段名/后缀/关键词**判定本来就逐段小写化，
 * 这里折叠的是整串（根前缀、平整路径比较）——不改变逐段判定的结果。
 * `platform` 参数供测试与跨平台诊断显式指定（生产调用一律取 process.platform）。
 */
export function normalizePathForJudge(p: string, platform: NodeJS.Platform = process.platform): string {
  const n = normPath(p)
  if (platform !== 'darwin') return n
  return stripMacPrivatePrefix(n).toLowerCase()
}

/** 文本级点段折叠：跳过 '.'，'..' 弹出上一段（相对路径首段 '..' 保留；绝对路径越根丢弃）。 */
function foldDotSegments(p: string): string {
  if (p === '' || p === '/') return p
  const abs = p.startsWith('/')
  const out: string[] = []
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop()
      else if (!abs) out.push('..')
      continue
    }
    out.push(seg)
  }
  if (out.length === 0) return abs ? '/' : '.'
  return (abs ? '/' : '') + out.join('/')
}

/**
 * round-16（SEC-5）：排他 tmp 落盘——writeFileSync 用 'wx'（O_EXCL|O_CREAT）拒绝
 * 已存在的路径：进程内插件可预测 `<file>.tmp.<pid>` 并预置符号链接指向受害文件
 * （如 ~/.bashrc），follow 语义下 vet 的写会盲写穿链接；wx 让这类预置直接 EEXIST
 * 失败（O_NOFOLLOW 语义的等价实现——Node 字符串 flags 不暴露 O_NOFOLLOW）。
 * EEXIST 的另两个来源：崩溃残留的 stale tmp（pid 复用时）、竞态下他人已建——
 * unlink 一次（移除的是预置物/残件本人）后重试 wx；写路径自始至终不跟随任何
 * 已存在的对象。调用方仍负责后续 rename 落位与失败降级（fail-open 纪律不变）。
 */
export function writeTmpExclusive(tmpPath: string, data: string | Buffer, mode: number): void {
  try {
    writeFileSync(tmpPath, data, { mode, flag: 'wx' })
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
    try {
      unlinkSync(tmpPath)
    } catch {
      // 预置物/残件已被他人清理或不可删（目录等）——交给重试决定成败
    }
    writeFileSync(tmpPath, data, { mode, flag: 'wx' })
  }
}