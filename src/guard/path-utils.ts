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