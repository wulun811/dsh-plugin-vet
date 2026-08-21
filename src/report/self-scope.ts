/**
 * vet 本体自扫的权威扫描范围（③ 工具 / ② 钉扎 / ④ 门禁共用，避免各写各的导致 pin 不一致）。
 *
 * 排除非本体顶层目录：gitignore 的构建产物 lib/（跨机构建字节可变、不可复制）、DSH 源码参考副本
 * dsh-src/、批量扫描临时目录 plugin-scan-tmp/、dist/coverage/build。这些目录不属于被审计的 vet
 * 发布物；面板对 vet 源码仓的自扫（src/scanner-bin/rules/test/scripts…）也同源。
 * 普通插件审计仍用 listSourceFiles 全量（含安装产物），不受影响。
 */
import { listSourceFiles } from '../scanner/package-sources.js'
import { relative } from 'node:path'

// 顶层目录排除：匹配 'lib/'、'dsh-src/' 等（[/] 括号形式避免转义斜杠）。注意 split('\\') 为反斜杠字符。
export const SELF_SCOPE_SKIP_RE = /^(lib|dsh-src|plugin-scan-tmp|dist|coverage|build)[/]/

/** vet 本体自扫范围：全量源文件减去非本体顶层目录。绝对路径，顺序同 listSourceFiles。 */
export function listSelfSourceFiles(root: string): string[] {
  return listSourceFiles(root).filter(f => !SELF_SCOPE_SKIP_RE.test(relative(root, f).split('\\').join('/')))
}
