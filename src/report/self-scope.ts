/**
 * vet 本体自扫的权威扫描范围（③ 工具 / ② 钉扎 / ④ 门禁共用，避免各写各的导致 pin 不一致）。
 *
 * 排除非本体顶层目录：gitignore 的构建产物 lib/（跨机构建字节可变、不可复制）、DSH 源码参考副本
 * dsh-src/、批量扫描临时目录 plugin-scan-tmp/、dist/coverage/build。这些目录不属于被审计的 vet
 * 发布物；面板对 vet 源码仓的自扫（src/scanner-bin/rules/test/scripts…）也同源。
 * 普通插件审计仍用 listSourceFiles 全量（含安装产物），不受影响。
 */
import { listSourceFiles, listInstructionFiles } from '../scanner/package-sources.js'
import { relative } from 'node:path'

// 顶层目录排除：匹配 'lib/'、'dsh-src/' 等（[/] 括号形式避免转义斜杠）。注意 split('\\') 为反斜杠字符。
export const SELF_SCOPE_SKIP_RE = /^(lib|dsh-src|plugin-scan-tmp|dist|coverage|build)[/]/

/** vet 本体自扫范围：全量源文件 + 指令/技能文件（R18 面），减去非本体顶层目录。绝对路径，顺序同 listSourceFiles。
 * round-12 起指令文件也进自扫范围（与 R18 扫描面一致），且必须经同一 SELF_SCOPE_SKIP_RE 过滤——
 * 否则 dsh-src/ 下的 AGENTS.md/SKILL.md 样例会被工具侧自扫拾取，与钉扎集合不一致（pin 失效）。 */
export function listSelfSourceFiles(root: string): string[] {
  const inScope = (f: string): boolean => !SELF_SCOPE_SKIP_RE.test(relative(root, f).split('\\').join('/'))
  const source = listSourceFiles(root).filter(inScope)
  const instruction = listInstructionFiles(root).filter(inScope)
  return [...source, ...instruction]
}
