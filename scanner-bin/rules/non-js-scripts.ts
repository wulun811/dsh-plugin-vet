import type { Finding } from '../protocol.js'

/**
 * R14 non-js-scripts: download-and-exec primitives in shipped script files.
 *
 * vet's AST rules cover JS/TS source; packages also ship shell/PowerShell
 * scripts (.sh/.ps1/.cmd/.bat) that run at install or invocation time with
 * arbitrary execution. This rule is a deterministic text scan (regex only,
 * never executed) over those files for the classic payload-drop shapes:
 * curl|sh, wget|sh, PowerShell download-and-invoke, encoded commands and
 * system download/exec primitives. generic（官方/信任包）降级 info，与 R10
 * 的 install 钩子降级同构。
 */
const DOWNLOAD_EXEC: { re: RegExp; desc: string }[] = [
  { re: /curl[^\n|]*\|\s*(ba|z)?sh\b/, desc: 'curl|sh 远程代码执行' },
  { re: /wget[^\n|]*\|\s*(ba|z)?sh\b/, desc: 'wget|sh 远程代码执行' },
  { re: /(iwr|Invoke-WebRequest|DownloadString)[^\n]*\|/, desc: 'PowerShell 下载管道' },
  { re: /powershell[^\r\n]{0,120}-enc(odedcommand)?\b/i, desc: '编码 PowerShell（隐藏载荷）' },
  { re: /\b(IEX|Invoke-Expression)\b/, desc: 'PowerShell Invoke-Expression' },
  { re: /\b(certutil|bitsadmin|mshta|regsvr32|scrobj|rundll32)\b/, desc: '系统下载/执行原语' },
  { re: /curl[^\n]*-o\s+\S+/, desc: 'curl 下载落盘' },
]

/** Script extensions this rule scans (complementary to the AST surface). */
export const NON_JS_SCRIPT_EXT = new Set(['sh', 'bash', 'ps1', 'cmd', 'bat', 'psm1', 'zsh'])

/** 1-based line number of a byte offset in text. */
function lineOfText(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line += 1
  }
  return line
}

/**
 * R14 download-and-exec in non-JS script files. high/likely（generic → info）。
 */
export function runNonJsScript(content: string, file: string, targetKind?: 'plugin' | 'generic'): Finding[] {
  const found: Finding[] = []
  for (const p of DOWNLOAD_EXEC) {
    const re = new RegExp(p.re.source, 'g')
    const m = re.exec(content)
    if (m === null) continue
    const generic = targetKind === 'generic'
    found.push({
      rule: 'R14',
      severity: generic ? 'info' : 'high',
      confidence: 'likely',
      message: '脚本下载即执行：' + p.desc + (generic ? '（能力触达面）' : '（脚本随包分发，安装/运行期任意代码执行面）'),
      evidence: m[0].slice(0, 200),
      file,
      line: lineOfText(content, m.index),
    })
    break // 每个 pattern 每文件一条
  }
  return found
}
