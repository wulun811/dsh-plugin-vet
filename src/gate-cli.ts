#!/usr/bin/env node
/**
 * vet-gate CLI：市场扫描闸口的命令行入口。
 * 用法：vet-gate --package <path> [--mode deny] [--denyOn critical] [--timeout 30000] [--osv]
 * 
 * 退出码：
 *   0 = clean/suspicious（不阻塞安装）
 *   1 = critical + mode=deny（阻塞安装）
 *   2 = 扫描失败
 */
import { runGate } from './gate.js'
import { parseCliArgs } from './cli-args.js'

/**
 * 写出一段文本并等它真正交给内核后再退出进程。
 *
 * 为什么必须等：管道（非 TTY、非文件重定向）下 stdout/stderr 是**异步**的，紧跟着调用
 * `process.exit()` 会丢弃尚未 drain 的写队列。实测 `vet-gate --package <大包>`（client UI
 * 产物，~150KB JSON）经管道输出被截到 **65536 字节 = 恰好一个管道缓冲区**，且不是合法 JSON
 * ——`vet-gate … | jq`、CI 采集、任何程序化调用都会直接解析失败。重定向到文件时 stdout 是
 * 同步写，这个缺陷不会显形（这正是它长期潜伏的原因）。
 *
 * `stream.write(text, cb)` 的回调在数据交给内核/排空后触发，所以「等回调 → 再 exit」既保住
 * 完整输出，也保住 `process.exit` 的强制终止语义（不必担心残留 handle 让进程挂住）。
 * EPIPE（下游如 `| head` 提前关闭）按 CLI 固有习惯静默收尾，不让未捕获错误覆盖退出码。
 */
function writeThenExit(stream: NodeJS.WriteStream, text: string, code: number): Promise<never> {
  return new Promise<void>((resolve) => {
    stream.once('error', () => resolve())
    stream.write(text, () => resolve())
  }).then(() => process.exit(code))
}

async function main(): Promise<void> {
  const args = parseCliArgs(process.argv)
  
  if (args.package === undefined || typeof args.package !== 'string') {
    return writeThenExit(
      process.stderr,
      'Usage: vet-gate --package <path> [--mode deny] [--denyOn critical] [--timeout 30000] [--osv]\n',
      2,
    )
  }

  if (args.format !== undefined && args.format !== 'json') {
    // round-5 review（B-A19）：未知 format 明确报错——旧实现静默空输出（不打印 JSON、
    // 退出码照常），首屏无输出最伤排查，与 vet-diff 已知边界同族但这里是 CLI 易错面。
    return writeThenExit(process.stderr, 'vet-gate: 不支持的 --format（当前仅支持 json）\n', 2)
  }

  // round-5 review（B-A2）：--timeout 必须为正有限数——parseInt 对 'abc'/尾随垃圾返回
  // NaN（NaN ?? 默认恒为 NaN 穿透到 scan，setTimeout(NaN)=0ms 立即超时）；'0'/负值同样拒绝。
  let timeoutMs: number | undefined
  if (typeof args.timeout === 'string') {
    const parsed = Number(args.timeout)
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return writeThenExit(process.stderr, 'vet-gate: --timeout 必须是正数（毫秒）\n', 2)
    }
    timeoutMs = parsed
  }

  try {
    const result = await runGate({
      packagePath: args.package,
      mode: args.mode === 'deny' ? 'deny' : 'report',
      denyOn: args.denyOn === 'suspicious' ? 'suspicious' : 'critical',
      timeoutMs,
      osvCheck: args.osv === true,
    })
    
    // 输出 JSON 结果（大包必须等排空，见 writeThenExit），并按 blocked 决定退出码
    const json = args.format === 'json' || args.format === undefined ? JSON.stringify(result, null, 2) + '\n' : ''
    return writeThenExit(process.stdout, json, result.blocked ? 1 : 0)
  } catch (err) {
    return writeThenExit(process.stderr, `vet-gate error: ${err instanceof Error ? err.message : String(err)}\n`, 2)
  }
}

main()
