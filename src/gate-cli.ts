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

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {}
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      const next = argv[i + 1]
      if (next === undefined || next.startsWith('--')) {
        args[key] = true
      } else {
        args[key] = next
        i++
      }
    }
  }
  return args
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv)
  
  if (args.package === undefined || typeof args.package !== 'string') {
    console.error('Usage: vet-gate --package <path> [--mode deny] [--denyOn critical] [--timeout 30000] [--osv]')
    process.exit(2)
  }

  if (args.format !== undefined && args.format !== 'json') {
    // round-5 review（B-A19）：未知 format 明确报错——旧实现静默空输出（不打印 JSON、
    // 退出码照常），首屏无输出最伤排查，与 vet-diff 已知边界同族但这里是 CLI 易错面。
    console.error('vet-gate: 不支持的 --format（当前仅支持 json）')
    process.exit(2)
  }

  // round-5 review（B-A2）：--timeout 必须为正有限数——parseInt 对 'abc'/尾随垃圾返回
  // NaN（NaN ?? 默认恒为 NaN 穿透到 scan，setTimeout(NaN)=0ms 立即超时）；'0'/负值同样拒绝。
  let timeoutMs: number | undefined
  if (typeof args.timeout === 'string') {
    const parsed = Number(args.timeout)
    if (!Number.isFinite(parsed) || parsed <= 0) {
      console.error('vet-gate: --timeout 必须是正数（毫秒）')
      process.exit(2)
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
    
    // 输出 JSON 结果
    if (args.format === 'json' || args.format === undefined) {
      console.log(JSON.stringify(result, null, 2))
    }
    
    // 退出码
    if (result.blocked) {
      process.exit(1)
    } else {
      process.exit(0)
    }
  } catch (err) {
    console.error('vet-gate error:', err instanceof Error ? err.message : String(err))
    process.exit(2)
  }
}

main()
