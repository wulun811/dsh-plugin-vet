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
  
  try {
    const result = await runGate({
      packagePath: args.package,
      mode: args.mode === 'deny' ? 'deny' : 'report',
      denyOn: args.denyOn === 'suspicious' ? 'suspicious' : 'critical',
      timeoutMs: typeof args.timeout === 'string' ? parseInt(args.timeout, 10) : undefined,
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
