/**
 * vet-gate CLI 参数解析（round-22 从 gate-cli.ts 拆出成为可测纯函数）：
 * 支持 `--key value` 与 `--key=value` 两种形态。
 * round-22 修复：旧实现只认 `--key value`——`--mode=deny` 会被解析成键
 * 「mode=deny」的布尔开关，args.mode 恒 undefined，CI/脚本最常用的
 * `--mode=deny` 静默回落到 report 模式（deny 门禁失效且无任何报错）。
 */
export function parseCliArgs(argv: readonly string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (!arg.startsWith('--')) continue
    const eq = arg.indexOf('=')
    if (eq >= 0) {
      // --key=value 形态（eq 只在 '=' 前存在；key 不可能是空串，否则不成 --key）
      const key = arg.slice(2, eq)
      if (key !== '') args[key] = arg.slice(eq + 1)
      continue
    }
    const key = arg.slice(2)
    if (key === '') continue // 裸 '--'：无意义，忽略
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) {
      args[key] = true
    } else {
      args[key] = next
      i++
    }
  }
  return args
}