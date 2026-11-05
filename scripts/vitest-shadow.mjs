#!/usr/bin/env node
/**
 * 跨平台入口：`VET_DOMAIN_SHADOW_STRICT=1 vitest run` 这种 env 前缀写法在 Windows cmd
 * 里不成立（npm script 会直接报 "不是内部或外部命令"）。用 Node 设环境变量再拉起
 * vitest 的可执行入口，Linux/macOS/Windows 同一行为。
 */
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const res = spawnSync(
  process.execPath,
  [join(ROOT, 'node_modules', 'vitest', 'vitest.mjs'), 'run', ...process.argv.slice(2)],
  { cwd: ROOT, stdio: 'inherit', env: { ...process.env, VET_DOMAIN_SHADOW_STRICT: '1' } },
)
process.exit(res.status ?? 1)
