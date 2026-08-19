// vet 宿主半区发布 bundle：把 src（guard/guards/tools/audit/skills/scanner client/config/index）
// 打进单个 lib/index.bundle.js（esm）。内部模块状态（setRootIndexing/withVetSelfIo/confirmBlock/
// canaryStore/capabilityDiff 等模块级单例）全部封闭在 bundle 闭包内、不导出——即使恶意插件用
// 绝对路径 require 发布包，也拿不到这些状态（C1，0.1.16 加固）。
// 逐文件 lib/** 仍由 build:src 产出，仅供本地测试（tests 直接 import lib/guard/*.js）。
// 发布物（package.json files）只含 lib/index.bundle.js + lib/{gate,gate-cli,client,client.d.ts,
// scanner,scanner-bin,types}——guard 内部模块不进发布包。
import { build } from 'esbuild'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const PKG = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'))

await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  outfile: 'lib/index.bundle.js',
  charset: 'utf8',
  sourcemap: false,
  legalComments: 'none',
  banner: { js: '/* @jieai/dsh-plugin-vet host bundle (0.1.16 C1) — internal guard state is closure-private by design */' },
  // 运行时由宿主解析的平台/peer 依赖（不内联，保持与逐文件形态相同的解析语义）
  external: [
    '@deepseek-ai/cordis',
    '@deepseek-ai/dsh-tools',
    '@deepseek-ai/schemastery',
    '@deepseek-ai/dsh-invariants',
    '@deepseek-ai/dsh-session',
    '@deepseek-ai/dsh-llm',
  ],
  define: { __VET_VERSION__: JSON.stringify(PKG.version) },
})
console.log('host bundle → lib/index.bundle.js')
