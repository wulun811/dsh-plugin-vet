// vet 浏览器半区构建：esbuild 打包 src/client → lib/client.js（react 内联，单文件）。
// 产物供 dsh client-modules 以 /plugins/<id>.js 提供服务（dsh.client 声明 + exports["./client"]）。
import { build } from 'esbuild'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const PKG = JSON.parse(
  readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
)

const loadBanner = (
  'window.__ModuleLoader__.load({\n' +
  `\tid: ${JSON.stringify(PKG.name)},\n` +
  '\tfactory: (require) => {\n' +
  '\t\tvar module = { exports: {} };\n' +
  '\t\tvar exports = module.exports;\n'
)

await build({
  entryPoints: ['src/client/index.ts'],
  bundle: true,
  // dsh client-modules 约定：bundle 必须以 window.__ModuleLoader__.load({ id, factory }) 注册。
  // cjs 产物无顶层 import/export，可整体嵌入 factory 闭包；react 等外部依赖由 __ModuleLoader__ 的 require 解析（与官方 tsdown preset 同构）。
  format: 'cjs',
  platform: 'browser',
  jsx: 'automatic',
  target: 'es2022',
  outfile: 'lib/client.js',
  legalComments: 'none',
  charset: 'utf8',
  external: ['react', 'react/jsx-runtime', 'react-dom'],
  define: { __VET_VERSION__: JSON.stringify(PKG.version) },
  banner: { js: loadBanner },
  footer: { js: '\n\t\treturn module.exports;\n\t}\n});\n' },
})
console.log('client bundle → lib/client.js')

// client 声明（手写：esbuild 产物不产出 d.ts，tsc 对 client 走 noEmit）
// 与 src/client/index.ts 的导出（inject / apply）保持同步。
await writeFileSync(
  fileURLToPath(new URL('../lib/client.d.ts', import.meta.url)),
  `/** vet 浏览器半区（GUI 盾牌）类型声明：esbuild 打包产物不产出 d.ts，此文件与 src/client/index.ts 手动同步。 */\n` +
    `export declare const inject: string[]\n` +
    `export declare function apply(ctx: {\n` +
    `  slots: {\n` +
    `    inject(name: string, register: () => unknown): unknown\n` +
    `    register(spec: { name: string; id: string; order?: number; locale?: string; inject?: Record<string, unknown> }, component: (props: Record<string, unknown>) => unknown): unknown\n` +
    `  }\n` +
    `  locale?: { register(ns: string, dicts: { zh: Record<string, string>; en: Record<string, string> }): unknown }\n` +
    `  effect?: (fn: () => unknown, label?: string) => unknown\n` +
    `}): void\n`,
  'utf8',
)
console.log('client types → lib/client.d.ts')
