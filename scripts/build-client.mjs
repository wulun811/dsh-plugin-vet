// vet 浏览器半区构建：esbuild 打包 src/client → lib/client.js（react 内联，单文件）。
// 产物供 dsh client-modules 以 /plugins/<id>.js 提供服务（dsh.client 声明 + exports["./client"]）。
import { build } from 'esbuild'

await build({
  entryPoints: ['src/client/index.ts'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  jsx: 'automatic',
  target: 'es2022',
  outfile: 'lib/client.js',
  legalComments: 'none',
})
console.log('client bundle → lib/client.js')
