import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules/**', 'dsh-src/**', 'lib/**'],
    environment: 'node',
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      // 统计 lib/ 编译产物（vitest 实际执行对象，tsc 从 src 直接编译、行号一一对应）。
      // 不统计 src//scanner-bin/ TS 源——它们只是 lib 的编译输入，v8 看不到执行会误报 0%。
      include: ['lib/**/*.js'],
      exclude: [
        'lib/client.js',              // 浏览器组件：node 环境不渲染，靠 typecheck + 人工验证
        'lib/index.js',               // 装配入口：apply 冒烟覆盖，行级意义小
        'lib/guard/runtime-watch.js', // 哨兵子进程：真实 /proc 集成场景（sidecarMain 不跑）
        'lib/guard/metrics.js',       // 宿主 /proc 读取：依赖真实系统，难稳定 mock
        'lib/report/types.js', 'lib/scanner/protocol.js', 'lib/scanner-bin/index.js',
        'lib/skills/index.js',        // client 入口壳
      ],
      reporter: ['text', 'text-summary'],
      thresholds: {
        lines: 70,
        functions: 70,
        statements: 70,
        branches: 50,
      },
    },
  },
})
