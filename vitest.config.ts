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
        'lib/index.bundle.js',        // C1（0.1.16）：宿主发布 bundle——单文件内联全部 src，测试面是逐文件 lib（同 src 编译，bundle 冒烟见 test/bundle.test.ts）
        'lib/index.js',               // 装配入口：apply 冒烟覆盖，行级意义小
        'lib/guard/runtime-watch.js', // 哨兵子进程：真实 /proc 集成场景（sidecarMain 不跑）
        // lib/guard/metrics.js 原在此排除（"难稳定 mock"）——round-20 起 deps 注入 + darwin
        // 异步缓存使其可全 mock（见 test/metrics-darwin.test.ts），移回统计。
        'lib/report/types.js', 'lib/scanner/protocol.js', 'lib/scanner-bin/index.js',
        'lib/skills/index.js',        // client 入口壳
      ],
      reporter: ['text', 'text-summary'],
      thresholds: {
        // round-18 棘轮：70/50 距实测（89.13/93.84/89.13/84.41）脱节 ~19pp，形同不设防——
        // 抬到留 ~4pp 余量的 85/80；下限只升不降，跌穿即红。
        lines: 85,
        functions: 85,
        statements: 85,
        branches: 80,
      },
    },
  },
})
