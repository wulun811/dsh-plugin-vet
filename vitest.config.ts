import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules/**', 'dsh-src/**', 'lib/**'],
    environment: 'node',
    testTimeout: 30000,
  },
})
