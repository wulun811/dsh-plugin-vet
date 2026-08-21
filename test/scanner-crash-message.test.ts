import { describe, expect, it } from 'vitest'
import { describeScannerCrash } from '../src/scanner/client.js'

/**
 * 0.2.4 用户机回归：typescript 被误删后，扫描子进程启动即崩，用户看到的警报是
 * 「scanner invalid output: SyntaxError: Unexpected end of JSON input」——真因埋在
 * stderr 尾部。describeScannerCrash 必须把已知崩溃形态翻译成点名结论。
 */
describe('scanner 启动崩溃可读化诊断（0.2.4 用户机回归）', () => {
  const USER_STDERR = "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'typescript' imported from /x/node_modules/@jieai/dsh-plugin-vet/lib/scanner-bin/ast.js"

  it('Cannot find package → 点名缺失依赖 + 重装指引', () => {
    const diag = describeScannerCrash(USER_STDERR)
    expect(diag).toBeDefined()
    expect(diag).toContain("missing runtime dependency 'typescript'")
    expect(diag).toContain('reinstall @jieai/dsh-plugin-vet')
  })

  it("Cannot find module → 安装不完整指引", () => {
    expect(describeScannerCrash("Error: Cannot find module './engine.js'")).toContain('module resolution failed')
  })

  it('普通 stderr（真实扫描错误）不误判为启动崩溃', () => {
    expect(describeScannerCrash('some plugin threw at Rule X')).toBeUndefined()
    expect(describeScannerCrash('')).toBeUndefined()
  })
})
