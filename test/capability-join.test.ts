import { describe, expect, it } from 'vitest'
import { extractCapabilities } from '../lib/scanner-bin/capability.js'
import { parseSource } from '../lib/scanner-bin/ast.js'

const sf = (code: string) => parseSource(code, 'input.js', 'js')

describe('round-15 path.join path collection（拼接路径静态盲区修复）', () => {
  it('path.join(os.homedir(), ".ssh", "id_rsa") → fsPaths 含 .ssh 与 id_rsa（动态前缀不阻塞）', () => {
    const m = extractCapabilities(sf(`const path = require('path'); path.join(os.homedir(), '.ssh', 'id_rsa')`))
    expect(m.fsPaths).toContain('.ssh')
    expect(m.fsPaths).toContain('id_rsa')
  })

  it('全字面量 join 合成整路径：path.join(".ssh", "id_rsa") → ".ssh/id_rsa"', () => {
    const m = extractCapabilities(sf(`const path = require('path'); path.join('.ssh', 'id_rsa')`))
    expect(m.fsPaths).toContain('.ssh/id_rsa')
  })

  it('ESM 具名绑定 join(...) → 合成；posix 归一 "./" 折叠', () => {
    const m = extractCapabilities(sf(`import { join } from 'node:path'; join('.', '.ssh', 'id_rsa')`))
    expect(m.fsPaths).toContain('.ssh/id_rsa')
    expect(m.fsPaths).toContain('id_rsa')
  })

  it('path.resolve("~/.aws", "credentials") → "~/.aws/credentials"', () => {
    const m = extractCapabilities(sf(`import * as path from 'node:path'; path.resolve('~/.aws', 'credentials')`))
    expect(m.fsPaths).toContain('~/.aws/credentials')
  })

  it('动态实参 → 不猜测：path.join(root, "data.json") 不收合成路径', () => {
    const m = extractCapabilities(sf(`const path = require('path'); const root = getRoot(); path.join(root, 'data.json')`))
    expect(m.fsPaths).not.toContain('data.json')
  })

  it('非敏感字面量拼合：path.join("a", "b") 不收 "a/b"（round-16：合成结果同样过 looksLikePath——' +
    '通用字符串拼接不再污染 fsPaths，与动态前缀漏收相反方向的误收已修）', () => {
    const m = extractCapabilities(sf(`const path = require('path'); path.join('a', 'b')`))
    expect(m.fsPaths).not.toContain('a/b')
  })

  it('require("path").join(...) 直接形态 → 合成', () => {
    const m = extractCapabilities(sf(`require('path').join('.ssh', 'id_rsa')`))
    expect(m.fsPaths).toContain('.ssh/id_rsa')
  })
})