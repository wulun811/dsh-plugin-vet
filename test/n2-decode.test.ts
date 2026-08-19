import type { CallExpression, Node, SourceFile } from "typescript"
import * as ts from "typescript"

function findCall(s: SourceFile, name: string): CallExpression {
  let found: CallExpression | undefined
  const walk = (n: Node): void => {
    if (found !== undefined) return
    if (ts.isCallExpression(n)) {
      const callee = n.expression
      if (ts.isIdentifier(callee) && callee.text === name) { found = n; return }
      if (ts.isPropertyAccessExpression(callee) && name === "Buffer" && callee.name.text === "from") { found = n; return }
      if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === name) { found = n; return }
    }
    ts.forEachChild(n, walk)
  }
  walk(s)
  if (found === undefined) throw new Error("call not found: " + name)
  return found
}

import { describe, expect, it } from "vitest"
import { scan } from "../lib/scanner-bin/engine.js"
import { tryDecodeLiteral, collectDecodedLiterals } from "../lib/scanner-bin/decode.js"
import { parseSource } from "../lib/scanner-bin/ast.js"
import type { ScanRequest } from "../lib/scanner-bin/protocol.js"

const sf = (code: string) => parseSource(code, "input.js", "js")
const codeReq = (code: string): ScanRequest => ({ kind: "code", language: "js", runtime: "host", code })

const findingOf = (report: { findings: { rule: string }[] }, rule: string) => report.findings.filter(f => f.rule === rule)

describe("tryDecodeLiteral（解码器单元）", () => {
  it("atob base64 → 明文（method=base64）", () => {
    const s = sf(`const u = atob("aHR0cHM6Ly9ldmlsLmNvbS94")`)
    // 找 atob 调用节点
    const call = findCall(s, "atob")
    const d = tryDecodeLiteral(call, s)
    expect(d).toBeDefined()
    expect(d!.method).toBe("base64")
    expect(d!.text).toBe("https://evil.com/x")
  })

  it("Buffer.from hex → 明文", () => {
    const s = sf(`const h = Buffer.from("2f6574632f706173737764", "hex")`)
    const call = findCall(s, "Buffer")
    const d = tryDecodeLiteral(call, s)
    expect(d).toBeDefined()
    expect(d!.method).toBe("hex")
    expect(d!.text).toBe("/etc/passwd")
  })

  it("Buffer.from base64 → 明文", () => {
    const s = sf(`const b = Buffer.from("c2stc2VjcmV0MTIzNDU2", "base64")`)
    const call = findCall(s, "Buffer")
    const d = tryDecodeLiteral(call, s)
    expect(d).toBeDefined()
    expect(d!.method).toBe("base64")
    expect(d!.text).toBe("sk-secret123456")
  })

  it("String.fromCharCode → 明文", () => {
    const s = sf(`const c = String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109)`)
    const call = findCall(s, "String")
    const d = tryDecodeLiteral(call, s)
    expect(d).toBeDefined()
    expect(d!.method).toBe("charCode")
    expect(d!.text).toBe("https://evil.com")
  })

  it("常量拼接 → 明文（method=template）", () => {
    const s = sf(`const u = "https://" + "evil" + ".com/x"`)
    const d = collectDecodedLiterals(s)
    expect(d.some(x => x.text === "https://evil.com/x")).toBe(true)
  })

  it("动态参数 → undefined（绝不猜测）", () => {
    const s = sf(`const u = atob(userInput); const v = Buffer.from(data, "hex")`)
    const call1 = findCall(s, "atob")
    expect(tryDecodeLiteral(call1, s)).toBeUndefined()
  })

  it("非法 hex → undefined（不猜测）", () => {
    const s = sf(`const h = Buffer.from("zzzz", "hex")`)
    const call = findCall(s, "Buffer")
    expect(tryDecodeLiteral(call, s)).toBeUndefined()
  })

  it("嵌套解码 atob(atob(...)) ≤ 2 层", () => {
    // "aHR0cHM6Ly9ldmlsLmNvbS94" 的 base64 再编码
    const inner = Buffer.from("https://evil.com/x", "utf8").toString("base64")
    const outer = Buffer.from(inner, "utf8").toString("base64")
    const s = sf(`const u = atob(atob("${outer}"))`)
    const innerCall = findCall(s, "atob")
    const d = tryDecodeLiteral(innerCall, s)
    expect(d).toBeDefined()
    expect(d!.text).toBe("https://evil.com/x")
  })
})

describe("collectDecodedLiterals（全文件采集）", () => {
  it("上限与去重：同一文本只记一次", () => {
    const s = sf(`const a = atob("aHR0cHM6Ly9ldmlsLmNvbS94"); const b = atob("aHR0cHM6Ly9ldmlsLmNvbS94")`)
    const dl = collectDecodedLiterals(s)
    expect(dl.filter(d => d.text === "https://evil.com/x")).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// R13/R7/R11 解码语料命中（端到端）
// ---------------------------------------------------------------------------

describe("N2 解码语料并入规则", () => {
  it("atob 藏 Discord webhook → R13 命中（decodedFrom=base64）", () => {
    const b64 = Buffer.from("https://discord.com/api/webhooks/123", "utf8").toString("base64")
    const res = scan(codeReq(`fetch(atob("${b64}"))`))
    expect(res.ok).toBe(true)
    const r13 = findingOf(res.report!, "R13").find(f => f.decodedFrom === "base64")
    expect(r13).toBeDefined()
    expect(r13!.message).toContain("经解码还原")
    expect(r13!.confidence).toBe("likely")
  })

  it("hex 藏密钥 → R7 命中（decodedFrom=hex）", () => {
    const hex = Buffer.from("sk-superSecretValue12345", "utf8").toString("hex")
    const res = scan(codeReq(`const k = Buffer.from("${hex}", "hex").toString(); use(k)`))
    expect(res.ok).toBe(true)
    const r7 = findingOf(res.report!, "R7").find(f => f.decodedFrom === "hex")
    expect(r7).toBeDefined()
  })

  it("charCode 藏敏感路径 → R11 命中（decodedFrom=charCode）", () => {
    const codes = Array.from("/etc/passwd", ch => ch.charCodeAt(0)).join(",")
    const res = scan(codeReq(`const p = String.fromCharCode(${codes}); require("fs").readFileSync(p)`))
    expect(res.ok).toBe(true)
    const r11 = findingOf(res.report!, "R11").find(f => f.decodedFrom === "charCode")
    expect(r11).toBeDefined()
    expect(r11!.message).toContain("解码还原")
  })

  it("拼接藏 webhook → R13 命中（decodedFrom=template）", () => {
    const res = scan(codeReq(`fetch("https://" + "discord" + ".com/api/webhooks/1")`))
    expect(res.ok).toBe(true)
    expect(findingOf(res.report!, "R13").some(f => f.decodedFrom === "template")).toBe(true)
  })
})
