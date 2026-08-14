import { basename } from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { scan } from '../scanner/client.js'
import { listSourceFiles } from '../scanner/package-sources.js'
import type { ScanRequest } from '../scanner/protocol.js'
import type { PluginScorecard } from '../report/types.js'
import { renderScorecard } from '../report/render.js'

interface ScanPluginArgs {
  target: 'dynamic-code' | 'package' | 'file'
  source?: string
  packagePath?: string
  reason?: string
}

function buildRequest(args: ScanPluginArgs): { request: ScanRequest; pluginName: string } {
  if (args.target === 'dynamic-code') {
    if (typeof args.source !== 'string') throw new Error('vet: dynamic-code 需要 source')
    return {
      pluginName: 'dynamic-code',
      request: { kind: 'code', language: 'js', runtime: 'host', code: args.source },
    }
  }
  if (args.target === 'file') {
    if (typeof args.source !== 'string') throw new Error('vet: file 需要 source')
    return { pluginName: basename(args.source), request: { kind: 'files', files: [args.source] } }
  }
  if (args.target === 'package') {
    if (typeof args.packagePath !== 'string') throw new Error('vet: package 需要 packagePath')
    const files = listSourceFiles(args.packagePath)
    if (files.length === 0) throw new Error(`vet: ${args.packagePath} 下没有可扫描的源码`)
    return { pluginName: basename(args.packagePath), request: { kind: 'files', files } }
  }
  throw new Error(`vet: 未知 target ${String(args.target)}`)
}

/** scan_plugin：确定性静态扫描工具（verdict 只来自静态层，LLM 不参与）。 */
export function createScanPluginTool() {
  return defineTool({
    name: 'scan_plugin',
    description: 'Static-scan plugin code or an installed package for escape patterns (constructor-chain, direct process access), dynamic execution, hardcoded secrets. Deterministic rule engine in an isolated process; returns a scorecard with verdict (critical/suspicious/clean) and staticScore. 静态层为确定性判定，LLM 不参与。',
    parameters: {
      target: {
        // 实现决策：dsh-tools 类型不支持 enum（ValueSchemaSpec 无 enum 字段），选项写入 description
        type: 'string', required: true,
        description: '扫描目标类型：dynamic-code（源码字符串）| package（插件包目录）| file（单文件路径）',
      },
      source: { type: 'string', description: 'dynamic-code 的源码字符串 / file 的文件路径' },
      packagePath: { type: 'string', description: 'package 的插件包目录（绝对路径）' },
      reason: { type: 'string', description: '扫描原因（审计留痕）' },
    },
    output: {
      // schema 内联以保留字面量推断（repo 约定，tool-skill 同款）
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          pluginName: { type: 'string', required: true },
          pluginVersion: { type: 'string' },
          scannedAt: { type: 'string', required: true },
          static: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              verdict: { type: 'string', required: true },
              staticScore: { type: 'number', required: true },
              findings: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
            },
          },
          llm: { type: 'object', additionalProperties: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderScorecard(value as unknown as PluginScorecard) }],
    },
    async execute(args) {
      const { request, pluginName } = buildRequest(args as unknown as ScanPluginArgs)
      const response = await scan(request, { timeoutMs: 60_000 })
      if (!response.ok || response.report === undefined) {
        throw new Error(`vet: 扫描失败 ${response.error ?? 'unknown'}`)
      }
      return {
        pluginName,
        scannedAt: new Date().toISOString(),
        static: {
          verdict: response.report.verdict,
          staticScore: response.report.staticScore,
          // 输出 schema 推断的 findings 项为开放对象，静态 Finding[] 断言为 JSON 值形状
          findings: response.report.findings as unknown as Record<string, JsonValue>[],
        },
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Scan plugin: ${args.target}`, kind: 'read', rawInput: args.target }),
  })
}
