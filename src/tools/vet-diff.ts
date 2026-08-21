/**
 * vet_diff：N6 版本行为差分审计工具（只读本地能力清单历史）。
 * 输入一个插件包名，输出该包在本地记录过的全部版本 + 最近两版的行为差分
 * （新增/移除的网络主机、敏感路径、子进程、依赖、网络/执行能力）。
 * 只报"能力变了"，不报"代码变了"；完全本地，不触发扫描、不联网。
 */
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { history, type VersionDiffHistory } from '../guard/version-diff.js'

export interface VetDiffArgs {
  package: string
}

/** 文本渲染：人类可读的行为 changelog。 */
function renderDiff(value: VersionDiffHistory): string {
  const lines: string[] = ['vet diff ' + value.package]
  if (value.records.length > 0) {
    lines.push('  历史版本: ' + value.records.map(r => r.version).join(' → '))
  }
  if (value.diff !== null) {
    lines.push('  行为差分 ' + value.diff.from + ' → ' + value.diff.to + ':')
    const added: string[] = []
    for (const h of value.diff.added.hosts) added.push('+ 网络主机 ' + h)
    for (const f of value.diff.added.fsPaths) added.push('+ 敏感路径 ' + f)
    for (const s of value.diff.added.spawnCmds) added.push('+ 子进程 ' + s)
    for (const i of value.diff.added.imports) added.push('+ 新依赖 ' + i + '（能力未知）')
    for (const i of value.diff.added.ghostDeps) added.push('+ 幽灵依赖 ' + i + '（未声明）')
    for (const i of value.diff.added.zombieDeps) added.push('+ 僵尸依赖 ' + i + '（声明但未安装）')
    if (value.diff.added.hasNetwork) added.push('+ 网络能力')
    if (value.diff.added.hasExec) added.push('+ 执行能力')
    const removed: string[] = []
    for (const h of value.diff.removed.hosts) removed.push('- 网络主机 ' + h)
    for (const f of value.diff.removed.fsPaths) removed.push('- 敏感路径 ' + f)
    for (const s of value.diff.removed.spawnCmds) removed.push('- 子进程 ' + s)
    for (const i of value.diff.removed.imports) removed.push('- 依赖 ' + i)
    for (const i of value.diff.removed.ghostDeps) removed.push('- 幽灵依赖 ' + i)
    for (const i of value.diff.removed.zombieDeps) removed.push('- 僵尸依赖 ' + i)
    if (value.diff.removed.hasNetwork) removed.push('- 网络能力')
    if (value.diff.removed.hasExec) removed.push('- 执行能力')
    if (added.length > 0) lines.push(...added)
    else lines.push('  （无新增能力）')
    if (removed.length > 0) lines.push('  移除能力（不报警，仅供审计）:', ...removed)
  }
  if (value.note !== null) lines.push('  ' + value.note)
  return lines.join('\n')
}

/** vet_diff 工具：读本地能力清单历史，输出某包的版本间行为差分。 */
export function createVetDiffTool(): ReturnType<typeof defineTool> {
  return defineTool({
    name: 'vet_diff',
    description:
      'Show the stored capability history and the behavior diff between the last two recorded versions of a plugin package (N6 upgrade behavioral diff). Read-only, purely local, no scanning or network. 输出某包本地记录过的版本历史与最近两版的行为差分（只报能力变化，不报代码变化）。',
    parameters: {
      package: {
        type: 'string',
        required: true,
        description: '插件包名（如 @scope/name），读取本地能力清单历史并输出其版本间行为差分',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          package: { type: 'string', required: true },
          records: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          latest: { type: 'string' },
          prior: { type: 'string' },
          diff: { type: 'object', additionalProperties: true },
          note: { type: 'string' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderDiff(value as unknown as VersionDiffHistory) }],
    },
    async execute(args) {
      const pkg = String(args.package ?? '')
      if (pkg === '') throw new Error('vet: vet_diff 需要 package 参数')
      const h = history(pkg)
      return {
        package: h.package,
        records: h.records.map(r => ({ version: r.version, recordedAt: r.recordedAt })),
        ...(h.latest !== null ? { latest: h.latest } : {}),
        ...(h.prior !== null ? { prior: h.prior } : {}),
        ...(h.diff !== null ? { diff: h.diff as unknown as Record<string, JsonValue> } : {}),
        ...(h.note !== null ? { note: h.note } : {}),
      }
    },
    presentCall: (args) => ({
      card: 'generic' as const,
      title: 'vet diff: ' + String(args.package ?? ''),
      kind: 'read' as const,
      rawInput: String(args.package ?? ''),
    }),
  })
}
