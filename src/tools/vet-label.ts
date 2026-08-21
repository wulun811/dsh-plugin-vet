
/**
 * vet_label：M2 能力营养标签（Capability Nutrition Label）工具——插件作者/用户自证清白、展示能力面的
 * 人类可读"营养标签"：访问哪些文件 / 连哪些域名 / 起哪些子进程 / 依赖哪些包（能力未知） / 是否具备
 * 网络与执行能力 / ESM 具名导入盲区标注 / 升级差分摘要。
 * 数据源 = N6 的能力清单历史（~/.dsh/vet/capabilities.json，只读本地）。完全离线，不触发扫描、不联网。
 * 注意（诚实边界）：dormant/观测能力在进程内存的 capability-diff 观测集里，独立进程的 CLI 读不到——
 * 本工具给出的是**声明能力**（静态清单）营养标签；运行时观测能力由运行中的盾牌/告警体现。
 */
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { label, type CapabilityLabel, isSensitiveFsPath } from '../guard/version-diff.js'

export interface VetLabelArgs {
  package: string
}

/** 文本渲染：人类可读的营养标签。 */
function renderLabel(value: CapabilityLabel): string {
  const lines: string[] = ['vet label ' + value.package]
  if (!value.present) {
    lines.push('  ' + (value.note ?? '无记录'))
    return lines.join('\n')
  }
  if (value.latest !== null && value.latest !== undefined) lines.push('  版本: ' + value.latest)
  const m = value.manifest
  // 四轮审查加固（与三轮 DSH.SO bug 同族，渲染层数据健壮性）：loadCapabilities 对单条记录
  // 零结构校验——残缺存储（手改/半写/旧版升级遗留）可让 manifest 经 execute 键省略 + JSON 往返
  // 变成 undefined（`=== null` 判断穿透后在 m.hasNetwork 崩溃），或缺数组字段（m.hosts.length 崩）。
  if (m === null || m === undefined) {
    if (value.note !== null && value.note !== undefined) lines.push('  ' + value.note)
    return lines.join('\n')
  }
  const flags: string[] = []
  if (m.hasNetwork) flags.push('网络')
  if (m.hasExec) flags.push('执行')
  if (m.esmNamedBuiltins === true) flags.push('⚠️ ESM 具名导入盲区')
  lines.push('  能力: ' + (flags.length > 0 ? flags.join(' / ') : '（无网络/执行声明）'))

  const hosts = Array.isArray(m.hosts) ? m.hosts : []
  const fsPaths = Array.isArray(m.fsPaths) ? m.fsPaths : []
  const spawnCmds = Array.isArray(m.spawnCmds) ? m.spawnCmds : []
  const imports = Array.isArray(m.imports) ? m.imports : []
  if (hosts.length > 0) lines.push('  网络主机:', ...hosts.map(h => '    · ' + h))
  if (fsPaths.length > 0) {
    lines.push('  敏感路径:')
    for (const fp of fsPaths) lines.push('    · ' + fp + (isSensitiveFsPath(fp) ? '' : '（常规）'))
  }
  if (spawnCmds.length > 0) lines.push('  子进程:', ...spawnCmds.map(s => '    · ' + s))
  if (imports.length > 0) lines.push('  依赖（能力未知，保守视作任意能力）:', ...imports.map(i => '    · ' + i))
  if (m.ghostDeps !== undefined && m.ghostDeps.length > 0) {
    lines.push('  ⚠️ 幽灵依赖（代码引用但 package.json 未声明，靠传递依赖提升侥幸可解析）:')
    for (const d of m.ghostDeps) lines.push('    · ' + d)
  }
  if (m.zombieDeps !== undefined && m.zombieDeps.length > 0) {
    lines.push('  ⚠️ 僵尸依赖（package.json 声明但 node_modules 缺失，运行到即失败）:')
    for (const d of m.zombieDeps) lines.push('    · ' + d)
  }
  if (hosts.length === 0 && fsPaths.length === 0 && spawnCmds.length === 0 && imports.length === 0) {
    lines.push('  （无静态敏感足迹）')
  }
  // 三轮审查修复（DSH.SO 反馈 bug）：execute 对 null 字段整键省略，JSON 往返后这里是 undefined
  // 而非 null——单条版本记录时上一版代码 `!== null` 判断穿透，读 .from 抛 TypeError 导致渲染失败。
  const ds: { from?: unknown; to?: unknown; added?: string[] } | null | undefined = value.diffSummary
  if (ds !== null && ds !== undefined && ds.from !== ds.to) {
    const added0 = Array.isArray(ds.added) ? ds.added : []
    lines.push('  最近升级 ' + String(ds.from) + ' → ' + String(ds.to) + ':')
    lines.push('    ' + (added0.length > 0 ? '新增 ' + added0.join('；') : '无新增能力'))
  }
  if (value.note !== null && value.note !== undefined) lines.push('  ' + value.note)
  return lines.join('\n')
}

/** vet_label 工具：读本地能力清单，输出某包的可读"营养标签"。 */
export function createVetLabelTool(): ReturnType<typeof defineTool> {
  return defineTool({
    name: 'vet_label',
    description:
      'Show a human-readable "capability nutrition label" for a plugin package (M2): which files it touches, which hosts it connects to, which subprocesses it spawns, which third-party deps it imports (capability unknown), and its network/exec capability flags. Sources from the local N6 capability history. Read-only, purely local, no scanning or network. 输出某包的能力营养标签（声明侧静态清单），供插件作者自证与用户审查。',
    parameters: {
      package: {
        type: 'string',
        required: true,
        description: '插件包名（如 @scope/name），读取本地能力清单并输出其营养标签',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          package: { type: 'string', required: true },
          present: { type: 'boolean', required: true },
          records: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          latest: { type: 'string' },
          manifest: { type: 'object', additionalProperties: true },
          diffSummary: { type: 'object', additionalProperties: true },
          note: { type: 'string' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: renderLabel(value as unknown as CapabilityLabel) }],
    },
    async execute(args) {
      const pkg = String(args.package ?? '')
      if (pkg === '') throw new Error('vet: vet_label 需要 package 参数')
      const v = label(pkg)
      return {
        package: v.package,
        present: v.present,
        records: v.records.map(r => ({ version: r.version, recordedAt: r.recordedAt })),
        ...(v.latest !== null ? { latest: v.latest } : {}),
        ...(v.manifest !== null ? { manifest: v.manifest as unknown as Record<string, JsonValue> } : {}),
        ...(v.diffSummary !== null ? { diffSummary: v.diffSummary as unknown as Record<string, JsonValue> } : {}),
        ...(v.note !== null ? { note: v.note } : {}),
      }
    },
    presentCall: (args) => ({
      card: 'generic' as const,
      title: 'vet label: ' + String(args.package ?? ''),
      kind: 'read' as const,
      rawInput: String(args.package ?? ''),
    }),
  })
}