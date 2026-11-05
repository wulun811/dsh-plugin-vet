/**
 * 从观测推出六个面的生效姿态（施工图 §5.3 的输入侧）。
 *
 * 判定本身在 `domain/posture.ts`（纯格运算）；这里只回答「四个输入各是什么」。
 * 分开的理由：输入是环境相关的（配置 + 心跳 + 目录可读），判定是要被 96 格穷举验证的。
 * 混在一起，测试就得造一整个配置对象才能验一格。
 */
import { FS_MODULES, NET_MODULES, SPAWN_MODULES } from './coverage.js'
import { postureEntry, type PostureEntry, type PostureInput } from '../domain/posture.js'

export interface PostureObservations {
  readonly autoScan: boolean
  readonly requireAudit: boolean
  readonly runtimeGuard: string
  readonly confirmBlock: string
  /** 钩子心跳的逐项结果（`hookHeartbeat().checks`）。 */
  readonly hookChecks: ReadonlyArray<{ module: string; op: string; intact: boolean }>
  /** 审计档案目录当前是否可读——`requireAudit` 打开但它不可读，等于没人能被审。 */
  readonly archiveDirReadable: boolean
  /** 最近一次扫描是否成功；`undefined` = 还没有扫过（不知道，不当成失败）。 */
  readonly lastScanOk: boolean | undefined
}

/** 某个模块集合的装配与健康：注册了没有、注册的还在不在。 */
function hooksFor(modules: ReadonlySet<string>, checks: PostureObservations['hookChecks']): { installed: boolean; healthy: boolean } {
  const relevant = checks.filter((c) => modules.has(c.module))
  return { installed: relevant.length > 0, healthy: relevant.length > 0 && relevant.every((c) => c.intact) }
}

const input = (desired: boolean, supported: boolean, installed: boolean | null, healthy: boolean | null): PostureInput => ({
  desired,
  supported,
  installed,
  healthy,
})

export function derivePosture(obs: PostureObservations): PostureEntry[] {
  const guardOn = obs.runtimeGuard !== 'off'
  const fs = hooksFor(FS_MODULES, obs.hookChecks)
  const net = hooksFor(NET_MODULES, obs.hookChecks)
  const spawn = hooksFor(SPAWN_MODULES, obs.hookChecks)
  return [
    // 加载前扫描：只要守卫在跑就装上了；健康度只能由「最近一次扫描成没成」回答，
    // 还没扫过就是不知道（null），不是「健康」。
    postureEntry('preload_scan', input(obs.autoScan, true, true, obs.lastScanOk ?? null)),
    // 审计闸门：装没装上等于档案目录读不读得到；读不到时 deny 会把所有第三方拒之门外，
    // 那是故障而不是保护，必须显示成 gap。
    postureEntry('audit_gate', input(obs.requireAudit, true, obs.archiveDirReadable, obs.archiveDirReadable)),
    postureEntry('runtime_fs', input(guardOn, true, fs.installed, fs.healthy)),
    postureEntry('runtime_net', input(guardOn, true, net.installed, net.healthy)),
    postureEntry('runtime_spawn', input(guardOn, true, spawn.installed, spawn.healthy)),
    // N7 确认拦截：拦截点就在 fs 包装里，守卫关着时它根本没有落点——此时「想要」是空话。
    // 所以 desired 里带上 guardOn：守卫关 → off（不是 gap）；守卫开但 fs 钩子没挂上 → degraded。
    postureEntry('confirm_block', input(obs.confirmBlock === 'block' && guardOn, true, fs.installed, fs.healthy)),
  ]
}
