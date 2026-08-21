/**
 * T2 进程内钩子（D22）：在宿主进程内包装 fs / child_process 内置模块导出。
 * 危险操作 → 取栈 → 归因插件包名 → 报警；N7（0.1.14 起）确认破坏类操作
 * （fs 族 1/2，confirmBlock 默认 block）在调用原函数前抛错拦截（fail-open：异常→放行）。
 * 已知旁路（PLAN §14.5 / README）：ESM 具名导入快照、worker_threads 独立 realm、
 * 原生插件、process.binding。
 *
 * P0-4 结构债拆分：实现按「操作表 / 降噪 / 归类 / 归因 / 计数 / 心跳 / 网络 / 包装」拆至
 * runtime-* 子模块，本文件仅作公共 API 再导出桶（外部 import 路径与符号不变）。
 */

export type { HookModule } from './runtime-ops.js'
export type { HookConfig } from './runtime-ops.js'
export { DEFAULT_HOOK_CONFIG } from './runtime-ops.js'
export type { HookAlarm, HookOp } from './runtime-ops.js'

export { chunkBytes, attachWriteCounter, attachCanaryScanner, attachReadCounter } from './runtime-count.js'

export { brandVetHook, isVetHook, registerHookTarget, resetHookRegistry, hookHeartbeat } from './runtime-heartbeat.js'
export type { HookHeartbeatResult } from './runtime-heartbeat.js'

export {
  setRootIndexing, isRootIndexing, isVetSelfIo, withVetSelfIo, isStackTraceTampered,
  isLockSiblingPath, isTransientTempPath, isSensitivePath, isSessionLogFile,
  isIntegrityPath, isHoneypotPath,
} from './runtime-denoise.js'

export { classifyOp } from './runtime-classify.js'
export { pluginFromStack, isOfficial } from './runtime-attrib.js'
export { isTrackedNetHost, extractNetworkTarget, classifyNetworkOp } from './runtime-net.js'
export { patchModule, patchNetworkModule } from './runtime-patch.js'
