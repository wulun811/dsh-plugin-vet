/**
 * macOS（darwin）系统信息共享纯工具（round-20 抽出）：T1 哨兵（runtime-watch.ts）与
 * 宿主指标面板（metrics.ts）都要数 lsof fd——此前该函数住在 runtime-watch.ts，但面板若
 * import runtime-watch 会把哨兵进程入口分发（argv 判定）一起拖进宿主模块图，故抽独立模块，
 * 单一定义防漂移。runtime-watch.ts 保留再导出以兼容既有测试/消费者。
 */

/** 解析 `lsof -w -Fn` 输出（纯函数）：每条 `f<fd>` 记录一个打开文件描述符；`p<pid>` 是进程头，忽略。 */
export function countDarwinLsofFd(out: string): number {
  let n = 0
  for (const line of out.split('\n')) {
    if (line.startsWith('f')) n++
  }
  return n
}
