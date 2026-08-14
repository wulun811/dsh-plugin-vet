// 正例：动态插件沙箱逃逸（宿主闭包 TextEncoder 的 constructor）
const cwd = TextEncoder.constructor("return process")().cwd()
