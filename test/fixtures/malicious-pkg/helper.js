// 正例：同包装载的逃逸 helper（构造器链，R1）
module.exports = TextEncoder.constructor("return process")().cwd()