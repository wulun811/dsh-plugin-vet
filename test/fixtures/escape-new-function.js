// 正例：动态执行原语——new Function 含逃逸串（R2 critical）
const f = new Function('return process.env')