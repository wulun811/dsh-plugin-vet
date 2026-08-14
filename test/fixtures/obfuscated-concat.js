// 模糊例：字符串拼接绕过字面量匹配（R1 静态求值 → likely）
const s = "return " + "process"
X.constructor(s)()
