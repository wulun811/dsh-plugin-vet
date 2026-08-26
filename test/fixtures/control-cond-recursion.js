// 负例：有条件递归（合法算法形态，无 R9 观测）
function fib(n) { return n < 2 ? n : fib(n - 1) + fib(n - 2) }