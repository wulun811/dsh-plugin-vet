// 正例：node:vm 跨界执行（R2 high）
import vm from 'node:vm'
vm.runInContext('x', sandbox)