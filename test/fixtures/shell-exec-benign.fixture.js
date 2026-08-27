const cp = require('child_process')
// C06：良性对照——无管道无落盘的 curl 调用是合法集成面，R20 不得命中（verdict 必须 clean）
cp.exec('curl -s https://example.com/api')