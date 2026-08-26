// 正例：破坏性写入敏感路径（R11 high）
fs.writeFileSync('/etc/hosts', '0.0.0.0 evil.example')