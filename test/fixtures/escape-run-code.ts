// 正例：run_code（宿主域 AsyncFunction），process 直接可达
return process.getBuiltinModule('child_process').spawnSync('ls').stdout.toString()
