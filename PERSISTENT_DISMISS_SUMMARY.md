# 持久化忽略警报修复完成 ✅

## 问题
用户点击"忽略"后，警报只在内存中标记（session 级），DSH 重启后丢失。导致：
- N3 无主 yellow：每次对话含 PEM 格式字符串都会重新报警
- esm-guard-coverage yellow：每次 DSH 重启都会重新报警

## 解决方案
实现持久化忽略机制：用户点击"忽略"后，警报 ID 写入 `~/.dsh/vet/dismissed-alerts.json`，跨 session 生效。

## 修改内容

### 1. 新增模块：`src/guard/dismissed-alerts.ts`
- 持久化存储：`~/.dsh/vet/dismissed-alerts.json`
- API：`isPersistentlyDismissed()`、`persistentlyDismiss()`、`restorePersistentDismissal()`
- 错误处理：写入失败静默处理（不影响运行）

### 2. 修改：`src/guard/status.ts`
- `dismiss()`：同时调用 `persistentlyDismiss()`
- `restore()`：同时调用 `restorePersistentDismissal()`
- `isDismissed()`：同时检查内存 Set 和持久化存储

### 3. 修改：`src/guard/runtime-sink.ts`
- N3 密钥外泄警报记录前检查 `isPersistentlyDismissed(alertId)`
- 已忽略的警报不再重新记录

### 4. 修改：`src/guards/internal-plugin.ts`
- esm-guard-coverage 警报记录前检查 `isPersistentlyDismissed(alertId)`
- 已忽略的警报不再重新记录

## 测试结果
- ✅ 715 tests passed
- ✅ 构建成功
- ✅ 已安装到运行环境

## 提交
`37f2dbf` feat: 持久化忽略警报（0.2.1）

## 使用方式
用户在 GUI 点击"忽略"后：
1. 警报 ID 写入 `~/.dsh/vet/dismissed-alerts.json`
2. DSH 重启后，该警报不再出现
3. 用户可在 GUI "已忽略"分区查看/恢复

## 存储格式
```json
{
  "dismissed": {
    "n3-key-leak-pem::abc123": {
      "dismissedAt": 1787300000000,
      "reason": "user dismissed"
    },
    "esm-guard-coverage:@deepseek-ai/dsh-client-connection": {
      "dismissedAt": 1787300100000
    }
  }
}
```

## 注意事项
- 持久化存储写入失败时静默处理（EROFS 等只读文件系统场景）
- 测试环境无法写入 `~/.dsh/vet/` 时，代码继续正常工作（内存 Set 仍生效）
- 生产环境正常写入，跨 session 持久化生效
