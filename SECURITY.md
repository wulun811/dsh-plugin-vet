# Security Policy

## 报告漏洞

vet 是 DSH 插件的信任层：扫描器判定、运行时守卫、蜜罐都直接关系用户环境安全。
发现安全漏洞请**不要公开提交 issue**，改为私下报告：

- 打开一个 GitHub Security Advisory：https://github.com/wulun811/dsh-plugin-vet/security/advisories/new
- 或给维护者发私信（GitHub 用户：wulun811）

请包含：影响版本、复现步骤、预期与实际的差异、可选的 PoC。

## 响应承诺

- 确认收到：2 个工作日内
- 严重性评估 + 修复计划：5 个工作日内
- 修复发布：视严重性，低危可并入下个版本

## 已知边界（设计使然，不属漏洞）

以下是**明确声明的非安全边界**（详见 docs/ARCHITECTURE.md 与 README）：

1. 静态扫描是「减速带 + 取证层」，不是安全边界——混淆/动态构造可绕过 AST 规则。
2. T1/T2 运行时守卫不覆盖 worker_threads 独立 realm、原生插件、process.binding。
3. T2 对 ESM 具名导入快照不覆盖。
4. /vet/status.json 无鉴权（盾牌轮询需要匿名 GET）——dsh web 绑定非回环地址时局域网可读。
5. vet 是 alarm-only：默认只报警不拦截；deny 拦截是部署者显式 opt-in。

## 依赖漏洞

- 运行时依赖极少（schemastery + typescript），请关注 npm audit。
- OSV 核对（osvCheck）只查插件 package.json 的已知漏洞，不保证覆盖全部供应链风险。