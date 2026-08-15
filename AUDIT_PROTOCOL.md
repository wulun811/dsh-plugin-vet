# VET 审计协议（AUDIT_PROTOCOL）

> 本协议是 vet 插件提供的**审查流程规范**：当 DSH 中的 agent 需要审查一个新插件（或用户要求评估某插件）时，
> **按下列步骤由 agent 亲自执行**。vet 不内置审计工具、不替 agent 调查——vet 只提供客观静态判据（scan_plugin）
> 与运行时监控，审查结论由 agent 形成并落盘为健康档案。

## 适用场景

- 用户要求评估某个将要安装/已安装的 DSH 插件
- 插件市场、`dsh plugin add` 前的新插件审查
- 对可疑插件（扫描 verdict=suspicious/critical）的深入调查

## 审查步骤（agent 按序执行）

### 第 1 步：静态判据（必做，秒级）

调用 `scan_plugin`（target=package, packagePath=插件包目录），拿到：

- **verdict**：critical / suspicious / clean（静态层权威判定）
- **staticScore**：0-100
- **findings**：每条静态发现（规则号、severity、message、文件、行号）

> verdict=critical 直接判定**拒绝安装**，跳过后续步骤，直接写档案（见第 5 步）。

### 第 2 步：读清单（必做）

用 `read`/`glob` 通读插件包：

- `package.json`：name、version、dependencies（重点看高危依赖：ssh2/shelljs/child_process 等）、peerDependencies、dsh 声明
- `cordis.patch.yml`（若有）：插件如何挂载
- 全部源码文件（lib/、src/），按行数从大到小读

### 第 3 步：逐条核实静态发现（必做）

对 scan_plugin 的每条 findings，用 `read`/`grep` 定位到具体行，判断：

- **真问题**：写出证据（文件:行 + 代码片段）
- **误报**：说明理由（如 for-of 有界遍历的 R9、客户端加载器 factory 形参 require 的 R2）

### 第 4 步：主动深挖（按插件能力面）

根据插件暴露的能力，用 `read`/`grep`/`web_search` 查证：

- **网络出站**：fetch/http 调用点、目标、超时、凭据是否随请求发出
- **文件系统**：读写路径是否受控、是否越界到敏感目录（/etc、~/.ssh、~/.dsh 凭据）
- **进程/执行**：child_process/spawn/exec 的调用面，命令拼接是否注入
- **凭据处理**：密码/密钥/token 的存储、传输、落盘（明文？权限？）
- **库的安全语义**：如 ssh2 连接是否校验 hostVerifier（缺省 auto-accept 有 MITM 风险）、依赖是否有已知 CVE（web_search 查证）

### 第 5 步：落盘健康档案（必做）

审查完成后，用系统文件写入能力（`write` 工具）把结论写到：

```
~/.dsh/vet/audits/<plugin-name>-<version>-<yyyyMMdd-HHmmss>.md
```

档案格式（Markdown）：

```markdown
# VET 健康档案：<plugin-name>@<version>

- 扫描时间: <ISO 时间>
- 静态判定: 🟢 clean / 🟠 suspicious / 🔴 critical（静态分 N/100）

## 静态发现
- [规则] severity: message（file:line）…

## agent 调查结论
- 风险: clean | low | medium | high | critical
- 建议: approve | review | reject
- 总结: <agent 的审查总结>

## 审查记录（证据）
- 逐条列出核实过的静态发现与深挖结果（文件:行 + 结论）
```

### 结论判据

| 静态 verdict | 深挖发现 | 建议 |
| --- | --- | --- |
| critical | — | **reject**（直接拒，无需深挖） |
| suspicious | 误报全部排除 | review 或 approve（附排除理由） |
| suspicious | 存在真问题 | reject 或 review（附证据） |
| clean | — | approve |
| clean | 深挖发现隐藏问题 | review 或 reject（附证据） |

## 强制机制（requireAudit）

vet 提供两层强制（config 开启 requireAudit: true 后）：

1. **加载前自动扫描**（默认开启 autoScan）：插件挂载时 vet 同步静态扫描，deny 模式拦截 critical/suspicious。
2. **审计门槛**（requireAudit，默认关）：插件加载时检查 ~/.dsh/vet/audits/ 是否有该插件档案——没有则 report 模式报警、deny 模式直接拦截（消息引用 vet-audit-protocol 要求先审查）。

> 门槛独立于包解析与扫描：档案存在与否只取决于 agent 是否按本协议审查过。
> 即使 agent 跳过协议，未审计的插件也无法加载（deny 时）——这就是"强制"的落点：不是控制 agent 的思考，而是让"未经审计"变成"不可用"。

## 边界（vet 的职责）

- vet **不做**：安装/卸载插件、阻止执行（deny 模式除外）、替 agent 下结论
- vet **做**：静态扫描给判据、运行时监控报警、档案目录约定（~/.dsh/vet/audits）
- 审查是 agent 的协议行为：过程透明、结论可追溯、档案可回看
