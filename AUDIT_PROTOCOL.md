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
- **findings**：每条静态发现（规则号、severity、message、文件、行号）——含 R12（Cordis/DSH bundle 契约：入口文件、bundle patch 声明、name、engines.node）

> verdict=critical 直接判定**拒绝安装**，跳过后续步骤，直接写档案（见第 5 步）。

### 第 2 步：读清单（必做）

先**定位插件包目录**（第 1 步 `packagePath` 的来源）：

- 已安装插件：`~/.dsh/profiles/<profile>/node_modules/<包名>`——用 `glob` 搜 `~/.dsh/profiles/*/node_modules/<name>/package.json`，或询问用户 profile 名
- 待安装/离线包：拿到包目录即可（npm 缓存、本地 clone）
- 定位失败时把 `scan_plugin` 的报错信息给用户，请其提供路径

再用 `read`/`glob` 通读插件包：

- `package.json`：name、version、dependencies（重点看高危依赖：ssh2/shelljs/child_process 等）、peerDependencies、exports/main 入口、dsh 声明
- `cordis.patch.yml`（若有）：插件如何挂载——条目形态、是否有 insert 嵌套、与其他 bundle 冲突面
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

### 第 4.5 步：契约与代码质量审计（必做）

> 静态扫描与安全深挖解决「**恶意**」问题；本步解决「**写得烂**」问题——**不是恶意的插件
> 也可能因为 bug 拖垮宿主**。粗判原则：静态层面可穷举的契约项由 R12 覆盖，这里由 agent
> 通读代码后逐项判断，缺陷写进档案并影响「建议」。

**Cordis/DSH 契约核对面**（与 R12 互证，能读到的更深一层）：

- 入口与声明：exports/main 指向真实存在、能导出标准插件形态（name / Config / apply(context, config)）；inject 声明的服务确实注入且使用一致
- 配置正确性：Config schema 与代码实际读取的键一一对应（读不存在的键、类型不匹配、空值未判）
- 生命周期卫生：事件监听/定时器/子进程有 dispose 路径；热重载（重新 apply）幂等，模块级状态不残留（vet 自己的二轮审查就修过这类：spawn error 未监听崩宿主、stdout 半行、报警永久滞留）

**代码质量/健壮性清单**（逐项核，有问题记 文件:行 + 说明）：

- 错误处理：未捕获的 promise（fetch/异步无 catch）、空 catch{} 吞错无日志、异常路径是否可诊断
- 同步阻塞：事件/异步回调里做 sync fs/网络/长循环——是否卡宿主事件循环
- 资源泄漏：timer/stream/listener 是否随用随清；worker/子进程是否可能成孤儿
- 异步正确性：漏 await、回调里启动异步不追结果、边界条件（空输入/超长/并发重入）
- 路径与平台：path.join 拼绝对路径、Windows 分隔符、敏感文件读写姿势
- 依赖卫生：dependencies 声明完整（无隐式依赖）、版本合理、peer 关系正确

**判定方向**：任何「能跑但会拖垮/静默失败」的缺陷 → 建议降为 **review**（即使静态 clean）；
契约项（入口缺失/声明不一致）→ 至少 review，重则 reject。

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

## 质量审计（第 4.5 步）
- 契约: 入口/inject/Config schema 核对面结论（或「通过」）
- 缺陷清单: 文件:行 + 问题描述 + 严重度
- 影响评估: 缺陷是否影响采纳（拖垮宿主/静默失败 → 至少 review）

## 审查记录（证据）
- 逐条列出核实过的静态发现与深挖结果（文件:行 + 结论）
```

### 结论判据

| 静态 verdict | 深挖发现 | 质量审计（4.5 步） | 建议 |
| --- | --- | --- | --- |
| critical | — | — | **reject**（直接拒，无需深挖） |
| suspicious | 误报全部排除 | 通过 | review 或 approve（附排除理由） |
| suspicious | 误报全部排除 | 有缺陷 | **review**（先修质量问题） |
| suspicious | 存在真问题 | — | reject 或 review（附证据） |
| clean | — | 通过 | approve |
| clean | — | 有「能跑但拖垮/静默失败」类缺陷 | **review**（静态干净≠值得装） |
| clean | 深挖发现隐藏问题 | — | review 或 reject（附证据） |

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
