# 变异语料击杀率 QA（mutant-score）

muteval 方法论（对 LLM eval 套件做变异测试的 QA 法）在 vet 上的落地：**被测系统 = 插件本体**，
逃逸形态做成 mutants，重跑静态引擎统计击杀率；存活者命名缺失检测，良性对照防误杀。
vet 的静态引擎是确定性规则引擎、无 LLM 参与——同一输入永远同一输出，比 LLM eval 套件更适合
变异测试，且击杀率是可重跑、可追踪的数字。

## 核心机制

- **语料权威登记表**：`test/mutants.manifest.json`——恶意 mutants（`layer: static`）+ 良性 controls。
  **manifest 即基线**：击杀判据写在每条目里，门禁每次全量重算，不存在"基线漂移"概念。
- **评测入口**：`lib/scanner-bin/engine.js` 的 `scan`——与 `test/plugins-matrix.test.ts` 同一入口，
  保证击杀率与对抗矩阵测的是同一把尺。
- **击杀判据（恶意 mutant）**：任一 `expect.rules` 命中即击杀。**用规则命中而非 verdict**——
  多数 R 规则 severity 不升级 verdict（R19 恒 info、间接 require 形态 medium），
  以 verdict 为判据会漏报"被规则识别但未升级"的击杀。
- **良性 controls**：实际 verdict 必须 `clean`，否则计 retained（precision 反项）。
- **runtime 面**：仅运行时层（T2）在拦的逃逸形态（双重编码 URL 出站、telemetry 定时外传、
  200 级"形态正常语义越界"fetch 等）标 `layer: runtime`，静态 gate 跳过并单列——它们是
  known-coverage-gap 的地图，不属于静态击杀率的漏报。

## 命令

```bash
npm run mutant-score        # 报告模式：score card + reports/mutant-score.json（产物已 gitignore）
npm run check:mutants       # 门禁模式：任一存活 / 任一误杀 / 任一评测失败 → exit 1
```

`prepublishOnly` 已接入 `check:mutants` 作为第 4 道发布门禁（build → pack-integrity → check:self → mutants）。

## 门禁纪律（防刷分三要素）

1. **基线全绿**：良性 controls 0 误杀（precision 不允许退）。
2. **应杀集合全杀**：击杀率按 manifest 的**每条目应杀规则**逐条校验，不是全局均值——
   塞好杀的 mutants 不能注水。
3. **存活者必须有处置**：新增待杀形态先登记再补规则；若有 mutant 暂时存活，禁止
   静默删除条目——必须补规则击杀，或显式移出 manifest 并在提交说明记录理由。

## 如何新增一个逃逸形态

1. 写语料文件到 `test/fixtures/`。**命名纪律**：files 模式评测的单文件恶意语料必须以
   `.fixture.js` 结尾（如 `exfil-discord-webhook.fixture.js`）——self-scan 的 devFixtures 豁免
   按 `DEV_FIXTURE_RE`（`.test/.spec/.e2e/.fixture/.sample` 结尾）识别夹具，违规命名的
   high/critical 语料会被 check:self 拦下（round-6 实测：R11/R13 语料曾因命名被正确拦截，
   门禁行为符合预期，是语料命名违规）。code 模式评测的不需要（finding 不带 file 属性，
   走 token 声明判定）。目录形态（package.json/AGENTS.md/cordis.patch.yml）不可改名
   （规则按真实文件名识别），其 info 档 finding 天然不进 decisive。
2. `test/mutants.manifest.json` 加条目：`id`（M+两位序号）、逃逸面、评测参数（`kind` files|code、
   language、runtime）、`expect.rules`（实证后的命中规则——先用报告模式跑一次确认）。
3. `npm run mutant-score` 看击杀；未击杀 → 补规则或处置（见上）。
4. 良性新形态进 `controls`，断言 verdict=clean。

## 已知覆盖边界（round-6 复核后收窄）

- **runtime 面真实缺口只有两个**：「运行时构造的出站目标」（目标来自 env/网络响应/计算结果，
  静态无字面量可扫）与「200 级语义越界」（请求合法但携带的数据敏感——exfil-ledger 读发关联面）。
  两者已有 T2 测试守着（n3-exfil-ledger / loopback-observe / network-egress 共 60+ 用例），
  只是**不进静态 score card**——缺的是量化归并，不是检测能力。未来挂载方案：e2e-local.mjs /
  smoke-sidecar.mjs 扩展成 runtime mutant harness，在真实守卫环境执行 mutant 并断言 T2 报警。
  **暂不实施**：运行时评测面成本高（spawn 宿主+守卫装载+时序断言）、易碎，而检测与测试已存在，
  边际价值低。
- **曾误列为缺口的「双重编码 URL」经实证移出**：百分号编码混淆的 webhook 字面量直接被 R13
  字符串匹配命中（编码段不破坏 `discord.com/api/webhooks` 子串），base64 全端点编码由
  R13+R15 解码链命中——静态面已覆盖，无需 runtime 评测。
- **有意不进语料库的规则面**：
  - R8 大文件——资源阈值面而非对抗逃逸形态，已有 r8-bigfile.test.ts 覆盖；
  - R12 bundle 契约——结构校验（name/apply/Config/inject）非恶意检测，不适合 mutant 框架；
  - LLM 深潜层（audit 协议）不可重跑、不进语料库——裁决键永远是静态 verdict + 确定性
    结构契约，深潜只做定性健康档案（架构纪律，见 docs/ARCHITECTURE.md）。

## 当前状态

- 22 恶意 mutants，击杀率 100%，覆盖 **13 个规则面**：R1 构造器链×4、R2 动态执行×5
  （eval/new Function/vm/间接 require/charCode 组合）、R3 process 直访、R5 未声明服务挂载、
  R6 组合证据混淆、R7 硬编码凭据、R9 资源面×2（fork 炸弹/ReDoS）、R10 postinstall 供应链钩子、
  R11 破坏性路径×2、R13 外联 sink×2（Discord webhook/云元数据）、R17 patch yml !!js 注入、
  R18 AGENTS.md 指令注入、R19 全角 typosquat；
- 5 良性 controls 0 误杀：干净工具插件、参数遮蔽 process、独立 charCode 编码、异步常驻服务、
  有条件递归——其中 4 只恶意 mutant 是「verdict clean 但规则命中」，反向验证击杀判据
  必须用规则而非 verdict；
- M20 语料（G-1 注入仿真）曾在代理会话中被实时加载并触发真实注入尝试——文件已加显式
  语料标注（不影响 R18 命中），这本身就是指令面威胁真实性的现场实证；
- 语料集体检：`test/mutant-score.test.ts` 每轮 vitest 全量跑 gate + 幽灵条目检查。