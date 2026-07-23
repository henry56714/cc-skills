# scan-android

面向**任意 Android 仓库**的增量式代码扫描器。覆盖三个**通用**维度——**安全 / 稳定性 / 性能**。规则按「技术存在与否」自动适用：用到某项技术（数据库、长连接、AIDL、周期调度…）才扫，没用到的 APK 自动跳过。支持多次运行累计覆盖面，产出结构化 finding 与人类可读报告。

skill 不内置任何特定项目的模块名 / flavor / 路径：这些由 `detect_project.py` 从仓库自身（`settings.gradle`、目录结构）自动探测，可选地被仓库根下的 `.scan/config.json` 覆盖。因此同一份 skill 可装在任意路径、扫描任意工程，零配置即可工作。

本文件只讲**怎么用**和**怎么看结果**。规则细节、schema、去重算法、项目配置见同目录下的 `SKILL.md` 与 `CONVENTIONS.md`。

---

## 环境要求

| 组件 | 说明 | 安装方式 |
|---|---|---|
| Python 3.8+ | 脚本运行时 | 系统自带或 brew/conda |
| Java 11+ | Detekt / PMD / Lint / FlowDroid | `brew install openjdk@21` |
| semgrep | P1 广度扫描（含社区 registry 包，含 taint 模式） | **自动安装到** `~/.scan-android/venv/` |
| Detekt JAR | P1 Kotlin 专项 | **自动下载**（~64 MB） |
| PMD | P1 Java 专项（errorprone/多线程/性能） | **自动下载**（~40 MB） |
| tree-sitter | **默认**精确导航后端 + hunter 的 RepoMap（独立 venv） | **自动安装**（pip，非阻塞） |

**首次扫描时引擎自动安装，无需手动操作。** semgrep 安装在专属虚拟环境 `~/.scan-android/venv/` 中，与系统 Python / conda 完全隔离；tree-sitter 精确层装在独立的 `~/.scan-android/repomap-venv/`（比照 semgrep 隔离）。

**strict 模式（唯一模式，无降级）：** 第 0 步 preflight 会校验所有必需引擎，缺失则自动安装；装不上即**中断报错**，不会降级跑半套。若某引擎（如无 Gradle wrapper 的库工程的 Lint）不需要，在 `.scan/config.json` 的 `excluded_engines` 中关闭它——被关闭的引擎不计入中断判定。（tree-sitter 精确层**非阻塞**：装不出只是回退纯标准库 source-nav。）

**跨文件导航后端——默认 tree-sitter（唯一精确层），source-nav 纯标准库兜底：** hunter 的 RepoMap（跨文件代码地图）与 verifier 的调用/类型取证都由 tree-sitter 引擎（`repo_map.py`）提供，导航门面 `nav_tools.py` 的后端由 `.scan/config.json` 的 `nav_backend`（默认 `auto`）选择：
- **tree-sitter（默认，唯一精确层）** 解析 Java/Kotlin，**AST 精确**识别 def/ref（不误命中注释/字符串、enclosing 精确、**自备 kotlin-tags 故 Kotlin 无盲区**）。**这是 source-nav 产不出的 RepoMap 能力的来源**（签名骨架 + PageRank + 跨文件关系）。同名重载不消歧，由 verifier 逐跳 Read 复核（基准实测导航精度与 source-nav 持平，采纳理由是 RepoMap）。装在独立 venv。
- **source-nav（纯标准库兜底）** 仅当 tree-sitter venv 装不出时回退，正则名义级、召回完整、**不需要任何编译**。

任何精确后端不可用都自动回退 source-nav（结果导向：能跑出导航结果优先于精确但零产出）。**选后端用基准 `nav_benchmark.py`（`benchmarks/*.json` 人工核验真值）跑数字，不凭口碑。**

**完整安装说明**（预热 / opt-in 引擎 / 环境变量）见 [`docs/install-engines.md`](docs/install-engines.md)。

---

## 快速开始

最简单的触发方式——直接对 Claude Code 说：

```
/scan-android
```

不带任何参数时默认扫描 `--diff HEAD~1`（最近一次提交的改动），每次跑全部规则（无维度/子集开关）。

也可以用自然语言触发：

- "扫描代码"
- "扫描 bug"
- "找出代码库中的问题"
- "对 app 模块做一次扫描"

---

## 检查覆盖

**一次扫描跑全部规则——不再按维度分、没有 `--checks` 子集。** 两类来源:

- **工具引擎(广度,规则来自社区库/引擎自带):** Semgrep(社区 registry 包 + `queries/semgrep/` 本地补充,含 taint 模式)、Detekt(Kotlin)、PMD(errorprone/多线程/性能)、Android Lint。随上游更新,本 skill 不维护单行规则。验证阶段用 `nav_tools.py` 取证跨文件调用/类型关系（唯一精确层 tree-sitter，AST 精确；source-nav 纯标准库兜底，不可用时告警回退）。
- **AI 支线(深度,`rules/ai/hunting.md`):** 鉴权绕过、跨文件越权数据流、并发竞态、生命周期错配、非幂等重试、缓存一致性、资源/WakeLock 释放、主线程阻塞、算法劣化等规则编不出的逻辑缺陷。

仍会发现安全/稳定性/性能类问题,但这只是覆盖范围的描述,不再是可选择的扫描维度。**没有业务/定制维度**——涉及某项技术(数据库、长连接、AIDL…)的规则都是**模式自门控**:用到才命中,没用到自动跳过。

---

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--diff [REF]` | `HEAD~1` | 扫描自 REF 以来变更的文件。未指定作用域时的默认值。 |
| `--full` | 关 | 扫描整个仓库。开销大，需显式声明。 |
| `--module=X` | — | 限定模块。模块名由 `detect_project.py` 自动探测；给错会提示可用模块。 |
| `--files=GLOB` | — | 限定 glob，例如 `**/db/**`。 |

作用域参数可组合，例如：

```
/scan-android --module=app
/scan-android --files=core/**/*.java
/scan-android --full   # 需要确认
```

> 若仓库不是 git 仓库，`--diff` 会中止。请改用 `--module`、`--files` 或 `--full`。

---

## 运行流程

一次扫描按固定流程执行（主工作流定义在 `SKILL.md`）：

1. 探测工程（`detect_project.py`）：模块、flavor、lint 任务、排除集、项目背景
2. 解析作用域（`git diff` / 模块 / glob / full）
3. 先跑 L0 静态工具：探测出的 `lint*` 任务（无网络或 framework JAR 缺失时自动跳过）
4. 引擎编排（`run_engines.py`）：运行各可用引擎 adapter（Semgrep 社区包+本地、Detekt、PMD、Lint），输出归一化候选
5. AI 检测支线：`build_hunt_batches.py` 把业务文件**确定性分批**（风险排序 + 文件覆盖率断言 + 技术存在标记 + 每批期望视角），`repo_map.py` 为每批生成 **tree-sitter 聚焦代码地图**（签名骨架 + 跨文件调用关系），逐批派发 `agents/hunter.md` 拿地图**顺藤摸瓜**、按 `rules/ai/hunting.md` **多视角自门控**狩猎深层逻辑 bug（无 WebView 自动跳过 WebView 视角等）；hunter 回执实际覆盖的视角，`check_hunt_coverage.py` **事后断言每批该过的视角都过了**（漏视角即报错重跑）。候选并入池（可在 `excluded_engines` 加 `"ai"` 关闭）
6. 独立验证（`agents/verifier.md` 子代理）：读源码逐个取证，confirmed 必附证据；注入项目背景 + `rules/ai/hunting.md` 的 FP 提示
7. 本次内去重后原子覆盖写 `.scan/findings.json`
8. 重新生成 `.scan/reports/findings.md`
9. 在对话中给出一段简要小结

---

## 项目配置（可选）

零配置即可扫描任意工程。若某仓库需要微调，在其根目录放一份 `.scan/config.json`（全部字段可选）：

```json
{
  "extra_excludes": ["vendor/**", "third_party/**"],
  "lint_tasks": ["lintPaidDebug", "lint"],
  "project_context": "长期运行的后台监控服务，进程级单例常驻属预期。"
}
```

- `extra_excludes` —— 追加项目级排除 glob（vendored 目录等）。
- `lint_tasks` —— 覆盖 L0 lint 任务建议（按序尝试，取首个成功）。
- `project_context` —— 注入 verifier，帮助 LLM 区分项目语境下可接受的写法（如故意常驻的单例、后台线程的同步 I/O）。
- `modules` —— 覆盖自动探测的模块列表。

字段说明见 `CONVENTIONS.md §项目配置`。

---

## 查看结果

所有结果位于被扫描仓库根目录下的 `.scan/`：

```
.scan/
  config.json         # 可选的项目配置
  findings.json       # 本次确认的 finding（每次覆盖）— 机器可读
  reports/
    findings.md       # 人类可读的报告（每次运行重新生成）
```

### 推荐阅读入口：`reports/findings.md`

按严重度分区展示：**Critical → Major → Minor → Info**，每条包含：

- 规则 id + category
- 一行标题 + `file:line`
- **Why**：为什么是 bug
- 代码证据
- **Repro**：复现步骤
- **Suggestion**：修复方向

同一严重度内按 `category` → `file` → `line` 排序。报告头记录本次用的引擎；**不含 commit/时间**（v3 无状态、无 ledger）。

### 需要原始数据：`findings.json`

机器可读，字段参见 `CONVENTIONS.md § findings.json schema`。关键字段：

- `id` — `sha1(file:line:category)`，用于本次内去重
- `status` — 恒为 `open`（v3 无状态，不跟踪 fixed/wontfix）
- `severity` ∈ `critical | major | minor | info`
- `dataflow_path` / `poc_result` — 可选（验证候选带有时透传）

---

## 人工维护

v3 起扫描**无状态**：`findings.json` 每次扫描覆盖写，手动编辑不会跨扫描保留——不要依赖编辑它来标记 `wontfix` / `false-positive`。

若某条规则持续产生误报，请更新 `rules/{category}.md`（或 `queries/semgrep/`、`rules/ai/`）中对应条目的 Verify / FP notes，**不要**直接禁用规则。

---

## 常见问题

**Q: 第一次跑提示 "Not a git repository" 怎么办？**
A: 仓库未初始化为 git 时 `--diff` 不可用。改用模块或 glob 作用域：

```
/scan-android --module=app
/scan-android --files=core/**/*.{java,kt}
```

**Q: `--module=X` 提示模块不存在？**
A: 模块名取自 `detect_project.py` 对 `settings.gradle` 的解析。运行它可看到可用模块列表；探测不准时可在 `.scan/config.json` 用 `modules` 覆盖。

**Q: 我只想看本次的问题小结。**
A: 每次运行末尾 Claude 会给出一段小结：本次按严重度分的数量、指向 `.scan/reports/findings.md` 的路径。

**Q: L0 静态工具（lint）没跑是为什么？**
A: 常见原因：无网络、缺 framework JAR、`gradle.properties` 的 `org.gradle.java.home` 指向当前主机不存在的 JDK 路径。Claude 会在末尾小结里提一句跳过原因。扫描会退回到引擎/模式扫描，功能不受影响但召回会下降。

**Q: 扫描扫了很久，能中途停掉吗？**
A: 可以安全重跑。v3 无状态——`findings.json` 原子覆盖写不会半写；中断后重跑直接得到本次最新结果（不依赖任何历史）。

**Q: 数据库 / 网络 / AIDL 这些规则会不会在没用到的 App 上误报？**
A: 不会。这些规则用对应技术的代码特征作锚点（`@Database`、`connectionLost`、`.Stub` 等），没用到该技术的 APK 根本不会命中——「用了就扫、没用就跳」是模式锚定的天然行为,无需任何开关。

---

## 扩展

- 加广度规则：优先调引擎包——加 Semgrep registry 包（`semgrep_registry_packs`）或在 `queries/semgrep/` 写少量项目特定规则；Detekt/PMD/Lint 规则自带。本 skill 不再维护单行检测规则。
- 加深度/逻辑狩猎线索：在 `rules/ai/hunting.md` 追加条目（自然语言，`R-AI-*` id）——AI 支线扩容方式。
- 调用/类型导航：用 `scripts/nav_tools.py` 查 `callers`/`definition`/`hierarchy`/`trace-origin`，后端自动选择（唯一精确层 tree-sitter `repo_map.py`，source-nav 纯标准库兜底）。hunter 的 RepoMap 由 `repo_map.py --action map` 产出。
- 规则调优：持续假阳性时更新对应来源（`queries/` 或 `rules/ai/`），不要静默禁用。
