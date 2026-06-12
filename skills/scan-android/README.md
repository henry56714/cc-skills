# scan-android

面向**任意 Android 仓库**的增量式代码扫描器。覆盖三个**通用**维度——**安全 / 稳定性 / 性能**。规则按「技术存在与否」自动适用：用到某项技术（数据库、长连接、AIDL、周期调度…）才扫，没用到的 APK 自动跳过。支持多次运行累计覆盖面，产出结构化 finding 与人类可读报告。

skill 不内置任何特定项目的模块名 / flavor / 路径：这些由 `detect_project.py` 从仓库自身（`settings.gradle`、目录结构）自动探测，可选地被仓库根下的 `.scan/config.json` 覆盖。因此同一份 skill 可装在任意路径、扫描任意工程，零配置即可工作。

本文件只讲**怎么用**和**怎么看结果**。规则细节、schema、去重算法、项目配置见同目录下的 `SKILL.md` 与 `CONVENTIONS.md`。

---

## 环境要求

| 组件 | 说明 | 安装方式 |
|---|---|---|
| Python 3.8+ | 脚本运行时 | 系统自带或 brew/conda |
| Java 11+ | Detekt / PMD / Joern / FlowDroid | `brew install openjdk@21` |
| semgrep | P1 广度扫描（含社区 registry 包） | **自动安装到** `~/.scan-android/venv/` |
| Detekt JAR | P1 Kotlin 专项 | **自动下载**（~64 MB） |
| PMD | P1 Java 专项（errorprone/多线程/性能） | **自动下载**（~40 MB） |
| Joern | P2 跨文件 CPG | **自动下载**（~2 GB） |

**首次扫描时引擎自动安装，无需手动操作。** semgrep 安装在专属虚拟环境 `~/.scan-android/venv/` 中，与系统 Python / conda 完全隔离。

**strict 模式（唯一模式，无降级）：** 第 0 步 preflight 会校验所有必需引擎，缺失则自动安装；装不上即**中断报错**，不会降级跑半套。若某引擎（如无 Gradle wrapper 的库工程的 Lint、或不想等 ~2 GB 的 Joern）不需要，在 `.scan/config.json` 的 `excluded_engines` 中关闭它——被关闭的引擎不计入中断判定。

**完整安装说明**（预热 / opt-in 引擎 / 环境变量）见 [`docs/install-engines.md`](docs/install-engines.md)。

---

## 快速开始

最简单的触发方式——直接对 Claude Code 说：

```
/scan-android
```

不带任何参数时默认扫描 `--diff HEAD~1`（最近一次提交的改动），检查集为通用三维 `security,stability,perf`。

也可以用自然语言触发：

- "扫描代码"
- "扫描 bug"
- "找出代码库中的问题"
- "对 app 模块做一次稳定性扫描"

---

## 三个通用维度

| 维度 | 重点 |
|---|---|
| **security** | 密钥硬编码、弱加密、TLS 信任任意、WebView 配置、导出组件/Provider、PendingIntent 可变性、明文传输、日志泄露、SQL/命令注入、IPC 调用方校验、Manifest 配置（debuggable/allowBackup）、Intent 重定向、receiver 导出标志、不安全反序列化/动态加载、敏感数据外部存储 |
| **stability** | 资源泄漏、生命周期泄漏、register/unregister 对称性、空 catch、NPE 路径、并发正确性、WakeLock、已弃用 API、Room 迁移、长连接重连、AIDL 兼容、崩溃处理器、周期任务回压、外部输入解析、前台服务启动时序/类型（Android 12/14）、非线程安全格式化器、ConcurrentModification、LiveData owner |
| **perf** | 主线程 I/O / DB / 网络、onDraw 分配、热路径反射、循环内拼接、Bitmap OOM、无界缓存、IPC 载荷、批量 DB 写未包事务、onReceive 重活 ANR |

这三者对所有 Android 工程通用,即全部检查集。**没有业务 / 定制维度**——凡是某项技术（数据库、长连接、AIDL、周期调度…）相关的规则都是**模式自门控**的:只在用到该技术的工程命中,没用到的 APK 不会产生候选。「用了就扫、没用就跳」是模式锚定架构的天然行为,无需配置或能力探测。

---

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--diff [REF]` | `HEAD~1` | 扫描自 REF 以来变更的文件。未指定作用域时的默认值。 |
| `--full` | 关 | 扫描整个仓库。开销大，需显式声明。 |
| `--module=X` | — | 限定模块。模块名由 `detect_project.py` 自动探测；给错会提示可用模块。 |
| `--files=GLOB` | — | 限定 glob，例如 `**/db/**`。 |
| `--checks=A,B,...` | `security,stability,perf` | 通用三项的子集。 |

作用域参数可组合，例如：

```
/scan-android --module=app --checks=security,perf
/scan-android --files=core/**/*.java --checks=stability
/scan-android --full --checks=security,stability,perf   # 需要确认
```

> 若仓库不是 git 仓库，`--diff` 会中止。请改用 `--module`、`--files` 或 `--full`。

---

## 运行流程

一次扫描按固定流程执行（主工作流定义在 `SKILL.md`）：

1. 探测工程（`detect_project.py`）：模块、flavor、lint 任务、排除集、项目背景
2. 解析作用域（`git diff` / 模块 / glob / full）
3. 先跑 L0 静态工具：探测出的 `lint*` 任务（无网络或 framework JAR 缺失时自动跳过）
4. 引擎编排（`run_engines.py`）：运行各可用引擎 adapter（Semgrep 社区包+本地、Detekt、PMD、Lint、Joern），输出归一化候选
5. AI 检测支线：派发 `agents/hunter.md` 按 `rules/ai/hunting.md` 在业务代码里狩猎深层逻辑 bug，候选并入池（可在 `excluded_engines` 加 `"ai"` 关闭）
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
- `modules` / `default_checks` —— 覆盖自动探测。

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
- 加 Joern 跨文件查询：在 `queries/joern/` 写 CPGQL。
- 规则调优：持续假阳性时更新对应来源（`queries/` 或 `rules/ai/`），不要静默禁用。
