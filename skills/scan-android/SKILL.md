---
name: scan-android
description: 通用 Android 代码扫描器，对任意 Android/APK 工程做单次、无状态扫描，覆盖安全、稳定性、性能等常见缺陷。每次跑全部规则（无维度/子集开关）。规则按「技术存在与否」自动适用——用到某项技术（数据库 / 长连接 / AIDL 等）才扫，没用到自动跳过。当用户要求"扫描代码""扫描 bug""找出代码库中的问题"或调用 `/scan-android` 时触发。支持参数 --diff（默认 HEAD~1）、--full、--module=NAME、--files=GLOB。
---

# scan-android

面向**任意** Android 仓库的代码扫描器。产出结构化结果 `.scan/findings.json` 以及人类可读报告 `.scan/reports/findings.md`。**每次扫描独立、无状态——只报本次确认的问题，不维护跨扫描 ledger、不比对历史**。

skill 不内置任何特定项目的模块名 / flavor / 路径——这些通过 `detect_project.py`（第 2 步）从仓库自身探测，可选地被仓库根下的 `.scan/config.json` 覆盖（见 CONVENTIONS §项目配置）。因此同一份 skill 可装在任意路径、扫描任意工程。

## 使用时机

用户表述如："扫描代码"、"scan for bugs"、"找出隐藏问题"、"run scan-android"、"对 X 模块做一次稳定性扫描"。若用户只是要求评审单个 PR 或单个 diff 的某次讨论，那是 *review* 任务，不要使用本 skill。

## 检查覆盖

**一次扫描跑全部规则——不再按维度分，也没有 `--checks` 子集。** 两类来源：

- **工具引擎（广度，规则来自社区库 / 引擎自带，随上游更新，本 skill 不维护单行规则）：** Semgrep（社区 registry 包 `p/security-audit·owasp·secrets·java·kotlin` + `queries/semgrep/` 本地补充，含 taint 模式）、Detekt（Kotlin）、PMD（errorprone / 多线程 / 性能）、Android Lint。
- **AI 支线（深度，`rules/ai/hunting.md`）：** 鉴权绕过、跨文件越权数据流、并发竞态、生命周期错配、非幂等重试、缓存一致性、资源 / WakeLock 释放、主线程阻塞、算法劣化等规则编不出的逻辑缺陷。检测阶段 hunter 拿 **tree-sitter 产出的聚焦代码地图**（跨文件调用关系）顺藤摸瓜；验证阶段用 **`nav_tools.py`** 取证跨文件调用/类型关系——**默认 tree-sitter（AST 精确，Java+Kotlin 无盲区）**，source-nav（纯标准库）为兜底、tree-sitter 不可用时自动回退。

> 仍会发现安全 / 稳定性 / 性能类问题，但这只是**覆盖范围的描述**，不再是可选择、可分批的扫描维度。

**没有业务 / 定制维度。** 凡涉及某项技术（数据库、长连接、AIDL、周期调度…）的规则都是**模式自门控**：只在用到该技术的工程里命中，没用到自动跳过——无需任何配置或能力探测。

## 参数

从用户消息中解析。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--diff [REF]` | `HEAD~1` | 作用域 = 自 REF 以来变更的文件。**未指定作用域时的默认值。** 需要仓库是 git 仓库；若不是 git 仓库，skill 中止并要求用户选择 `--module`、`--files` 或 `--full`。 |
| `--full` | off | 作用域 = 整个仓库。开销大，必须用户显式启用。 |
| `--module=X` | — | 限定到模块 `X/`。模块名由 `detect_project.py` 自动探测（见第 2 步）；若用户给的模块不在探测列表中，提示可用模块。 |
| `--files=GLOB` | — | 限定到 glob（相对仓库根）。 |

作用域参数可组合：`--module=app --files=**/db/**` ⇒ 匹配该 glob 的 `app/` 下文件。

若用户请求不含 `--full`、`--module` 或 `--files`，默认使用 `--diff HEAD~1`。若用户要求全量扫描但未指定模块，先确认再执行——全仓扫描开销很大。

## 工作流（按顺序执行）

> **执行环境——两个独立的根，别混淆：**
>
> - **`<SKILL_DIR>`** = 本 skill 的安装目录（即本 SKILL.md 与 `scripts/`、`rules/`、`agents/`、`CONVENTIONS.md` 所在目录）。**它可以在任意路径**——可能是 `<repo>/.claude/skills/scan-android/`，也可能在仓库之外被符号链接进来。你在加载本 skill 时已经知道该绝对路径：**下文所有 `<SKILL_DIR>/...` 都替换成这个实际路径**（不要写死成 `.claude/skills/...`；shell 环境变量在 Bash 调用间不保留，所以每条命令都直接内联实际路径，而不是 `export` 一次）。
> - **仓库根** = 被扫描工程的根目录 = 你执行命令时的 **cwd**。脚本的 `--repo-root` 默认 `.`、产物 `.scan/...` 都相对这里。所以**在被扫描仓库的根目录执行命令**。
>
> 脚本自身的 `rules/` 通过 `__file__` 自动定位（无需 `--rules-dir`），因此无论 `<SKILL_DIR>` 在哪、cwd 是哪都能找到规则。

### 第 0 步 — 预检（Preflight）

**这是所有步骤中最先执行的一步。任何扫描工作开始前必须先通过预检。**

> **⛔ 执行约束（必须遵守，无例外）**
>
> - `preflight.py` **必须同步（前台）运行**，绝不使用 `run_in_background`。
>   原因：预检负责安装依赖并输出 `ready` JSON——后台运行会使后续步骤在结果未知时擅自推进，与"预检通过才能扫描"的保证完全矛盾。
> - 必须等到 preflight **stdout 输出完整 JSON**（含 `ready` 字段）后，才能进入第 1 步。
> - 若预检因依赖下载耗时过长导致超时，**不得绕过**，应告知用户当前正在安装哪个引擎
>   （如 Detekt JAR / PMD / tree-sitter via pip），等待其完成；如需跳过某引擎，可在
>   `.scan/config.json` 的 `excluded_engines` 中加入该引擎名后重新运行，然后等待用户决定。

```
python3 <SKILL_DIR>/scripts/preflight.py --repo-root .
```

脚本先读取 `.scan/config.json` 确定哪些引擎是"needed"，然后循环执行"检测 → 安装缺失项 → 再检测"，直到没有新的可安装项为止：

> **strict 模式（v3，唯一模式，无降级）：** 任一**必需**引擎/工具未就绪即 `ready=false` 中断。某引擎在 `.scan/config.json` 的 `excluded_engines` 中关闭后，其工具标记 `skip`、不计入中断判定（决定 3）。

| 检查项 | 预检范围条件 | 可自动安装 | 未就绪时处理 |
|---|---|---|---|
| Python 3.8+ | 始终 | 否 | **阻塞** |
| Java 11+ | Detekt/Lint 任一启用 | 否 | **阻塞**（依赖它的引擎需要；手动装 JDK） |
| venv | semgrep 启用 | 是 | **阻塞**（semgrep 前提） |
| semgrep | `semgrep` 未在 `excluded_engines` 中 | 是（pip） | **阻塞** |
| Detekt JAR | `detekt` 未在 `excluded_engines` 中 | 是（~64 MB） | **阻塞** |
| PMD | `pmd` 未在 `excluded_engines` 中 | 是（~40 MB） | **阻塞** |
| repomap (tree-sitter) | `nav_backend` 为 `auto`/`treesitter`（默认 auto） | 是（pip 装独立 venv `~/.scan-android/repomap-venv/`，依赖：`tree-sitter` + `tree-sitter-java` + `tree-sitter-kotlin`） | **不阻塞**（唯一精确层；缺失时自动回退 source-nav，并打印 `[WARN] nav-degraded` 告警） |
| gradlew | `lint` 未在 `excluded_engines` 中 | 否 | **阻塞**（仅 Lint 依赖；无 wrapper 的工程请关闭 lint） |
| git | 始终 | 否 | 警告（仅 --diff 不可用，不阻塞） |

> **导航后端——默认 tree-sitter（唯一精确层），source-nav 为纯标准库兜底：** 验证阶段的跨文件取证 + hunter 的 RepoMap 都由 tree-sitter 引擎提供（`repo_map.py`）；导航门面 `nav_tools.py` 的后端由 `.scan/config.json` 的 `nav_backend`（或环境变量 `SCAN_ANDROID_NAV_BACKEND`）选择，默认 `auto`：
>
> - **tree-sitter（默认，唯一精确层）：** tree-sitter 解析 Java/Kotlin，**AST 精确**识别 def/ref（不误命中注释/字符串、enclosing scope 精确、**自备 kotlin-tags.scm 故 Kotlin 无盲区**）。**这是 source-nav 做不到的 RepoMap 能力的来源**（签名骨架 + PageRank + 跨文件关系，喂给 hunter）。同名重载/接收者类型**不消歧**——常见名（`init`/`d`）歧义仍由 verifier 逐跳 Read 复核（与 source-nav 一致；基准 `nav_benchmark.py` 实测导航精度与 source-nav 持平，采纳理由是 RepoMap，非导航精度）。装在独立 venv（`~/.scan-android/repomap-venv/`，比照 semgrep）。
> - **source-nav（纯标准库兜底）：** 仅当 tree-sitter venv 装不出时回退。对源码做正则检索，**不需要任何编译**、召回完整、精确率被同名碰撞拖累。**保证裸机首启动/离线时导航仍能跑出调用链。**
>
> **tree-sitter 用于两处：**
> 1. **AI 狩猎（第 5.5 步）**：生成聚焦代码地图（RepoMap）喂给 hunter，含签名骨架、跨文件调用关系、技术标记
> 2. **验证阶段（第 6 步）**：条件触发型规则的跨文件调用链回溯（`nav_tools.py --action trace-origin`）
>
> **依赖：** `tree-sitter` + `tree-sitter-java` + `tree-sitter-kotlin`（pip 安装在独立 venv，首次自动安装）
>
> **回退机制：** tree-sitter venv 安装失败时，自动回退 `source-nav.py`（纯标准库正则导航），不阻塞扫描。任何精确后端缺失/不可用都**不影响扫描运行**——一律自动回退 source-nav（结果导向：能在真实工程上跑出导航结果，胜过精确但零产出）。**选后端用基准 `nav_benchmark.py` 跑数字，不凭口碑。**

读取 stdout JSON（`{ready, checks, blockers, warnings}`，已无 `degraded`）：

- **`ready=false`（`blockers` 非空）** → 把 `blockers` 中的原因展示给用户，**立即中止，不得进入第 1 步**。
- **`ready=true`** → 所有必需引擎就绪，继续扫描。

脚本的 stderr 实时打印安装进度和最终状态表格（带图标），无需额外输出。

### 第 1 步 — 读取规范
加载 `<SKILL_DIR>/CONVENTIONS.md`（只需一次）。它定义了 `findings.json` 的 schema、`.scan/config.json` 项目配置、本次内去重算法、严重程度级别和报告渲染规则——脚本已按此实现，读规范是为了在脚本无法覆盖的判断（例如 LLM 验证、异常回退）时保持一致。

### 第 2 步 — 探测工程并确定作用域

**先探测工程**（一次），把硬编码替换为仓库自身的事实：

```
python3 <SKILL_DIR>/scripts/detect_project.py
```

stdout JSON 给出：`modules`（模块目录列表）、`has_flavors` / `flavors`、`suggested_lint_tasks`（第 3 步用）、`default_excludes` + `extra_excludes`（合并为排除集）、`project_context`（第 6 步注入 verifier）、`is_git`、`language`（`"zh"` 或 `"en"`，第 6 步语言约束用）。后续步骤复用这些值——**不要**再凭记忆假设模块名或路径。

然后生成具体的文件列表：
- `--diff REF`：先用 `detect_project.py` 的 `is_git`（或 `git rev-parse --is-inside-work-tree`）确认是 git 仓库。**若不是 git 仓库，立即中止**，并提示三种替代方案：`--module=X`、`--files=GLOB` 或 `--full`。**不要**退回到 mtime、"最近改动"或其它启发式——静默 fallback 会掩盖真正的问题并使作用域不可复现。若存在 git，运行 `git diff --name-only REF`，过滤出源文件扩展名（`detect_project.py` 的 `source_extensions`，即 `*.{java,kt,xml,aidl}`）和 `**/AndroidManifest.xml`。应用排除集（`default_excludes + extra_excludes`），除非检查类别显式面向测试。
- `--full`：按探测到的模块根目录 glob 所有源文件；应用相同排除集。
- `--module=X`：限定到 `X/**`。若 `X` 不在探测出的 `modules` 里，提示可用模块后中止。
- `--files=GLOB`：与 glob 求交集。

打印解析出的文件数。若 > 500 且未显式指定 `--full`，中止并要求用户缩小范围。

**把最终的作用域相对路径逐行写入 `.scan/tmp/scope.txt`**（父目录不存在则建之），供后续步骤复用。

### 第 3 步 — 先运行静态工具（L0 扫描）
在任何模式扫描之前，先跑一遍廉价的确定性工具——它们能免费找出很多问题。按 `detect_project.py` 给出的 `suggested_lint_tasks` 顺序尝试，用**第一个成功的**：

```
./gradlew <suggested_lint_task>     # 例如 lintDebug / lintPaidDebug / lint
```

解析输出，将每个问题映射为 `(file, line, severity, category)`，与模式命中一同进入候选池。**不要**重新发出用户已经 baseline 的 lint 问题。

若这些命令失败（无网络、无 framework JAR、JDK 路径不匹配等），在第 9 步总结里向用户提一句失败原因，并仅以引擎/模式扫描继续——功能不受影响，召回略降。

### 第 4 步 — 规则来源（无需手动加载）
本 skill 不内置单行检测规则。**广度规则**由各引擎自带 / 社区库提供，第 5 步 `run_engines.py` 自动加载（Semgrep registry 包 + 本地 `queries/semgrep/` 补充、Detekt、PMD、Lint）；**深层跨文件/逻辑缺陷**由 AI 支线的 `rules/ai/hunting.md` 覆盖（第 5.5 步）。验证阶段（第 6 步）把 `rules/ai/hunting.md` 的验证要点 / FP 提示注入 verifier 作判断依据。本步无需任何操作。

### 第 5 步 — 引擎编排（脚本）
**不要**手工调 Grep 工具遍历规则。调用引擎编排器：

```
python3 <SKILL_DIR>/scripts/run_engines.py --scope-files .scan/tmp/scope.txt
```

`run_engines.py` 按 v2 可插拔架构注册并运行所有**可用**引擎 adapter，把各引擎产出归一化为统一**候选契约**后聚合：

| 优先级 | 引擎 | 触发条件 |
|---|---|---|
| P1 广度 | `semgrep` | 自动检测/安装（pip）；社区 registry 包 + 本地补充；AST 感知、跨 Java/Kotlin |
| P1 Kotlin | `detekt` | 自动检测/安装（下载 JAR）；Kotlin 专项 |
| P1 Java | `pmd` | 自动检测/安装（下载 ~40 MB）；errorprone / 多线程 / 性能 |
| P1 Manifest | `lint` | 调用 `./gradlew lint`；Android 感知 |
| 验证导航（非候选引擎） | `nav_tools.py` | 跨文件调用方/定义/类型/trace-origin；**唯一精确层 = tree-sitter（AST 精确，Java+Kotlin 无盲区）**，source-nav 为纯标准库兜底（tree-sitter 不可用时回退并告警） |
| P4 opt-in | `mobsf` | 需 `SCAN_ANDROID_ENABLE_MOBSF=1` |
| P4 opt-in | `flowdroid` | 需 `SCAN_ANDROID_ENABLE_FLOWDROID=1` |

> 深层污点/数据流（原 Joern/CodeQL 的角色）现由 **Semgrep taint 模式 + AI 狩猎**（`rules/ai/hunting.md`）覆盖；tree-sitter 只做精确的调用/类型导航，不做数据流。

引擎自动检测并在首次使用时安装（除 opt-in 引擎需手动启用）。`--engines auto`（默认）运行所有可用引擎；`--engines semgrep,detekt` 可指定子集。

安装器内置**断点续传 + 自动重试**（最多 3 次，间隔 5 s / 15 s / 45 s），能应对大文件（~2 GB）下载中途断开的情况。

> **⚠ 安装失败 = 中止扫描（strict，不得继续）**
>
> 正常情况下第 0 步 preflight 已保证所有必需引擎就绪。若运行中某必需引擎仍安装失败，
> `run_engines.py` 将以**退出码 1** 退出，stdout JSON 含 `"fatal_error"` 字段，stderr 有详细错误和修复建议。
>
> **此时必须立即停止扫描**，将 stderr 的错误信息展示给用户，不得继续第 6-8 步。
>
> 用户修复网络后重新运行即可；或在 `.scan/config.json` 的 `excluded_engines` 中关闭该引擎（其工具将不再计入 strict 中断判定）。

读取 stdout JSON：
- `candidates` 数组（归一化契约，元素含 `engine,rule_id,category,severity,file,line,snippet`，污点引擎还带 `dataflow_path`）作为第 6 步输入；
- `engines_used` 透传给第 8 步报告头（`render_report.py --engines-used`）与第 9 步总结。

### 第 5.5 步 — AI 检测支线（开放式狩猎）

工具支线（第 5 步）给广度；AI 支线找规则编不出来的深层逻辑 bug（鉴权绕过、跨文件越权数据流、WebView URL 校验绕过、非幂等重试、缓存一致性、并发竞态…）。

**触发条件（同时满足才执行本支线）：**
1. 作用域 > 50 个业务文件（`.scan/tmp/hunt_scope.txt` 行数 > 50）
2. `.scan/config.json` 的 `excluded_engines` 未包含 `"ai"`
3. 模型配置中有 `verify` 档模型

**不满足条件时：**
- 跳过本支线，直接进入第 6 步验证
- 在第 9 步总结中说明："作用域较小（{N} 个业务文件），已跳过 AI 狩猎支线"
- 理由：小作用域下工具引擎已覆盖充分，AI 狩猎边际收益低

---

1. **降维出业务文件列表**：在第 2 步 `.scan/tmp/scope.txt` 基础上，排除生成码 / vendored / 第三方 / framework 包，把剩下的**业务代码**相对路径写入 `.scan/tmp/hunt_scope.txt`。

2. **确定性分批 + 覆盖率断言（脚本）**：
   ```
   python3 <SKILL_DIR>/scripts/build_hunt_batches.py --scope-files .scan/tmp/hunt_scope.txt --batch-size 15
   ```
   脚本把 hunt_scope.txt 按风险降序切成 `.scan/tmp/hunt_batch_{N}.json`，并写覆盖率清单 `.scan/tmp/hunt_coverage.json`。读 stdout JSON：
   - **`coverage_ok=false`（退出码 1）** → 有文件未进任何批次（`uncovered` 列出）= **漏文件，必须排查后重跑，不得带病继续**。
   - 每个 batch 含 `files`（风险降序，带 `risk_score`/`tech`）+ `tech_present`（技术存在标记，供 hunter 自门控视角）。
   - 顶层 `tech_present` 是全作用域技术集合；`generated_excluded`/`missing` 记录被剔除/找不到的文件。

3. **为每批生成聚焦代码地图（脚本）**：对**每个** `hunt_batch_{N}.json`，用 tree-sitter 产出跨文件地图，写入 `.scan/tmp/repo_map_{N}.md`：
   ```
   python3 <SKILL_DIR>/scripts/repo_map.py --repo . --action map --batch-file .scan/tmp/hunt_batch_{N}.json --out .scan/tmp/repo_map_{N}.md --budget 12000
   ```
   
   **地图含三部分内容**（示例见 `.scan/tmp/repo_map_0.md`）：
   
   1. **签名骨架**：本批每个类的方法签名（参数类型 + 返回类型），按 PageRank 排序（高频调用的方法在前）
   2. **跨文件关系**：本批方法被**批外**哪些代码调用，每个调用方含：
      - 调用点文件:行号
      - 调用所在方法（enclosing_symbol）
      - 调用点源码 snippet（1-2 行）
   3. **技术标记**：本批涉及的技术（WebView / 数据库 / AIDL 等），供 hunter 自门控视角
   
   **hunter 使用方式：**
   - 读签名骨架 → 识别高风险方法（如 `loadUrl(String)` / `execute(String)` 等）
   - 读跨文件关系 → 顺藤摸瓜找调用链（如 `loadUrl` 被 `Intent.getData()` 调用 → 疑似深链劫持）
   - 技术标记 → 跳过不相关视角（无 WebView 时不过 WebView 组规则）
   
   **降级处理：**
   - tree-sitter 不可用时，`repo_map.py` 写降级说明（"地图降级，请 hunter 自行追调用关系"）
   - hunter 收到空地图/降级说明时，改用**手动追踪流程**：
   
   **RepoMap 降级时 hunter 的手动追踪流程：**
   
   > **为什么使用 Grep + Read 而不是 source-nav？**
   > 
   > - hunter 是 LLM 子代理，只能使用 Claude 的通用工具（Read、Grep、Bash）
   > - source-nav 是 Python 脚本（`source_nav.py`），不是 Claude 工具
   > - RepoMap 是 hunter 的**输入**（喂给 hunter 的地图），不是工具
   > - nav_tools.py（内部可选 source-nav）是**验证阶段**用的，不是 hunter 用的
   > - 验证阶段的 verifier 会调用 nav_tools.py，该工具内部自动选择后端（tree-sitter 或 source-nav）
   
   1. **Grep 定位命中处：**
      - 对每条候选假设（如"loadUrl 可能被外部 Intent 调用"），用 Grep 工具搜索关键方法在本批文件中的出现
      - 搜索模式：`loadUrl\(` 或方法名的正则
      - 记录所有命中位置 `{file, line}`
   
   2. **Read 精读上下文（窗口 ±30 行）：**
      - 对每个命中位置：`Read {file}:{line-30}:{line+30}`
      - 判断是否在风险路径上（方法名含 `onNewIntent` / `handleDeepLink` / `onReceive` 等）
      - 识别调用模式（直接调用 / 回调 / 反射）
   
   3. **有界追调用方（Grep + Read，最多 3 跳）：**
      - 如果命中处在疑似风险方法中，Grep 搜索该方法在整个仓库的调用：`methodName\(`
      - Read 前 3 个调用方的上下文（±20 行）
      - 判断调用链是否连通到外部入口（exported Activity / BroadcastReceiver / ContentProvider）
      - 超过 3 跳或无明确结论 → 标记为"需人工复核"，仍产出候选但降低置信度
   
   4. **产出候选时附带追踪记录：**
      ```json
      {
        "rule_id": "R-AI-DEEPLINK-HIJACK",
        "file": "app/MainActivity.java",
        "line": 156,
        "why": "loadUrl 被 onNewIntent 调用，Intent 来源外部",
        "trace": [
          "loadUrl@MainActivity:156",
          "onNewIntent@MainActivity:89 (调用 loadUrl)",
          "外部 Intent → onNewIntent (Activity exported=true)"
        ],
        "trace_method": "manual-grep-read"
      }
      ```

4. **逐批派发 hunter 子代理（并发）**：对**每个** `hunt_batch_{N}.json`，用 `<SKILL_DIR>/agents/hunter.md` 作提示词模板，填充 `{PROJECT_CONTEXT}`、`{LANGUAGE}`、`{HUNTING_RULES}` = `<SKILL_DIR>/rules/ai/hunting.md` 的完整内容、`{BATCH_FILE}` = 该批次文件的绝对路径、`{REPO_MAP}` = `.scan/tmp/repo_map_{N}.md` 的绝对路径（第 3 步产出）。hunter 按批次 `tech_present` **自门控多视角**逐轮过本批（无 WebView 自动跳过 WebView 视角…），本批文件**必须全部读到**，并用聚焦地图「顺藤摸瓜」做跨文件分析。用配置的 **verify 档模型**跑（见 §模型分层）。
   - hunter 现在返回 **JSON 对象** `{batch, perspectives_covered, candidates}`（不是裸数组）。对每个 hunter 回复，按「子代理输出提取约定」取出该对象，并**把回执持久化**到 `.scan/tmp/hunt_attest_{N}.json`（多次采样写 `hunt_attest_{N}_{S}.json`），内容至少含 `{batch, perspectives_covered}`——供第 5 步覆盖断言核对。`candidates` 取入候选池。
   - **（可选）多次采样并集**：`.scan/config.json` 的 `hunt_samples`（默认 1）> 1 时，对每批跑该次数的 hunter，候选**并集**后再交验证——重复缺陷由第 6 步验证器去重（self-consistency，提召回）。`--full` 大作用域建议设 2。
   
   **多次采样的候选去重逻辑：**
   - **hunter 阶段（本步骤）：** 不去重，保留所有采样的候选
     ```python
     all_candidates = []
     for sample in range(hunt_samples):
         hunter_result = run_hunter(batch_N, sample)
         all_candidates.extend(hunter_result["candidates"])
     # 不去重，全部交给验证器
     ```
   - **验证器阶段（第 6 步）：** 按 `file+line+category` 去重
     - 同一批次中，如果多个候选的 `file + line + category` 相同，合并为一条
     - 取最高 `severity`，合并 `evidence`（多个引擎的证据），`rule_id` 取第一个
     - 详见 `verifier.md` 中的"合并同一缺陷"规则

5. **多视角覆盖断言（脚本）**：所有 hunter 回执落盘后，核对每批是否真把该过的视角都过了：
   ```
   python3 <SKILL_DIR>/scripts/check_hunt_coverage.py --min-samples <hunt_samples>
   ```
   它把每批 `expected_perspectives`（build_hunt_batches 据 `tech_present` 算出）与回执的 `perspectives_covered`（多采样取并集）逐批比对。读 stdout JSON / 退出码：
   - **退出码 1**（某批 `missing` 非空、无回执、或采样不足）= **有视角漏过 / hunter 未上报**，必须排查（补跑该批 / 该视角）后重跑，不得带病进入验证。
   - 退出码 0 = 每批 expected ⊆ covered，视角覆盖完整。

6. **合并候选**：所有批次（及多次采样）的 `candidates`（`rule_id` 以 `R-AI-` 开头，带缺陷假设 + 可选 `dataflow_path`）**并入第 5 步的工具候选池**，一同进入第 6 步验证。扫描结束（第 8 步完成）后清理：`rm -f .scan/tmp/hunt_batch_*.json .scan/tmp/hunt_attest_*.json .scan/tmp/repo_map_*.md`。

> **AI 支线只产候选、不下结论。** 它的发现和工具候选一样，必须过第 6 步的**独立验证闸**取证才会上报——发现者不给自己盖章。

### 第 6 步 — LLM 验证（独立验证闸）
候选池含**两类来源**：工具候选（第 5 步，按引擎 `message` + 源码核实）+ AI 狩猎候选（第 5.5 步，`R-AI-*`，核实其缺陷假设）。两者统一按"读源码取证"判定。完整验证逻辑见 `<SKILL_DIR>/agents/verifier.md`——内联验证遵循同一套，派发子代理时直接用它作模板。

要点（详见 verifier.md）：
1. 读取所在函数/类（Read 工具，窗口 ≤ 60 行）。
2. 核实候选描述的缺陷（工具看 `message`，AI 看 `why` 假设）是否在真实代码路径上成立；参照 `rules/ai/hunting.md` 的验证要点/FP 提示压假阳性。
3. 交叉检查缓解手段（`try-finally`、null 保护、生命周期、`@WorkerThread`、`BuildConfig.DEBUG` 门控…）。
4. **独立验证闸**：confirmed 必须附**客观证据**（`evidence` 引真实源码、`why` 引具体代码、跨文件须给验证过的 `dataflow_path`）；不因候选"看着像 bug"就盖章。
5. **条件触发型规则必须先用 `nav_tools.py` 把关键值逐跳回溯到源头**（详见下文"条件触发型规则清单"）。
6. **有界自愈**：判不准时最多再追 2~3 次定向 Read 后再判；仍不清 → 丢弃，不输出 `unclear`。
7. 只有 `confirmed` 成为正式 finding。

#### 条件触发型规则清单（需 trace-origin 回溯）

以下 `rule_id` 前缀的候选，**必须**先用 `nav_tools.py --action trace-origin` 回溯关键值到源头：

| rule_id 前缀 | 需回溯的关键值 | 判据 | 示例 |
|-------------|--------------|------|------|
| `context-leak` / `static-context` / `activity-reference` | Context 来源 | Application = FP，Activity/Service/View = 真泄漏 | 静态变量持有 Activity |
| `main-thread-block` / `network-on-main` / `disk-on-main` | 调用线程 | 主线程 = 真阻塞，工作线程 = FP | 网络请求在 onClick 中 |
| `unauthorized-access` / `permission-bypass` | 调用方权限 | 有权限 = FP，无权限 = 真越权 | 越权读取其他 app 数据 |
| `exported-no-check` / `intent-injection` | Intent 数据来源 | 外部 = 真风险，内部 = FP | 导出组件无校验 |
| 候选带 `dataflow_path` 字段 | 污点数据流 | 验证每跳真实存在 | Semgrep taint 产出 |

**非条件触发型规则（无需 trace-origin）：**
- 其他所有规则（空 catch 块、资源未关闭、硬编码敏感信息、SQL 注入单点等）
- 这些缺陷在命中点本地可验证，Read 所在函数即可

#### 跨文件导航工具（nav_tools.py）

条件触发型规则的跨文件取证统一走 `nav_tools.py`，它按 `nav_backend` 选后端：

**调用示例：**

```bash
# 查找调用方（谁调用了 init 方法）
python3 <SKILL_DIR>/scripts/nav_tools.py --repo . --action callers --symbol "init"

# 查找定义（init 方法定义在哪）
python3 <SKILL_DIR>/scripts/nav_tools.py --repo . --action definition --symbol "DbManager#init"

# 回溯调用链到入口（条件触发型规则必用）
python3 <SKILL_DIR>/scripts/nav_tools.py --repo . --action trace-origin --symbol "DbManager#init" --depth 6

# 查找继承关系
python3 <SKILL_DIR>/scripts/nav_tools.py --repo . --action hierarchy --symbol "BaseActivity"
```

**输出格式：**

- `callers`: `[{file, line, snippet, enclosing_symbol}]`
- `definition`: `[{symbol, file, line}]`
- `trace-origin`: `{target, chains: [{symbol, definition, callers: [...]}], backend: "treesitter"|"source-nav"}`
- `hierarchy`: `{definitions: [...], references: [...]}`

**后端判断：**

- stderr 输出 `导航后端: treesitter` → tree-sitter 正常工作
- stderr 输出 `[WARN] nav-degraded` → 已回退 source-nav（名义级精度，需更严格 Read 复核）
- JSON 输出的 `backend` 字段标明实际后端

**精度说明：**

- tree-sitter 和 source-nav **都不消歧同名重载**（如多个 `init(...)` 重载）
- 必须对每跳结果用 Read 交叉复核 snippet，剔除同名误命中
- tree-sitter 优势：不误命中注释/字符串、enclosing scope 精确、Kotlin 无盲区
- source-nav 优势：零依赖、离线可用、永远可用（兜底保证）

#### trace-origin 输出的解析与使用

**1. 读取 JSON 输出：**
```python
result = json.loads(nav_tools_stdout)
backend = result["backend"]  # "treesitter" 或 "source-nav"
chains = result["chains"]    # 每个定义点一条链
```

**2. 提取源头点（递归遍历到 entry_point）：**
```python
def extract_entry_points(callers_list):
    entries = []
    for c in callers_list:
        if c.get("entry_point"):
            # 到达入口点 = 源头
            entries.append(c)
        elif "callers" in c:
            # 继续递归
            entries.extend(extract_entry_points(c["callers"]))
    return entries

all_entries = []
for chain in chains:
    all_entries.extend(extract_entry_points(chain["callers"]))
```

**3. 逐跳 Read 复核（必须）：**
- 对每个 entry_point：`Read {file}:{line-10}:{line+10}`
- 确认 snippet 确实在该位置
- 确认 enclosing_symbol 匹配（剔除同名误命中）
- 判断源头类型（Application / Activity / 外部 Intent 等）

**4. 写入 evidence：**
```python
evidence = f"回溯调用链 ({backend})：{target} ← ... ← 源头 {entry_type} @ {entry_file}:{entry_line}"
```

---

每条 `confirmed` 输出 `merge_findings.py` 要求的 10 个字段：
`file, line, rule_id, category, severity, title, evidence, why, repro, suggestion`（`end_line`、`dataflow_path` 可选）。`category`/`severity` 默认沿用候选自带值（工具来自引擎/adapter，AI 来自 hunter），验证器取证后可微调。

**语言约束：** `title`、`why`、`repro`、`suggestion` 四个文本字段必须**全部**使用第 2 步 `detect_project.py` 输出的 `language` 值对应的语言编写——`"zh"` = 中文，`"en"` = 英文。同一次扫描内不允许混用。`evidence` 字段照抄源码，不受此约束。

**调度策略：**

所有模式下，**在验证前必须先将候选按 ≤ 20 条分批**，写入 `.scan/tmp/candidates_batch_{N}.json`（N 从 0 递增）。这一限制是强制的，不因规则数量或候选总量而放宽——pattern-too-broad 的规则单次可命中数百条，若内联进提示词会撑爆上下文并引发工具调用截断（表现为 `H.startsWith is not a function` / `Argument expected for -c` 等 Bun 运行时错误）。

> **必须先按 `file` 排序再切批**：同一文件的候选要尽量落在**同一批次**。原因——同一处代码常被多个引擎重复命中（如空 catch 同时被 semgrep 与 PMD 报出），验证器只有在**同批**看到这些重复才能按 verifier.md「合并同一缺陷」合并成一条并取最高 severity。打散到不同批次会导致重复 finding + severity 不一致。

```bash
# 写批次文件（示例，Python 实现更可靠）
python3 - <<'EOF'
import json, pathlib
candidates = <run_engines 输出的 candidates 数组>
candidates.sort(key=lambda c: (c.get("file", ""), int(c.get("line", 0))))  # 按文件聚批，让同处重复落同批
batch_size = 20
pathlib.Path(".scan/tmp").mkdir(parents=True, exist_ok=True)
for i in range(0, len(candidates), batch_size):
    pathlib.Path(f".scan/tmp/candidates_batch_{i // batch_size}.json").write_text(
        json.dumps(candidates[i:i+batch_size], ensure_ascii=False, indent=2)
    )
EOF
```

- `--diff` 或作用域 ≤ 30 文件 → **内联验证**，但仍按批次文件逐批读取处理（每批 ≤ 20 候选），处理完一批再读下一批。
- `--module` 或作用域 30–200 文件 → 同上，内联逐批处理。
- `--full` 或作用域 > 200 文件 → **为每个批次文件各派发一个 verifier 子代理（并发）**：
  1. 按上述方法把候选写入 `.scan/tmp/candidates_batch_{N}.json`
  2. 对每个批次文件，用 `<SKILL_DIR>/agents/verifier.md` 作为提示词模板，填充 `{PROJECT_CONTEXT}`、`{LANGUAGE}`、`{SCOPE}`、`{HUNTING_RULES}` = `<SKILL_DIR>/rules/ai/hunting.md` 的完整内容、`{CANDIDATES_FILE}` = 该批次文件的绝对路径
  3. 并发等待所有子代理完成，按下方「子代理输出提取约定」从各自回复中取出 JSON 数组后合并
  4. 扫描结束（第 8 步完成）后清理：`rm -f .scan/tmp/candidates_batch_*.json`

> **子代理输出提取约定（重要）：** 子代理被要求"只输出 JSON"，但实际回复**可能夹带前导分析文字、说明或 ` ```json ` 代码围栏**（实测会发生）。收集时**不要**对整段回复直接 `json.loads`，先剥离 ` ``` ` 围栏，再按子代理类型取末尾完整 JSON：
> - **verifier**：返回**裸数组**——提取最后一个完整 JSON 数组（定位最后一个 `]`、向前匹配配对的 `[`）。
> - **hunter**：返回 **JSON 对象** `{batch, perspectives_covered, candidates}`——提取最后一个完整 JSON 对象（定位最后一个 `}`、向前匹配配对的 `{`）；取 `candidates` 入池、把 `{batch, perspectives_covered}` 写入 `hunt_attest_{N}.json`。若只解析出裸数组（旧式/不合规回复），按 `candidates` 处理且 `perspectives_covered=[]`（→ 第 5.5 步覆盖断言会判该批漏视角，promptly 暴露不合规）。
>
> 某个子代理解析失败时，将其视为"本批 0 确认 / 0 候选"并记一条 note，**不要因此中断整次扫描**（但缺回执会被第 5.5 步覆盖断言捕获）。

### 第 7 步 — 写 findings（脚本，无状态）
把所有 `confirmed` finding 放进一个 JSON 数组，管道给：

```
echo "$CONFIRMED_JSON" | python3 <SKILL_DIR>/scripts/merge_findings.py
```

脚本处理：sha1 id 计算、**本次内**按 `file:line:category` 去重、原子覆盖写 `.scan/findings.json`（`schema_version: 2`）。

> **v3 无状态：** 不读旧 findings、不维护 first/last_seen、不做回归重开或关闭消失项——每次只反映本次确认的问题。

脚本 stdout 一行 JSON：`{findings_total, findings_duplicate}`。

### 第 8 步 — 生成报告（脚本）
```
python3 <SKILL_DIR>/scripts/render_report.py \
    --engine-stats '<第5步 run_engines 输出的 engine_stats JSON 数组>' \
    --models <本次所用模型 CSV>
```

脚本把 `.scan/findings.json` 渲染为 `.scan/reports/findings.md`（覆盖旧文件）。`--engine-stats` 写入报告头——**列出本次用了哪些工具引擎、每个引擎命中多少条规则、产出多少候选**（直接传第 5 步 run_engines 的 `engine_stats` 字段）；`--models` 写所用模型。若只有引擎名没有统计，可退用 `--engines-used <CSV>`。**报告不含 commit/时间**（v3 去 ledger）。严重度排序在脚本内实现。

### 第 9 步 — 给用户的总结
用一小段话：扫描的文件数、按严重度分的 finding 数（本次）、指向 `.scan/reports/findings.md` 的路径。**不要**把 finding 内容内联输出。

## 模型分层

按任务难度把活分到不同档的模型控成本（配置见 `.scan/config.json` 的 `models`，默认 Haiku/Sonnet）：

| 档 | 默认模型 | 用在哪 |
|---|---|---|
| `triage` | `claude-haiku-4-5` | 机械结构化、候选初筛、跨源语义去重 |
| `verify` | `claude-sonnet-4-6` | 第 5.5 步 hunter 狩猎、第 6 步 verifier 验证（主力） |
| `escalate` | 关（留空） | 可选：对 critical 候选派一轮更强模型（如 `claude-opus-4-8`）二次复核 |

派发子代理（hunter / verifier）时用对应档模型；未配置则用 `verify` 默认。本次实际所用模型透传给第 8 步报告头（`render_report.py --models <CSV>`）。

## 项目配置（.scan/config.json）

`<SKILL_DIR>/config.example.json` 是完整的配置样例，包含每个字段的说明。使用前将其拷贝到被扫描项目的 `.scan/` 目录：

```bash
mkdir -p <项目根>/.scan
cp <SKILL_DIR>/config.example.json <项目根>/.scan/config.json
# 然后按需编辑，删除所有 _ 开头的注释键
```

常见场景示例：

```jsonc
// 场景 A：离线/受限环境，强制用纯标准库 source-nav（跳过 tree-sitter venv 安装）
{
  "nav_backend": "source"
}

// 场景 B：CI 环境，额外启用 MobSF（已有 APK）
{
  "opt_in_engines": ["mobsf"],
  "apk_path": "app/build/outputs/apk/debug/app-debug.apk"
}

// 场景 C：多 flavor 项目，指定 lint 任务和模块
{
  "modules": ["app", "core"],
  "lint_tasks": ["lintPaidDebug", "lintDebug"],
  "extra_excludes": ["**/generated/**"]
}
```

## 约束

- **绝不修改源代码。** 本 skill 只读。
- **严守假阳性纪律。** 验证不确定就丢弃。用户信任 > 召回率。
- **尊重既有状态。** 不要重新发出 `findings.json` 中已标记 `wontfix` 或 `false-positive` 的 finding。
- **原子写入。** 绝不让 `findings.json` 处于半写状态。
- **不臆测。** 只接受带有具体 `file:line` 和可复现条件的 finding。
- **严守作用域。** 验证期间不要读取作用域外的文件，除非用于确认调用者或缓解手段。
- **不硬编码项目细节。** 模块名 / flavor / 额外排除 / 项目背景一律来自 `detect_project.py` 与 `.scan/config.json`，不要写死在工作流里。

## 范围外

- 生成代码修复
- 代码风格 / 命名 / 格式
- 架构层面的批评
- 与 Android 无关的任何内容

## 扩展

- 加广度规则：**优先调引擎包**——加 Semgrep registry 包（`semgrep_registry_packs`）或在 `queries/semgrep/` 写少量 Android/项目特定规则；Detekt/PMD/Lint 的规则由其自带。本 skill 不再维护单行检测规则。
- 加深度/逻辑狩猎线索：在 `rules/ai/hunting.md` 追加条目（自然语言，`R-AI-*` id）——这是 AI 支线的扩容方式，可随时增删。
- 调用/类型导航：用 `scripts/nav_tools.py` 查 `callers`/`definition`/`hierarchy`/`trace-origin`，**后端自动选择**：默认 `repo_map.py`（tree-sitter AST 精确、读最新源码、Java+Kotlin 无盲区），tree-sitter 不可用时回退纯标准库 `source_nav.py`。hunter 的 RepoMap（`repo_map.py --action map`）也由同一 tree-sitter 引擎产出。tree-sitter 不可用时 nav_tools 回退纯标准库 `source_nav.py` 并打印 [WARN] nav-degraded 告警。
- 规则调优：若某类持续假阳性，更新对应来源（`queries/` 或 `rules/ai/`）的模式/验证要点——不要静默禁用。
- 脚本位于 `<SKILL_DIR>/scripts/`，仅用 Python 标准库；改动时保持 `--help` 文档与本 SKILL.md 的用法同步。

---

## 附录：导航后端对比（tree-sitter vs source-nav）

| 维度 | tree-sitter | source-nav |
|------|-------------|-----------|
| **依赖** | 需要 venv + language-pack（`tree-sitter` + `tree-sitter-java` + `tree-sitter-kotlin`） | 纯 Python 标准库（`os.walk` + `re`） |
| **AST 精度** | ✅ AST 解析，不误命中注释/字符串 | ⚠️ 正则匹配，可能误命中 |
| **enclosing scope** | ✅ 精确识别调用所在方法 | ⚠️ 向上扫描最近方法声明 |
| **同名消歧** | ❌ 不解析重载/类型（需 Read 复核） | ❌ 同样不消歧 |
| **Kotlin 支持** | ✅ 完整支持（自写 kotlin-tags.scm） | ⚠️ 基础支持（fun/override） |
| **离线可用** | ⚠️ 首次需联网安装 venv | ✅ 完全离线 |
| **RepoMap** | ✅ 产生签名骨架+PageRank 地图 | ❌ 不产生（hunter 被要求自行追） |
| **召回完整性** | ✅ 可靠 | ✅ 可靠（宁可误召，不漏真实） |
| **输出格式** | 与 source-nav 同形 | 与 tree-sitter 同形 |
| **性能** | ✅ 快（索引+查询） | ⚠️ 慢（~2s/1000文件，全文件遍历） |
| **触发方式** | 自动（`nav_backend=auto` 默认） | 自动（tree-sitter 不可用时回退） |

### 选择逻辑

`nav_tools.py` 按 `nav_backend`（`.scan/config.json` 或 `SCAN_ANDROID_NAV_BACKEND` 环境变量）选后端：

- **`auto`（默认）**：优先 tree-sitter，不可用时回退 source-nav
- **`treesitter`**：强制 tree-sitter，不可用时报错
- **`source`**：强制 source-nav（离线/受限环境测试用）

### 何时回退 source-nav

- tree-sitter venv 安装失败（离线/网络受限/权限不足）
- `~/.scan-android/repomap-venv/` 已损坏
- 用户显式设置 `nav_backend=source`

### 回退时的影响

1. **RepoMap（AI 狩猎）**：`repo_map.py` 写降级说明，hunter 被要求自行追调用关系
2. **跨文件导航（验证）**：`nav_tools.py` 输出 `[WARN] nav-degraded`，verifier 需更严格 Read 复核
3. **精度下降**：可能误命中注释/字符串，同名歧义更多（但召回不减少）

### 共同限制

- 两者**都不消歧同名重载**（verifier 必须逐跳 Read 复核）
- 两者**都不做数据流分析**（污点追踪改由 Semgrep taint + 人工追源）
- 两者**都依赖 Read 工具复核每跳 snippet**（剔除同名误命中）

### 使用建议

- **默认场景**：使用 `nav_backend=auto`（默认），让系统自动选择最佳后端
- **离线环境**：显式设置 `nav_backend=source`，跳过 tree-sitter 安装
- **CI 环境**：首次运行允许联网安装 tree-sitter，后续离线使用缓存的 venv
- **开发调试**：可通过 stderr 输出的 `导航后端: treesitter` 或 `[WARN] nav-degraded` 判断实际使用的后端
