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

- **工具引擎（广度，规则来自社区库 / 引擎自带，随上游更新，本 skill 不维护单行规则）：** Semgrep（社区 registry 包 `p/security-audit·owasp·secrets·java·kotlin` + `queries/semgrep/` 本地补充）、Detekt（Kotlin）、PMD（errorprone / 多线程 / 性能）、Android Lint、Joern（跨文件 CPG）。
- **AI 支线（深度，`rules/ai/hunting.md`）：** 鉴权绕过、跨文件越权数据流、并发竞态、生命周期错配、非幂等重试、缓存一致性、资源 / WakeLock 释放、主线程阻塞、算法劣化等规则编不出的逻辑缺陷。

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
> - 若预检因大型依赖下载（如 Joern ~2 GB）耗时过长导致超时，**不得绕过**，应告知用户
>   "当前正在下载 Joern，可能需要数十分钟；如需跳过，可在 `.scan/config.json` 中将
>   `joern` 加入 `excluded_engines` 后重新运行"，然后等待用户决定。

```
python3 <SKILL_DIR>/scripts/preflight.py --repo-root .
```

脚本先读取 `.scan/config.json` 确定哪些引擎是"needed"，然后循环执行"检测 → 安装缺失项 → 再检测"，直到没有新的可安装项为止：

> **strict 模式（v3，唯一模式，无降级）：** 任一**必需**引擎/工具未就绪即 `ready=false` 中断。某引擎在 `.scan/config.json` 的 `excluded_engines` 中关闭后，其工具标记 `skip`、不计入中断判定（决定 3）。

| 检查项 | 预检范围条件 | 可自动安装 | 未就绪时处理 |
|---|---|---|---|
| Python 3.8+ | 始终 | 否 | **阻塞** |
| Java 11+ | Detekt/Joern/Lint 任一启用 | 否 | **阻塞**（依赖它的引擎需要；手动装 JDK） |
| venv | semgrep 启用 | 是 | **阻塞**（semgrep 前提） |
| semgrep | `semgrep` 未在 `excluded_engines` 中 | 是（pip） | **阻塞** |
| Detekt JAR | `detekt` 未在 `excluded_engines` 中 | 是（~64 MB） | **阻塞** |
| PMD | `pmd` 未在 `excluded_engines` 中 | 是（~40 MB） | **阻塞** |
| Joern | `joern` 未在 `excluded_engines` 中 | 是（~2 GB） | **阻塞** |
| CodeQL | `codeql` 在 `opt_in_engines` 中且未被排除 | 是（~2 GB） | **阻塞** |
| gradlew | `lint` 未在 `excluded_engines` 中 | 否 | **阻塞**（Lint 依赖 gradlew；无 wrapper 的工程请关闭 lint） |
| git | 始终 | 否 | 警告（仅 --diff 不可用，不阻塞） |

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
| P2 深度（骨干） | `joern` | 自动安装（~2 GB）；跨文件 CPG 污点追踪 |
| P4 opt-in | `codeql` | 需 `SCAN_ANDROID_ENABLE_CODEQL=1` |
| P4 opt-in | `mobsf` | 需 `SCAN_ANDROID_ENABLE_MOBSF=1` |
| P4 opt-in | `flowdroid` | 需 `SCAN_ANDROID_ENABLE_FLOWDROID=1` |

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

工具支线（第 5 步）给广度；AI 支线找规则编不出来的深层逻辑 bug（鉴权绕过、跨文件越权数据流、非幂等重试、缓存一致性、并发竞态…）。**可在 `.scan/config.json` 的 `excluded_engines` 加入 `"ai"` 跳过本支线（纯工具扫描）。**

#### 5.5.1 降维出业务文件列表

在第 2 步 `.scan/tmp/scope.txt` 基础上，排除生成码 / vendored / 第三方 / framework 包，把剩下的**业务代码**相对路径写入 `.scan/tmp/hunt_scope.txt`。

#### 5.5.2 生成代码骨架（orchestrator 执行一次，hunter 不做）

在派发 hunter **之前**，生成一份紧凑的**代码结构骨架**存入 `.scan/tmp/code_skeleton.json`。骨架只含类名、字段声明、方法签名和调用度，不含方法体，供 hunter 在不大量读取原始文件的情况下定位可疑目标。

调用 `nav_tools.py --action skeleton`（Joern server 模式，CPG 构建完成后直接写 JSON 文件）：

```bash
python3 <SKILL_DIR>/scripts/nav_tools.py \
  --repo "$(pwd)" \
  --action skeleton \
  --output-file "$(pwd)/.scan/tmp/code_skeleton.json"
```

Joern server 首次启动 + CPG 构建约需 2–5 分钟（workspace 有缓存时更快）。若命令以非零退出码退出，**中止 AI 支线并向用户报错**——骨架是 hunter 的前提，无骨架不得派发 hunter。用户可在 `.scan/config.json` 的 `excluded_engines` 加入 `"ai"` 跳过整条 AI 支线。

#### 5.5.3 派发 hunter 子代理

用 `<SKILL_DIR>/agents/hunter.md` 作提示词模板，填充：
- `{PROJECT_CONTEXT}`
- `{LANGUAGE}`
- `{HUNTING_RULES}` = `<SKILL_DIR>/rules/ai/hunting.md` 的完整内容
- `{SCOPE_FILES_PATH}` = `.scan/tmp/hunt_scope.txt`
- `{SKELETON_FILE}` = `.scan/tmp/code_skeleton.json` 的**绝对路径**（骨架文件不存在时传字面量 `null`）

用配置的 **verify 档模型**跑狩猎（见 §模型分层）。大作用域可并发多个 hunter，每个 hunter 独立读取完整骨架后自行决定深读哪些文件，无需再按文件分批——hunter 的 Read 调用上限（≤ 20 次）自然控制了每个 agent 的开销。

#### 5.5.4 合并候选

hunter 返回的 JSON 数组（`rule_id` 以 `R-AI-` 开头，带缺陷假设 + 可选 `dataflow_path`）**并入第 5 步的工具候选池**，一同进入第 6 步验证。按下方「子代理输出提取约定」从 hunter 回复中稳健取出 JSON。

> **AI 支线只产候选、不下结论。** 它的发现和工具候选一样，必须过第 6 步的**独立验证闸**取证才会上报——发现者不给自己盖章。

### 第 6 步 — LLM 验证（独立验证闸）
候选池含**两类来源**：工具候选（第 5 步，按引擎 `message` + 源码核实）+ AI 狩猎候选（第 5.5 步，`R-AI-*`，核实其缺陷假设）。两者统一按"读源码取证"判定。完整验证逻辑见 `<SKILL_DIR>/agents/verifier.md`——内联验证遵循同一套，派发子代理时直接用它作模板。

要点（详见 verifier.md）：
1. 读取所在函数/类（Read 工具，窗口 ≤ 60 行）。
2. 核实候选描述的缺陷（工具看 `message`，AI 看 `why` 假设）是否在真实代码路径上成立；参照 `rules/ai/hunting.md` 的验证要点/FP 提示压假阳性。
3. 交叉检查缓解手段（`try-finally`、null 保护、生命周期、`@WorkerThread`、`BuildConfig.DEBUG` 门控…）。
4. **独立验证闸**：confirmed 必须附**客观证据**（`evidence` 引真实源码、`why` 引具体代码、跨文件须给验证过的 `dataflow_path`）；不因候选"看着像 bug"就盖章。
5. **有界自愈**：判不准时最多再追 2~3 次定向 Read 后再判；仍不清 → 丢弃，不输出 `unclear`。
6. 只有 `confirmed` 成为正式 finding。

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

> **子代理输出提取约定（重要）：** hunter / verifier 子代理被要求"只输出 JSON 数组"，但实际回复**可能夹带前导分析文字、说明或 ` ```json ` 代码围栏**（实测会发生）。收集时**不要**对整段回复直接 `json.loads`——而是**提取最后一个完整的 JSON 数组**：定位回复中最后一个 `]`、向前匹配到配对的 `[` 再解析（或先剥离 ` ``` ` 围栏）。某个子代理解析失败时，将其视为"本批 0 确认 / 0 候选"并记一条 note，**不要因此中断整次扫描**。

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
// 场景 A：有 GitHub Advanced Security 许可，用 CodeQL 替换 Joern
{
  "opt_in_engines": ["codeql"],
  "excluded_engines": ["joern"]
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
- 加 Joern 跨文件查询：在 `queries/joern/` 写 CPGQL。
- 规则调优：若某类持续假阳性，更新对应来源（`queries/` 或 `rules/ai/`）的模式/验证要点——不要静默禁用。
- 脚本位于 `<SKILL_DIR>/scripts/`，仅用 Python 标准库；改动时保持 `--help` 文档与本 SKILL.md 的用法同步。
