# scan-android 规范

扫描系统的参考文档。当需要了解 schema、去重、报告细节时由 `scan-android` 加载。不要把这些细节内联到 `SKILL.md`——它们独立演进。

## 目录结构

两个**互相独立**的根：`<SKILL_DIR>`（skill 安装目录，可在任意路径）与被扫描仓库根（cwd）。

```
<SKILL_DIR>/            # skill 安装目录——可在任意路径，不必是 .claude/skills/
  SKILL.md             # 入口
  CONVENTIONS.md       # 本文件
  requirements.txt     # Python 依赖（由 installer 写入 venv）
  rules/
    ai/hunting.md      # AI 支线狩猎启发集（自然语言，R-AI-* id）
  queries/
    semgrep/           # 本地补充 Semgrep 规则（全部加载；社区 registry 包另由 adapter 挂载）
    detekt/            # Detekt 配置（detekt.yml）
    flowdroid/         # FlowDroid SourcesAndSinks（opt-in）
  agents/
    hunter.md          # AI 狩猎子代理提示词模板
    verifier.md        # 独立验证子代理提示词模板
  docs/
    install-engines.md # 引擎安装指南（venv / JVM 工具 / opt-in）
  scripts/
    detect_project.py  # 探测模块 / flavor / lint 任务 / 语言 / 读取项目配置
    run_engines.py     # 引擎编排器：注册并运行各引擎 adapter，输出归一化候选
    build_hunt_batches.py # AI 支线确定性分批 + 覆盖率断言 + 风险排序 + 技术存在标记 + 每批期望视角
    check_hunt_coverage.py # AI 支线「多视角覆盖」事后断言：每批 expected ⊆ hunter 回执 covered
    adapters/          # 引擎 adapter（base.py / semgrep / detekt / pmd / lint / mobsf / flowdroid）
    tools/
      installer.py     # 依赖管理：ensure_venv() + ensure_semgrep() + ensure_detekt() + ensure_repomap_venv() + ...
    lib_scan.py        # 共享库：Candidate 契约、id 计算、JSON I/O
    dynamic_poc.py     # P5 动态 PoC 验证（ADB）
    nav_tools.py       # LLM 导航工具（后端按 nav_backend 选择：treesitter(唯一精确层)→source-nav 兜底，回退时告警）
    repo_map.py        # tree-sitter 代码地图 + AST 精确导航（默认精确层）；hunter RepoMap + verifier 导航
    tags/              # tree-sitter tags 查询（java-tags.scm + 自写 kotlin-tags.scm）
    source_nav.py      # 纯标准库源码级导航（tree-sitter 不可用时的兜底后端；调用方/定义/继承/trace-origin）
    nav_benchmark.py   # 导航后端 ground-truth 基准评测器（非扫描流程；选后端用数字而非口碑）
    ...
~/.scan-android/        # 工具缓存目录（与 skill 解耦，跨工程共享）
  venv/                # Python 虚拟环境（semgrep 等；SCAN_ANDROID_VENV_DIR 可覆盖）
  repomap-venv/        # tree-sitter 精确层专属 venv（tree-sitter + language-pack；SCAN_ANDROID_REPOMAP_VENV 可覆盖）
  tools/               # JVM 工具二进制（SCAN_ANDROID_TOOLS_DIR 可覆盖）
    detekt/            # Detekt JAR
    flowdroid/         # FlowDroid JAR（opt-in）
<被扫描仓库根>/         # = 运行命令时的 cwd
  .scan/               # 全部产物都落在这里，与 skill 解耦
    config.json        # 可选：项目级配置（额外排除、项目背景等）
    findings.json      # 本次扫描确认的 finding（每次覆盖，无历史）
    cache/             # CPG / DB 缓存（重型引擎用，按 commit 键控）
    tmp/               # 中间产物：scope.txt、hunt_scope.txt、候选批次、
                       #   hunt_batch_{N}.json + hunt_coverage.json（AI 支线分批/文件覆盖率）、
                       #   repo_map_{N}.md（每批 tree-sitter 聚焦代码地图，喂 hunter）、
                       #   hunt_attest_*.json（hunter 视角回执）+ hunt_perspective_coverage.json（视角覆盖断言）
    reports/
      findings.md      # 生成的人类可读报告
```

- **`<SKILL_DIR>`** 可装在任意路径（含被多个仓库共享 / 符号链接）。脚本通过 `Path(__file__)` 自定位其同级资源（`rules/`、`lib_scan.py`），因此不依赖任何固定安装位置或 cwd。文档/工作流中凡引用 skill 内文件，一律写 `<SKILL_DIR>/...` 并由调用方替换为实际安装路径——**不要**硬编码 `.claude/skills/...`。
- **`.scan/*`** 产物与可选的 `.scan/config.json` 始终位于**被扫描仓库**的根目录（cwd），与 skill 本身解耦。

## 作用域语义

一次扫描只由 **作用域（scope）** 参数化——决定检查**哪些文件**。规则不再分维度/子集：每次都跑全部规则（v3 去掉了 `--checks`）。

| 作用域参数 | 解析方式 |
|---|---|
| `--diff REF` | `git diff --name-only REF` 与源文件扩展名求交集 |
| `--full` | 所有模块根目录下的源文件 |
| `--module=X` | `X/**` |
| `--files=GLOB` | 按 glob 匹配（相对仓库根） |

除非显式覆盖，始终应用以下**通用默认排除**（见 `detect_project.py` 的 `default_excludes`）：`**/build/**`、`**/generated/**`、`**/test/**`、`**/androidTest/**`、`**/.gradle/**`、`**/.idea/**`。

项目专属的额外排除（例如 vendored 的 `vendor/`、`third_party/`、`prebuilt/` 等）**不**硬编码，而是通过 `.scan/config.json` 的 `extra_excludes` 提供；`detect_project.py` 会把它与默认排除合并。

源文件扩展名：`.java`、`.kt`、`.xml`、`.aidl`、`.gradle`、`.properties`（后两者仅当规则显式指定时纳入）。

## 项目配置（.scan/config.json，可选）

skill 默认对任意 Android 工程零配置工作（模块 / flavor / lint 任务全部由 `detect_project.py` 自动探测）。当某个仓库需要微调时，在其根目录放一份 `.scan/config.json`——所有字段均可选，`detect_project.py` 会读取并合并：

```json
{
  "modules": ["app", "core", "feature/login"],
  "extra_excludes": ["vendor/**", "third_party/**", "prebuilt/**"],
  "lint_tasks": ["lintPaidDebug", "lint"],
  "language": "zh",
  "opt_in_engines": ["mobsf"],
  "project_context": "（可选）一句话项目背景，帮助验证器消歧。例如：长期运行的后台服务，进程级单例常驻属预期；或：纯前台 App，无后台常驻组件。"
}
```

| 字段 | 作用 |
|---|---|
| `modules` | 覆盖自动探测的模块列表（探测不准或需收窄时用） |
| `extra_excludes` | 追加到默认排除之外的项目级排除 glob |
| `lint_tasks` | 覆盖 L0 lint 任务建议（按顺序尝试，取首个成功） |
| `language` | 生成文本字段（`title`/`why`/`repro`/`suggestion`）使用的语言：`"zh"` 或 `"en"`。未设置时自动检测系统 locale（`$LANG`），检测不到则默认 `"zh"` |
| `opt_in_engines` | 为本仓库持久化启用 opt-in 引擎，可选值 `"mobsf"`、`"flowdroid"`。等效于对应的环境变量（`SCAN_ANDROID_ENABLE_MOBSF` 等），两者取并集 |
| `project_context` | 注入 verifier 子代理 `{PROJECT_CONTEXT}` 占位符的项目背景；帮助 LLM 区分「单例故意常驻」「后台线程可接受同步 I/O」等项目语境 |

config **不**引入新规则——它只调参（排除、lint、模块、引擎开关、模型、验证背景）。广度规则来自引擎自带 / 社区库（Semgrep registry + Detekt + PMD + Lint），深层逻辑缺陷由 AI 支线 `rules/ai/hunting.md` 覆盖，按技术存在与否自动适用。

## findings.json schema

```json
{
  "schema_version": 2,
  "findings": [
    {
      "id": "sha1(file:line:category), hex",
      "file": "app/src/main/java/.../Foo.java",
      "line": 42,
      "end_line": 48,
      "rule_id": "R-SEC-001",
      "category": "security/hardcoded-secret",
      "severity": "critical",
      "title": "FooClient 中硬编码的 API key",
      "evidence": "private static final String KEY = \"abc...\";",
      "why": "该 key 会随 release APK 一起分发，并拥有后端写权限。",
      "repro": "在生成的 apk 里 grep 该字面量。",
      "suggestion": "改为通过 BuildConfig 从构建时的密钥源注入。",
      "status": "open",
      "dataflow_path": [ { "file": "...", "line": 0, "message": "..." } ]
    }
  ]
}
```

### 字段规则
- `id` — 确定性计算（`sha1(file:line:category)`）；由脚本生成
- `file` — 相对仓库根，使用正斜杠
- `line` — 从 1 开始，指向主要违规行
- `severity` ∈ `critical | major | minor | info`（见下）
- `status` — v3 无状态：恒为 `"open"`（不再跟踪 fixed/wontfix/历史）
- `dataflow_path` / `poc_result` — 可选；若验证候选带有则原样透传
- **v3 起不再有** `first_seen_*` / `last_seen_*` 等跨扫描字段

### 写入
**每次扫描覆盖写**：`merge_findings.py` 不读旧文件，仅按本次确认候选去重后原子写 `findings.json`。

> **v3：无 ledger、无跨扫描状态机、无降级可见性。** 每次扫描独立，只反映本次确认的问题；运行元信息（引擎层级）仅写入报告头，不持久化。

## 严重度定义

严格按照下述含义使用——不要模糊其边界。

| 级别 | 含义 |
|---|---|
| **critical** | 崩溃、数据丢失、安全事件或在真实代码路径上触发 ANR。阻止发布。 |
| **major** | 资源泄漏、线程错误 I/O、竞态、缺少对合理输入的 null 保护——压力下必然在现场触发故障。需在发布前修复。 |
| **minor** | 潜在正确性风险、代码质量缺陷。顺手修复即可。 |
| **info** | 值得记录但并非错误（例如："此处继续使用已弃用 API，但无实际影响"）。 |

在两个级别之间犹豫时，**选较低的**那个——严重度通胀会摧毁优先级信号。

## 去重算法（仅本次内）

v3 无状态：去重只发生在**本次确认候选**之间，不与历史比对、不跨扫描合并。

```
id = sha1(file + ":" + line + ":" + category)
# 本次内首个命中保留；后续相同 id 计为 duplicate 丢弃
```

`merge_findings.py` 据此对本次候选去重后**覆盖写** `findings.json`。不读旧文件，不做 open/fixed/reopen/close-missing 等状态迁移。

## 报告渲染（findings.md）

每次运行都从 `findings.json` 生成 `.scan/reports/findings.md`。

结构：

```markdown
# 扫描结果

> **引擎层级:** **semgrep** ✓ · **detekt** ✓ · **pmd** ✓ · **lint** ✓

**本次发现：** 3 critical · 12 major · 45 minor · 8 info（合计 68）

## Critical

### R-SEC-001 · security/hardcoded-secret
**FooClient 中硬编码的 API key** — app/src/main/java/.../Foo.java:42

Why: 该 key 会随 release APK 一起分发，并拥有后端写权限。

```java
private static final String KEY = "abc...";
```

Repro: 在生成的 apk 里 grep 该字面量。
Suggestion: 改为通过 BuildConfig 从构建时的密钥源注入。

---

## Major
...

## Minor
...

## Info
...
```

报告头记录本次实际用的引擎（`--engines-used`）。**不含 commit/时间**（v3 去 ledger）。同一严重度内的排序：按 `category` 升序，再按 `file` 升序，再按 `line` 升序。

## 运行生命周期

每次运行是原子的：若中途崩溃，`findings.json` 不会半写（原子写）。v3 无 ledger、无跨扫描状态——重跑即得本次最新结果，可安全重跑。

## 人工维护

v3 无状态：`findings.json` 每次覆盖，手动编辑**不会**跨扫描保留——不要依赖编辑它来标记 `wontfix`。

若某条规则持续产生假阳性，更新 `rules/*.md`（或 `queries/semgrep/`、`rules/ai/`）中对应条目——优化模式或验证清单。**不要**直接禁用规则。
