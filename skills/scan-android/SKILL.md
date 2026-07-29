---
name: scan-android
description: 扫描 Android 源码仓库中的安全、稳定性、隐私、性能、生命周期、IPC、WebView、并发和现代 Android API 问题。仅支持 source 扫描，不接受 APK/AAB，也没有 hybrid 模式。用户要求扫描 Android 代码、找漏洞、找隐藏 bug 或运行 scan-android 时使用。支持 --diff（默认 HEAD~1）、--full、--module、--files。
---

# scan-android

对 Android **源码仓库**做一次无状态扫描。产物：

- `.scan/findings.json`：已确认问题
- `.scan/needs-review.json`：有价值但证据不足的线索
- `.scan/reports/findings.md` 与 `.scan/reports/needs-review.md`

每次覆盖，不维护历史 ledger。只读目标源码；除 `.scan/` 产物和用户显式授权的 Gradle Lint 外，不执行目标仓库代码。

默认只纳入生产源码、Manifest、资源、安全配置、构建脚本与 JNI；排除 `.cxx`、`.externalNativeBuild`、`CMakeFiles`、`build/generated`、测试、IDE 配置、`local.properties` 和文档示例。只有配置 `include_documentation=true` 才把 docs 纳入工具 scope；AI hunter 仍不审查文档示例。

## 边界

- 只支持 `source`。输入若是 `.apk`、`.aab`、反编译目录或要求 `apk/aab/hybrid`，明确说明不支持并停止；不得自行反编译或改成别的模式。
- 不把“某引擎失败”解释为“没有漏洞”。保留其他引擎结果，并把扫描标记为 incomplete。
- 不把“证据不足”静默丢弃；送入 `needs-review`。
- 不声称导航是完整语义分析。tree-sitter/source-nav 都需逐跳读源码消歧。

## 参数与作用域

作用域由 `scripts/prepare_scope.py` 唯一生成：

| 参数 | 语义 |
|---|---|
| 无作用域参数 | 等同 `--diff HEAD~1` |
| `--diff [REF]` | REF 到工作区的已跟踪变更 + 未跟踪源文件 |
| `--full` | 全仓源码 |
| `--module X` | 与 diff/full 求交；单独使用时扫描整个模块 |
| `--files GLOB` | 可重复；与 diff/full/module 求交，单独使用时扫描匹配文件 |
| `--impact-depth N` | diff 模式调用方/被调方影响切片深度，默认 2 |
| `--no-impact` | 仅扫描直接变更，不扩影响切片 |

源码扩展名、默认排除、模块和配置来自 `detect_project.py`。作用域脚本会扩入：

- Java/Kotlin 变更声明的直接/递归调用方；
- 变更文件中调用的方法定义；
- 模块 Manifest、构建脚本、安全 XML 变化对应的整个模块；
- 根级 settings/version catalog/wrapper 等全局构建变化对应的全仓。

影响分析是保守名义级近似，不能替代 verifier 逐跳确认。

## 工作流

`<SKILL_DIR>` 是本文件所在目录；所有命令从被扫描仓库根执行，并使用 `<SKILL_DIR>` 的绝对路径。

### 1. 预检

```text
python3 <SKILL_DIR>/scripts/preflight.py --repo-root .
```

只有 Python 版本是硬阻塞。Semgrep、Detekt、PMD、tree-sitter、Java、Gradle wrapper 缺失会成为 warning；继续处理可用引擎并最终如实标记 incomplete。不要绕过或隐藏 warning。

首次安装会联网和写 `~/.scan-android`；若执行环境要求权限，先取得用户授权。依赖版本固定在 installer/requirements 中。

### 2. 生成工程事实与确定性作用域

将用户参数原样映射到：

```text
python3 <SKILL_DIR>/scripts/prepare_scope.py --repo-root . [--diff REF|--full] [--module X] [--files GLOB ...] [--impact-depth N|--no-impact] --language <用户本次对话语言 zh|en>
```

读取 stdout 与以下文件：

- `.scan/tmp/project.json`
- `.scan/tmp/scope.txt`
- `.scan/tmp/hunt_scope.txt`
- `.scan/tmp/scope_meta.json`
- `.scan/tmp/run_manifest.json`：本次 run ID、scope、仓库 revision/dirty、skill/config fingerprint；仅描述当前运行，不形成跨扫描状态。

`scope.txt` 为空时，报告“作用域中没有可扫描源码”并停止。diff 默认 REF 不存在时，不猜测其他基线；提示用户指定 REF 或 `--full`。

### 3. 工具候选

```text
python3 <SKILL_DIR>/scripts/run_engines.py --repo-root . --scope-files .scan/tmp/scope.txt
```

把完整 stdout 保存为 `.scan/tmp/engine-results.json`。默认引擎：

- Semgrep：固定版本、本地 Android 规则与 taint 候选；verifier 读取 source/sink 重建并核实路径。在线 registry 默认关闭，需配置显式开启。
- Detekt：Kotlin。
- PMD：Java。
- Android Lint：默认**不运行**，因为它会执行目标仓库 Gradle 逻辑。只有用户信任仓库并显式授权时才加 `--allow-build-execution`，或设置 `allow_gradle_execution=true`。

PMD 默认使用高信号候选 profile：资源泄漏、非线程安全 formatter、硬编码密码学密钥进入漏洞 verifier；style/advisory 命中以 `suppressed/suppression_summary` 明确记账，不静默消失。只有用户显式设置 `pmd_include_advisories=true` 才把全部 PMD 命中送入 verifier。

读取 `status/scan_complete/configured_complete/coverage_complete/coverage_gaps/incomplete_engines/engine_stats/candidates`：

- `complete`：已选择能力全部完成；
- `complete_with_skips`：执行过程完成，但 Lint 未授权或引擎被显式排除，存在覆盖缺口；
- `incomplete`：引擎失败、partial 或截断。

`not_applicable`（例如 Java-only 仓库的 Detekt）不是覆盖缺口。即使 incomplete/with-skips，也继续验证现有候选并展示原因。

单规则默认不截断。用户显式传 `--max-per-rule N` 时，任何截断都会把该引擎标为 partial。

### 4. AI 深层狩猎

只要 `.scan/tmp/hunt_scope.txt` 非空且 `excluded_engines` 不含 `ai`，就运行 AI 支线；不再按文件数跳过。

1. 读取 `rules/ai/hunting.md` 与 `agents/hunter.md`。
2. 确定性分批：

```text
python3 <SKILL_DIR>/scripts/build_hunt_batches.py --repo-root . --scope-files .scan/tmp/hunt_scope.txt --batch-size <config.hunt_batch_size_or_15> --token-budget <config.hunt_token_budget_or_36000>
```

`coverage_ok=false` 必须修复后重跑，不能漏文件继续。缺失/不可读文件也算覆盖失败。

3. 对每个 `hunt_batch_N.json` 生成聚焦地图：

```text
python3 <SKILL_DIR>/scripts/repo_map.py --repo . --action map --batch-file .scan/tmp/hunt_batch_N.json --out .scan/tmp/repo_map_N.md --budget 12000
```

4. 对每批派发独立 hunter。可并行，但每个 hunter 必须完整读取批次全部文件，并真实完成批次 `expected_perspectives`。核心视角始终启用；IPC、存储、网络密码学、modern runtime、WebView、native 视角仅在批次 marker 命中时启用。把严格 JSON 输出写成 `.scan/tmp/hunt_result_N_SAMPLE.json`；同时把 `{batch,perspectives_covered}` 写为 `.scan/tmp/hunt_attest_N_SAMPLE.json`。

5. 每批采样次数为 `config.hunt_samples`（默认 2）。多次结果取并集，交给 verifier 去重，不能只保留第一次。若用户为了成本显式降为 1，交付时说明单样本召回可能波动。

6. 机械核对视角覆盖：

```text
python3 <SKILL_DIR>/scripts/check_hunt_coverage.py --repo-root . --out-dir .scan/tmp --min-samples <hunt_samples>
```

失败表示批次、结果文件、采样次数或视角漏扫，重跑缺失项。

### 5. 构造无损 verifier 批次

```text
python3 <SKILL_DIR>/scripts/build_verify_batches.py --repo-root . --input .scan/tmp/engine-results.json --input-glob '.scan/tmp/hunt_result_*.json' --out-dir .scan/tmp --max-candidates 20 --token-budget 30000
```

若 AI 被配置关闭，则省略 `--input-glob`。检查 `verify_coverage.json` 的 `coverage_ok=true` 和 input/batched 数相等。批次数量不限，不得只处理前几批。

脚本为每条输入加入稳定 `candidate_id` 与 provenance（工具引擎或 hunter batch/sample），并按同规则/同定位聚拢，减少重复候选跨批边界。Verifier 必须回传这些字段。

### 6. 独立验证

读取 `agents/verifier.md` 与 `rules/ai/hunting.md`。为每个 `verify_batch_N.json` 启动独立 verifier，将严格 JSON 对象保存为 `.scan/tmp/verified_batch_N.json`。

Verifier 输出必须带完整性回执：

```json
{"batch":0,"candidates_input":12,"candidates_adjudicated":12,"false_positive_count":11,"duplicates_merged_count":1,"confirmed":[],"needs_review":[]}
```

四类计数之和必须覆盖输入候选；`merge_findings.py` 会对照原始 `verify_batch_N.json` 强制校验，防止 verifier 静默漏处理。

- confirmed：真实可达、无缓解且证据完整。
- needs_review：有实质线索，但缺 merged manifest、动态分派目标、外部契约、终端 source 或其他关键证据。
- false positive：不输出。

每个 confirmed/needs_review 还必须包含：

- `root_cause`: `{primary_file,symbol,failure_mode}`。表示一次修复可消除的根因；同一根因跨 source/config/sink 必须使用相同三元组，不同失效模式不得合并；
- `source_candidate_ids`: 本记录吸收的全部输入 ID；
- `provenance`: 对应工具/AI 样本来源的去重并集。

Verifier 进程失败、输出无法解析或某批未返回时，不能丢掉该批。为该批所有候选生成 `needs_review` 条目，`review_reason` 写明验证失败原因，保留 candidate_id/provenance；无法判断根因时使用候选定位作为唯一 `root_cause.primary_file/symbol`，`failure_mode=verifier-failed-unresolved`，然后继续其他批。

条件触发类（外部数据流、主线程、Context 生命周期、组件导出/IPC）confirmed 必须带 `dataflow_path` 或 `origin_trace`。导航结果只作线索，每跳回读源码确认。

### 7. 合并与报告

```text
python3 <SKILL_DIR>/scripts/merge_findings.py --verified-glob '.scan/tmp/verified_batch_*.json'
python3 <SKILL_DIR>/scripts/render_report.py --engine-stats '<engine_stats JSON>' --models '<运行时实际模型 ID CSV>' --language <zh|en>
```

`merge_findings.py` 会：

- 优先按结构化 `root_cause` 跨文件、跨 rule/category 合并一次修复对应的表现；
- 缺 root_cause 的兼容输入仅做精确 file/line/category/rule 去重，并在统计中暴露；
- 保留同一行不同 root cause；合并时保留全部 `related_locations/source_candidate_ids/provenance`；
- 同一根因同时出现在 confirmed/needs-review 时由 confirmed 胜出并显式计数；
- 将缺 origin 的条件触发 confirmed 移入 needs-review，而不是丢弃；
- 原子覆盖两个机器可读结果。

它还会对照 `verify_coverage.json` 拒绝缺失或额外的 verifier 批次；不得绕过该检查。

检查四个最终产物都存在。报告头必须保留 complete/partial/failed/skipped/not_applicable、suppressed、截断和 coverage gap；`run_manifest.json` 必须由渲染步骤写入实际模型、引擎统计、结束时间和结果计数。模型 ID 不可得时写 `unknown`，不要写泛化品牌名冒充精确版本。

### 8. 交付

向用户报告：

- confirmed 按 critical/major/minor/info 数量；
- needs-review 数量；
- 扫描是 complete、complete_with_skips 还是 incomplete；后两者列出缺口与原因；
- 实际作用域（direct/impact 文件数）和实际运行的模型/引擎；
- 两份报告的绝对路径。

不要说“安全”或“没有漏洞”；最多说“在本次已完成的作用域和引擎中未确认问题”。

## 配置

可选 `.scan/config.json`，字段见 `config.example.json`。关键项：

- `excluded_engines`: `semgrep|detekt|pmd|lint|ai`
- `allow_gradle_execution`: 默认 false
- `semgrep_use_registry`: 默认 false；true 会联网且规则可能随 registry 更新
- `hunt_samples`, `hunt_batch_size`, `hunt_token_budget`, `impact_depth`
- `pmd_include_advisories`: 默认 false；true 将 PMD style/advisory 一并送入 verifier
- `include_documentation`: 默认 false；true 只把 docs 加入工具 scope
- `modules`, `extra_excludes`, `lint_tasks`, `language`, `project_context`

## 维护规则

- 新的浅层/数据流模式优先加到 `queries/semgrep/android.yaml`，同时给 metadata 的 `rule_id/category/severity`。
- 新的跨文件/业务逻辑线索加到 `rules/ai/hunting.md`，并把新主题映射到 hunter perspective。
- 新 adapter 必须输出统一 Candidate、明确 complete/partial/failed，并提供解析/超时/截断测试。
- 不添加 APK/AAB/反编译路径或 hybrid 分支。
