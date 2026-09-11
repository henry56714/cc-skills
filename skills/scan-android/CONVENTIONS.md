# scan-android 约定

## 产品边界

只扫描 Android 源码仓库。不接受 APK/AAB，不反编译，也没有 hybrid 模式。目标源码只读；扫描产物只写到目标仓库 `.scan/`。

## 目录

```text
.scan/
  config.json                 可选项目配置
  findings.json               confirmed
  needs-review.json           证据不足但值得继续查
  reports/findings.md
  reports/needs-review.md
  tmp/run_manifest.json       当前运行的可复现性事实；不跨扫描累计
  tmp/relation_graph.json     source-only Android 文件关系及边证据
  tmp/repo_map_N.meta.json    每批导航后端、降级、未索引文件与地图哈希
  tmp/hunt_perspective_coverage.json
  tmp/gap_audit_plan.json
  tmp/gap_audit_coverage.json 第二位检测者的漏报审计完整性回执
  tmp/                        可重建的作用域、候选、批次、地图与覆盖率文件
```

## 配置

以 `config.example.json` 为准。`.scan/config.json` 属于被审仓库数据，默认不得改变扫描。只有调用方审阅后，对 `preflight.py`、`prepare_scope.py`、`run_engines.py` 一致传 `--trust-project-config`，才采用以下策略字段：

- `excluded_engines`: `semgrep`, `detekt`, `pmd`, `lint`, `ai`
- `semgrep_registry_packs`: 只选择 registry pack；不授予联网能力，值限 `p/...` ID
- `pmd_include_advisories`: 默认 false；低信号命中仍在 stats 中显式记账
- `include_documentation`: 默认 false；仅影响工具 scope，AI 不审查 docs 示例
- `impact_depth`, `hunt_samples`, `hunt_batch_size`, `hunt_token_budget`
- `modules`, `extra_excludes`, `lint_tasks`, `language`
- `lint_report_paths`: 可选的仓库内 Lint XML；未授权 Gradle 时只读解析并标 partial

能力授权与策略配置分离：`--allow-build-execution`、`--allow-network-rules`、`--install-missing` 分别授权执行目标 Gradle、联网加载固定 Semgrep registry pack、安装缺失工具。任何仓库字段（即使配置策略被信任）都不能授予这些能力。导航降级后端只接受调用方环境变量 `SCAN_ANDROID_NAV_BACKEND`。仓库 `project_context` 只会作为 `repository_context_hint` 暴露为不可信数据，绝不注入 agent prompt。

未知字段忽略。配置解析失败不得猜测；使用安全默认并在 notes/warnings 中显示。

`prepare_scope.py` 会把规范化后的 `hunt_samples/hunt_batch_size/hunt_token_budget` 固化为 `run_manifest.effective_hunt_policy`。批次构建和每批 `repo_map.py --budget` 必须共同使用这份 token budget；后续 merge 必须核对实际批次和采样回执与该策略完全一致，禁止事后降低采样数来制造完整状态。

`run_manifest.skill_fingerprint` 绑定扫描指令、agent prompt、规则/查询、脚本及 tree-sitter tag query。Merge 和 render 都重新计算；作用域生成后修改任一执行语义文件，必须重跑。Merge receipt 另对 run manifest 的作用域、策略、信任和仓库版本等不可变字段做独立摘要，允许 render 追加结果统计，但拒绝事后改写扫描策略。

## 工具候选契约

所有 adapter 输出统一 Candidate：

```json
{
  "engine": "semgrep",
  "native_rule_id": "scan-android-r-sec-056-intent-to-webview-taint",
  "rule_id": "R-SG-056",
  "file": "app/src/main/java/example/Web.kt",
  "line": 42,
  "end_line": 43,
  "category": "security/webview-untrusted-data-flow",
  "severity": "critical",
  "snippet": "web.loadUrl(intent.getStringExtra(\"url\"))",
  "message": "外部数据流入 WebView",
  "dataflow_path": []
}
```

`file` 是存在且未越界的仓库相对 POSIX 路径；`line` 为 1-based。所有模型候选和 verifier 的 `file/root_cause.primary_file/dataflow_path/origin_trace/related_locations` 在进入后续 prompt 或最终 JSON 前重新校验。`dataflow_path` 可选，元素为 `{file,line,message}`。

Adapter 必须返回 `complete|partial|failed`，并记录 `truncated`。缺失/超时/解析失败不得伪装为 complete。
调用方显式传 `--engines` 子集时，未选的已注册引擎也必须生成 `skipped` 记录；重复引擎名只运行一次。合并闸会根据逐引擎记录重算顶层状态、缺口、未完成列表和已运行列表，拒绝不一致产物。

## verifier 输出

严格对象（含批次完整性回执）：

```json
{"batch": 0, "candidates_input": 12, "candidates_adjudicated": 12, "false_positive_count": 11, "false_positive_ids": ["..."], "duplicates_merged_count": 1, "confirmed": [], "needs_review": []}
```

`confirmed + needs_review + false_positive_count + duplicates_merged_count` 必须等于输入候选数；`false_positive_ids` 的长度必须等于假阳性计数。glob 合并模式会对照原始 verifier 批次，要求所有 finding 的 `source_candidate_ids` 与 `false_positive_ids` 互斥并精确覆盖全部输入 ID；同时核对候选输入/批次哈希和 provenance，拒绝只改总数、漏候选或替换产物。

confirmed 必需字段：

`file,line,rule_id,category,severity,title,evidence,why,repro,suggestion,root_cause,source_candidate_ids,provenance`

needs-review 至少再有 `review_reason`，建议提供 `missing_evidence`。条件触发问题的 confirmed 必须含非空 `dataflow_path` 或 `origin_trace`；否则 merge 自动转为 needs-review。

`root_cause` 为 `{primary_file,symbol,failure_mode}`：一次修复可消除的多个命中使用同一三元组；同一位置的不同失效模式使用不同三元组。

## findings.json schema v4

```json
{
  "schema_version": 4,
  "findings": [
    {
      "id": "sha1(root_cause.primary_file + symbol + failure_mode)",
      "file": "app/src/main/java/example/Foo.kt",
      "line": 42,
      "end_line": 45,
      "rule_id": "R-AI-002",
      "category": "security/path-traversal-data-flow",
      "severity": "critical",
      "title": "外部路径逃逸缓存目录",
      "evidence": "...",
      "why": "...",
      "repro": "...",
      "suggestion": "...",
      "status": "open",
      "dedup_scope": "root_cause",
      "root_cause": {
        "primary_file": "app/src/main/java/example/Foo.kt",
        "symbol": "Foo.importFile",
        "failure_mode": "unvalidated-path-containment"
      },
      "source_candidate_ids": ["..."],
      "provenance": [{"source_kind": "ai_hunter", "hunter_batch": 2, "hunter_sample": 0}],
      "related_locations": [],
      "dataflow_path": []
    }
  ]
}
```

needs-review schema v2 的数组键为 `needs_review`，条目 `status=needs_review`，使用同一 root-cause/provenance 契约。

## 本次内去重

1. Build-verify 给候选加入 ID/provenance，并尽量把同规则/同定位放在同批。
2. Verifier 为一次修复对应的所有表现分配相同结构化 root cause，并聚合 source IDs。
3. Merge 以 root cause 跨文件、跨规则合并；保留证据更完整的主记录、最高受支持严重度及所有 related locations/provenance。
4. 缺 root cause 的旧输入只做精确位置去重，并标记 `dedup_scope=exact_location`。
5. Confirmed 与 needs-review 的同根因冲突由 confirmed 胜出并计数。
6. 不跨扫描记忆，不维护 fixed/wontfix/first_seen。

## 严重度

- `critical`: 可直接造成越权、敏感数据泄露/篡改、RCE、关键业务损失或高确定性严重崩溃。
- `major`: 真实用户可触发的稳定性、隐私、性能或安全问题，影响显著但条件/范围受限。
- `minor`: 局部影响、恢复容易或低频边界问题。
- `info`: 有价值的工程风险，当前不构成直接缺陷。

不要仅因规则默认值升级；升降级必须在 `why` 写出项目中的具体触发条件。

## 完整性语义

AI hunter coverage 当前 schema v3 先用 `scope_receipt/context_scope_receipt` 绑定输入清单，并根据当前源码确定性重建全部批次和关系图，拒绝自洽但漏文件、漏技术视角或使用旧关系图的计划。随后逐个核对 `hunt_result`：每个独立 sample 必须覆盖本批全部 `expected_perspectives` 和 `expected_case_ids`，并逐 case 输出 `{status,signals_checked,evidence,conclusion}`；`candidate/mitigated` 证据必须是批内有效 file:line。`business_logic` 每批必做，固定覆盖状态机、身份绑定、金额/配额、分页、时间和分支语义。`files_reviewed[{file,sha256,line_count,ranges}]` 必须精确覆盖批次全部文件。sha256/line_count 必须匹配当前文件，ranges 必须使用严格整数边界且合并后恰好覆盖全文；不同 sample 不得通过并集补齐彼此缺口。`repo_map_N.meta.json` 还必须证明地图未降级、未截断、无未索引源码且与批次/地图哈希一致。

Hunter coverage 通过后必须建立 schema v2 `gap_audit_plan.json`。第二位检测者先独立完整读取相同生产文件，再读取分离的 `gap_prior_N.json` 挑战第一轮 `no_signal/mitigated`；输出 `hunt_gap_result_N.json`。`gap_audit_coverage.json` 会从 schema v3 Hunter 计划和当前 Hunter 结果确定性重建整个 gap plan，拒绝自洽但漏批次/漏 case 的计划；随后对 `perspectives_audited`、逐 case disposition、全文哈希/范围、证据行号和新候选一一校验。它降低模型型漏报，但布尔顺序声明和双遍扫描都不是“理解质量证明”，最终候选仍须 verifier 取证。

- `complete`: 所选作用域、全部选择能力、AI 文件/视角/case、独立 gap audit、verifier 批次和 merge receipt 全部完成且无截断/跳过。
- `complete_with_skips`: 执行成功，但存在显式排除或未授权 Lint 等覆盖缺口；`scan_complete=false`。
- `incomplete`: 任一启用引擎 partial/failed、文件不可读/未索引/超预算、Hunter 或 gap-audit 覆盖率不通过、verifier 批缺失或输出不可解析。
- `not_applicable`: 作用域无该引擎支持的语言；不是覆盖缺口。
- `skipped`: 明确配置排除，或 Lint 因未授权构建执行而安全跳过；进入 complete_with_skips。

“0 confirmed”不等于安全。报告用“本次已完成的作用域和引擎中未确认问题”。
