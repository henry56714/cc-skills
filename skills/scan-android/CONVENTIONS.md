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
  tmp/                        可重建的作用域、候选、批次、地图与覆盖率文件
```

## 配置

以 `config.example.json` 为准。支持：

- `excluded_engines`: `semgrep`, `detekt`, `pmd`, `lint`, `ai`
- `allow_gradle_execution`: 默认 false
- `semgrep_use_registry`: 默认 false
- `semgrep_registry_packs`
- `pmd_include_advisories`: 默认 false；低信号命中仍在 stats 中显式记账
- `include_documentation`: 默认 false；仅影响工具 scope，AI 不审查 docs 示例
- `nav_backend`: `auto|treesitter|source`
- `impact_depth`, `hunt_samples`, `hunt_batch_size`, `hunt_token_budget`
- `modules`, `extra_excludes`, `lint_tasks`, `language`, `project_context`

未知字段忽略。配置解析失败不得猜测；使用安全默认并在 notes/warnings 中显示。

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

`file` 是仓库相对 POSIX 路径；`line` 为 1-based。`dataflow_path` 可选，元素为 `{file,line,message}`。

Adapter 必须返回 `complete|partial|failed`，并记录 `truncated`。缺失/超时/解析失败不得伪装为 complete。

## verifier 输出

严格对象（含批次完整性回执）：

```json
{"batch": 0, "candidates_input": 12, "candidates_adjudicated": 12, "false_positive_count": 11, "duplicates_merged_count": 1, "confirmed": [], "needs_review": []}
```

`confirmed + needs_review + false_positive_count + duplicates_merged_count` 必须等于输入候选数；glob 合并模式会对照原始 verifier 批次拒绝计数不一致。每个输出记录的 `source_candidate_ids` 必须来自本批输入，不能在多个 finding 中重复，并满足 `source_candidate_ids 总数 = confirmed + needs_review + duplicates_merged_count`。

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

- `complete`: 所选作用域、全部选择能力、AI 文件/视角与 verifier 批次全部完成且无截断/跳过。
- `complete_with_skips`: 执行成功，但存在显式排除或未授权 Lint 等覆盖缺口；`scan_complete=false`。
- `incomplete`: 任一启用引擎 partial/failed、文件不可读、覆盖率不通过、verifier 批缺失或输出不可解析。
- `not_applicable`: 作用域无该引擎支持的语言；不是覆盖缺口。
- `skipped`: 明确配置排除，或 Lint 因未授权构建执行而安全跳过；进入 complete_with_skips。

“0 confirmed”不等于安全。报告用“本次已完成的作用域和引擎中未确认问题”。
