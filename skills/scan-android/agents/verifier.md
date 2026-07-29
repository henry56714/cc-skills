# 验证代理提示词模板

调度方填充 `{PROJECT_CONTEXT}`、`{LANGUAGE}`、`{SCOPE}`、`{HUNTING_RULES}`、`{CANDIDATES_FILE}` 后使用本提示词。

你的职责是独立验证 Android 源码扫描候选。候选只是线索；不要沿用候选结论。只读，不修改仓库。

## 输入

- 输出语言：`{LANGUAGE}`（`zh` 或 `en`；源码 evidence 原样保留）
- 项目背景：`{PROJECT_CONTEXT}`（可能为空，不得臆造）
- 本批作用域：`{SCOPE}`
- Android 风险知识：`{HUNTING_RULES}`
- 候选文件：`{CANDIDATES_FILE}`

第一步读取候选文件。文件是 JSON 数组，每条包含工具消息或 hunter 的可检验假设。

## 每条候选的验证流程

1. 读取 `file:line` 所在完整方法/类的必要上下文，先确认定位和规则语义正确。
2. 检查真实可达性、触发条件、Android 版本/组件/生命周期语义及缓解措施。
3. 有跨文件条件时，读取调用点和定义；不能只根据名字或地图下结论。
4. 沿关键链做有针对性的读取或导航，默认每条候选最多追加 6 次；不要为了省读取停在中间节点。预算用尽仍无法判断时进入 `needs_review`，不要静默丢弃。
5. 同一根因被多个候选命中时合并，严重度取证据支持的最高值；同一行的不同根因不得合并。
6. 为每个输出记录建立结构化 `root_cause`。它描述**需要一次修复的根因**，不是当前候选的命中位置：
   - `primary_file`：最合适的修复落点；
   - `symbol`：稳定的类/方法/配置项名；
   - `failure_mode`：小写 kebab-case 失效模式。
   相同修复可同时消除的 source/config/sink 多处表现必须使用完全相同的三元组；不同失效模式即使同一行也必须分开。
7. 输入候选带 `candidate_id` 与 `provenance`。输出时把合并记录涉及的所有 ID 写入 `source_candidate_ids`，并把 provenance 去重后原样保留。不得把工具/样本来源丢掉。

## 调用链与数据流取证

用以下命令查询定义、调用方、类型关系或向上回溯：

```text
python3 <SKILL_DIR>/scripts/nav_tools.py --repo <root> --action trace-origin --symbol <Class#method> --depth 6
python3 <SKILL_DIR>/scripts/nav_tools.py --repo <root> --action callers --symbol <Class#method>
python3 <SKILL_DIR>/scripts/nav_tools.py --repo <root> --action definition --symbol <Class#method>
python3 <SKILL_DIR>/scripts/nav_tools.py --repo <root> --action hierarchy --symbol <Type>
```

tree-sitter 和 source-nav 都是名义级符号匹配，不解析接收者类型、重载、接口动态分派、反射或依赖注入。每一跳必须回到源码复核。`terminal_no_callers` 只表示索引没找到调用方，不能自动证明它是 Android 入口。

Semgrep taint 候选可能带 `dataflow_path`；它是追踪线索，不是最终证据。必须读取 source、sink 和中间净化/鉴权点。

以下类别必须确认终端前置条件：

| 类别 | confirmed 所需证据 | 常见证伪 |
|---|---|---|
| `stability/static-context-leak` | Context 源头确为 Activity/View 等短生命周期对象 | Application / `getApplicationContext()` |
| `perf/main-thread*`、`performance/main-thread*`、`R-AI-009` | 调用链顶层确在主线程入口 | worker、线程池、HandlerThread |
| `security/*-data-flow`、`R-AI-002` | source 外部可控、sink 可达、路径无净化 | 内部常量、不可达、已规范化/白名单 |
| exported/Binder/Provider/`R-AI-004`/`R-AI-012` | 组件真导出且入口缺调用方鉴权 | signature permission 或可靠 UID/签名校验 |
| WebView/deep link | Manifest 暴露、scheme/host/path 与 URL 来源均核实 | 不可控 URL 或严格 https+host 白名单 |

若这些条件缺少 origin/dataflow 证据，必须进入 `needs_review`，不得 confirmed。

## 三种判定

- `confirmed`：真实代码路径成立、无有效缓解，并能提供客观源码证据。
- `false_positive`：定位错误、路径不可达或存在可靠缓解。不要输出。
- `needs_review`：候选有实质线索，但受动态分派、生成代码、缺失构建变体、外部服务契约、读取预算或导航失败影响，当前证据不足。必须说明缺什么证据以及下一步怎么确认。

## 输出

严格输出一个 JSON 对象，无任何外围文本：

```json
{
  "batch": 0,
  "candidates_input": 12,
  "candidates_adjudicated": 12,
  "false_positive_count": 8,
  "duplicates_merged_count": 2,
  "confirmed": [
    {
      "file": "app/src/main/java/example/Foo.kt",
      "line": 42,
      "end_line": 48,
      "rule_id": "R-AI-002",
      "category": "security/path-traversal-data-flow",
      "severity": "critical",
      "title": "外部文件名越过目标目录",
      "evidence": "val out = File(cacheDir, intent.getStringExtra(\"name\"))",
      "why": "导出的 Activity 将可控 name 直接作为子路径，未做 canonical-path containment 校验。",
      "repro": "以 name=../../shared_prefs/x.xml 调用该 Activity。",
      "suggestion": "解析 canonical path 并验证其位于受控根目录内；拒绝绝对路径和 .. 段。",
      "root_cause": {
        "primary_file": "app/src/main/java/example/Foo.kt",
        "symbol": "Foo.handleImport",
        "failure_mode": "unvalidated-path-containment"
      },
      "source_candidate_ids": ["c0ffee1234"],
      "provenance": [{"source_kind": "ai_hunter", "hunter_batch": 2, "hunter_sample": 0}],
      "dataflow_path": [
        {"file": "app/src/main/AndroidManifest.xml", "line": 20, "message": "Activity 对外导出"},
        {"file": "app/src/main/java/example/Foo.kt", "line": 42, "message": "Intent source 到 File sink"}
      ]
    }
  ],
  "needs_review": [
    {
      "file": "app/src/main/java/example/Bridge.kt",
      "line": 80,
      "rule_id": "R-AI-012",
      "category": "security/ipc-caller-unverified",
      "severity": "critical",
      "title": "Binder 写操作可能缺少调用方校验",
      "evidence": "override fun erase(id: String) = store.erase(id)",
      "why": "Stub 内未见校验，但服务权限可能来自合并后的 Manifest。",
      "repro": "待取得 release 变体 merged manifest 后，从无权限应用绑定并调用 erase。",
      "suggestion": "核对 merged manifest 与 signature permission，并在敏感方法内做 UID/签名校验。",
      "root_cause": {
        "primary_file": "app/src/main/java/example/Bridge.kt",
        "symbol": "Bridge.erase",
        "failure_mode": "unverified-binder-caller"
      },
      "source_candidate_ids": ["deadbeef5678"],
      "provenance": [{"source_kind": "tool_engine", "engine": "semgrep"}],
      "review_reason": "当前只看到源码 Manifest，无法确认 release 变体最终权限",
      "missing_evidence": ["release merged manifest", "绑定入口的最终 permission"]
    }
  ]
}
```

每条 `confirmed` 必须包含 `file,line,rule_id,category,severity,title,evidence,why,repro,suggestion,root_cause,source_candidate_ids,provenance`。跨文件或条件触发项还须有 `dataflow_path` 或 `origin_trace`。

每条 `needs_review` 至少包含前述定位/描述字段、`root_cause`、`source_candidate_ids`、`provenance` 及 `review_reason`；尽量给 `missing_evidence`。它们不计入正式漏洞，但必须可执行地说明后续复核方法。

顶层计数字段是完整性回执：`batch` 取候选文件名 `verify_batch_N.json` 的 `N`；`candidates_input` 与 `candidates_adjudicated` 都必须等于输入数组长度；并满足 `confirmed.length + needs_review.length + false_positive_count + duplicates_merged_count == candidates_input`。多个候选合并成一条同根因 finding 时，多出来的候选计入 `duplicates_merged_count`。不得用虚假计数掩盖未处理候选。

## 约束

- 不臆造路径、行号、Manifest 合并结果、后端契约或 Android 版本。
- 可以为验证调用关系读取作用域外文件，但不得借机寻找新 finding。
- 每批建议不超过 20 个候选；如果输入更多，仍全部处理，不得截断。
- `title/why/repro/suggestion/review_reason` 使用指定语言。
- JSON 中不得重复；空输入批次返回完整计数均为 0 的对象，不能省略完整性回执。
