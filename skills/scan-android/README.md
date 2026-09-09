# scan-android

面向 Android **源码仓库**的 AI + 静态分析 skill。只支持 source 扫描，不支持 APK/AAB 或 hybrid。

覆盖：组件与 IPC、外部数据流、WebView、存储与隐私、网络与密码学、生命周期/并发、Compose/Room/WorkManager、稳定性、性能和业务逻辑。

## 快速使用

```text
/scan-android                         # 默认 diff HEAD~1 + 影响切片
/scan-android --diff origin/main
/scan-android --module app
/scan-android --files 'app/src/main/**'
/scan-android --full
```

默认不会执行目标仓库 Gradle；已有 Lint XML 会被只读解析并标记 partial。若仓库可信并希望生成当前变体的 Android Lint 报告：

```json
{"allow_gradle_execution": true}
```

将其写入目标仓库 `.scan/config.json`，或在工作流中显式传 `--allow-build-execution`。

## 扫描结构

1. `prepare_scope.py` 生成变更 + 影响切片：先沿 Manifest/component、资源、source set、import 与 Gradle module 关系扩展，再补 callers/callees；默认排除 `.cxx`、生成物、IDE、本地属性和 docs 示例。
2. Semgrep、Detekt、PMD 高信号 profile、已有 Lint XML，以及显式授权生成的 Android Lint 报告产生候选；被抑制的低信号命中仍显式计数。
3. `relation_graph.py` 构建 source-only Android 文件图；AI hunter 以风险为种子、按关系聚类分批，使用 LSP（宿主可用时）或 tree-sitter/source-nav 跨文件导航，逐项完成 marker 门控 case 清单和默认双采样。
4. 独立 verifier 逐条取证，回传结构化 root cause、candidate IDs 与 provenance。
5. Merge 按一次修复对应的根因跨文件/规则合并，并保留全部相关定位。
6. 报告最终闸同时核对 engine、Hunter、verifier、merge receipt；任一阶段缺失都只能是 incomplete，并写当前 run manifest。

每个 hunter 样本在单一结果文件中回传逐文件 sha256、行数和实际 Read ranges。覆盖检查逐样本核对全文范围与文件版本，不再依赖单独的 `hunt_attest` 自述文件。

## 结果

```text
.scan/findings.json
.scan/needs-review.json
.scan/reports/findings.md
.scan/reports/needs-review.md
.scan/tmp/run_manifest.json
.scan/tmp/relation_graph.json
```

`findings.json` 只含已确认问题；不确定项不会静默消失，而在 needs-review 中列出缺少的证据和复核建议。

## 安全与可复现性

- Semgrep、tree-sitter 依赖固定版本并装在隔离 venv。
- Semgrep 在线 registry 默认关闭；开启会联网且规则随上游变化。
- Lint 默认不执行 Gradle；已有 XML 只读摄取但不冒充当前变体完整结果。
- 缺失工具默认不自动安装；只有显式 `--install-missing` 才联网并写 `~/.scan-android`。
- 引擎失败不会抹掉其他结果，但扫描会标为 incomplete。
- 目标源码只读，所有产物写入 `.scan/`。

## 配置

复制 `config.example.json` 到目标仓库 `.scan/config.json`。常用字段：

- `excluded_engines`: `semgrep|detekt|pmd|lint|ai`
- `allow_gradle_execution`
- `semgrep_use_registry`, `semgrep_registry_packs`
- `pmd_include_advisories`, `include_documentation`
- `impact_depth`
- `hunt_samples`, `hunt_batch_size`, `hunt_token_budget`
- `modules`, `extra_excludes`, `lint_tasks`, `lint_report_paths`, `project_context`, `language`

详细工作流见 `SKILL.md`，数据契约见 `CONVENTIONS.md`。

## 开发验证

```text
python3 -m unittest discover -s skills/scan-android/tests -v
PYTHONPYCACHEPREFIX=/tmp/scan-android-pycache python3 -m py_compile skills/scan-android/scripts/*.py skills/scan-android/scripts/adapters/*.py
```

新增规则应配最小 vulnerable/safe fixture；新增 adapter 应覆盖成功、超时、解析失败和截断状态。
