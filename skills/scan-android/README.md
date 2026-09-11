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

默认不会执行目标仓库 Gradle；已有 Lint XML 会被只读解析并标记 partial。若仓库可信并希望生成发布变体的 Android Lint 报告，只能在本次工作流命令上显式传：

```text
--allow-build-execution
```

目标仓库 `.scan/config.json` 不能授权执行 Gradle、联网或安装工具。该文件默认作为不可信数据忽略；只有调用方审阅后传 `--trust-project-config`，才会采用其中的 scope/engine/task 策略。

## 扫描结构

1. `prepare_scope.py` 生成变更 + 影响切片：先沿 Manifest/component、资源、source set、import 与 Gradle module 关系扩展，再补 callers/callees；删除文件从基线提取声明并保守扩到调用方/模块。测试、规格和 docs 单列为只读逻辑上下文。
2. Semgrep、Detekt、PMD correctness/concurrency/security profile、已有 Lint XML，以及显式授权生成的全部发布变体 Android Lint 报告产生候选；被抑制的 advisory 仍显式计数。
3. `relation_graph.py` 构建 source-only Android 文件图；AI hunter 以风险为种子、按关系聚类分批，使用 LSP（宿主可用时）或 tree-sitter/source-nav 跨文件导航，逐项完成 case assessment 和默认双采样。业务逻辑视角每批必审，不依赖 marker。
4. 第二位 gap auditor 先独立通读，再挑战 Hunter 的 `no_signal/mitigated`，专查状态机、切号、金额/配额、分页、时区、失败回滚及乱序/重复回调漏报；完整性闸会从 Hunter 产物确定性重建它的全部批次和 case。
5. 独立 verifier 对工具、Hunter 和 gap-auditor 的全部候选逐条取证，回传结构化 root cause、candidate IDs 与 provenance。
6. Merge 按一次修复对应的根因跨文件/规则合并，并保留全部相关定位。
7. 报告最终闸同时核对 engine、两轮 AI 检测、固化的采样/批次策略、verifier 候选 ID 精确归属、源码哈希和 merge receipt；任一阶段缺失都只能是 incomplete，并写当前 run manifest。

每个 hunter 样本在单一结果文件中回传逐文件 sha256、行数和实际 Read ranges。覆盖检查先从带哈希的 scope/context 清单确定性重建批次与关系图，再逐样本核对全文范围与文件版本，不再依赖单独的 `hunt_attest` 自述文件。

## 结果

```text
.scan/findings.json
.scan/needs-review.json
.scan/reports/findings.md
.scan/reports/needs-review.md
.scan/tmp/run_manifest.json
.scan/tmp/relation_graph.json
.scan/tmp/hunt_perspective_coverage.json
.scan/tmp/gap_audit_coverage.json
```

`findings.json` 只含已确认问题；不确定项不会静默消失，而在 needs-review 中列出缺少的证据和复核建议。

## 安全与可复现性

- Semgrep、tree-sitter 依赖固定版本并装在隔离 venv。
- Semgrep 在线 registry 默认关闭；只有本次调用的 `--allow-network-rules` 能开启，仓库配置不能授予网络能力。
- Lint 默认不执行 Gradle；已有 XML 只读摄取但不冒充当前变体完整结果。授权后逐项运行探测到的 shipping 变体，不在首个成功任务停止。
- 缺失工具默认不自动安装；只有显式 `--install-missing` 才联网并写 `~/.scan-android`。
- 引擎失败不会抹掉其他结果，但扫描会标为 incomplete。
- 目标源码只读，所有产物写入 `.scan/`。
- 模型输出中的路径、行号、批次 coverage 和 evidence 都经过仓库边界/哈希/范围检查；仓库文本不能修改代理指令。
- 作用域固化当前 skill/prompt/rule/query/tag-query 指纹；merge 和 render 都重算，防止扫描中途替换规则后继续交付旧结论。
- 显式 `--engines` 子集会把未选引擎记为覆盖缺口；不会因只跑一个引擎就报 complete。

## 配置

复制 `config.example.json` 到目标仓库 `.scan/config.json`。调用方审阅后，对预检、scope 和 engine 命令一致传 `--trust-project-config` 才采用它。常用策略字段：

- `excluded_engines`: `semgrep|detekt|pmd|lint|ai`
- `semgrep_registry_packs`（只选择 pack，不授权联网）
- `pmd_include_advisories`, `include_documentation`
- `impact_depth`
- `hunt_samples`, `hunt_batch_size`, `hunt_token_budget`
- `modules`, `extra_excludes`, `lint_tasks`, `lint_report_paths`, `language`

Hunter 批次和每批关系图共同使用固化后的 `hunt_token_budget`，避免源码可读但关系图因较小固定预算被截断。

Gradle 执行、Semgrep registry、缺失工具安装分别由 `--allow-build-execution`、`--allow-network-rules`、`--install-missing` 授权，不是配置字段。

详细工作流见 `SKILL.md`，数据契约见 `CONVENTIONS.md`。

## 开发验证

```text
python3 -m unittest discover -s skills/scan-android/tests -v
PYTHONPYCACHEPREFIX=/tmp/scan-android-pycache python3 -m py_compile skills/scan-android/scripts/*.py skills/scan-android/scripts/adapters/*.py
```

新增规则应配最小 vulnerable/safe fixture；新增 adapter 应覆盖成功、超时、解析失败和截断状态。
