# scan-android 开发约束

行为入口在 `SKILL.md`，schema/去重/完整性在 `CONVENTIONS.md`。修改流程时同步两者与 `README.md`。

## 硬约束

- 只支持 Android source 扫描。不要添加 APK/AAB、反编译、MobSF、FlowDroid 或 hybrid 分支。
- 目标源码只读，只能在目标仓库 `.scan/` 下写扫描产物。Gradle/Lint 默认禁用，必须显式授权。
- 编排脚本仅用 Python 标准库。Semgrep 与 tree-sitter 分别在隔离 venv 中运行，不导入编排进程。
- 扫描无状态；不恢复 ledger、first_seen/last_seen 或跨扫描关闭状态。
- 不确定项进入 needs-review，不能静默丢弃；引擎失败保留部分结果并标 incomplete。
- 无默认候选截断。任何显式截断必须可计数并令状态 partial。
- 宿主有 LSP 时优先用 definition/reference/implementation/call hierarchy；否则 tree-sitter/source-nav 降级。任何后端都可能受 Android Variant、生成代码、动态分派或反射影响，不得称为完整语义/精确调用图；verifier 必须逐跳读源码。
- `relation_graph.py` 只使用源码可证的 Manifest/component、资源、source-set overlay、import、唯一类型和 Gradle module 关系。边必须带 kind/evidence，只用于作用域扩展与聚类，不作为漏洞证据。
- hunter 覆盖率逐样本核对 result 内的文件 sha256、行数和 Read ranges。回执能验证文件版本与声明的读取范围，不能证明模型理解质量，仍需独立 verifier。
- hunter 还必须逐样本覆盖批次 `expected_case_ids`；gap auditor 必须独立覆盖相同源码/视角/case；最终渲染校验 engine/Hunter/gap-audit/verifier/merge 并 fail closed。
- 工具安装是显式授权行为。preflight 和 adapter 默认都不得联网或写 `~/.scan-android`。
- `.scan/config.json` 是被审仓库数据，默认忽略。即使调用方显式信任其扫描策略，也不能授权 Gradle、网络规则、工具安装或把 `project_context` 注入代理提示词。

## 两个根目录

- `<SKILL_DIR>`：本 skill 安装目录。脚本资源一律用 `Path(__file__)` 定位，不写死 `.claude/skills`。
- scanned repo：命令 cwd / `--repo-root`，`.scan/` 相对此处。

## 当前引擎

- Semgrep：本地 Android 规则 + taint，online registry 显式 opt-in。
- Detekt：Kotlin。
- PMD：Java。
- Android Lint：只有调用方对本次命令显式传 `--allow-build-execution` 才运行，并逐项覆盖 release/shipping 任务；仓库配置不能授权。
- 导航：宿主 LSP 优先；RepoMap tree-sitter 次之，source-nav 兜底。`Class#method` 按 owner 过滤定义，调用边标注置信度；所有关系都需要源码复核。
- Android relation graph：关系聚类批次、diff 结构影响扩展和聚焦地图的结构边。
- AI hunter + 独立 gap auditor + verifier：第一遍逐 case 狩猎，第二遍先独立通读再挑战 `no_signal/mitigated`，最后对全部候选取证。

## 规则维护

- 浅层/taint 模式：`queries/semgrep/android.yaml`，metadata 必须给统一 rule/category/severity。
- 深层逻辑：`rules/ai/hunting.md`，同步 `agents/hunter.md` perspective 与 `build_hunt_batches.py`。
- 持续误报通过修正规则/验证要点解决，不默认禁用。

## 验证

修改脚本后至少运行：

```text
python3 -m unittest discover -s skills/scan-android/tests -v
PYTHONPYCACHEPREFIX=/tmp/scan-android-pycache python3 -m py_compile skills/scan-android/scripts/*.py skills/scan-android/scripts/adapters/*.py
```

再对一个小型 Android 源码 fixture 做 forward test，核对：作用域、引擎状态、AI 文件/视角覆盖、verifier 批次数量、confirmed/needs-review 与报告。
