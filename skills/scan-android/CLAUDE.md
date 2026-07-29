# scan-android 开发约束

行为入口在 `SKILL.md`，schema/去重/完整性在 `CONVENTIONS.md`。修改流程时同步两者与 `README.md`。

## 硬约束

- 只支持 Android source 扫描。不要添加 APK/AAB、反编译、MobSF、FlowDroid 或 hybrid 分支。
- 目标源码只读，只能在目标仓库 `.scan/` 下写扫描产物。Gradle/Lint 默认禁用，必须显式授权。
- 编排脚本仅用 Python 标准库。Semgrep 与 tree-sitter 分别在隔离 venv 中运行，不导入编排进程。
- 扫描无状态；不恢复 ledger、first_seen/last_seen 或跨扫描关闭状态。
- 不确定项进入 needs-review，不能静默丢弃；引擎失败保留部分结果并标 incomplete。
- 无默认候选截断。任何显式截断必须可计数并令状态 partial。
- tree-sitter 提供更好的语法级 def/ref 与 RepoMap，但仍不解析重载、接收者类型、动态分派或反射。不要称其为完整语义/精确调用图；verifier 必须逐跳读源码。

## 两个根目录

- `<SKILL_DIR>`：本 skill 安装目录。脚本资源一律用 `Path(__file__)` 定位，不写死 `.claude/skills`。
- scanned repo：命令 cwd / `--repo-root`，`.scan/` 相对此处。

## 当前引擎

- Semgrep：本地 Android 规则 + taint，online registry 显式 opt-in。
- Detekt：Kotlin。
- PMD：Java。
- Android Lint：只有 `allow_gradle_execution=true` 或 CLI 显式授权才运行。
- RepoMap/nav：tree-sitter 优先，source-nav 兜底；二者都需要源码复核。
- AI hunter + 独立 verifier：深层逻辑与跨文件判断。

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
