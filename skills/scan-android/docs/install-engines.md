# scan-android source 引擎安装指南

scan-android 只扫描 Android 源码仓库。它不安装或调用 APK/AAB 反编译、设备、模拟器或动态验证工具。

## 工具与隔离目录

| 用途 | 工具 | 安装方式 | 默认位置 |
|---|---|---|---|
| Android/通用 AST 与 taint 候选 | Semgrep | 固定版本 pip venv | `~/.scan-android/venv/` |
| Kotlin 静态分析 | Detekt | 固定版本 JAR | `~/.scan-android/tools/detekt/` |
| Java 静态分析 | PMD | 固定版本 ZIP | `~/.scan-android/tools/pmd/` |
| 语法级 RepoMap/导航 | tree-sitter + language pack | 固定版本独立 venv | `~/.scan-android/repomap-venv/` |
| Android 官方源码检查 | Android Lint | 目标仓库 Gradle wrapper | 不安装 |

Python 编排脚本需要 Python 3.9+。Semgrep 与 tree-sitter 的隔离环境需要 Python 3.10+；安装器会自动寻找合适解释器。Detekt、PMD 和已授权的 Lint 需要 Java 11+。

## 推荐方式：预检自动安装

从被扫描源码仓库根目录执行：

```bash
python3 <SKILL_DIR>/scripts/preflight.py --repo-root .
```

预检会检测固定版本并自动补装缺失项。首次安装需要联网，并写入 `~/.scan-android/`。Python 是唯一硬前提；某个可选工具安装失败时，扫描保留其他引擎结果并明确标记 incomplete。

## 手动预热

在 skill 目录执行：

```bash
python3 scripts/tools/installer.py --install all
python3 scripts/tools/installer.py --status
```

也可只安装单项：

```bash
python3 scripts/tools/installer.py --install semgrep
python3 scripts/tools/installer.py --install detekt
python3 scripts/tools/installer.py --install pmd
python3 scripts/tools/installer.py --install repomap
```

安装器只接受它管理的固定版本，不使用 PATH 中版本不明的 Semgrep/PMD。PMD ZIP 会在解压前检查路径穿越，Detekt JAR 会校验归档格式。

## Java

确认环境提供 Java 11 或更高版本：

```bash
java -version
```

Java 不可用时 Semgrep 与 AI 支线仍可继续，Detekt/PMD/Lint 会在结果中标记未完成。

## Android Lint 的安全边界

Lint 会运行目标源码仓库的 Gradle 构建逻辑，因此默认跳过。只有在用户信任仓库并显式授权后才能启用：

```bash
python3 <SKILL_DIR>/scripts/run_engines.py \
  --repo-root . \
  --scope-files .scan/tmp/scope.txt \
  --allow-build-execution
```

也可在 `.scan/config.json` 设置：

```json
{
  "allow_gradle_execution": true
}
```

适配器不会修改 `gradlew` 权限；wrapper 不可执行时会报告失败，而不是改写目标仓库。

## Semgrep 规则来源

本地 Android 规则默认离线运行。在线 registry 包默认关闭，避免扫描时隐式联网和规则漂移。确需使用时显式配置：

```json
{
  "semgrep_use_registry": true,
  "semgrep_registry_packs": ["p/security-audit", "p/owasp-top-ten"]
}
```

registry 内容可能变化；报告会记录实际规则来源。

## 导航层

tree-sitter 提供 Java/Kotlin 的语法级定义、引用、层级和聚焦 RepoMap；不可用时回退纯标准库 `source-nav`。两者都是名义级导航，不解析重载、接收者类型、动态分派或反射，verifier 必须逐跳读取源码确认。

可强制使用回退层：

```bash
export SCAN_ANDROID_NAV_BACKEND=source
```

## 路径覆盖

```bash
export SCAN_ANDROID_VENV_DIR=/shared/scan-android/venv
export SCAN_ANDROID_TOOLS_DIR=/shared/scan-android/tools
export SCAN_ANDROID_REPOMAP_VENV=/shared/scan-android/repomap-venv
```

这些目录必须是可信、可写且专用于 scan-android 的位置。
