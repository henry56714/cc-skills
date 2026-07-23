# scan-android 引擎安装指南

scan-android v2 采用**分层自动安装**策略：

| 类型 | 工具 | 安装方式 | 存放位置 |
|---|---|---|---|
| Python 包 | semgrep | pip → venv | `~/.scan-android/venv/` |
| JVM 工具 | Detekt | JAR 下载 | `~/.scan-android/tools/detekt/` |
| JVM 工具 | PMD | ZIP 下载（~40 MB） | `~/.scan-android/tools/pmd/` |
| 验证导航 + RepoMap | tree-sitter | pip 装独立 venv（自动、非阻塞） | `~/.scan-android/repomap-venv/` |
| Opt-in | FlowDroid | JAR 下载（Maven） | `~/.scan-android/tools/flowdroid/` |
| Opt-in | MobSF | 需本地服务 | — |
| 系统工具（手动） | Java 11+ | brew / apt / 系统包管理 | 系统 PATH |
| 系统工具（手动） | ADB | Android SDK | 系统 PATH |

---

## 快速开始（自动安装）

**正常使用时无需手动操作**。首次扫描时引擎编排器会自动：

1. 创建 Python 虚拟环境 `~/.scan-android/venv/`
2. 安装 semgrep 到 venv
3. 下载 Detekt JAR

跨文件导航的唯一精确层是 **tree-sitter**（AST 精确，装在独立 venv、pip 自动安装、非阻塞，详见下方「跨文件调用/类型导航」节）；tree-sitter 不可用时回退纯标准库 source-nav 并打印 `[WARN] nav-degraded` 告警。

---

## 预热安装（可选，避免首次扫描时等待）

```bash
# 1. 创建 venv + 安装所有 Python 依赖
python3 -m venv ~/.scan-android/venv
~/.scan-android/venv/bin/pip install -r requirements.txt

# 2. 安装 Detekt（~64 MB）
python3 scripts/tools/installer.py --install detekt

# 3. 安装 PMD（~40 MB）
python3 scripts/tools/installer.py --install pmd

# 4. 安装 tree-sitter 精确层（preflight 会自动做；非阻塞，装不出回退 source-nav）
python3 scripts/tools/installer.py --install repomap
```

---

## 系统依赖（需用户手动安装）

### Java 11+（Detekt / Lint / FlowDroid 必需）

```bash
# macOS
brew install openjdk@21
# Ubuntu/Debian
sudo apt install openjdk-21-jdk
# 验证
java -version
```

### ADB（P5 动态 PoC 验证可选）

```bash
# macOS — 推荐通过 Android Studio 安装 platform-tools
# 或
brew install android-platform-tools
# 验证
adb version
```

---

## Python 虚拟环境详解

**为什么用 venv 而不是全局 pip？**

| | 全局 pip | scan-android venv |
|---|---|---|
| 与系统/conda 隔离 | ❌ 可能冲突 | ✅ 完全隔离 |
| 需要 root | 有时 | ❌ 无需 |
| 版本固定 | ❌ | ✅ requirements.txt 管理 |
| 激活才能用 | — | ❌ 无需激活（用绝对路径） |

**venv 路径：** `~/.scan-android/venv/`（可通过 `SCAN_ANDROID_VENV_DIR` 覆盖）

semgrep_adapter 查找 semgrep 的顺序：
1. `~/.scan-android/venv/bin/semgrep` — venv 内（优先）
2. `shutil.which("semgrep")` — 系统 PATH（兼容已有安装）

---

## JVM 工具详解

**所有 JVM 工具目录：** `~/.scan-android/tools/`（可通过 `SCAN_ANDROID_TOOLS_DIR` 覆盖）

### Detekt（Kotlin 专项静态分析）

- **版本：** 1.23.7
- **大小：** ~64 MB
- **下载源：** GitHub releases
- **路径：** `~/.scan-android/tools/detekt/detekt-cli-1.23.7-all.jar`
- **触发：** 首次扫描时自动下载

### 跨文件调用/类型导航（唯一精确层 tree-sitter；source-nav 纯标准库兜底）

hunter 的 RepoMap（跨文件代码地图）与 verifier 取证跨文件调用关系都由 tree-sitter 引擎（`repo_map.py`）提供；导航门面 `nav_tools.py` 按 `.scan/config.json` 的 `nav_backend`（或环境变量 `SCAN_ANDROID_NAV_BACKEND`，默认 `auto`）选择后端，缺则回退：

- **tree-sitter（默认，唯一精确层）：** `scripts/repo_map.py` 用 tree-sitter 解析 Java/Kotlin，**AST 精确**识别 def/ref（不误命中注释/字符串、enclosing scope 精确、**自备 `scripts/tags/kotlin-tags.scm` 故 Kotlin 无盲区**），提供 `callers`/`definition`/`hierarchy`/`trace-origin` + `map`（RepoMap）。同名重载/接收者类型**不消歧**——常见名歧义由 verifier 逐跳 Read 复核（基准 `nav_benchmark.py` 实测导航精度与 source-nav 持平；采纳理由是 **source-nav 产不出的 RepoMap 能力**：签名骨架 + PageRank + 跨文件关系，喂给 hunter 做跨文件分析）。**安装：** `tree-sitter` + `tree-sitter-language-pack` 经 pip 装到独立 venv `~/.scan-android/repomap-venv/`（比照 semgrep 隔离；preflight 自动安装，**非阻塞**——装不出只回退 source-nav）。可用 `SCAN_ANDROID_REPOMAP_VENV` 覆盖 venv 路径。
- **source-nav（纯标准库兜底，无需安装）：** `scripts/source_nav.py` 直接对源码做正则检索，**不需要任何编译**、召回完整、仅用 Python 标准库。**tree-sitter venv 装不出时回退它——保证裸机/离线时导航仍能跑出调用链**；此时 `nav_tools` 会打印 `[WARN] nav-degraded` 告警（精度下降，请修复 repomap venv）。

```bash
# 手动安装 tree-sitter 精确层（preflight 会自动做，这里供手动修复）
python3 scripts/tools/installer.py --install repomap
```

---

## Opt-in 引擎

以下引擎默认关闭。有两种启用方式，效果相同，两者取并集：

**方式一：项目级配置（推荐，持久化）**

在被扫描仓库根目录的 `.scan/config.json` 中添加：

```json
{
  "opt_in_engines": ["mobsf"]
}
```

**方式二：环境变量（临时 / CI）**

```bash
export SCAN_ANDROID_ENABLE_MOBSF=1
```

---

### MobSF（APK 级别扫描）

opt_in_engines 值：`"mobsf"` / 环境变量：`SCAN_ANDROID_ENABLE_MOBSF=1`

- **前置条件：** 本地运行 MobSF 服务（`http://localhost:8000`）
- **本地 fallback：** 若 MobSF 不可达，使用 aapt2 分析 Manifest

```bash
# 启动 MobSF（Docker）
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

### FlowDroid（精确污点传播分析）

opt_in_engines 值：`"flowdroid"` / 环境变量：`SCAN_ANDROID_ENABLE_FLOWDROID=1`

- **前置条件：** Android SDK platforms 目录（`ANDROID_HOME` 或 `ANDROID_SDK_ROOT`）
- **大小：** JAR ~200 MB（Maven Central）
- **需要：** 编译好的 APK

---

## P5 动态 PoC 验证

```bash
python3 <SKILL_DIR>/scripts/dynamic_poc.py \
  --repo /path/to/project \
  --package com.example.app \
  [--apk app-debug.apk] \
  [--dry-run]
```

- **前置条件：** ADB 可用 + 设备/模拟器已连接
- **支持规则：** R-SEC-005 / R-SEC-007 / R-SEC-014 / R-SEC-015

---

## 引擎层级（报告头）

v3 strict 无降级：所有必需引擎在 preflight 保证就绪，否则中断。报告头记录本次实际用的引擎：

```
> **引擎层级:** semgrep ✓ · detekt ✓ · pmd ✓ · lint ✓
```

若关闭了某引擎（`excluded_engines`），它不出现在此列表，也不参与中断判定。

---

## 路径与版本覆盖

```bash
# 覆盖 venv 路径（例如用公共共享 venv）
export SCAN_ANDROID_VENV_DIR=/shared/scan-android/venv

# 覆盖工具目录（例如 CI 的固定挂载路径）
export SCAN_ANDROID_TOOLS_DIR=/opt/scan-android/tools

# 启用 opt-in 引擎
export SCAN_ANDROID_ENABLE_MOBSF=1
export SCAN_ANDROID_ENABLE_FLOWDROID=1

# 导航后端：默认 auto（tree-sitter→source-nav 兜底）；离线/受限可强制 source
export SCAN_ANDROID_NAV_BACKEND=source           # 跳过 tree-sitter venv，强制纯标准库导航
export SCAN_ANDROID_REPOMAP_VENV=/path/to/venv   # 覆盖 tree-sitter 精确层 venv 路径
```
