# scan-android 引擎安装指南

scan-android v2 采用**分层自动安装**策略：

| 类型 | 工具 | 安装方式 | 存放位置 |
|---|---|---|---|
| Python 包 | semgrep | pip → venv | `~/.scan-android/venv/` |
| JVM 工具 | Detekt | JAR 下载 | `~/.scan-android/tools/detekt/` |
| JVM 工具（骨干） | Joern | ZIP 下载（~2 GB） | `~/.scan-android/tools/joern/` |
| Opt-in | CodeQL | bundle 下载（~2 GB） | `~/.scan-android/tools/codeql/` |
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

Joern 因体积大（~2 GB）同样会自动下载，但首次需要时间，下载失败后 1 小时内不重试。

---

## 预热安装（可选，避免首次扫描时等待）

```bash
# 1. 创建 venv + 安装所有 Python 依赖
python3 -m venv ~/.scan-android/venv
~/.scan-android/venv/bin/pip install -r requirements.txt

# 2. 安装 Detekt（~64 MB）
python3 scripts/tools/installer.py --install detekt

# 3. 安装 Joern（~2 GB；strict 默认必需，不需要可在 excluded_engines 关闭）
python3 scripts/tools/installer.py --install joern
```

---

## 系统依赖（需用户手动安装）

### Java 11+（Detekt / Joern / FlowDroid 必需）

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

### Joern（跨文件 CPG 骨干）

- **版本：** 最新 release（fallback: 4.0.404）
- **大小：** ~2 GB（包含 Scala 运行时 + 所有语言前端）
- **下载源：** GitHub releases（`joern-cli.zip`）
- **路径：** `~/.scan-android/tools/joern/joern-cli/joern`
- **触发：** 首次扫描时自动下载；失败后 1 小时内不重试
- **strict：** Joern 默认必需，装不上即中断；不需要可在 `.scan/config.json` 的 `excluded_engines` 加入 `"joern"` 关闭（关闭后不计入中断判定）

```bash
# 手动安装 Joern（macOS，推荐方式）
brew install joern
```

---

## Opt-in 引擎

以下引擎默认关闭。有两种启用方式，效果相同，两者取并集：

**方式一：项目级配置（推荐，持久化）**

在被扫描仓库根目录的 `.scan/config.json` 中添加：

```json
{
  "opt_in_engines": ["codeql"]
}
```

**方式二：环境变量（临时 / CI）**

```bash
export SCAN_ANDROID_ENABLE_CODEQL=1
```

---

### CodeQL（深度路径污点分析）

- **前置条件：** 已持有 CodeQL 许可（开源项目免费，商业项目需授权）
- **大小：** bundle ~2 GB
- **下载源：** github/codeql-action releases

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
> **引擎层级:** joern ✓ · semgrep ✓ · detekt ✓ · lint ✓
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
export SCAN_ANDROID_ENABLE_CODEQL=1
export SCAN_ANDROID_ENABLE_MOBSF=1
export SCAN_ANDROID_ENABLE_FLOWDROID=1
```
