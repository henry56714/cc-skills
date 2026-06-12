# AI Skills 集合

**中文** | **[English](README.md)**

一组开箱即用的 AI Skills，每个 skill 针对一类特定任务，用自然语言一句话触发，AI 自动完成完整工作流。

Skills 遵循通用格式（SKILL.md + 脚本 + 规则），兼容 [Claude Code](https://claude.ai/code) 及其他支持自定义 skill / 插件的 AI 编程工具。

| Skill | 触发方式 | 能做什么 |
|---|---|---|
| **[scan-android](#scan-android)** | `/scan-android` · "扫描代码" | 对任意 Android 工程做安全 / 稳定性 / 性能三维增量扫描，产出结构化 finding 与 Markdown 报告 |

---

## 安装

以 Claude Code 为例，将 skill 目录复制（或符号链接）到 skills 路径下：

```bash
cp -r skills/scan-android ~/.claude/skills/scan-android
# 或使用符号链接
ln -s /path/to/cc-skills/skills/scan-android ~/.claude/skills/scan-android
```

其他 AI 工具请参考各自文档中关于自定义 skill / 插件的安装说明，将对应 skill 目录指向工具的加载路径即可。

每个 skill 目录均可放在任意路径，内部不含硬编码路径，下载后开箱即用。

---

## Skills

### scan-android

面向**任意 Android 仓库**的增量式代码扫描器，覆盖三个通用维度：

| 维度 | 重点 |
|---|---|
| **security** | 密钥硬编码、弱加密、TLS 信任任意、WebView 配置、导出组件、明文传输、SQL 注入等 |
| **stability** | 资源泄漏、生命周期泄漏、NPE、并发错误、WakeLock、前台服务时序、ConcurrentModification 等 |
| **perf** | 主线程 I/O、onDraw 分配、热路径反射、Bitmap OOM、无界缓存、批量 DB 写未包事务等 |

规则按「技术存在与否」自动适用——只扫用到的技术，没用到的自动跳过，零配置对任意工程生效。多次运行通过去重 + ledger 积累覆盖面。

**触发方式**

```
/scan-android
/scan-android --module=app --checks=security
/scan-android --full
```

或用自然语言：「扫描代码」「找出代码库中的问题」「对 app 模块做稳定性扫描」

**产物**

```
.scan/
  findings.json        ← 结构化 finding（open / fixed / wontfix）
  ledger.json          ← 每次运行日志 + 覆盖面映射
  reports/
    findings.md        ← 人类可读报告（按 critical → major → minor → info 排序）
```

**环境要求：** Python 3.8+，无第三方依赖，仅使用标准库。

详见 [`skills/scan-android/README.md`](skills/scan-android/README.md)

---

## 许可

MIT
