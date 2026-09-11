# AI Skills 集合

**中文** | **[English](README.md)**

一组开箱即用的 AI Skills，每个 skill 针对一类特定任务，用自然语言一句话触发，AI 自动完成完整工作流。

每个 skill 是一个以 `SKILL.md` 驱动的自包含目录（部分还附带脚本与规则），兼容 [Claude Code](https://claude.ai/code) 及其他支持自定义 skill / 插件的 AI 编程工具。

| Skill | 触发方式 | 能做什么 |
|---|---|---|
| **[scan-android](#scan-android)** | `/scan-android` · "扫描代码" | 任意 Android 工程的源码/APK 扫描器（安全、稳定性、性能缺陷），产出结构化 finding 与 Markdown 报告 |
| **[teach](#teach)** | "讲一下这章" · "为什么 X 有效？" | 把一章内容或一个具体问题讲成初学者也能听懂的深度学习讲解，可写入 Markdown 文件（中文输出） |
| **[improve-notes](#improve-notes)** | "完善我的笔记" · "把这一章笔记改好" | 基于完整参考资料，把粗糙的章节笔记升级为自洽的专业复习资料（中文输出） |

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
/scan-android --module=app
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

### teach

把**一章内容或一个具体问题**讲成初学者也能听懂的深度讲解。最初为《动手学深度学习》（PyTorch 版）而写，同样适用于任何技术材料（Notebook、论文、源码）。

- **直觉先行**：先打比方建立画面感，再上术语；公式在直觉之后引入，每个符号都解释含义。
- **举例驱动**：用具体数字和小张量帮助理解，不停留在抽象描述。
- **代码关联**：说明每段代码做什么、为什么这样做、对应哪个公式。
- **忠于原文**：讲解严格依据参考材料，不编造概念、公式或数值。

可把讲解写入指定的 Markdown 文件：不存在则创建，已存在则追加（以新 `##` 标题分隔，不覆盖原有内容）。输出为中文。

**触发方式** — 自然语言指向章节文件或直接提问：

```
讲一下 chapter_convolutional-modern/resnet.ipynb，写到 notes/resnet讲解.md
为什么 BatchNorm 能加速收敛？
```

纯提示词 skill：只有一个 [`SKILL.md`](skills/teach/SKILL.md)，无脚本、无依赖。

### improve-notes

把一份粗糙的章节笔记升级为**自洽的专业复习资料**。给定笔记文件和参考资料（Notebook、Markdown、代码），先穷尽阅读全部参考资料——每个 code cell、输出和练习题都不放过——再逐节重写笔记。

每个 `##` 小节是一张独立自洽的卡片（适合转 Anki），覆盖：解决的问题、直觉理解、严格数学定义（逐符号解释）、代码关联、超参数与工程实践、常见误区。内容严格来自参考资料，不编造；资料不足处显式标注，不硬填。

**触发方式** — 给出笔记文件与参考资料路径：

```
完善 src/06chapter_convolutional-neural-networks/06chapter_convolutional-neural-networks_note.md，
参考资料在 chapter_convolutional-neural-networks 目录
```

纯提示词 skill：只有一个 [`SKILL.md`](skills/improve-notes/SKILL.md)，无脚本、无依赖。

---

## 许可

MIT
