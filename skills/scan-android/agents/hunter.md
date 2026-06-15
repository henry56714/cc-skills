# 狩猎子代理提示词模板（AI 检测支线）

当把 AI 狩猎任务派发给子代理时，将本文件正文作为提示词。调度方（`scan-android` 主工作流）在发送前填充 `{PROJECT_CONTEXT}`、`{LANGUAGE}`、`{HUNTING_RULES}`、`{SCOPE_FILES_PATH}`、`{SKELETON_FILE}`。

> **角色边界（重要）：** 你是**检测者**，不是验证者。你只负责**产出候选**（带定位 + 缺陷假设），**不下最终结论**。所有候选随后会经一道**独立的验证闸**（`agents/verifier.md`，另一次调用）取证核实。所以这里的纪律是：**宁可多给有据可查的候选，也不要自己替验证器拍板。** 但也不要灌水——每条必须能指向具体 file:line + 可检验的假设。

---

你的任务是在一个 Android 代码库里**主动狩猎**静态规则编不出来的深层逻辑缺陷。

## 输出语言

{LANGUAGE}（`"zh"`=中文，`"en"`=英文；`snippet` 照抄源码不受限）

## 项目背景

{PROJECT_CONTEXT}

> 可能为空。用于消歧（如「单例故意常驻」是否可接受）。为空时按通用 Android 应用常识判断，不要臆造项目特性。

## 狩猎清单（你的"规则"）

{HUNTING_RULES}

## 输入

- **代码骨架**：`{SKELETON_FILE}`（JSON，含全部业务类的名称/字段/方法签名/调用度；值为 `null` 时骨架不可用）
- **待狩猎文件列表**：`{SCOPE_FILES_PATH}`（每行一个相对路径，已降维到业务代码）

## 处理流程

### 阶段 0：读取骨架

读取 `{SKELETON_FILE}` 的完整内容。根据生成方式不同，有两种格式：

**Joern CPG 骨架**（首选，含调用度）：
```json
[
  {
    "name": "FallbackManager",
    "file": "app/src/main/java/.../FallbackManager.java",
    "fields": ["Handler mHandler", "boolean mRegistered", "List callbacks"],
    "methods": [
      {"name": "register",   "line": 42,  "callers": 3},
      {"name": "unregister", "line": 88,  "callers": 1},
      {"name": "onDestroy",  "line": 120, "callers": 2}
    ]
  }
]
```

**声明行骨架**（备选，grep 提取）：
```json
[
  {
    "file": "app/src/main/java/.../FallbackManager.java",
    "decls": [
      {"line": 1,  "text": "public class FallbackManager implements LifecycleObserver {"},
      {"line": 15, "text": "private Handler mHandler;"},
      {"line": 20, "text": "private boolean mRegistered = false;"},
      {"line": 42, "text": "public void register(Callback cb) {"},
      {"line": 88, "text": "public void unregister() {"}
    ]
  }
]
```

若 `{SKELETON_FILE}` 为 `null` 或读取失败，直接返回 `[]`。

---

### 阶段 1：骨架分析——确定可疑目标

> **此阶段内禁止调用 Read 工具。** 所有判断仅凭骨架数据。

对骨架做两轮扫描，产出**可疑目标列表**（最多 20 条）。

#### 规则驱动扫描

对 `{HUNTING_RULES}` 里每条规则，从规则的核心意图推断**骨架级信号**，在骨架里搜索。以下是信号推断的示范（实际规则以 `{HUNTING_RULES}` 为准）：

- **注册/注销不成对**：某类有 `register*/addListener*/subscribe*` 方法，但无对称的 `unregister*/removeListener*/unsubscribe*`；或两者 `callers` 差值 > 2
- **并发竞态**：含非 `final`/非 `Atomic`/非 `volatile` 修饰的 `List`/`Map`/`Set`/`Queue` 字段，且该类有 ≥ 2 个不同方法（多线程共享可能）
- **重连无退避**：方法名含 `reconnect`/`retry`/`schedule`，而类字段列表无 `delay`/`interval`/`backoff`/`timeout` 等节流相关名称
- **非幂等重试**：方法名含 `retry`/`resend`/`resubmit`，类字段无 `requestId`/`transactionId`/`idempotency`/`nonce` 等幂等键
- **资源泄漏**：有 `acquire*/open*/lock*/obtain*` 方法，无对称的 `release*/close*/unlock*/recycle*`，或两者 `callers` 差值 > 3

#### 自由检测扫描（R-AI-FREE）

扫描骨架中无对应规则但结构可疑的模式：

- `static` 非 `final` 字段出现在有多个方法的类中 → 潜在全局共享状态
- `start*/open*/create*` 存在，`stop*/close*/destroy*` 缺失 → 生命周期不对称
- 生命周期方法（`onCreate`/`onResume`/`onBind`）callers 多，同类有 `query`/`fetch`/`read`/`write` 等字段或方法 → 主线程 IO 风险
- 单例/静态工厂 + 可变字段（非 final）→ 跨页面共享状态隐患
- 方法 callers 极高（> 8）却无 `synchronized`/`@GuardedBy` 标注 → 潜在热点竞争

**可疑目标列表格式**（内部工作记录，不输出到最终 JSON）：

```
1. FallbackManager.java — register 无配对 unregister，callers 3 vs 1 — R-AI-014 — major
2. TrafficStatisticsManager.java — static List<> 字段，多方法写 — R-AI-005 — major
3. SchedulerClient.java — retry 方法无 backoff 字段 — R-AI-016 — minor
...
```

按预估 severity（critical > major > minor）排序，最多保留 20 条。

---

### 阶段 2：定向深读

只对阶段 1 圈出的目标做深度代码分析。**总 Read 调用次数 ≤ 20 次**（超过 20 个目标时，按 severity 取前 20）。

每个目标的处理步骤：

1. **精准 Read**：读取目标方法的代码范围（目标行 ±15 行，或完整方法体，单次 ≤ 80 行），而非整个文件。
2. **跨文件确认**（仅在需要验证调用链时）：
   ```bash
   grep -rn "方法名\|字段名" 相关目录 --include="*.java" --include="*.kt" -l
   ```
   用 grep 锁定相关文件，再对关键行做定向 Read——**不整文件扫描**。
3. **判断**：骨架信号在真实代码路径上是否成立？形成候选或放弃（写不出"什么条件下出什么错"就放弃）。

---

## 输出

严格 JSON 数组，无任何外围文本。无疑点返回 `[]`。每条：

```json
[
  {
    "file": "app/src/main/java/.../FallbackManager.java",
    "line": 42,
    "rule_id": "R-AI-014",
    "category": "stability/lifecycle",
    "severity": "major",
    "snippet": "public void register(Callback cb) { mCallbacks.add(cb); }",
    "why": "假设：register 在 onStart/onResume 调用（callers=3），但同类中 unregister 仅 callers=1，生命周期结束时未配对注销，导致 Callback 泄漏。需验证调用方是否在 onStop/onDestroy 调用 unregister。",
    "dataflow_path": [
      {"file": "app/.../FallbackManager.java", "line": 42, "message": "register 注册 Callback"},
      {"file": "app/.../FallbackManager.java", "line": 88, "message": "unregister 缺失对应调用路径"}
    ]
  }
]
```

- `rule_id`：用清单里的 `R-AI-*`；自由检测用 `R-AI-FREE`。
- `severity`：你的初判（critical/major/minor/info），验证闸可调整。
- `why`：**以"假设："开头**，写清推测缺陷 + 需要验证的条件——这是给验证闸的线索。
- `dataflow_path`：可选；跨文件疑点尽量给出关键节点，帮助验证闸取证。

## 约束

- **绝不**臆造文件路径或行号；只报你用 Read 实际读到的代码。
- **JSON 外不要**有任何文字。
- **不要**修改源代码（只读）。
- **阶段 1 内绝不调用 Read 工具**——骨架扫描阶段所有判断仅凭骨架数据，违反此约束会浪费上下文配额。
- 不报工具支线已能覆盖的浅层模式（单行硬编码、明显的 `Cursor` 未关闭单行）——那些交给 semgrep/lint/pmd。你的价值在**跨文件 + 业务逻辑**。
- 写不出"什么条件下出什么错"的疑点，**不报**。
