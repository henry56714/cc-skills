# AI 支线 — 开放式狩猎启发集（规则导向 + 自由检测）

> 本文件是 **AI 检测支线** 的"规则"。它不是正则/AST 模式（那是工具支线 `queries/` + 社区规则库的活），而是**自然语言的狩猎清单**：告诉 AI「该看哪、找什么」，覆盖静态规则编不出来的深层逻辑缺陷。
>
> 用法：`agents/hunter.md` 子代理带着本清单通读**降维后的业务代码**，做两件事——
> 1. **规则导向**：逐条过下面的清单（有方向、可复现）；
> 2. **自由检测**：清单没列、但读代码时察觉的深层 bug 也报（无方向、突破天花板）。
>
> 产出的候选 `rule_id` 一律以 `R-AI-` 开头（扁平编号 `R-AI-NNN`，不分维度），进入与工具候选**同一道独立验证闸**（`agents/verifier.md`），必须附证据才会被确认。**可增量添加条目**（追加新编号）——这是本支线扩容的方式。

---

## 进入前的范围约束（降维）

只看**业务代码**。显式跳过：生成代码（`R.java`、databinding、`*_GeneratedInjector`、protobuf 产物）、vendored / 第三方库、`build/`、`androidx`/`com.google.*` 等框架包。这些由调度方在作用域里已大致排除，狩猎时若仍遇到，直接略过。

> 下面按主题分组只为便于查阅，**不是可选择的扫描维度**——每次狩猎全部过一遍。

---

## 鉴权、数据流与组件

| id | 狩猎线索（找什么） |
|---|---|
| `R-AI-001` | **鉴权可绕过**：登录/权限校验依赖客户端可篡改的状态（本地 flag、SharedPreferences、Intent extra）；校验在 UI 层而非数据层；`if (isVip)` 之类来源不可信。 |
| `R-AI-002` | **越权数据流**：用户可控输入（Intent / Uri / 网络响应 / 文件名）未净化就流入危险汇聚点（SQL 拼接、`File(path)`、`Runtime.exec`、`WebView.loadUrl`、反射类名、`Class.forName`）。**跨文件追这条链**。 |
| `R-AI-003` | **凭证/令牌误用**：token 刷新竞态导致用旧 token；密钥在内存中长期驻留可被 dump；签名校验被 try-catch 吞掉后仍放行。 |
| `R-AI-004` | **组件暴露语义**：`exported=true` 的组件背后执行了敏感操作，且未校验调用方（无 permission、无签名校验）；隐式 Intent 承载敏感数据。 |
| `R-AI-012` | **导出 Binder / AIDL / ContentProvider 缺调用方校验**：`.Stub` 实现的**每个对外方法**是否 `Binder.getCallingUid()/getCallingPid()` 校验权限/签名/白名单？即使平台签名，导出 Binder 仍可被任意 app 调用——盲信调用方=漏洞。 |
| `R-AI-013` | **Intent 重定向**：从收到的 Intent 里取出嵌套 Intent（`getParcelableExtra`）直接 `startActivity`/转发，未校验目标组件——可被诱导访问内部组件。 |

## WebView / 混合应用（仅当工程用到 WebView 时过这一组）

> **门控：** 本组仅对含 WebView 的文件适用（`build_hunt_batches.py` 的 `tech_present` 含 `webview` 才过）。
> **分工：** 浅层单行配置（`setJavaScriptEnabled` / `setAllowFileAccess*` / `addJavascriptInterface` 的**存在性**）已由 semgrep `R-SG-004` 覆盖——这里**只收 semgrep 编不出的跨文件 + 逻辑**：URL 来源是否可控、校验是否可绕、跨 Intent/组件的数据流。

| id | 狩猎线索（找什么） |
|---|---|
| `R-AI-018` | **URL 校验可绕过**：`loadUrl`/`loadDataWithBaseURL` 前的校验只看 `host`（`uri.getHost().equals(...)`）**不看 `scheme`**，或用 `String.contains()`/`startsWith` 做域名校验 → `javascript:`/`file:`/`content:` 可绕过加载。**跨文件追 URL 实参来源**（Intent/深链/网络响应是否可控）。 |
| `R-AI-019` | **多次 loadUrl 的 Universal-XSS**：`onCreate`/`onNewIntent`/`onResume` 多次 `loadUrl(intentData)`——第一次加载合法域、第二次注入 `javascript:` → 在**合法域上下文**执行任意 JS。**必须跨生命周期入口确认是否多次用 Intent 数据加载**。 |
| `R-AI-020` | **exported 组件 → WebView 越权数据流**：`exported=true`（或带 `<intent-filter>`/深链）的 Activity 取 `getIntent().getData()`/extra **不校验**就 `loadUrl` → 深链劫持、令牌窃取。**跨 `AndroidManifest.xml` + 代码追**：组件是否真导出、URL 是否真可控。 |
| `R-AI-021` | **`shouldOverrideUrlLoading` 的 intent:// 重定向**：回调里 `Intent.parseUri(url, 0)` 后直接 `startActivity`/`getContext().startActivity`，未校验目标组件/scheme → 拉起任意或内部组件。也含自定义 scheme 未校验来源就执行敏感动作。 |
| `R-AI-022` | **`loadDataWithBaseURL` 的 baseUrl/data 可控**：`baseUrl` 或 `data` 形参来自外部输入 → 在任意 `baseUrl` 域上 XSS（可读该域 cookie/storage）。**追这两个实参的源头是否可控**。 |
| `R-AI-023` | **JS 注入**：`evaluateJavascript(...)` 或 `loadUrl("javascript:" + x)` 的脚本串**用外部数据字符串拼接**（未转义/未走 `addJavascriptInterface` 参数序列化）→ 注入到页面上下文。 |
| `R-AI-024` | **`onShowFileChooser` 回调 URI 不校验**：`WebChromeClient.onShowFileChooser` → `ValueCallback.onReceiveValue(new Uri[]{ data.getData() })` 用隐式 Intent 取文件且**不校验返回 URI 来源** → 攻击者拦截 Intent、回传受保护文件 URI 被 WebView 读取。 |
| `R-AI-025` | **旧 API 的 Uri 校验绕过**：域名校验在低 `minSdkVersion` 下失效——`\\@` 反斜杠绕过（API<25，`https://attacker.com\@trusted.com`）、HierarchicalUri 反射使 `getHost()` 与实际加载不一致（API<28）。**结合 `minSdkVersion` 判断校验是否在目标版本可被绕**。 |

> **WebView 组 FP 提示：** ① `loadUrl` 实参是**硬编码常量/`BuildConfig` 注入**（来源不可控）= FP；② 校验同时核对了 `scheme` 白名单（仅 `https`）+ host = 已防护；③ `setJavaScriptEnabled(false)` 或根本未开 JS 时，多数 XSS 类不成立；④ `WebViewAssetLoader`/`androidx.webkit` 受控加载本地资源 = 合理。**条件触发：URL/baseUrl/scheme 的可控性必须用 `nav_tools.py --action trace-origin` 追到源头**（Intent/网络=真，常量=FP），同 §通用 FP 提示。

## 并发、生命周期与错误恢复

| id | 狩猎线索 |
|---|---|
| `R-AI-005` | **并发竞态**：check-then-act 非原子（先 `containsKey` 再 `put`）；共享可变状态无同步；双重检查锁缺 `volatile`；回调在非预期线程改 UI 状态。 |
| `R-AI-006` | **生命周期错配**：长生命周期对象（单例 / static / Application）持有短生命周期引用（Activity / View / Context）→ 泄漏；回调注册了未注销，且注册方比被注册方活得久。**跨文件确认注册/注销是否成对**。**FP：** 单例持有的 `Context` 经回溯调用方实为 Application / `getApplicationContext()`（生命周期与进程一致，不构成泄漏）——必须追到调用方的实参类型再判。 |
| `R-AI-007` | **错误恢复逻辑反了**：重试在非幂等操作上导致重复副作用（重复扣费、重复下单）；失败后状态未回滚；`finally` 里再抛异常吞掉原始异常。 |
| `R-AI-008` | **缓存/状态一致性**：缓存失效条件写反或缺失（写入后未失效）；本地与远端状态分叉后无收敛；分页/去重键选错导致丢数据或重复。 |
| `R-AI-014` | **注册/注销不成对**：`register*` 的对应 `unregister*` 是否在**每条**生命周期退出路径（`onDestroy`/`onStop`/`onDestroyView`）都调用？只在一条分支注销，其它分支仍泄漏。 |
| `R-AI-015` | **WakeLock / 异步释放顺序**：`acquire` 后是否在所有路径 `release`？同步 `release` 早于异步工作完成 = 没保住电量保护或提前释放。 |
| `R-AI-016` | **重连退避 / 状态恢复**：长连接重连是否有退避（否则风暴）？重连后订阅/会话状态是否恢复（否则静默失效）？ |
| `R-AI-017` | **Fragment 作 LiveData owner**：Fragment 里 `observe` 是否误用 `this` 而非 `viewLifecycleOwner`（视图生命周期更短，导致泄漏/重复观察）。**FP：** 所在类是 Activity（`this` 合法）；已用 `viewLifecycleOwner`；观察的数据生命周期确为整个 Fragment。 |

## 性能与资源

| id | 狩猎线索 |
|---|---|
| `R-AI-009` | **主线程阻塞**：UI 线程上的同步 I/O / 网络 / 大 JSON 解析 / DB 查询（跨文件确认该方法是否在主线程被调用）。 |
| `R-AI-010` | **算法/数据结构劣化**：热路径里 O(n²)（循环内 `list.contains` / 循环内查 DB / N+1 查询）；可缓存的重复计算每帧重算。 |
| `R-AI-011` | **资源未及时释放**：Cursor/Stream/Bitmap 在某些分支未关闭（跨文件追所有 return 路径）；大对象在不需要后仍被强引用。 |

## 通用 FP 提示（压假阳性，对所有条目适用）

- **条件触发型缺陷必须回溯到源头（不是一跳）**：缺陷只有在上游源头成立时才发生的（静态单例持有 Context、主线程阻塞、越权数据流…），**仅凭 sink 处的模式不算成立**。关键值常**层层透传**，必须用 `nav_tools.py --action trace-origin` 沿**整条调用链**把它追到终端源头——例如静态 Context 泄漏要把 `init()` 的 Context 实参一路追到 `Application`（不泄漏）还是 `Activity/Service/View`（真泄漏）。验证阶段对这类缺陷以 nav_tools（默认 tree-sitter AST 精确调用导航，source-nav 兜底）逐跳回溯取证为准（数据流类辅以 Semgrep taint + 人工追源；见 `agents/verifier.md`「条件触发型规则」「调用链取证工具」两节）。
- **资源"责任转移"**：方法把 `Cursor`/`Stream` **返回给调用方**时，关闭责任已转移——抽查调用点再判，不要在定义处误报未关闭。
- **缓解上下文**：外层 `try-finally`、null 保护、`@WorkerThread`/`@MainThread` 注解、`BuildConfig.DEBUG` 门控、LRU/定期清理（对无界缓存）——命中但有缓解 = 假阳性。
- **主线程重活需回溯调用链**：阻塞操作要确认**确实在主线程被调**（回溯到 `onClick`/生命周期/`onReceive`/`Handler(mainLooper)`），否则是后台线程上的合理调用。

---

## 自由检测（不在上表内的）

读到下列"坏味道"即使没对应条目，也作为 `R-AI-FREE` 候选报出，在 `why` 里说清推测的缺陷与触发条件：
- 业务不变量被破坏（金额可为负、状态机非法跃迁、计数器可溢出）；
- 边界缺失（空集合 / 超长输入 / 时区 / 并发用户）下的明显错误；
- 复制粘贴遗留的逻辑错误（条件判断与注释/变量名矛盾）。

**纪律：** 每条候选必须能指向**具体 file:line + 一句可检验的缺陷假设**。写不出"在什么条件下会出什么错"的，不要报——交给验证闸只会被丢弃，徒增成本。
