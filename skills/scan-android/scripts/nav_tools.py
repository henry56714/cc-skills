#!/usr/bin/env python3
"""
LLM 导航工具 —— 跨文件调用/类型查询的统一门面，把 LLM 从"猜文件"变成"查索引"。

后端按 `nav_backend`（config 或 env `SCAN_ANDROID_NAV_BACKEND`，取值 auto|treesitter|source）选择：
  - treesitter（auto 首选）—— tree-sitter 语法级识别 def/ref，不误命中注释/字符串；
    同名重载、接收者类型与动态分派不消歧，必须由 verifier 逐跳 Read 复核。
  - source-nav（纯标准库兜底）—— 正则名义级索引，永远可用。**仅当 tree-sitter
    不可用时启用，并打印 `[WARN] nav-degraded` 告警。**

用法（由 verifier agent 调用）:
  from nav_tools import NavTools
  nav = NavTools(repo="/abs/path/to/project")
  nav.start()                       # 就绪后端（幂等）
  callers = nav.get_callers("DbSizeManager#init")
  defs    = nav.get_definition("DbSizeManager#init")

调用图能力:
  get_definition / get_callers / get_callees / get_type_hierarchy / trace_origin
数据流/污点可达性（get_dataflow_to）不提供 —— 见下方说明（Semgrep taint + AI 狩猎覆盖）。

CLI:
  nav_tools.py --repo <repo> --action callers --symbol "DbSizeManager#init"
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _log(msg: str) -> None:
    print(f"[nav_tools] {msg}", file=sys.stderr, flush=True)


def _nav_backend_pref(repo: Path) -> str:
    """读取导航后端偏好：env `SCAN_ANDROID_NAV_BACKEND` 优先，其次 `.scan/config.json` 的
    `nav_backend`。取值 auto|treesitter|source，默认 auto。
    `auto` = treesitter（语法级索引）→ source（纯标准库兜底）。"""
    val = (os.environ.get("SCAN_ANDROID_NAV_BACKEND") or "").strip().lower()
    if not val:
        try:
            cfg_path = repo / ".scan" / "config.json"
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                val = str(cfg.get("nav_backend", "")).strip().lower()
        except Exception:
            val = ""
    return val if val in ("auto", "treesitter", "source") else "auto"


class NavTools:
    """tree-sitter 语法索引 + source-nav 正则兜底支撑的 LLM 导航工具集。"""

    def __init__(self, repo: str | Path):
        self.repo = Path(repo).resolve()
        self._src: Any = None          # source_nav.SourceNav 纯标准库兜底后端
        self._ts: Any = None           # repo_map.RepoMap / RepoMapNav 精确后端（tree-sitter）
        self.backend: str = ""         # "treesitter" | "source"
        self.degraded: bool = False    # True = tree-sitter 不可用、已回退 source-nav（附告警）

    # ------------------------------------------------------------------
    # 索引生命周期
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """就绪导航后端（幂等）。后端选择（默认 auto）：

        - `nav_backend=treesitter`（auto 首选）：tree-sitter 解析 Java/Kotlin，
          语法级识别 def/ref（不误命中注释/字符串，enclosing scope 较可靠）。同名重载、
          接收者类型与动态分派不消歧——必须由 verifier 逐跳 Read 复核。
          需 tree-sitter（本进程可导入或 repomap venv 就绪）；不可用则**告警并回退 source-nav**。
        - 兜底：纯标准库 source-nav（正则名义级，永远可用）。仅当 tree-sitter 不可用时启用，
          且会打印 `[WARN] nav-degraded` 告警——精度低于 tree-sitter，请优先修复 repomap venv。**

        无论选择如何，最终都会落到一个可用后端。恒返回 True。"""
        if self._src is not None or self._ts is not None:
            return True
        pref = _nav_backend_pref(self.repo)

        # 0) tree-sitter 语法索引（auto 首选 或显式 treesitter）
        if pref in ("auto", "treesitter"):
            try:
                from repo_map import repomap_available, RepoMap, RepoMapNav, _ts_available
                if repomap_available():
                    self._ts = RepoMap(self.repo) if _ts_available() else RepoMapNav(self.repo)
                    self.backend = "treesitter"
                    _log("导航后端: treesitter（语法级 def/ref；重载/接收者/动态分派由 Read 复核）")
                    return True
                _log("tree-sitter 不可用（repomap venv 未装）")
            except Exception as e:
                _log(f"tree-sitter 后端初始化失败: {e}")

        # 1) 兜底：纯标准库源码级导航（名义级精度，同名歧义由 Read 复核）
        from source_nav import SourceNav
        self._src = SourceNav(self.repo)
        self.backend = "source"
        self.degraded = True
        if pref != "source":
            # 用户期望 tree-sitter 但未就绪 → 明确告警
            _log("[WARN] nav-degraded: tree-sitter 语法索引不可用，已回退 source-nav（纯标准库，正则名义级）。"
                 "请安装 repomap venv（preflight 会自动装 tree-sitter + tree-sitter-language-pack）以恢复精确导航。")
        else:
            _log("导航后端: source-nav（纯标准库兜底；正则名义级线索，需逐跳 Read）")
        return True

    # 兼容旧调用名（verifier 历史脚本可能调用 start_server / stop_server）
    def start_server(self) -> bool:
        return self.start()

    def stop_server(self) -> None:
        self._ts = None
        self._src = None

    # ------------------------------------------------------------------
    # 导航工具接口（verifier agent 调用）
    # ------------------------------------------------------------------

    def _backend(self):
        """返回当前后端对象（tree-sitter 语法索引优先，否则 source-nav 兜底）。"""
        self.start()
        return self._ts if self._ts is not None else self._src

    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        """查找符号定义位置。symbol 为 `Class#method` 子串，如 "DbSizeManager#init"。
        返回 [{symbol, file, line}]"""
        return self._backend().get_definition(symbol)

    def get_callers(self, method: str, depth: int = 1) -> list[dict[str, Any]]:
        """查找所有调用方/引用点。返回 [{file, line, enclosing_symbol, snippet}]
        snippet = 调用点源码行；enclosing_symbol = 发起该调用的方法（下一跳回溯目标）。"""
        return self._backend().get_callers(method, depth)

    def get_callees(self, method: str) -> list[dict[str, Any]]:
        """查找某方法体内调用的子方法（callees）。

        两个后端都按 occurrence/名义匹配，未单独物化 callee 边。因此这里返回方法的定义
        位置，由 verifier 用 Read 打开方法体、对体内出现的符号逐个 get_definition 解析
        —— 这是最可靠的 callee 取证方式。返回 [{symbol, file, line, hint}]。
        """
        defs = self._backend().get_definition(method)
        for d in defs:
            d["hint"] = "用 Read 打开此方法体，对体内符号逐个 get_definition 得到 callees"
        return defs

    def get_type_hierarchy(self, type_name: str) -> dict[str, Any]:
        """查找类型的定义与所有引用点（近似继承/使用关系）。
        返回 {definitions: [...], references: [...]}，verifier 结合 Read 复核继承声明。
        """
        return self._backend().get_type_hierarchy(type_name)

    def get_dataflow_to(self, sink_method: str, source_methods: list[str] | None = None) -> list[dict[str, Any]]:
        """数据流/污点可达性 —— 导航后端不提供。

        tree-sitter / source-nav 都是**调用图/类型**导航，不含数据流分析。污点类缺陷改由
        Semgrep（taint 模式）+ AI 狩猎（rules/ai/）覆盖。本方法保留接口以兼容旧调用，恒返回空。
        """
        _log("get_dataflow_to: 导航后端不做数据流；污点检测见 Semgrep + rules/ai/hunting.md")
        return []

    def trace_origin(self, symbol: str, max_depth: int = 6, max_callers: int = 25) -> dict[str, Any]:
        """逐跳向上回溯调用链（条件触发型规则的核心取证工具）。

        从 `symbol`（`Class#method` 子串）解析出的方法定义出发，递归列出
        「谁调用了它 → 调用所在方法 → 谁又调用了那个方法 → …」，每跳附调用点源码
        `snippet` 与所在方法 `enclosing_symbol`，直到索引无调用方或达 max_depth。

        无 AST 实参映射：本工具给出调用方链 + 每跳源码，由验证器读 snippet 沿目标实参
        （如 Context）人工判定其真实来源（Application / Activity / 字面量 / 外部输入）。

        返回 {target, chains: [节点树]}；节点 = {file,line,snippet,enclosing_symbol,callers:[...]}。
        """
        return self._backend().trace_origin(symbol, max_depth=max_depth, max_callers=max_callers)

    def raw_query(self, *_args, **_kwargs) -> Any:
        """已废弃（无图查询后端）。"""
        _log("raw_query: 已废弃；请用 get_callers/get_definition/trace_origin")
        return None


# ------------------------------------------------------------------
# CLI 入口（供 verifier agent 直接调用）
# ------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="LLM 跨文件导航工具 CLI（tree-sitter 语法索引 + source-nav 兜底）")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--action", required=True,
                    choices=["callers", "callees", "definition", "hierarchy", "dataflow", "trace-origin"])
    ap.add_argument("--symbol", default="")
    ap.add_argument("--depth", type=int, default=6, help="trace-origin 的最大回溯深度")
    ap.add_argument("--sources", nargs="*", default=None)
    args = ap.parse_args()

    nav = NavTools(args.repo)
    nav.start()  # 恒返回 True（tree-sitter 不可用会告警并回退 source-nav）

    result: Any
    if args.action == "callers":
        result = nav.get_callers(args.symbol)
    elif args.action == "callees":
        result = nav.get_callees(args.symbol)
    elif args.action == "definition":
        result = nav.get_definition(args.symbol)
    elif args.action == "hierarchy":
        result = nav.get_type_hierarchy(args.symbol)
    elif args.action == "dataflow":
        result = nav.get_dataflow_to(args.symbol, args.sources)
    elif args.action == "trace-origin":
        result = nav.trace_origin(args.symbol, max_depth=args.depth)
    else:
        result = None

    print(json.dumps(result, ensure_ascii=False, indent=2))
