#!/usr/bin/env python3
"""
source_nav.py — 纯标准库的源码级调用/类型导航（tree-sitter 精确层不可用时的兜底后端）。

目标导向：导航的目的是给 verifier 提供「谁调用了它 / 它定义在哪 / 谁继承它」这类**调用逻辑**，
用来判断漏洞与业务逻辑是否成立。默认精确层是 tree-sitter（repo_map.py，AST 精确、Java+Kotlin
无盲区）；但它需要 repomap venv（tree-sitter + language-pack）。本后端**只用 Python 标准库、零依赖**，
直接对源码做 AST 友好的正则检索，输出与 tree-sitter 后端**同形**的结果——保证在**任意**工程、
**裸机/离线**环境上跨文件取证都能跑出东西（nav_tools 回退到它时会打印 [WARN] nav-degraded 告警）。

精度说明：基于「方法名 + 调用/声明形态」的名义匹配，不解析重载/泛型/具体类型（与 tree-sitter
后端一样不消歧同名重载，但缺少 AST 精度：可能命中注释/字符串）。跨文件的调用方 / 定义 / 继承
关系**可靠召回**；同名歧义由调用方读 snippet 复核——verifier 本就逐跳 Read。

仅用 Python 标准库（os.walk + re）。只读被扫描仓库。
CLI 与 nav_tools.py 对齐：--action callers|definition|hierarchy|trace-origin --symbol "Class#method"。
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

_SRC_EXT = (".java", ".kt", ".aidl")
_SKIP_DIRS = {"build", ".gradle", ".git", "generated", ".idea", "node_modules"}
_MAX_FILE_BYTES = 800_000

# 控制流关键字——形如 name( 但不是方法声明/调用目标
_CTRL = {"if", "for", "while", "switch", "catch", "synchronized", "return",
         "new", "else", "do", "try", "when", "super", "this"}

_MODS = r"(?:public|private|protected|static|final|synchronized|abstract|native|default|override|open|internal|suspend)"
_COMMENT_RE = re.compile(r"^\s*(//|\*|/\*|\*/)")
# 任意方法声明行（用于求 enclosing）：有修饰符或 fun 或 返回类型 + 名字(
_DECL_ANY_RE = re.compile(
    r"^\s*(?:@\w[\w.]*(?:\([^)]*\))?\s*)*"          # 注解
    r"(?:" + _MODS + r"\s+)*"                          # 修饰符*
    r"(?:fun\s+)?"                                       # kotlin fun
    r"(?:[\w.$<>\[\],?&]+\s+)?"                          # 可选返回类型
    r"([A-Za-z_]\w*)\s*\("                              # 方法名(
)


def _method_hint(symbol: str) -> str | None:
    if "#" in symbol:
        tail = symbol.split("#", 1)[1].split("(")[0].strip().strip("`")
        return tail or None
    return None


def _type_hint(symbol: str) -> str:
    return symbol.split("#", 1)[0].split(".")[-1].strip().strip("`")


def _is_decl_of(line: str, method: str) -> bool:
    """该行是否为 method 的声明（而非调用/注释）。"""
    if _COMMENT_RE.match(line):
        return False
    if (method + "(") not in line.replace(" ", "") and not re.search(r"\b" + re.escape(method) + r"\s*\(", line):
        return False
    # kotlin fun
    if re.search(r"\bfun\s+" + re.escape(method) + r"\s*[(<]", line):
        return True
    # java: 修饰符 ... name(   或   返回类型 name(...) {|throws|;(接口)
    if re.search(r"(?:" + _MODS + r"\s+).*\b" + re.escape(method) + r"\s*\(", line):
        return True
    if re.search(r"[\w.$<>\[\],?&]+\s+" + re.escape(method) + r"\s*\([^;{]*\)\s*(?:\{|throws|;)\s*$", line):
        return True
    return False


def _is_call_of(line: str, method: str) -> bool:
    if _COMMENT_RE.match(line):
        return False
    if not re.search(r"(?:\.|\b)" + re.escape(method) + r"\s*\(", line):
        return False
    return not _is_decl_of(line, method)


class SourceNav:
    """编译无关的源码导航后端（与 nav_tools.NavTools 同接口子集）。"""

    def __init__(self, repo: str | Path):
        self.repo = Path(repo).resolve()
        self._files: list[Path] | None = None
        self._lines: dict[str, list[str]] = {}

    # ---- 文件/行缓存 ----
    def _source_files(self) -> list[Path]:
        if self._files is None:
            out: list[Path] = []
            for dp, dns, fns in os.walk(self.repo):
                dns[:] = [d for d in dns if d not in _SKIP_DIRS]
                for fn in fns:
                    if fn.endswith(_SRC_EXT):
                        out.append(Path(dp) / fn)
            self._files = out
        return self._files

    def _lines_of(self, p: Path) -> tuple[str, list[str]]:
        rel = p.relative_to(self.repo).as_posix()
        if rel not in self._lines:
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    self._lines[rel] = []
                else:
                    self._lines[rel] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._lines[rel] = []
        return rel, self._lines[rel]

    def _enclosing(self, lines: list[str], idx: int) -> str:
        """从 idx(0-based) 向上找最近的方法声明名（下一跳回溯目标）。"""
        for i in range(idx, -1, -1):
            m = _DECL_ANY_RE.match(lines[i])
            if m and m.group(1) not in _CTRL:
                return m.group(1)
        return ""

    # ---- 导航接口（与 tree-sitter 后端同形） ----
    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        method = _method_hint(symbol)
        out: list[dict[str, Any]] = []
        if method:
            for p in self._source_files():
                rel, lines = self._lines_of(p)
                for i, ln in enumerate(lines):
                    if _is_decl_of(ln, method):
                        out.append({"symbol": f"{rel}#{method}", "file": rel, "line": i + 1})
        else:
            t = _type_hint(symbol)
            decl = re.compile(r"\b(class|interface|object|enum)\s+" + re.escape(t) + r"\b")
            for p in self._source_files():
                rel, lines = self._lines_of(p)
                for i, ln in enumerate(lines):
                    if decl.search(ln):
                        out.append({"symbol": f"{rel}#{t}", "file": rel, "line": i + 1})
        return out

    def get_callers(self, method: str, depth: int = 1) -> list[dict[str, Any]]:
        m = _method_hint(method) or method
        out: list[dict[str, Any]] = []
        for p in self._source_files():
            rel, lines = self._lines_of(p)
            for i, ln in enumerate(lines):
                if _is_call_of(ln, m):
                    out.append({
                        "file": rel, "line": i + 1,
                        "snippet": ln.strip()[:200],
                        "enclosing_symbol": self._enclosing(lines, i),
                    })
        return out

    def get_type_hierarchy(self, type_name: str) -> dict[str, Any]:
        t = _type_hint(type_name)
        defs = self.get_definition(t)
        sub = re.compile(r"\b(class|interface|object|enum)\s+\w+[^{]*\b(?:extends|implements|:)\b[^{]*\b" + re.escape(t) + r"\b")
        refs: list[dict[str, Any]] = []
        for p in self._source_files():
            rel, lines = self._lines_of(p)
            for i, ln in enumerate(lines):
                if sub.search(ln):
                    refs.append({"file": rel, "line": i + 1, "snippet": ln.strip()[:200]})
        return {"definitions": defs, "references": refs}

    def trace_origin(self, symbol: str, max_depth: int = 6, max_callers: int = 25) -> dict[str, Any]:
        method = _method_hint(symbol) or symbol
        defs = self.get_definition(symbol)
        visited: set[str] = set()

        def expand(name: str, depth: int) -> list[dict[str, Any]]:
            if depth <= 0 or name in visited or not name:
                return [{"truncated": True, "reason": "达到深度上限或检测到环"}] if (name in visited or depth <= 0) and name else []
            visited.add(name)
            callers = self.get_callers(name)
            nodes: list[dict[str, Any]] = []
            for c in callers[:max_callers]:
                node: dict[str, Any] = dict(c)
                enc = c.get("enclosing_symbol") or ""
                if enc and depth > 1:
                    node["callers"] = expand(enc, depth - 1)
                elif not enc:
                    node["note"] = "无法定位调用所在方法（lambda/匿名类/字段初始化，请 Read 复核）"
                nodes.append(node)
            if len(callers) > max_callers:
                nodes.append({"truncated": True, "reason": f"调用方过多，仅列前 {max_callers} 个"})
            if not callers:
                nodes.append({"entry_point": True, "note": "无调用方（入口/未被调用/仅经接口或反射调用）"})
            return nodes

        chains = []
        targets = defs or [{"symbol": symbol, "file": "", "line": 0}]
        for d in targets:
            chains.append({
                "symbol": d["symbol"],
                "definition": {"file": d["file"], "line": d["line"]},
                "callers": expand(method, max_depth),
            })
        return {"target": symbol, "chains": chains, "backend": "source-nav"}


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="编译无关的源码级调用/类型导航 CLI")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--action", required=True,
                    choices=["callers", "definition", "hierarchy", "trace-origin"])
    ap.add_argument("--symbol", default="")
    ap.add_argument("--depth", type=int, default=6)
    args = ap.parse_args()

    nav = SourceNav(args.repo)
    if args.action == "callers":
        result: Any = nav.get_callers(args.symbol)
    elif args.action == "definition":
        result = nav.get_definition(args.symbol)
    elif args.action == "hierarchy":
        result = nav.get_type_hierarchy(args.symbol)
    else:
        result = nav.trace_origin(args.symbol, max_depth=args.depth)
    print(json.dumps(result, ensure_ascii=False, indent=2))
