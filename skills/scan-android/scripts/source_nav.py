#!/usr/bin/env python3
"""
source_nav.py — 纯标准库的源码级调用/类型导航（tree-sitter 语法索引不可用时的兜底后端）。

目标导向：导航的目的是给 verifier 提供「谁调用了它 / 它定义在哪 / 谁继承它」这类**调用逻辑**，
用来判断漏洞与业务逻辑是否成立。默认后端是 tree-sitter（repo_map.py，语法级 def/ref）；
但它需要 repomap venv（tree-sitter + language-pack）。本后端**只用 Python 标准库、零依赖**，
直接对源码做 AST 友好的正则检索，输出与 tree-sitter 后端**同形**的结果——保证在**任意**工程、
**裸机/离线**环境上跨文件取证都能跑出东西（nav_tools 回退到它时会打印 [WARN] nav-degraded 告警）。

精度说明：基于「方法名 + 调用/声明形态」的名义匹配，不解析重载/泛型/具体类型/动态分派，
并可能命中注释或字符串。跨文件关系只提供保守线索；反射和间接调用仍可能漏报，所有命中必须读源码复核。

仅用 Python 标准库（os.walk + re）。只读被扫描仓库。
CLI 与 nav_tools.py 对齐：--action callers|definition|hierarchy|trace-origin --symbol "Class#method"。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

_SRC_EXT = (".java", ".kt", ".aidl")
_SKIP_DIRS = {
    "build", ".gradle", ".git", "generated", ".idea", "node_modules",
    ".cxx", ".externalNativeBuild", "CMakeFiles", ".scan", ".vscode", "docs",
}
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
_TYPE_DECL_ANY_RE = re.compile(r"\b(?:class|interface|object|enum\s+class|enum)\s+([A-Za-z_]\w*)\b")


def _method_hint(symbol: str) -> str | None:
    if "#" in symbol:
        tail = symbol.split("#", 1)[1].split("(")[0].strip().strip("`")
        return tail or None
    return None


def _type_hint(symbol: str) -> str:
    return symbol.split("#", 1)[0].split(".")[-1].strip().strip("`")


def _class_hint(symbol: str) -> str:
    if "#" not in symbol:
        return ""
    hint = _type_hint(symbol)
    return "" if hint.lower() in {"", "any", "unknown", "*"} else hint


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

    def _enclosing_type(self, lines: list[str], idx: int) -> str:
        """Best-effort owning type for fallback disambiguation."""
        for i in range(idx, -1, -1):
            match = _TYPE_DECL_ANY_RE.search(lines[i])
            if match and (i == idx or sum(line.count("{") - line.count("}") for line in lines[i:idx + 1]) > 0):
                return match.group(1)
        return ""

    @staticmethod
    def _inferred_receiver_type(lines: list[str], receiver: str) -> str:
        if not receiver or receiver in {"this", "super"}:
            return ""
        text = "\n".join(lines)
        name = re.escape(receiver.rsplit(".", 1)[-1])
        for pattern in (
            rf"\b([A-Z][A-Za-z0-9_$.]*)\s+{name}\s*(?:[=;,)]|$)",
            rf"\b(?:val|var)\s+{name}\s*:\s*([A-Z][A-Za-z0-9_$.]*)",
            rf"\b(?:val|var)\s+{name}\s*=\s*([A-Z][A-Za-z0-9_$.]*)\s*\(",
        ):
            match = re.search(pattern, text, re.MULTILINE)
            if match:
                return match.group(1).rsplit(".", 1)[-1]
        return ""

    # ---- 导航接口（与 tree-sitter 后端同形） ----
    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        method = _method_hint(symbol)
        out: list[dict[str, Any]] = []
        if method:
            class_hint = _class_hint(symbol)
            for p in self._source_files():
                rel, lines = self._lines_of(p)
                for i, ln in enumerate(lines):
                    owner = self._enclosing_type(lines, i)
                    if _is_decl_of(ln, method) and (not class_hint or owner == class_hint):
                        out.append({
                            "symbol": f"{owner}#{method}" if owner else f"{rel}#{method}",
                            "file": rel, "line": i + 1, "owner": owner,
                        })
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
        class_hint = _class_hint(method)
        out: list[dict[str, Any]] = []
        for p in self._source_files():
            rel, lines = self._lines_of(p)
            for i, ln in enumerate(lines):
                if _is_call_of(ln, m):
                    owner = self._enclosing_type(lines, i)
                    enclosing = self._enclosing(lines, i)
                    receiver_match = re.search(
                        r"(?:\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*)?"
                        + re.escape(m) + r"\s*\(", ln,
                    )
                    receiver = receiver_match.group(1) if receiver_match and receiver_match.group(1) else ""
                    receiver_tail = receiver.rsplit(".", 1)[-1]
                    inferred_type = self._inferred_receiver_type(lines, receiver)
                    if not class_hint:
                        confidence, matched_by = "nominal", "method-name"
                    elif receiver_tail == class_hint:
                        confidence, matched_by = "high", "explicit-receiver"
                    elif inferred_type == class_hint:
                        confidence, matched_by = "high", "inferred-receiver-type"
                    elif re.search(
                        rf"\b{re.escape(class_hint)}\b[^;\n]*\.\s*{re.escape(m)}\s*\(", ln,
                    ):
                        confidence, matched_by = "nominal", "type-reference-chain"
                    elif owner == class_hint and receiver_tail in {"", "this"}:
                        confidence, matched_by = "high", "same-owner"
                    elif receiver_tail == "super":
                        confidence, matched_by = "ambiguous", "super-dispatch"
                    else:
                        confidence, matched_by = "ambiguous", "method-name-only"
                    out.append({
                        "file": rel, "line": i + 1,
                        "snippet": ln.strip()[:200],
                        "enclosing_symbol": f"{owner}#{enclosing}" if owner and enclosing else enclosing,
                        "receiver": receiver,
                        "receiver_type": inferred_type,
                        "confidence": confidence,
                        "matched_by": matched_by,
                    })
        return sorted(out, key=lambda item: (
            {"high": 0, "nominal": 1, "ambiguous": 2}.get(item["confidence"], 3),
            item["file"], item["line"],
        ))

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
        defs = self.get_definition(symbol)
        def expand(name: str, depth: int, path: frozenset[str]) -> list[dict[str, Any]]:
            # Cycle detection must be path-local.  A global visited set silently
            # drops sibling branches when two callers have the same method name.
            if depth <= 0 or name in path or not name:
                return [{"truncated": True, "reason": "达到深度上限或检测到当前路径中的环"}] if (name in path or depth <= 0) and name else []
            next_path = path | {name}
            callers = self.get_callers(name)
            nodes: list[dict[str, Any]] = []
            for c in callers[:max_callers]:
                node: dict[str, Any] = dict(c)
                enc = c.get("enclosing_symbol") or ""
                if c.get("confidence") == "ambiguous":
                    node["not_expanded"] = True
                    node["note"] = "歧义名称匹配仅作线索，不参与递归调用链"
                elif enc and depth > 1:
                    node["callers"] = expand(enc, depth - 1, next_path)
                elif not enc:
                    node["note"] = "无法定位调用所在方法（lambda/匿名类/字段初始化，请 Read 复核）"
                nodes.append(node)
            if len(callers) > max_callers:
                nodes.append({"truncated": True, "reason": f"调用方过多，仅列前 {max_callers} 个"})
            if not callers:
                nodes.append({
                    "terminal_no_callers": True,
                    "entry_point": False,
                    "note": "静态名义索引未找到调用方；可能是框架入口、未调用代码、接口分派或反射，须结合 Manifest/override 复核",
                })
            return nodes

        chains = []
        targets = defs or [{"symbol": symbol, "file": "", "line": 0}]
        for d in targets:
            chains.append({
                "symbol": d["symbol"],
                "definition": {"file": d["file"], "line": d["line"]},
                "callers": expand(d["symbol"] if defs else symbol, max_depth, frozenset()),
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
