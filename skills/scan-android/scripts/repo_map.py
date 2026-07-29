#!/usr/bin/env python3
"""
repo_map.py — tree-sitter 驱动的跨文件「代码地图」+ AST 精确调用/类型导航（唯一精确层）。

动机（见 SKILL.md 第 5.5 步与 CLAUDE.md「Engine set」）：
  hunter（AI 检测子代理）过去只拿到批次文件、孤立 Read，**既无 repo 全局代码地图、也不能查调用关系**
  → 形不成跨文件漏洞假设。本模块复刻 Aider `repomap.py` 的思路，但用 tree-sitter-language-pack 直接
  驱动，并**自备 Kotlin tags**（Aider 只有 java-tags.scm，照搬会让 Android 的 Kotlin 成为盲区）：

    1. tree-sitter 解析 Java/Kotlin 源，用 tags 查询（scripts/tags/*.scm）抽取【定义】+【引用】；
    2. 建符号引用图，纯标准库幂迭代 PageRank 排序（被引多的类/方法权重高）；
    3. 在 token 预算内输出签名骨架（函数体折叠为 `...`）——「全局地图」或「聚焦地图」；
    4. 同时暴露与 source_nav 同接口的 get_callers/get_definition/get_type_hierarchy/trace_origin，
       供 nav_tools.py 作**唯一精确后端**（AST 精确：不误命中注释/字符串，enclosing scope 精确）。

诚实取舍：AST 精确识别 def/ref，但**不解析重载/接收者类型**——常见名（init/d）消歧仍是名义级，
由 verifier 逐跳 Read 补齐（与 source-nav 一致）。相比 source-nav 的正则，精度提升在「不误命中
非代码文本 + enclosing 精确 + Kotlin 结构正确」；相比 joern 放弃了编译器级消歧，换来免编译 +
Kotlin 无盲区 + 兼服务 hunter。

依赖与降级：
  - tree-sitter + tree-sitter-language-pack 装在独立 venv（~/.scan-android/repomap-venv/，比照 semgrep）。
  - 本脚本被系统 python 启动时，若检测到 tree-sitter 不可导入但 venv 存在 → **自动 re-exec 到 venv python**；
    venv 也没有 → **回退 source_nav**（正则名义级，永远能跑）。保证任意工程都能跑出结果。

CLI（与 nav_tools/source_nav 对齐）：
  repo_map.py --repo <root> --action map --scope-files <f> [--budget 8000]
  repo_map.py --repo <root> --action map --batch-file <hunt_batch_N.json> [--budget 6000] [--out <md>]
  repo_map.py --repo <root> --action callers|definition|hierarchy|trace-origin --symbol "Class#method"
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

SKILL_SCRIPTS = Path(__file__).resolve().parent
TAGS_DIR = SKILL_SCRIPTS / "tags"
REPOMAP_VENV = Path(os.environ.get(
    "SCAN_ANDROID_REPOMAP_VENV", Path.home() / ".scan-android" / "repomap-venv"))

_SRC_LANG = {".java": "java", ".kt": "kotlin"}
_SKIP_DIRS = {"build", ".gradle", ".git", "generated", ".idea", "node_modules"}
_MAX_FILE_BYTES = 800_000
_CHARS_PER_TOKEN = 4  # 粗略 token 估算（char/4），仅用于预算截断


def _log(msg: str) -> None:
    print(f"[repo_map] {msg}", file=sys.stderr, flush=True)


def _repomap_python() -> Path:
    if platform.system() == "Windows":
        return REPOMAP_VENV / "Scripts" / "python.exe"
    return REPOMAP_VENV / "bin" / "python"


def _ts_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_language_pack  # noqa: F401
        return True
    except Exception:
        return False


def repomap_available() -> bool:
    """本后端是否可用：当前解释器能 import tree-sitter，或 repomap venv 已就绪。"""
    return _ts_available() or _repomap_python().exists()


# ──────────────────────────────────────────────────────────────────────────────
# tree-sitter 解析 + tags 抽取（仅在 tree-sitter 可导入时可实例化）
# ──────────────────────────────────────────────────────────────────────────────

_METHOD_DECL_TYPES = {"method_declaration", "constructor_declaration", "function_declaration"}


class RepoMap:
    """tree-sitter 驱动的代码地图 + AST 导航。需 tree-sitter 在本解释器可用。"""

    def __init__(self, repo: str | Path):
        from tree_sitter_language_pack import get_language, get_parser
        self._get_language = get_language
        self._get_parser = get_parser
        self.repo = Path(repo).resolve()
        # tree-sitter >=0.25 用 Query(lang, src) + QueryCursor(q).captures()；
        # 旧版用 lang.query(src) + q.captures()。构造时探测一次。
        try:
            from tree_sitter import Query, QueryCursor  # noqa: F401
            self._Query = Query
            self._QueryCursor = QueryCursor
        except Exception:
            self._Query = None
            self._QueryCursor = None
        self._parsers: dict[str, Any] = {}
        self._queries: dict[str, Any] = {}
        self._defs: list[dict[str, Any]] | None = None   # {name, kind, file, line, sig}
        self._refs: list[dict[str, Any]] | None = None    # {name, kind, file, line, enclosing, snippet}

    # ---- tree-sitter 资源 ----
    def _parser(self, lang: str):
        if lang not in self._parsers:
            self._parsers[lang] = self._get_parser(lang)
        return self._parsers[lang]

    def _query(self, lang: str):
        if lang not in self._queries:
            scm = (TAGS_DIR / f"{lang}-tags.scm").read_text(encoding="utf-8")
            language = self._get_language(lang)
            if self._Query is not None:               # tree-sitter >=0.25
                self._queries[lang] = self._Query(language, scm)
            else:                                       # 旧版
                self._queries[lang] = language.query(scm)
        return self._queries[lang]

    def _captures(self, query, root) -> list[tuple[Any, str]]:
        """兼容新旧 tree-sitter API：统一返回 [(node, capture_name), ...]。"""
        if self._QueryCursor is not None:               # >=0.25: QueryCursor(q).captures()
            res = self._QueryCursor(query).captures(root)
        else:
            res = query.captures(root)
        if isinstance(res, dict):                       # {name: [nodes]}
            return [(n, name) for name, nodes in res.items() for n in nodes]
        return list(res)                                # 旧版: [(node, name)]

    @staticmethod
    def _text(node) -> str:
        try:
            return node.text.decode("utf-8", "replace")
        except Exception:
            return ""

    def _enclosing_name(self, node) -> str:
        """向上找最近的方法/函数/构造声明名（下一跳回溯目标）。"""
        cur = node.parent
        while cur is not None:
            if cur.type in _METHOD_DECL_TYPES:
                nm = cur.child_by_field_name("name")
                if nm is not None:
                    return self._text(nm)
                for ch in cur.children:  # kotlin function_declaration 无 name 字段
                    if ch.type in ("simple_identifier", "identifier"):
                        return self._text(ch)
            cur = cur.parent
        return ""

    # ---- 文件遍历 ----
    def _source_files(self) -> list[Path]:
        out: list[Path] = []
        for dp, dns, fns in os.walk(self.repo):
            dns[:] = [d for d in dns if d not in _SKIP_DIRS]
            norm = dp.replace("\\", "/") + "/"
            if "/src/test/" in norm or "/src/androidTest/" in norm or "/src/AndroidTest/" in norm:
                continue  # 测试代码不进地图/导航索引
            for fn in fns:
                if Path(fn).suffix in _SRC_LANG:
                    out.append(Path(dp) / fn)
        return out

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.repo).as_posix()

    # ---- 建立 def/ref 索引 ----
    def build_index(self) -> None:
        if self._defs is not None:
            return
        defs: list[dict[str, Any]] = []
        refs: list[dict[str, Any]] = []
        for p in self._source_files():
            lang = _SRC_LANG[p.suffix]
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    continue
                src = p.read_bytes()
            except OSError:
                continue
            try:
                tree = self._parser(lang).parse(src)
                caps = self._captures(self._query(lang), tree.root_node)
            except Exception as e:
                _log(f"解析失败 {self._rel(p)}: {e}")
                continue
            lines = src.split(b"\n")
            rel = self._rel(p)
            for node, cap in caps:
                if cap.startswith("name.definition."):
                    kind = cap.rsplit(".", 1)[1]
                    # 签名行取「名字所在行」而非声明起始行——后者可能是 @Override 等注解行
                    row = node.start_point[0]
                    sig = lines[row].decode("utf-8", "replace").strip()[:200] if row < len(lines) else ""
                    defs.append({"name": self._text(node), "kind": kind,
                                 "file": rel, "line": row + 1, "sig": sig})
                elif cap.startswith("name.reference."):
                    kind = cap.rsplit(".", 1)[1]
                    row = node.start_point[0]
                    snip = lines[row].decode("utf-8", "replace").strip()[:200] if row < len(lines) else ""
                    refs.append({"name": self._text(node), "kind": kind,
                                 "file": rel, "line": row + 1,
                                 "enclosing": self._enclosing_name(node), "snippet": snip})
        self._defs, self._refs = defs, refs

    # ---- PageRank（纯标准库幂迭代，文件级引用图） ----
    def _pagerank_files(self, damping: float = 0.85, iters: int = 30) -> dict[str, float]:
        self.build_index()
        assert self._defs is not None and self._refs is not None
        # name -> 定义它的文件集合
        name_files: dict[str, set[str]] = {}
        for d in self._defs:
            name_files.setdefault(d["name"], set()).add(d["file"])
        files = sorted({d["file"] for d in self._defs} | {r["file"] for r in self._refs})
        if not files:
            return {}
        idx = {f: i for i, f in enumerate(files)}
        n = len(files)
        # 出边权重：文件 A 引用了在文件 B 定义的符号 → A→B +1
        out_w: list[dict[int, float]] = [dict() for _ in range(n)]
        for r in self._refs:
            src = r["file"]
            for tgt in name_files.get(r["name"], ()):  # 名义级：同名多定义均计入
                if tgt == src:
                    continue
                out_w[idx[src]][idx[tgt]] = out_w[idx[src]].get(idx[tgt], 0.0) + 1.0
        rank = [1.0 / n] * n
        for _ in range(iters):
            new = [(1.0 - damping) / n] * n
            for a in range(n):
                tot = sum(out_w[a].values())
                if tot <= 0:
                    # 悬挂节点：均摊
                    share = damping * rank[a] / n
                    for b in range(n):
                        new[b] += share
                    continue
                for b, w in out_w[a].items():
                    new[b] += damping * rank[a] * (w / tot)
            rank = new
        return {f: rank[idx[f]] for f in files}

    # ---- 导航接口（与 source_nav 同形，供 nav_tools 路由） ----
    def _method_hint(self, symbol: str) -> str | None:
        if "#" in symbol:
            tail = symbol.split("#", 1)[1].split("(")[0].strip().strip("`")
            return tail or None
        return None

    def _type_hint(self, symbol: str) -> str:
        return symbol.split("#", 1)[0].split(".")[-1].strip().strip("`")

    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        self.build_index()
        assert self._defs is not None
        method = self._method_hint(symbol)
        if method:
            return [{"symbol": f"{d['file']}#{d['name']}", "file": d["file"], "line": d["line"]}
                    for d in self._defs if d["name"] == method and d["kind"] in ("method",)]
        t = self._type_hint(symbol)
        return [{"symbol": f"{d['file']}#{d['name']}", "file": d["file"], "line": d["line"]}
                for d in self._defs if d["name"] == t and d["kind"] in ("class", "interface", "type")]

    def get_callers(self, method: str, depth: int = 1) -> list[dict[str, Any]]:
        self.build_index()
        assert self._refs is not None
        m = self._method_hint(method) or method
        return [{"file": r["file"], "line": r["line"], "snippet": r["snippet"],
                 "enclosing_symbol": r["enclosing"]}
                for r in self._refs if r["name"] == m and r["kind"] == "method"]

    def get_type_hierarchy(self, type_name: str) -> dict[str, Any]:
        self.build_index()
        assert self._defs is not None and self._refs is not None
        t = self._type_hint(type_name)
        defs = [{"symbol": f"{d['file']}#{d['name']}", "file": d["file"], "line": d["line"]}
                for d in self._defs if d["name"] == t and d["kind"] in ("class", "interface", "type")]
        refs = [{"file": r["file"], "line": r["line"], "snippet": r["snippet"]}
                for r in self._refs
                if r["name"] == t and r["kind"] in ("class", "interface", "implementation")]
        return {"definitions": defs, "references": refs}

    def trace_origin(self, symbol: str, max_depth: int = 6, max_callers: int = 25) -> dict[str, Any]:
        method = self._method_hint(symbol) or symbol
        defs = self.get_definition(symbol)
        visited: set[str] = set()

        def expand(name: str, depth: int) -> list[dict[str, Any]]:
            if depth <= 0 or name in visited or not name:
                return [{"truncated": True, "reason": "达到深度上限或检测到环"}] if name and (name in visited or depth <= 0) else []
            visited.add(name)
            callers = self.get_callers(name)
            nodes: list[dict[str, Any]] = []
            for c in callers[:max_callers]:
                node = dict(c)
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
        for d in (defs or [{"symbol": symbol, "file": "", "line": 0}]):
            chains.append({"symbol": d["symbol"], "definition": {"file": d["file"], "line": d["line"]},
                           "callers": expand(method, max_depth)})
        return {"target": symbol, "chains": chains, "backend": "treesitter"}

    # ---- 地图渲染 ----
    def _file_skeleton(self, rel: str) -> list[str]:
        """一个文件的签名骨架（类/方法/接口声明行，函数体折叠为 ...）。"""
        assert self._defs is not None
        ds = sorted((d for d in self._defs if d["file"] == rel), key=lambda d: d["line"])
        if not ds:
            return []
        out = [f"### {rel}"]
        for d in ds:
            out.append(f"  {d['sig']}" + ("" if d["sig"].rstrip().endswith(("{", ";")) else "  ...")
                       if d["kind"] == "method" else f"  {d['sig']}")
        return out

    def global_map(self, budget_tokens: int) -> str:
        ranks = self._pagerank_files()
        ranked = sorted(ranks, key=lambda f: -ranks[f])
        out: list[str] = ["# 代码地图（PageRank 排序的签名骨架；函数体已折叠）", ""]
        used = 0
        for rel in ranked:
            block = self._file_skeleton(rel)
            if not block:
                continue
            chunk = "\n".join(block) + "\n"
            cost = len(chunk) // _CHARS_PER_TOKEN
            if used + cost > budget_tokens:
                out.append(f"\n_（预算 {budget_tokens} tok 已用尽，省略其余 {len(ranked)} 个较低权重文件）_")
                break
            out.append(chunk)
            used += cost
        return "\n".join(out)

    def focused_map(self, batch_files: list[str], budget_tokens: int,
                    risk_by_file: dict[str, int] | None = None) -> str:
        """聚焦地图：本批文件的签名骨架 + 其符号的跨文件调用方/被调关系 + 类型层次。

        `risk_by_file`（可选，来自批次文件的 risk_score）用于**按风险降序**输出跨文件关系——
        让高攻击面文件的调用方优先进 token 预算，避免低风险的 listener 注册占满预算把高风险符号截断。
        """
        self.build_index()
        assert self._defs is not None and self._refs is not None
        risk_by_file = risk_by_file or {}
        bset = set(batch_files)
        out: list[str] = ["# 聚焦代码地图（本批符号 + 跨文件关系；线索非结论，仍须逐文件通读）", ""]

        out.append("## 本批文件签名骨架")
        for rel in batch_files:
            block = self._file_skeleton(rel)
            if block:
                out += block
        out.append("")

        # 跨文件关系：本批定义的符号，谁在批外调用它 / 它调用了批外什么
        out.append("## 跨文件关系（顺藤摸瓜的线索；按所属文件风险降序）")
        # 每个本批方法符号 → 其定义所在文件的最高 risk_score（跨同名多定义取最大）
        name_risk: dict[str, int] = {}
        for d in self._defs:
            if d["file"] in bset and d["kind"] == "method":
                r = risk_by_file.get(d["file"], 0)
                if r > name_risk.get(d["name"], -1):
                    name_risk[d["name"]] = r
        # 风险降序、同风险按名字升序（确定性）
        batch_names = sorted(name_risk, key=lambda n: (-name_risk[n], n))
        name_files: dict[str, set[str]] = {}
        for d in self._defs:
            name_files.setdefault(d["name"], set()).add(d["file"])

        used = len("\n".join(out)) // _CHARS_PER_TOKEN
        for name in batch_names:
            # 批外调用方（谁调用了本批方法）
            ext_callers = [r for r in self._refs
                           if r["name"] == name and r["kind"] == "method" and r["file"] not in bset]
            if not ext_callers:
                continue
            seg = [f"- **{name}()**（所属文件风险 {name_risk.get(name, 0)}）被批外调用："]
            for r in ext_callers[:8]:
                seg.append(f"    - {r['file']}:{r['line']}  在 `{r['enclosing'] or '?'}()`  → `{r['snippet']}`")
            if len(ext_callers) > 8:
                seg.append(f"    - …（共 {len(ext_callers)} 处，余略）")
            chunk = "\n".join(seg) + "\n"
            cost = len(chunk) // _CHARS_PER_TOKEN
            if used + cost > budget_tokens:
                out.append(f"\n_（预算 {budget_tokens} tok 已用尽，跨文件关系部分截断）_")
                break
            out.append(chunk)
            used += cost
        return "\n".join(out)


# ──────────────────────────────────────────────────────────────────────────────
# 导航后端门面：ts 可直接用则用之，否则 subprocess 到 venv python；供 nav_tools 调用
# ──────────────────────────────────────────────────────────────────────────────

class RepoMapNav:
    """与 source_nav.SourceNav 同接口的门面。ts 在进程内可用则直接调 RepoMap；
    否则 subprocess 到 repomap venv 的 python 上运行本 CLI 并解析 JSON。"""

    def __init__(self, repo: str | Path):
        self.repo = Path(repo).resolve()
        self._rm: RepoMap | None = RepoMap(self.repo) if _ts_available() else None

    def _sub(self, action: str, symbol: str, depth: int = 6) -> Any:
        py = _repomap_python()
        if not py.exists():
            raise RuntimeError("repomap venv 不存在，无法 subprocess 导航")
        cmd = [str(py), str(Path(__file__).resolve()), "--repo", str(self.repo),
               "--action", action, "--symbol", symbol, "--depth", str(depth)]
        p = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except Exception:
            _log(f"subprocess 导航解析失败 action={action}: {p.stderr[:200]}")
            return [] if action != "trace-origin" else {"target": symbol, "chains": []}

    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        return self._rm.get_definition(symbol) if self._rm else self._sub("definition", symbol)

    def get_callers(self, method: str, depth: int = 1) -> list[dict[str, Any]]:
        return self._rm.get_callers(method, depth) if self._rm else self._sub("callers", method)

    def get_type_hierarchy(self, type_name: str) -> dict[str, Any]:
        return self._rm.get_type_hierarchy(type_name) if self._rm else self._sub("hierarchy", type_name)

    def trace_origin(self, symbol: str, max_depth: int = 6, max_callers: int = 25) -> dict[str, Any]:
        if self._rm:
            return self._rm.trace_origin(symbol, max_depth=max_depth, max_callers=max_callers)
        return self._sub("trace-origin", symbol, depth=max_depth)


# ──────────────────────────────────────────────────────────────────────────────
# 降级：ts 与 venv 都没有时，用 source_nav 产出名义级地图/导航
# ──────────────────────────────────────────────────────────────────────────────

def _source_nav_fallback(repo: str):
    from source_nav import SourceNav
    return SourceNav(repo)


def _degraded_map_from_source(repo: str, files: list[str]) -> str:
    """tree-sitter 不可用时的降级地图：用 source_nav 的定义抽取列签名（名义级）。"""
    nav = _source_nav_fallback(repo)
    out = ["# 代码地图（降级：tree-sitter 不可用，改用 source-nav 名义级抽取）", ""]
    for rel in files:
        out.append(f"### {rel}")
        # source_nav 无「列某文件全部定义」的接口；此处仅提示 hunter 直接 Read 该文件
        out.append("  （降级模式无签名骨架，请 Read 本文件；跨文件关系用 nav_tools 查）")
    return "\n".join(out)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _load_batch_files(repo: Path, batch_file: Path) -> list[str]:
    obj = json.loads(batch_file.read_text(encoding="utf-8"))
    return [f["file"] for f in obj.get("files", [])]


def _load_batch_risk(repo: Path, batch_file: Path) -> dict[str, int]:
    """从批次文件读 {file(rel-posix): risk_score}，供聚焦地图按风险排序跨文件关系。"""
    obj = json.loads(batch_file.read_text(encoding="utf-8"))
    out: dict[str, int] = {}
    for f in obj.get("files", []):
        rel = str(f.get("file", "")).replace("\\", "/")
        if rel:
            out[rel] = int(f.get("risk_score", 0))
    return out


def _load_scope_files(repo: Path, scope_file: Path) -> list[str]:
    out: list[str] = []
    for ln in scope_file.read_text(encoding="utf-8").splitlines():
        rel = ln.strip().replace("\\", "/")
        if rel and not rel.startswith("#"):
            out.append(rel)
    return out


def _maybe_reexec() -> None:
    """系统 python 启动、ts 不可导入但 venv 存在 → re-exec 到 venv python（防循环）。"""
    if _ts_available() or os.environ.get("_REPOMAP_REEXEC") == "1":
        return
    py = _repomap_python()
    if py.exists():
        os.environ["_REPOMAP_REEXEC"] = "1"
        try:
            os.execv(str(py), [str(py), str(Path(__file__).resolve())] + sys.argv[1:])
        except Exception as e:
            _log(f"re-exec 到 repomap venv 失败，改用降级: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="tree-sitter 代码地图 + AST 导航 CLI")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--action", required=True,
                    choices=["map", "callers", "definition", "hierarchy", "trace-origin"])
    ap.add_argument("--symbol", default="")
    ap.add_argument("--scope-files", default="")
    ap.add_argument("--batch-file", default="")
    ap.add_argument("--budget", type=int, default=8000, help="地图 token 预算（char/4 估算）")
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--out", default="", help="map：写入的 .md 路径（缺省打到 stdout）")
    args = ap.parse_args()

    _maybe_reexec()
    repo = Path(args.repo).resolve()

    # ── map 动作 ──
    if args.action == "map":
        if not _ts_available():
            files = (_load_batch_files(repo, Path(args.batch_file)) if args.batch_file
                     else _load_scope_files(repo, Path(args.scope_files)) if args.scope_files else [])
            md = _degraded_map_from_source(str(repo), files)
        else:
            rm = RepoMap(repo)
            if args.batch_file:
                md = rm.focused_map(_load_batch_files(repo, Path(args.batch_file)), args.budget,
                                    risk_by_file=_load_batch_risk(repo, Path(args.batch_file)))
            elif args.scope_files:
                # 全局地图仍先建全量索引，再仅渲染 scope 内文件权重最高者
                md = rm.global_map(args.budget)
            else:
                _log("map 需 --batch-file 或 --scope-files")
                return 1
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(md + "\n", encoding="utf-8")
            print(json.dumps({"out": args.out, "backend": "treesitter" if _ts_available() else "source-degraded"},
                             ensure_ascii=False))
        else:
            print(md)
        return 0

    # ── 导航动作 ──
    if _ts_available():
        nav: Any = RepoMap(repo)
    elif _repomap_python().exists():
        nav = RepoMapNav(repo)  # 门面会 subprocess（但通常已 re-exec，不会走到这里）
    else:
        _log("tree-sitter 与 repomap venv 均不可用，导航回退 source-nav")
        nav = _source_nav_fallback(str(repo))

    if args.action == "callers":
        result: Any = nav.get_callers(args.symbol)
    elif args.action == "definition":
        result = nav.get_definition(args.symbol)
    elif args.action == "hierarchy":
        result = nav.get_type_hierarchy(args.symbol)
    else:
        result = nav.trace_origin(args.symbol, max_depth=args.depth)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
