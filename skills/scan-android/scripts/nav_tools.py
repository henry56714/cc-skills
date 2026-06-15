#!/usr/bin/env python3
"""
P3 LLM 导航工具 —— 基于 Joern server 的可查询语义图接口。

verifier agent 通过本模块提问代码结构问题，把 LLM 从"猜文件"变成"查图"。

用法（由 verifier agent 调用，需要 Joern server 在 localhost:2342 运行）:
  from nav_tools import NavTools
  nav = NavTools(repo="/abs/path/to/project")
  nav.start_server()   # 启动 Joern server（幂等）并自动 importCode
  callers = nav.get_callers("processPayment")
  nav.generate_skeleton("/abs/path/skeleton.json")
  nav.stop_server()

Joern server API（异步）:
  POST /query   Body: {"query": "..."}   → {"success":true, "uuid":"..."}
  GET  /result/{uuid}                    → {"success":true, "uuid":"...", "stdout":"..."}
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_JOERN_HOST = "localhost"
_JOERN_PORT = int(os.environ.get("JOERN_SERVER_PORT", "2342"))
_JOERN_URL = f"http://{_JOERN_HOST}:{_JOERN_PORT}"

_SKILL_ROOT = Path(__file__).resolve().parent.parent


class NavTools:
    """Joern-backed LLM 导航工具集。"""

    def __init__(self, repo: str | Path):
        self.repo = Path(repo).resolve()
        self._server_proc: subprocess.Popen | None = None
        self._server_pgid: int | None = None
        self._server_ready = False

    # ------------------------------------------------------------------
    # Server 生命周期
    # ------------------------------------------------------------------

    def start_server(self) -> bool:
        """启动 Joern server（幂等）。返回 True 表示 server 就绪。"""
        if self._ping():
            self._server_ready = True
            return True

        joern = _find_joern()
        if not joern:
            _log("Joern 未找到，nav_tools 不可用")
            return False

        cmd = [
            str(joern),
            "--server",
            f"--server-host={_JOERN_HOST}",
            f"--server-port={_JOERN_PORT}",
        ]
        _log(f"启动 Joern server: {' '.join(cmd)}")
        self._server_proc = subprocess.Popen(
            cmd,
            cwd=str(self.repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "JAVA_OPTS": "-Xmx4g"},
            start_new_session=True,  # 新 session 使进程组 kill 能到达 Java 子进程
        )
        self._server_pgid = self._server_proc.pid  # pgid == pid when start_new_session=True

        # 等待 server 就绪（最多 60 秒）
        deadline = time.time() + 60
        while time.time() < deadline:
            if self._ping():
                self._server_ready = True
                _log("Joern server 就绪")
                # 导入代码构建 CPG
                self._import_code()
                return True
            time.sleep(2)

        _log("Joern server 启动超时")
        return False

    def stop_server(self) -> None:
        if self._server_pgid:
            # 杀整个进程组：joern 的 shell wrapper fork 了 Java，
            # terminate() 只能打到已退出的 shell wrapper，需用 killpg 才能到达 Java 子进程
            try:
                os.killpg(self._server_pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            time.sleep(3)
            try:
                os.killpg(self._server_pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass  # 已全部退出或无权限（进程组不再存在）
            self._server_pgid = None
        if self._server_proc:
            try:
                self._server_proc.wait(timeout=5)
            except Exception:
                pass
            self._server_proc = None
        self._server_ready = False

    # ------------------------------------------------------------------
    # 导航工具接口（verifier agent 调用）
    # ------------------------------------------------------------------

    def get_definition(self, symbol: str) -> list[dict[str, Any]]:
        """查找符号定义位置。返回 [{file, line, signature}]"""
        cpgql = f"""
cpg.method.name("{symbol}").map(m => Map(
  "name" -> m.name,
  "file" -> m.file.name.headOption.getOrElse(""),
  "line" -> m.lineNumber.getOrElse(-1),
  "signature" -> m.signature
)).l
"""
        return self._query(cpgql) or []

    def get_callers(self, method: str, depth: int = 1) -> list[dict[str, Any]]:
        """查找所有调用者。返回 [{name, file, line}]"""
        cpgql = f"""
cpg.method.name("{method}").caller.map(m => Map(
  "name" -> m.name,
  "file" -> m.file.name.headOption.getOrElse(""),
  "line" -> m.lineNumber.getOrElse(-1)
)).l
"""
        return self._query(cpgql) or []

    def get_callees(self, method: str) -> list[dict[str, Any]]:
        """查找方法调用的所有子方法。返回 [{name, file, line}]"""
        cpgql = f"""
cpg.method.name("{method}").callee.map(m => Map(
  "name" -> m.name,
  "file" -> m.file.name.headOption.getOrElse(""),
  "line" -> m.lineNumber.getOrElse(-1)
)).l
"""
        return self._query(cpgql) or []

    def get_dataflow_to(self, sink_method: str, source_methods: list[str] | None = None) -> list[dict[str, Any]]:
        """查找到达 sink 的数据流路径。"""
        sources = source_methods or [
            "getStringExtra", "getIntExtra", "getParcelableExtra",
            "getQueryParameter", "readLine", "nextLine"
        ]
        sources_str = ", ".join(f'"{s}"' for s in sources)
        cpgql = f"""
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
implicit val context: EngineContext = EngineContext()
val sources = cpg.call.nameExact({sources_str})
val sinks = cpg.call.nameExact("{sink_method}")
sinks.reachableByFlows(sources).map(flow =>
  flow.elements.map(e => Map(
    "file" -> e.file.name.headOption.getOrElse(""),
    "line" -> e.lineNumber.getOrElse(-1),
    "code" -> e.code.take(100)
  ))
).l
"""
        return self._query(cpgql) or []

    def get_type_hierarchy(self, type_name: str) -> dict[str, Any]:
        """查找类继承层次。返回 {inherits_from, implemented_by}"""
        cpgql = f"""
Map(
  "inherits_from" -> cpg.typeDecl.name("{type_name}").inheritsFromTypeFullName.l,
  "implemented_by" -> cpg.typeDecl.inheritsFromTypeFullName("{type_name}").name.l
)
"""
        result = self._query(cpgql)
        if isinstance(result, list) and result:
            return result[0]
        return {}

    def synthesize_query(self, description: str) -> list[dict[str, Any]]:
        """QLCoder 模式：让 LLM 合成 CPGQL 并立即执行（仅限受信场景）。

        description: 用自然语言描述要查询什么
        注意: 本函数不直接调用 LLM，由 verifier agent 负责合成查询后传入 raw_query() 执行。
        """
        raise NotImplementedError("请使用 raw_query(cpgql) 传入已合成的查询")

    def raw_query(self, cpgql: str, timeout: int = 30) -> Any:
        """直接执行 CPGQL 查询（仅限受信代码路径）。"""
        return self._query(cpgql, timeout=timeout)

    def generate_skeleton(self, output_file: str) -> bool:
        """提取代码骨架写入 output_file（JSON）。需先调用 start_server()。
        CPGQL 直接写文件，绕过 stdout 解析。返回 True 表示成功。"""
        # 转义 output_file 路径中可能存在的反斜杠（Windows 路径兼容）
        safe_out = output_file.replace("\\", "\\\\")
        cpgql = (
            'import ujson._\n'
            f'val _outFile = "{safe_out}"\n'
            'val _skeleton = cpg.typeDecl\n'
            '  .filter(_.isExternal == false)\n'
            '  .map(t => ujson.Obj(\n'
            '    "name"    -> t.name,\n'
            '    "file"    -> t.file.name.headOption.getOrElse(""),\n'
            '    "fields"  -> ujson.Arr(t.member.map(m =>\n'
            '      ujson.Str(m.typeFullName.split("\\\\.").last + " " + m.name)\n'
            '    ).toSeq: _*),\n'
            '    "methods" -> ujson.Arr(t.method\n'
            '      .filterNot(_.name.startsWith("<"))\n'
            '      .map(m => ujson.Obj(\n'
            '        "name"    -> m.name,\n'
            '        "line"    -> m.lineNumber.getOrElse(0),\n'
            '        "callers" -> m.caller.size\n'
            '      )).toSeq: _*)\n'
            '  )).toSeq\n'
            'os.write.over(os.Path(_outFile), ujson.write(_skeleton, indent = 2))\n'
            '_skeleton.size\n'
        )
        result = self._query(cpgql, timeout=120)
        if result is None:
            _log(f"骨架生成失败（查询超时或 server 错误）")
            return False
        _log(f"骨架写入 {output_file}")
        return True

    # ------------------------------------------------------------------
    # 内部实现
    # ------------------------------------------------------------------

    def _ping(self) -> bool:
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"{_JOERN_URL}/", timeout=2) as r:
                return r.status in (200, 404)
        except urllib.error.HTTPError as e:
            return e.code in (200, 404)
        except Exception:
            return False

    def _import_code(self) -> None:
        """在 server 中导入 Java 源码构建 CPG（幂等）。
        强制使用 Java 源码前端（importCode.java），避免 importCode 自动选择字节码前端。"""
        cpgql = f'importCode.java("{self.repo}", "android-project")'
        self._query(cpgql, timeout=300)

    def _query(self, cpgql: str, timeout: int = 30) -> Any:
        """提交 CPGQL 并轮询结果（Joern server 异步 API）。"""
        if not self._server_ready and not self._ping():
            return None

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        # 1. 提交查询，取回 UUID
        payload = json.dumps({"query": cpgql}).encode("utf-8")
        submit_req = urllib.request.Request(
            f"{_JOERN_URL}/query",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with opener.open(submit_req, timeout=10) as r:
                resp = json.load(r)
                uuid = resp.get("uuid")
                if not uuid:
                    _log(f"Joern server 未返回 UUID: {resp}")
                    return None
        except urllib.error.HTTPError as e:
            _log(f"Joern server 提交查询失败 HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            _log(f"Joern server 提交查询失败: {e}")
            return None

        # 2. 轮询结果
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                poll_req = urllib.request.Request(f"{_JOERN_URL}/result/{uuid}")
                with opener.open(poll_req, timeout=5) as r:
                    body = json.load(r)
                    if body.get("success"):
                        return _parse_repl_stdout(body.get("stdout", ""))
            except urllib.error.HTTPError:
                pass  # 结果未就绪
            except Exception as e:
                _log(f"Joern server 轮询失败: {e}")
            time.sleep(1)

        _log(f"Joern 查询超时（{timeout}s）UUID={uuid}")
        return None


def _parse_repl_stdout(stdout: str) -> Any:
    """从 Joern REPL stdout 中提取最后一条结果值（去 ANSI 后取 val resN = VALUE）。"""
    import re
    clean = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", stdout)
    # 找最后一条赋值行：val resN: TYPE = VALUE
    matches = re.findall(r"val res\d+: [^\n]+ = (.+)", clean)
    if not matches:
        return stdout  # 无法解析时返回原文
    val_str = matches[-1].strip()
    try:
        return json.loads(val_str)
    except Exception:
        return val_str  # 非 JSON（如 Scala List/Map 表示）则返回原始字符串


def _find_joern() -> str | None:
    existing = shutil.which("joern")
    if existing:
        return existing
    try:
        from tools.installer import TOOLS_DIR
        local = TOOLS_DIR / "joern" / "joern-cli" / "joern"
        if local.exists():
            return str(local)
    except Exception:
        pass
    return None


def _log(msg: str) -> None:
    print(f"[nav_tools] {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------
# CLI 入口（供 verifier agent 直接调用）
# ------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Joern 导航工具 CLI")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--action", required=True,
                    choices=["callers", "callees", "definition", "dataflow", "hierarchy", "query", "skeleton"])
    ap.add_argument("--symbol", default="")
    ap.add_argument("--query", default="")
    ap.add_argument("--output-file", default="", help="skeleton action 的输出 JSON 路径")
    ap.add_argument("--sources", nargs="*", default=None)
    args = ap.parse_args()

    nav = NavTools(args.repo)
    if not nav.start_server():
        print(json.dumps({"error": "Joern server 未能启动"}), file=sys.stderr)
        sys.exit(1)

    result: Any = None
    if args.action == "callers":
        result = nav.get_callers(args.symbol)
    elif args.action == "callees":
        result = nav.get_callees(args.symbol)
    elif args.action == "definition":
        result = nav.get_definition(args.symbol)
    elif args.action == "dataflow":
        result = nav.get_dataflow_to(args.symbol, args.sources)
    elif args.action == "hierarchy":
        result = nav.get_type_hierarchy(args.symbol)
    elif args.action == "query":
        result = nav.raw_query(args.query)
    elif args.action == "skeleton":
        if not args.output_file:
            print(json.dumps({"error": "--output-file 是必填参数"}), file=sys.stderr)
            nav.stop_server()
            sys.exit(1)
        ok = nav.generate_skeleton(args.output_file)
        nav.stop_server()
        sys.exit(0 if ok else 1)

    nav.stop_server()
    print(json.dumps(result, ensure_ascii=False, indent=2))
