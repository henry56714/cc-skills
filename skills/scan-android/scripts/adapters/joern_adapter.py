"""Joern adapter —— P2 跨文件 CPG 深度分析（开源骨干引擎）。

自动探测/下载 Joern CLI，构建代码属性图（CPG），
运行 CPGQL 查询，将跨文件发现（含 dataflow_path）归一化为 Candidate。

CPG 缓存: .scan/cache/cpg-<commit>-<version>.bin
就绪: v3 strict 下 Joern 由 preflight 保证就绪（缺则中断），本引擎无降级路径。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib_scan import Candidate

from .base import AdapterResult, EngineAdapter, InstallationError, ScanContext

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
_QUERIES_SCRIPT = _SKILL_ROOT / "queries" / "joern" / "all_queries.sc"
_CPG_CACHE_DIR = Path(".scan") / "cache"


class JoernAdapter(EngineAdapter):
    name = "joern"

    def is_available(self, ctx: ScanContext) -> tuple[bool, str]:
        java_ok, java_msg = _check_java()
        if not java_ok:
            return False, f"Joern 需要 Java: {java_msg}"
        # macOS: Joern shell 脚本依赖 greadlink（GNU coreutils）
        if sys.platform == "darwin" and not shutil.which("greadlink"):
            return False, "Joern 在 macOS 上需要 greadlink（brew install coreutils）"
        joern = _find_joern()
        if joern:
            return True, ""
        # 自动安装：失败时抛出 InstallationError 以中止整次扫描
        try:
            from tools.installer import ensure_joern
            path, _ = ensure_joern()
            if path and Path(path).exists():
                return True, ""
        except Exception as e:
            raise InstallationError(
                f"Joern 安装失败（已重试多次）: {e}\n"
                "请检查网络连接或代理设置后重新运行扫描。\n"
                "若要在无 Joern 的情况下继续，请在 .scan/config.json 中添加 "
                "\"excluded_engines\": [\"joern\"]"
            ) from e
        raise InstallationError("Joern 可执行文件安装后仍未找到，请手动检查安装目录。")

    def run(self, ctx: ScanContext) -> AdapterResult:
        result = AdapterResult(engine=self.name)
        joern = _find_joern()
        if not joern:
            result.available = False
            result.unavailable_reason = "joern 可执行文件未找到"
            return result

        if not _QUERIES_SCRIPT.exists():
            result.available = False
            result.unavailable_reason = f"Joern 查询脚本不存在: {_QUERIES_SCRIPT}"
            return result

        # 构建 CPG（或使用缓存）
        cpg_path, cache_hit = _get_or_build_cpg(joern, ctx)
        if cpg_path is None:
            result.available = False
            result.unavailable_reason = "CPG 构建失败"
            return result

        cache_note = "CPG 命中缓存" if cache_hit else "CPG 新建完成"
        result.notes.append({"engine": self.name, "note": cache_note})

        # 运行查询脚本
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        ) as tf:
            out_file = tf.name

        cmd = [
            str(joern),
            "--script", str(_QUERIES_SCRIPT),
            "--param", f"srcDir={ctx.repo}",
            "--param", f"outFile={out_file}",
        ]

        scan_dir = ctx.repo / ".scan"
        scan_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # CPG 导入 + 查询可能需要几分钟
                cwd=str(scan_dir),  # 避免 Joern 在项目根创建 workspace/
                env={**os.environ, "JAVA_OPTS": "-Xmx4g"},
            )
        except subprocess.TimeoutExpired:
            result.notes.append({"engine": self.name, "note": "Joern 查询超时（600s）"})
            Path(out_file).unlink(missing_ok=True)
            return result
        except Exception as e:
            result.available = False
            result.unavailable_reason = f"Joern 运行失败: {e}"
            Path(out_file).unlink(missing_ok=True)
            return result

        if proc.returncode != 0:
            result.notes.append({
                "engine": self.name,
                "note": f"Joern 退出码 {proc.returncode}，stderr: {proc.stderr[:500]}",
            })

        # 解析结果
        try:
            out_path = Path(out_file)
            if out_path.exists() and out_path.stat().st_size > 0:
                with open(out_path, "r", encoding="utf-8") as f:
                    items = json.load(f)
                scope_set = set(ctx.scope_files)
                for item in items:
                    c = _item_to_candidate(item, ctx.repo, scope_set)
                    if c:
                        result.candidates.append(c)
                result.rules_run = len({c.rule_id for c in result.candidates})
                result.rules_total = result.rules_run
            else:
                result.notes.append({"engine": self.name, "note": "Joern 未产生输出文件"})
        except Exception as e:
            result.notes.append({"engine": self.name, "note": f"Joern 结果解析失败: {e}"})
        finally:
            Path(out_file).unlink(missing_ok=True)

        return result


def _find_joern() -> str | None:
    existing = shutil.which("joern")
    if existing:
        return existing
    from tools.installer import TOOLS_DIR
    local = TOOLS_DIR / "joern" / "joern-cli" / "joern"
    if local.exists():
        return str(local)
    return None


def _check_java() -> tuple[bool, str]:
    try:
        out = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True, timeout=5)
        return True, out.strip().split("\n")[0]
    except Exception as e:
        return False, str(e)


def _get_or_build_cpg(joern: str, ctx: ScanContext) -> tuple[Path | None, bool]:
    """返回 (cpg_file_path, was_cached)。CPG 文件是 Joern CPG 二进制。"""
    # 用 commit + 文件集合哈希作缓存键
    commit = _git_head(ctx.repo)
    joern_ver = _joern_version(joern)
    cache_key = hashlib.sha256(
        f"{commit}:{joern_ver}:{','.join(sorted(ctx.scope_files))}".encode()
    ).hexdigest()[:16]

    cache_dir = ctx.repo / _CPG_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)
    cpg_path = cache_dir / f"cpg-{cache_key}.bin"

    if cpg_path.exists():
        return cpg_path, True

    # 查找 joern-parse 工具
    joern_parse = Path(joern).parent / "joern-parse"
    if not joern_parse.exists():
        # 有些版本直接用 joern 导入
        joern_parse = None

    if joern_parse and joern_parse.exists():
        # 使用 joern-parse 预构建 CPG
        cmd = [str(joern_parse), str(ctx.repo), "--output", str(cpg_path)]
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                timeout=600,
                cwd=str(ctx.repo / ".scan"),  # 避免 Joern 在项目根创建 workspace/
                env={**os.environ, "JAVA_OPTS": "-Xmx4g"},
            )
            if cpg_path.exists():
                return cpg_path, False
        except Exception:
            pass

    # 回退：不分离 CPG 构建，让查询脚本自己 importCode
    # 返回一个"占位"路径（脚本内部会自行构建）
    return cpg_path.parent / "inline-build.marker", False


def _git_head(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except Exception:
        return "unknown"


def _joern_version(joern: str) -> str:
    try:
        out = subprocess.check_output(
            [joern, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return out.stdout.strip()[:20]
    except Exception:
        return "unknown"


def _item_to_candidate(item: dict, repo: Path, scope_set: set[str]) -> Candidate | None:
    file_str = item.get("file", "")
    # 转相对路径
    try:
        rel = Path(file_str).resolve().relative_to(repo).as_posix()
    except ValueError:
        rel = file_str.lstrip("/")
    # 过滤作用域
    if scope_set and rel not in scope_set:
        return None
    if not rel or rel == ".":
        return None

    line = int(item.get("line", 0))
    if line < 0:
        line = 0

    return Candidate(
        engine="joern",
        rule_id=item.get("rule_id", "R-JOERN"),
        native_rule_id=item.get("native_rule_id", "joern"),
        file=rel,
        line=line,
        category=item.get("category", ""),
        severity=item.get("severity", "major"),
        snippet=item.get("snippet", "")[:300],
        message=item.get("message", ""),
        dataflow_path=item.get("dataflow_path", []),
    )
