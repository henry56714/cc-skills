#!/usr/bin/env python3
"""确定性准备 Android 源码扫描作用域。

输出：
  .scan/tmp/project.json    工程探测与配置
  .scan/tmp/scope.txt       工具扫描作用域
  .scan/tmp/hunt_scope.txt  AI hunter 业务文件作用域

diff 模式不是简单的 changed-files：它会加入受构建/Manifest 变更影响的模块，
沿 Android 文件关系图扩展，并对 Java/Kotlin 的变更方法做有界 callers/callees 扩展。
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detect_project import detect_project  # noqa: E402
from lib_scan import (  # noqa: E402
    atomic_write_json, current_skill_fingerprint, effective_excluded_engines,
    effective_hunt_policy, now_iso, resolve_cli_path, resolve_repo_path,
)
from relation_graph import build_relation_graph, expand_from_files  # noqa: E402
from source_nav import SourceNav  # noqa: E402


SKIP_DIRS = {
    ".git", ".gradle", ".idea", ".scan", ".claude", ".codex",
    ".cxx", ".externalNativeBuild", ".vscode", "CMakeFiles",
    "build", "generated", "node_modules",
}
HUNT_SKIP_DIRS = {
    "vendor", "vendors", "third_party", "third-party", "external",
    ".cxx", ".externalNativeBuild", "CMakeFiles", "docs", ".vscode",
}
SKIP_FILES = {"local.properties", "CMakeCache.txt", "compile_commands.json"}
HUNT_EXTENSIONS = {
    ".java", ".kt", ".kts", ".xml", ".aidl",
    ".js", ".ts", ".dart", ".c", ".cc", ".cpp", ".h", ".hpp", ".rs",
    ".gradle", ".properties", ".toml", ".pro", ".cfg", ".json",
    ".html", ".htm", ".sql", ".proto", ".mk", ".yaml", ".yml",
}
SOURCE_FILENAMES = {"CMakeLists.txt", "Android.mk", "Application.mk", "Android.bp"}
CONTEXT_EXTENSIONS = {
    ".java", ".kt", ".kts", ".xml", ".json", ".yaml", ".yml",
    ".md", ".txt", ".feature", ".proto",
}
CONTEXT_DIRS = {"test", "tests", "androidTest", "integrationTest", "docs", "doc"}
GLOBAL_BUILD_FILES = {
    "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts",
    "gradle.properties", "gradle/libs.versions.toml", "gradle/verification-metadata.xml",
}
MODULE_WIDE_NAMES = {
    "AndroidManifest.xml", "build.gradle", "build.gradle.kts", "proguard-rules.pro",
    "consumer-rules.pro", "network_security_config.xml", "data_extraction_rules.xml",
    "backup_rules.xml",
}
DECL_RE = re.compile(
    r"(?:\bfun\s+|\b(?:public|private|protected|internal|static|final|synchronized|native|abstract|"
    r"suspend|inline|open|override|operator|infix|tailrec|external)\s+)*"
    r"(?:[A-Za-z_$][\w$<>?\[\]., ]+\s+)?([A-Za-z_$][\w$]*)\s*\("
)
CALL_RE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")
CALL_STOP = {
    "if", "for", "while", "when", "switch", "catch", "return", "throw", "new",
    "super", "this", "synchronized", "require", "check", "assert",
}
TYPE_DECL_RE = re.compile(
    r"\b(?:class|interface|object|record|enum\s+class|enum)\s+([A-Za-z_$][\w$]*)"
)


def _matches_any(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or Path(rel).match(p) for p in patterns)


def _excluded(rel: str, patterns: list[str]) -> bool:
    path = Path(rel)
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return True
    if path.name in SKIP_FILES:
        return True
    return _matches_any(rel, patterns)


def _iter_source_files(repo: Path, roots: list[str], extensions: set[str], excludes: list[str]):
    repo = repo.resolve()
    seen: set[str] = set()
    walk_roots = [repo / r for r in roots] if roots else [repo]
    for root in walk_roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = []
            for dp, dns, fns in os.walk(root):
                dns[:] = [d for d in dns if d not in SKIP_DIRS]
                candidates.extend(Path(dp) / fn for fn in fns)
        for p in candidates:
            if p.suffix.lower() not in extensions and p.name not in SOURCE_FILENAMES:
                continue
            try:
                rel = p.resolve().relative_to(repo).as_posix()
            except ValueError:
                continue
            if rel in seen or _excluded(rel, excludes):
                continue
            seen.add(rel)
            yield rel


def _iter_context_files(repo: Path) -> list[str]:
    """Return tests/spec/docs as read-only invariant clues, never finding scope."""
    candidates = _iter_source_files(repo, [], CONTEXT_EXTENSIONS, [])
    result: list[str] = []
    for rel in candidates:
        path = Path(rel)
        parts = set(path.parts)
        if parts & CONTEXT_DIRS or path.name.lower().startswith(("readme", "architecture", "security")):
            result.append(rel)
    return sorted(set(result))


def _parse_git_name_status(text: str) -> list[tuple[str, bool]]:
    """Return (path, known_deleted) entries for Git name-status output."""
    names: list[tuple[str, bool]] = []
    for raw in text.splitlines():
        fields = raw.split("\t")
        if len(fields) < 2:
            continue
        status = fields[0]
        if status.startswith(("R", "C")) and len(fields) >= 3:
            # Rename removes the old identity; copy keeps it. Keep both paths
            # without inventing a deletion for Git's C status.
            names.append((fields[1], status.startswith("R")))
            names.append((fields[2], False))
        else:
            names.append((fields[1], status.startswith("D")))
    return names


def _git_changed(repo: Path, ref: str) -> tuple[list[str], list[str]]:
    check = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", ref],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        raise ValueError(f"git ref 不存在或浅克隆中不可用: {ref}")
    diff = subprocess.run(
        ["git", "-C", str(repo), "diff", "--name-status", "--find-renames", ref, "--"],
        capture_output=True, text=True, check=True,
    )
    untracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True, check=True,
    )
    names = _parse_git_name_status(diff.stdout)
    names.extend((raw, False) for raw in untracked.stdout.splitlines())
    seen: set[str] = set()
    existing: list[str] = []
    missing: list[str] = []
    for raw, known_deleted in names:
        rel = raw.strip().replace("\\", "/")
        if not rel or rel in seen:
            continue
        seen.add(rel)
        source_path = repo / rel
        if not known_deleted and source_path.is_file():
            try:
                resolved = resolve_repo_path(repo, source_path, label="git changed path")
            except ValueError as exc:
                raise ValueError(f"git 变更路径不安全: {rel}: {exc}") from exc
            existing.append(resolved.relative_to(repo.resolve()).as_posix())
        else:
            missing.append(rel)
    return existing, missing


def _module_for(rel: str, modules: list[str]) -> str | None:
    matches = [m for m in modules if rel == m or rel.startswith(m.rstrip("/") + "/")]
    return max(matches, key=len) if matches else None


def _extract_symbols_text(text: str) -> tuple[set[str], set[str]]:
    declarations = {m.group(1) for m in DECL_RE.finditer(text)} - CALL_STOP
    calls = {m.group(1) for m in CALL_RE.finditer(text)} - CALL_STOP
    return declarations, calls


def _extract_types_text(text: str) -> set[str]:
    return {match.group(1) for match in TYPE_DECL_RE.finditer(text)}


def _extract_symbols(path: Path) -> tuple[set[str], set[str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set(), set()
    return _extract_symbols_text(text)


def _git_file_text(repo: Path, ref: str, rel: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{rel}"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return proc.stdout if proc.returncode == 0 else ""


def _impact_expand(
    repo: Path,
    direct: set[str],
    all_files: set[str],
    modules: list[str],
    depth: int,
    *,
    deleted: set[str] | None = None,
    diff_ref: str = "HEAD~1",
    diagnostics: list[dict] | None = None,
) -> set[str]:
    repo = repo.resolve()
    impacted = set(direct)
    deleted = deleted or set()
    changed_paths = direct | deleted

    # 全局构建配置影响所有变体；模块 Manifest/构建/安全 XML 影响模块内所有代码和资源。
    # 任意删除也保守扩到所在模块：删除的资源、consumer rules、source-set
    # overlay 或声明可能无法再从当前工作树的关系图恢复。
    if any(rel in GLOBAL_BUILD_FILES for rel in changed_paths):
        impacted.update(all_files)
    else:
        affected_modules = {
            mod for rel in changed_paths
            if Path(rel).name in MODULE_WIDE_NAMES or rel in deleted
            for mod in [_module_for(rel, modules)] if mod
        }
        if any(_module_for(rel, modules) is None for rel in deleted):
            # A deleted root/unmapped resource or config has no current node to
            # recover relationships from.  Full expansion is safer than
            # silently treating it as having no consumers.
            impacted.update(all_files)
        for mod in affected_modules:
            impacted.update(f for f in all_files if f == mod or f.startswith(mod + "/"))

    if depth > 0 and direct:
        # Add Android-aware structural neighbors before method-name expansion:
        # Manifest/component, code/resource, source-set overlays, imports and
        # Gradle project relations.  This is source-only and deterministic.
        graph = build_relation_graph(repo, sorted(all_files))
        graph_gaps = graph.get("stats", {}).get("files_not_fully_indexed", [])
        if graph_gaps and diagnostics is not None:
            diagnostics.append({"backend": "relation_graph", "files": graph_gaps})
        impacted.update(expand_from_files(graph, direct, depth) & all_files)

    changed_code = [f for f in direct if Path(f).suffix.lower() in {".java", ".kt"}]
    deleted_code = [f for f in deleted if Path(f).suffix.lower() in {".java", ".kt"}]
    if not (changed_code or deleted_code) or depth <= 0:
        return impacted

    nav = SourceNav(repo)
    declarations: set[str] = set()
    calls: set[str] = set()
    for rel in changed_code:
        ds, cs = _extract_symbols(repo / rel)
        declarations.update(ds)
        calls.update(cs)
    for rel in deleted_code:
        ds, cs = _extract_symbols_text(_git_file_text(repo, diff_ref, rel))
        declarations.update(ds)
        calls.update(cs)

    # A deleted type with no methods can still break callers/importers. Scan
    # current Java/Kotlin sources for exact type-name references instead of
    # depending only on method-name navigation.
    deleted_types: set[str] = set()
    for rel in deleted_code:
        deleted_types.update(_extract_types_text(_git_file_text(repo, diff_ref, rel)))
    if deleted_types:
        type_ref = re.compile(
            r"\b(?:" + "|".join(re.escape(name) for name in sorted(deleted_types)) + r")\b"
        )
        for rel in sorted(all_files):
            if Path(rel).suffix.lower() not in {".java", ".kt", ".kts"}:
                continue
            try:
                if type_ref.search((repo / rel).read_text(encoding="utf-8", errors="replace")):
                    impacted.add(rel)
            except OSError:
                if diagnostics is not None:
                    diagnostics.append({"backend": "deleted_type_reference", "files": [rel]})

    # Callees：把变更文件直接调用的方法定义加入作用域。
    for name in sorted(calls):
        for d in nav.get_definition(f"Any#{name}"):
            if d.get("file") in all_files:
                impacted.add(d["file"])

    # Callers：逐层加入调用者文件；名字级导航宁可扩宽，不静默漏掉潜在入口。
    frontier = set(declarations)
    seen_names: set[str] = set()
    for _ in range(depth):
        next_frontier: set[str] = set()
        for name in sorted(frontier - seen_names):
            seen_names.add(name)
            for caller in nav.get_callers(name):
                rel = caller.get("file", "")
                if rel in all_files:
                    impacted.add(rel)
                enclosing = caller.get("enclosing_symbol", "")
                if enclosing:
                    next_frontier.add(enclosing)
        frontier = next_frontier
        if not frontier:
            break
    if nav.files_not_indexed and diagnostics is not None:
        diagnostics.append({"backend": "source_nav", "files": nav.files_not_indexed})
    return impacted


def _apply_user_filters(files: set[str], modules: list[str], module: str | None, globs: list[str]) -> set[str]:
    if module:
        if module not in modules:
            raise ValueError(f"未知模块 {module!r}；可用模块: {', '.join(modules) or '(未探测到)'}")
        prefix = module.rstrip("/") + "/"
        files = {f for f in files if f == module or f.startswith(prefix)}
    if globs:
        files = {f for f in files if _matches_any(f, globs)}
    return files


def prepare_scope(
    repo: Path,
    *,
    diff_ref: str | None,
    full: bool,
    module: str | None,
    globs: list[str],
    impact_depth: int,
    impact: bool,
    out_dir: Path,
    language: str | None = None,
    trust_project_config: bool = False,
) -> dict:
    repo = repo.resolve()
    _invalidate_previous_run(out_dir)
    info = detect_project(repo, trust_project_config=trust_project_config)
    if language in {"zh", "en"}:
        info["language"] = language
        info["notes"].append(f"output language overridden by invocation: {language}")
    modules = info["modules"]
    excludes = list(info["default_excludes"]) + list(info["extra_excludes"])
    extensions = set(info["source_extensions"])
    # Scan the whole source repository, not only settings.gradle modules: included
    # builds, convention plugins and shared/native roots can sit outside modules.
    all_files = set(_iter_source_files(repo, [], extensions, excludes))

    # 根级构建/版本目录不一定落在某个模块下，显式补入。
    for rel in GLOBAL_BUILD_FILES:
        candidate = repo / rel
        try:
            safe_candidate = resolve_repo_path(repo, candidate, label="global build file")
        except ValueError:
            continue
        if safe_candidate.is_file() and not _excluded(rel, excludes):
            all_files.add(safe_candidate.relative_to(repo).as_posix())

    missing_changed: list[str] = []
    deleted_relevant: set[str] = set()
    mode = "full" if full or (module or globs) and diff_ref is None else "diff"
    if mode == "diff":
        if not info["is_git"]:
            raise ValueError("当前目录不是 git 仓库；请使用 --full、--module 或 --files")
        direct_list, missing_changed = _git_changed(repo, diff_ref or "HEAD~1")
        direct = {
            f for f in direct_list
            if (Path(f).suffix.lower() in extensions or Path(f).name in SOURCE_FILENAMES)
            and not _excluded(f, excludes)
        }
        deleted_relevant = {
            f for f in missing_changed
            if (Path(f).suffix.lower() in extensions or Path(f).name in SOURCE_FILENAMES)
            and not _excluded(f, excludes)
        }
        if deleted_relevant and not impact:
            raise ValueError(
                "diff 含已删除源码/配置，--no-impact 无法审查删除造成的调用方或模块影响；请启用 impact"
            )
        impact_diagnostics: list[dict] = []
        selected = _impact_expand(
            repo,
            direct,
            all_files,
            modules,
            impact_depth,
            deleted=deleted_relevant,
            diff_ref=diff_ref or "HEAD~1",
            diagnostics=impact_diagnostics,
        ) if impact else direct
        if impact_diagnostics:
            raise ValueError(
                "diff 影响切片存在未索引源码，不能宣称完整: "
                + json.dumps(impact_diagnostics, ensure_ascii=False)
            )
    else:
        direct = set(all_files)
        selected = set(all_files)

    selected = _apply_user_filters(selected, modules, module, globs)
    direct = _apply_user_filters(direct, modules, module, globs)
    scope = sorted(selected)
    hunt_scope = sorted(
        f for f in selected
        if (Path(f).suffix.lower() in HUNT_EXTENSIONS or Path(f).name in SOURCE_FILENAMES)
        and not (set(Path(f).parts) & HUNT_SKIP_DIRS)
    )
    context_scope = _iter_context_files(repo)

    cfg = info.get("config", {})
    excluded = effective_excluded_engines(cfg)
    ai_enabled = "ai" not in excluded
    result = {
        "mode": mode,
        "diff_ref": (diff_ref or "HEAD~1") if mode == "diff" else None,
        "direct_files": len(direct),
        "impact_added": len(selected - direct),
        "scope_files": len(scope),
        "hunt_files": len(hunt_scope),
        "context_files": len(context_scope),
        "should_hunt": ai_enabled and bool(hunt_scope),
        "impact_depth": impact_depth if impact else 0,
        "missing_changed": missing_changed,
        "deleted_files": sorted(deleted_relevant),
        "direct_paths_total": len(direct) + len(deleted_relevant),
        "modules": modules,
        "scope_path": str(out_dir / "scope.txt"),
        "hunt_scope_path": str(out_dir / "hunt_scope.txt"),
        "context_scope_path": str(out_dir / "context_scope.txt"),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scope.txt").write_text("".join(f"{f}\n" for f in scope), encoding="utf-8")
    (out_dir / "hunt_scope.txt").write_text("".join(f"{f}\n" for f in hunt_scope), encoding="utf-8")
    (out_dir / "context_scope.txt").write_text("".join(f"{f}\n" for f in context_scope), encoding="utf-8")
    (out_dir / "project.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "scope_meta.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    atomic_write_json(out_dir / "run_manifest.json", _run_manifest(repo, info, result))
    return result


def _invalidate_previous_run(out_dir: Path) -> None:
    """Remove only known generated artifacts before assigning a new run id."""
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_patterns = (
        "engine-results.json", "hunt_batch_*.json", "hunt_result_*.json",
        "repo_map_*.md", "repo_map_*.meta.json",
        "gap_audit_batch_*.json", "gap_prior_*.json", "hunt_gap_result_*.json",
        "verify_batch_*.json", "verified_batch_*.json",
        "hunt_coverage.json", "hunt_perspective_coverage.json",
        "gap_audit_plan.json", "gap_audit_coverage.json", "context_scope.txt",
        "verify_coverage.json", "relation_graph.json", "merge_receipt.json",
    )
    for pattern in generated_patterns:
        for path in out_dir.glob(pattern):
            if path.is_file():
                path.unlink()
    scan_root = out_dir.parent
    for relative in (
        "findings.json", "needs-review.json",
        "reports/findings.md", "reports/needs-review.md",
    ):
        path = scan_root / relative
        if path.is_file():
            path.unlink()


def _run_manifest(repo: Path, info: dict, scope: dict) -> dict:
    revision = ""
    dirty = None
    if info.get("is_git"):
        try:
            revision = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5, check=True,
            ).stdout.strip()
            dirty = bool(subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True, text=True, timeout=5, check=True,
            ).stdout.strip())
        except (OSError, subprocess.SubprocessError):
            revision = ""
            dirty = None
    config_bytes = json.dumps(info.get("config", {}), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "started_at": now_iso(),
        "source_only": True,
        "repo_revision": revision,
        "repo_dirty": dirty,
        "skill_fingerprint": current_skill_fingerprint(),
        "config_fingerprint": hashlib.sha256(config_bytes).hexdigest(),
        "language": info.get("language", "zh"),
        "scan_mode": scope.get("mode"),
        "scope": {
            "direct_files": scope.get("direct_files", 0),
            "impact_added": scope.get("impact_added", 0),
            "scope_files": scope.get("scope_files", 0),
            "hunt_files": scope.get("hunt_files", 0),
            "context_files": scope.get("context_files", 0),
            "deleted_files": len(scope.get("deleted_files", [])),
        },
        "config_trusted": bool(info.get("config_trusted")),
        "effective_hunt_policy": effective_hunt_policy(info.get("config")),
        "effective_excluded_engines": effective_excluded_engines(info.get("config")),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--diff", nargs="?", const="HEAD~1", default=None)
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--module")
    ap.add_argument("--files", action="append", default=[], metavar="GLOB")
    ap.add_argument("--impact-depth", type=int, default=None)
    ap.add_argument("--no-impact", action="store_true")
    ap.add_argument("--language", choices=("zh", "en"), help="覆盖本次报告语言")
    ap.add_argument(
        "--trust-project-config", action="store_true",
        help="允许已审阅的目标仓库配置改变作用域；不授予代码执行或联网能力",
    )
    ap.add_argument("--out-dir", default=".scan/tmp")
    args = ap.parse_args()

    if args.full and args.diff is not None:
        print(json.dumps({"error": "--full 与 --diff 不能同时使用"}, ensure_ascii=False))
        return 2
    repo = Path(args.repo_root).resolve()
    info = detect_project(repo, trust_project_config=args.trust_project_config)
    cfg = info.get("config", {})
    try:
        depth = args.impact_depth if args.impact_depth is not None else int(cfg.get("impact_depth", 2))
    except (TypeError, ValueError):
        print(json.dumps({"error": "config.impact_depth 必须是非负整数"}, ensure_ascii=False))
        return 2
    if depth < 0:
        print(json.dumps({"error": "--impact-depth 必须 >= 0"}, ensure_ascii=False))
        return 2
    # 未给任何作用域时保留增量默认，但使用 impact slice，而非只扫 changed-files。
    diff_ref = args.diff
    if not args.full and args.diff is None and not args.module and not args.files:
        diff_ref = "HEAD~1"
    try:
        out_dir = resolve_cli_path(repo, args.out_dir, label="scope output directory")
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    try:
        result = prepare_scope(
            repo,
            diff_ref=diff_ref,
            full=args.full,
            module=args.module,
            globs=args.files,
            impact_depth=depth,
            impact=not args.no_impact,
            out_dir=out_dir,
            language=args.language,
            trust_project_config=args.trust_project_config,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
