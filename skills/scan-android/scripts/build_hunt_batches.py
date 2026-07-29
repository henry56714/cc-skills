#!/usr/bin/env python3
"""
build_hunt_batches.py — AI 狩猎支线的确定性分批 + 覆盖率断言 + 风险排序 + 技术存在标记。

动机（见 SKILL.md 第 5.5 步）：
  旧流程把 hunt_scope.txt 直接交给编排 LLM「大作用域按文件分批并发」——分批是临时的、
  无覆盖率核对，可能漏文件。本脚本把它变成确定性、可复现、可断言：

    1. 读 hunt_scope.txt（降维后的业务文件清单，每行一相对路径）；
    2. 防御性剔除明显的生成码（即使降维漏了也不进批次），单独记账；
    3. 对每个文件做一次廉价正则扫描，标出【技术存在】（webview/aidl/db/...）与【风险信号】；
    4. 按风险降序、文件数和估算 token 双上限切批，写 hunt_batch_{N}.json；
    5. 写覆盖率清单 hunt_coverage.json，并【断言每个存在且非生成的输入文件恰好进了一个批次】
       ——不满足即非零退出（堵「漏文件」）。

技术存在标记供上层做「模式自门控」：没有某项技术的批次跳过对应狩猎视角（如无 WebView 跳过
WebView 视角），既不漏（有就扫）又不浪费（没有就跳）。

仅用 Python 标准库。只读被扫描仓库，产物写在 --out-dir（默认 .scan/tmp）。

退出码：
    0 — 覆盖率断言通过（所有存在且非生成的文件都进了批次）
    1 — 覆盖率断言失败 / 输入缺失等错误（详见 stderr 与 stdout JSON 的 error 字段）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# 防御性生成码过滤（降维已大致排除，这里兜底；命中即不进批次、单独记账）
# ──────────────────────────────────────────────────────────────────────────────
_GENERATED_RES = [re.compile(p) for p in (
    r"/build/",
    r"(^|/)\.cxx/",
    r"(^|/)\.externalNativeBuild/",
    r"(^|/)CMakeFiles/",
    r"(^|/)CMakeCache\.txt$",
    r"(^|/)compile_commands\.json$",
    r"(^|/)compiler_id_[^/]*\.(c|cc|cpp)$",
    r"(^|/)R\.java$",
    r"BuildConfig\.(java|kt)$",
    r"databinding",
    r"DataBinderMapper",
    r"_GeneratedInjector",
    r"(^|/)Dagger[A-Z]\w*\.java$",
    r"\.g\.(kt|java)$",
    r"GeneratedAppGlideModule",
)]


# ──────────────────────────────────────────────────────────────────────────────
# 技术存在标记：上层据此自门控狩猎视角（命中即认为该文件「用到」该技术）。
# 故意放宽以覆盖第三方 WebView 内核与 XML 布局等间接形态。
# ──────────────────────────────────────────────────────────────────────────────
TECH_MARKERS = {
    "webview": re.compile(
        r"WebView|WebViewClient|WebChromeClient|addJavascriptInterface|"
        r"loadDataWithBaseURL|\bloadUrl\b|evaluateJavascript|CookieManager|"
        r"com\.tencent\.smtt|webview_flutter|react-native-webview|<WebView"
    ),
    "ipc_aidl": re.compile(
        r"\.Stub\b|extends\s+\w+\.Stub|\bIInterface\b|"
        r"\bonTransact\b|\bMessenger\b|\.aidl\b"
    ),
    "content_provider": re.compile(r"ContentProvider|ContentResolver|content://|UriMatcher"),
    "long_conn": re.compile(r"\bSocket\b|WebSocket|OkHttpClient|\bMqtt|\bXMPP\b|EventSource"),
    "database": re.compile(r"SQLiteOpenHelper|rawQuery|execSQL|@Dao\b|RoomDatabase|ContentValues|SQLiteDatabase"),
    "native": re.compile(r"System\.loadLibrary|System\.load\b|DexClassLoader|InMemoryDexClassLoader|\bJNI\b"),
    "crypto": re.compile(r"\bCipher\b|MessageDigest|KeyStore|SecretKey|\bIvParameterSpec\b"),
    "concurrency": re.compile(r"\bsynchronized\b|\bvolatile\b|Atomic[A-Z]\w+|ExecutorService|\bThread\b|CoroutineScope|runBlocking|GlobalScope"),
    "reflection": re.compile(r"Class\.forName|getDeclaredMethod|getMethod\s*\(|\.invoke\s*\(|getDeclaredField"),
    "exported": re.compile(r'android:exported\s*=\s*"true"'),
    "storage_privacy": re.compile(r"SharedPreferences|DataStore|ClipboardManager|MediaStore|FileProvider|FLAG_SECURE"),
    "network": re.compile(r"Retrofit|OkHttpClient|HttpURLConnection|networkSecurityConfig|CertificatePinner"),
    "work_background": re.compile(r"WorkManager|Worker\b|JobScheduler|ForegroundService|startForeground|AlarmManager"),
    "room": re.compile(r"@Database\b|@Dao\b|RoomDatabase|@Transaction\b|Migration\b"),
    "compose": re.compile(r"@Composable\b|rememberSaveable|LaunchedEffect|collectAsStateWithLifecycle"),
    "deeplink": re.compile(r"autoVerify|intent-filter|ACTION_VIEW|getDataString|getQueryParameter"),
}


# ──────────────────────────────────────────────────────────────────────────────
# 风险信号 → 权重：把高攻击面文件排到批次前列（绝不被漏分析）。
# 用「是否出现」×权重（不按出现次数），避免大文件因重复命中而虚高。
# ──────────────────────────────────────────────────────────────────────────────
RISK_SIGNALS = [
    (re.compile(r"addJavascriptInterface"), 4),
    (re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true"), 4),
    (re.compile(r"setAllowFileAccessFromFileURLs\s*\(\s*true"), 3),
    (re.compile(r'android:exported\s*=\s*"true"'), 3),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder"), 4),
    (re.compile(r"DexClassLoader|InMemoryDexClassLoader|System\.load\b"), 4),
    (re.compile(r"\.Stub\b|extends\s+\w+\.Stub"), 2),
    (re.compile(r"Class\.forName|\.invoke\s*\("), 2),
    (re.compile(r"Intent\.parseUri|getParcelableExtra|getSerializableExtra"), 2),
    (re.compile(r"rawQuery\s*\([^)]*\+|execSQL\s*\([^)]*\+"), 3),
    (re.compile(r"MODE_WORLD_(READABLE|WRITEABLE)"), 3),
    (re.compile(r"checkServerTrusted|HostnameVerifier|onReceivedSslError"), 3),
    (re.compile(r"\bloadUrl\b|loadDataWithBaseURL|evaluateJavascript"), 2),
    (re.compile(r"\bWebView\b"), 1),
]

_MAX_READ_BYTES = 400_000  # 单文件读取上限，避免极大文件拖慢扫描


# ──────────────────────────────────────────────────────────────────────────────
# 狩猎视角 → 门控技术（None = 始终过）。用于「多视角覆盖」事后断言：
# 本脚本据每批 tech_present 算出 expected_perspectives，hunter 回执 perspectives_covered，
# check_hunt_coverage.py 交叉核对——少过一个视角即报错（堵「漏视角」）。
# 视角 id 必须与 agents/hunter.md、check_hunt_coverage.py 三处保持一致。
# ──────────────────────────────────────────────────────────────────────────────
PERSPECTIVES: list[tuple[str, str | None]] = [
    ("auth_dataflow", None),
    ("platform_ipc", "platform_ipc"),
    ("lifecycle_concurrency", None),
    ("storage_privacy", "storage_privacy"),
    ("network_crypto", "network_crypto"),
    ("performance", None),
    ("modern_runtime", "modern_runtime"),
    ("webview", "webview"),
    ("native_dependency", "native"),
    ("free", None),
]


def _expected_perspectives(tech_present: list[str]) -> list[str]:
    tp = set(tech_present)
    capability_gates = {
        "platform_ipc": {"ipc_aidl", "content_provider", "exported", "deeplink"},
        "storage_privacy": {"storage_privacy", "content_provider"},
        "network_crypto": {"network", "crypto", "long_conn"},
        "modern_runtime": {"compose", "room", "work_background"},
    }
    return [
        name for name, gate in PERSPECTIVES
        if gate is None
        or gate in tp
        or bool(capability_gates.get(gate, set()) & tp)
    ]


def _is_generated(rel: str) -> bool:
    return any(rx.search(rel) for rx in _GENERATED_RES)


def _read_text(path: Path) -> tuple[str, bool] | None:
    try:
        size = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read(_MAX_READ_BYTES), size > _MAX_READ_BYTES
    except OSError:
        return None


def _analyze(text: str) -> tuple[int, list[str], int]:
    """返回 (risk_score, tech_list, estimated_tokens)。"""
    risk = sum(w for rx, w in RISK_SIGNALS if rx.search(text))
    if text.count("\n") > 600:
        risk += 1
    tech = [name for name, rx in TECH_MARKERS.items() if rx.search(text)]
    # Prompt overhead and code fences make char/4 optimistic; char/3 is safer.
    estimated_tokens = max(64, (len(text) + 2) // 3)
    return risk, tech, estimated_tokens


def _read_scope(scope_path: Path, repo_root: Path) -> list[str]:
    lines = scope_path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for ln in lines:
        rel = ln.strip()
        if not rel or rel.startswith("#"):
            continue
        # 归一为正斜杠相对路径，去重保序
        rel = rel.replace("\\", "/")
        candidate = Path(rel)
        if candidate.is_absolute():
            raise ValueError(f"作用域路径必须是仓库相对路径: {rel}")
        resolved = (repo_root / candidate).resolve()
        try:
            normalized = resolved.relative_to(repo_root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(f"作用域路径越出仓库: {rel}") from exc
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def build_batches(
    repo_root: Path, scope_path: Path, out_dir: Path, batch_size: int,
    token_budget: int = 36_000,
) -> dict:
    inputs = _read_scope(scope_path, repo_root)

    generated: list[str] = []
    missing: list[str] = []
    analyzed: list[dict] = []  # {file, risk_score, tech}

    for rel in inputs:
        if _is_generated(rel):
            generated.append(rel)
            continue
        p = repo_root / rel
        if not p.is_file():
            missing.append(rel)
            continue
        read_result = _read_text(p)
        if read_result is None:
            missing.append(rel)
            continue
        text, content_truncated = read_result
        risk, tech, _ = _analyze(text)
        # Batch sizing uses full byte size even though marker analysis is capped.
        estimated_tokens = max(64, (p.stat().st_size + 2) // 3)
        analyzed.append({
            "file": rel,
            "risk_score": risk,
            "tech": tech,
            "estimated_tokens": estimated_tokens,
            "marker_scan_truncated": content_truncated,
        })

    # 风险降序、路径升序 → 确定性
    analyzed.sort(key=lambda d: (-d["risk_score"], d["file"]))

    # 确定性切批
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("hunt_batch_*.json"):
        stale.unlink()
    for pattern in ("hunt_result_*.json", "hunt_attest_*.json", "repo_map_*.md"):
        for stale in out_dir.glob(pattern):
            stale.unlink()
    for stale_name in ("hunt_perspective_coverage.json",):
        stale = out_dir / stale_name
        if stale.exists():
            stale.unlink()
    batch_files: list[str] = []
    batches_detail: list[dict] = []
    batched_set: set[str] = set()
    chunks: list[list[dict]] = []
    current: list[dict] = []
    current_tokens = 0
    for item in analyzed:
        item_tokens = int(item["estimated_tokens"])
        if current and (len(current) >= batch_size or current_tokens + item_tokens > token_budget):
            chunks.append(current)
            current = []
            current_tokens = 0
        current.append(item)
        current_tokens += item_tokens
    if current:
        chunks.append(current)

    for idx, chunk in enumerate(chunks):
        tech_union = sorted({t for d in chunk for t in d["tech"]})
        expected = _expected_perspectives(tech_union)
        batch_tokens = sum(int(d["estimated_tokens"]) for d in chunk)
        batch_obj = {
            "batch": idx,
            "file_count": len(chunk),
            "estimated_tokens": batch_tokens,
            "token_budget": token_budget,
            "tech_present": tech_union,
            "expected_perspectives": expected,
            "files": chunk,
        }
        bf = out_dir / f"hunt_batch_{idx}.json"
        bf.write_text(json.dumps(batch_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        batch_files.append(str(bf))
        batches_detail.append({
            "batch": idx,
            "file_count": len(chunk),
            "estimated_tokens": batch_tokens,
            "tech_present": tech_union,
            "expected_perspectives": expected,
        })
        batched_set.update(d["file"] for d in chunk)
    n_batches = len(chunks)

    # ── 覆盖率断言：每个「存在且非生成」的文件必须恰好进一个批次 ──
    expected = {d["file"] for d in analyzed}
    uncovered = sorted(expected - batched_set)
    coverage_ok = not uncovered and not missing

    tech_present_all = sorted({t for d in analyzed for t in d["tech"]})
    marker_scan_truncated = sorted(d["file"] for d in analyzed if d["marker_scan_truncated"])

    coverage = {
        "total_input": len(inputs),
        "analyzed": len(analyzed),
        "batched": len(batched_set),
        "generated_excluded": generated,
        "missing": missing,
        "uncovered": uncovered,
        "coverage_ok": coverage_ok,
        "batches": n_batches,
        "batch_size": batch_size,
        "token_budget": token_budget,
        "tech_present": tech_present_all,
        "marker_scan_truncated": marker_scan_truncated,
        "batch_files": batch_files,
        "batches_detail": batches_detail,
    }
    (out_dir / "hunt_coverage.json").write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return coverage


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repo-root", default=".", help="被扫描仓库根目录（默认 .）")
    ap.add_argument(
        "--scope-files", default=".scan/tmp/hunt_scope.txt",
        help="降维后的业务文件清单（每行一相对路径），默认 .scan/tmp/hunt_scope.txt",
    )
    ap.add_argument(
        "--out-dir", default=".scan/tmp",
        help="批次与覆盖率清单输出目录（默认 .scan/tmp）",
    )
    ap.add_argument(
        "--batch-size", type=int, default=15,
        help="每批文件数上限（默认 15；hunter 子代理逐文件通读，宜小于候选批次）",
    )
    ap.add_argument(
        "--token-budget", type=int, default=36_000,
        help="每批源码估算 token 上限（默认 36000；单个超大文件允许独占一批并超限）",
    )
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    scope_path = Path(args.scope_files)
    if not scope_path.is_absolute():
        scope_path = repo_root / scope_path
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir

    if args.batch_size < 1:
        print(json.dumps({"error": "batch-size 必须 >= 1"}, ensure_ascii=False))
        return 1
    if args.token_budget < 1000:
        print(json.dumps({"error": "token-budget 必须 >= 1000"}, ensure_ascii=False))
        return 1
    if not scope_path.is_file():
        print(json.dumps(
            {"error": f"作用域清单不存在: {scope_path}（先在第 5.5 步降维写 hunt_scope.txt）"},
            ensure_ascii=False,
        ))
        return 1

    try:
        cov = build_batches(repo_root, scope_path, out_dir, args.batch_size, args.token_budget)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "coverage_ok": False}, ensure_ascii=False))
        return 1

    # stderr 人类可读小结
    print(
        f"[build_hunt_batches] 输入 {cov['total_input']} → 分析 {cov['analyzed']} 文件，"
        f"切 {cov['batches']} 批（每批≤{cov['batch_size']} 文件 / 约 {cov['token_budget']} tokens）；"
        f"生成码剔除 {len(cov['generated_excluded'])}，缺失 {len(cov['missing'])}。",
        file=sys.stderr,
    )
    if cov["tech_present"]:
        print(f"[build_hunt_batches] 技术存在: {', '.join(cov['tech_present'])}", file=sys.stderr)
    if not cov["coverage_ok"]:
        print(
            f"[build_hunt_batches] ❌ 覆盖率断言失败：{len(cov['uncovered'])} 个文件未进任何批次，"
            f"{len(cov['missing'])} 个文件缺失或不可读",
            file=sys.stderr,
        )

    # stdout：完整 JSON（供编排方读取 batch_files / tech_present）
    print(json.dumps(cov, ensure_ascii=False, indent=2))
    return 0 if cov["coverage_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
