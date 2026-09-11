#!/usr/bin/env python3
"""
build_hunt_batches.py — AI 狩猎支线的关系聚类分批 + 覆盖率断言 + 风险排序 + 技术存在标记。

动机（见 SKILL.md 第 5.5 步）：
  旧流程把 hunt_scope.txt 直接交给编排 LLM「大作用域按文件分批并发」——分批是临时的、
  无覆盖率核对，可能漏文件。本脚本把它变成确定性、可复现、可断言：

    1. 读 hunt_scope.txt（降维后的业务文件清单，每行一相对路径）；
    2. 防御性剔除明显的生成码（即使降维漏了也不进批次），单独记账；
    3. 对每个文件做一次廉价正则扫描，标出【技术存在】（webview/aidl/db/...）与【风险信号】；
    4. 构建 source-only Android 文件关系图，以风险作为种子、关系权重作为扩展顺序，
       在文件数和估算 token 双上限内切批，写 hunt_batch_{N}.json；
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
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from relation_graph import build_relation_graph, cluster_items, edges_for_batch  # noqa: E402
from lib_scan import resolve_repo_path  # noqa: E402


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
        r"\bonTransact\b|\bMessenger\b|\.aidl\b|JNIEXPORT|RegisterNatives"
    ),
    "platform_surface": re.compile(
        r"PendingIntent\.(?:getActivity|getBroadcast|getService|getForegroundService)|"
        r"\bregisterReceiver\s*\(|RECEIVER_(?:EXPORTED|NOT_EXPORTED)|"
        r"BroadcastReceiver|Notification(?:Manager|Compat)|RemoteViews|AppWidget|"
        r"\bstartActivity\s*\(|ActivityOptions|MODE_BACKGROUND_ACTIVITY_START|"
        r"taskAffinity|launchMode"
    ),
    "content_provider": re.compile(r"ContentProvider|ContentResolver|content://|UriMatcher"),
    "long_conn": re.compile(r"\bSocket\b|WebSocket|OkHttpClient|\bMqtt|\bXMPP\b|EventSource"),
    "database": re.compile(r"SQLiteOpenHelper|rawQuery|execSQL|@Dao\b|RoomDatabase|ContentValues|SQLiteDatabase"),
    "native": re.compile(
        r"System\.loadLibrary|System\.load\b|DexClassLoader|InMemoryDexClassLoader|"
        r"\bJNI(?:EXPORT|Env)?\b|RegisterNatives|#\s*include\s*[<\"]jni\.h[>\"]|"
        r"\b(?:external|native)\s+fun\b|\bstd::"
    ),
    "crypto": re.compile(r"\bCipher\b|MessageDigest|KeyStore|SecretKey|\bIvParameterSpec\b"),
    "concurrency": re.compile(r"\bsynchronized\b|\bvolatile\b|Atomic[A-Z]\w+|ExecutorService|\bThread\b|CoroutineScope|runBlocking|GlobalScope"),
    "reflection": re.compile(r"Class\.forName|getDeclaredMethod|getMethod\s*\(|\.invoke\s*\(|getDeclaredField"),
    "exported": re.compile(r'android:exported\s*=\s*"true"'),
    "storage_privacy": re.compile(r"SharedPreferences|DataStore|ClipboardManager|MediaStore|FileProvider|FLAG_SECURE"),
    "network": re.compile(
        r"Retrofit|OkHttpClient|HttpURLConnection|networkSecurityConfig|CertificatePinner|"
        r"NsdManager|MulticastSocket|DatagramSocket|WifiAwareManager"
    ),
    "work_background": re.compile(r"WorkManager|Worker\b|JobScheduler|ForegroundService|startForeground|AlarmManager"),
    "room": re.compile(r"@Database\b|@Dao\b|RoomDatabase|@Transaction\b|Migration\b"),
    "compose": re.compile(r"@Composable\b|rememberSaveable|LaunchedEffect|collectAsStateWithLifecycle"),
    "deeplink": re.compile(r"autoVerify|intent-filter|ACTION_VIEW|getDataString|getQueryParameter"),
    "permissions": re.compile(
        r"<uses-permission|requestPermissions|checkSelfPermission|AppOpsManager|"
        r"ACCESS_(?:FINE|COARSE|BACKGROUND)_LOCATION|NEARBY_WIFI_DEVICES|POST_NOTIFICATIONS|"
        r"ACCESS_LOCAL_NETWORK|NsdManager|MulticastSocket|WifiAwareManager|"
        r"BluetoothManager|WifiManager|MediaProjectionManager|HealthConnectClient|"
        r"android\.permission\.health|"
        r"READ_MEDIA_(?:IMAGES|VIDEO|AUDIO)|READ_HEALTH_DATA_IN_BACKGROUND"
    ),
    "hidden_api": re.compile(
        r"getDeclaredField|getDeclaredMethod|setAccessible\s*\(\s*true|dalvik\.system|VMRuntime"
    ),
    "sdk_library": re.compile(
        r"com\.android\.library|consumerProguardFiles|externalNativeBuild|System\.loadLibrary|"
        r"api\s+project|implementation\s+project"
    ),
    "privacy_identity": re.compile(
        r"ANDROID_ID|Build\.getSerial|TelephonyManager|getImei|getDeviceId|AdvertisingId|"
        r"SSID|BSSID|LocationManager|ACCESS_FINE_LOCATION"
    ),
    "failure_contract": re.compile(
        r"ThreadPoolExecutor|RejectedExecution|execute\s*\(|enqueue\s*\(|retry|backoff|shutdown"
    ),
    "state_snapshot": re.compile(
        r"System\.currentTimeMillis|elapsedRealtime|synchronized|volatile|Atomic|snapshot|generation"
    ),
    "serialization": re.compile(
        r"ObjectInputStream|readObject\s*\(|getSerializableExtra|Parcelable|Parcelize|"
        r"Gson|Moshi|kotlinx\.serialization|Json\.decodeFromString"
    ),
    "logic_state_machine": re.compile(
        r"enum\s+class\s+\w*(?:State|Status)|sealed\s+(?:class|interface)\s+\w*(?:State|Status)|"
        r"\b(?:state|status|phase|generation)\b|onSuccess|onFailure|compareAndSet"
    ),
    "logic_identity": re.compile(
        r"\b(?:accountId|userId|tenantId|profileId|sessionId|currentUser|switchAccount)\b"
    ),
    "logic_numeric": re.compile(
        r"\b(?:BigDecimal|amount|price|balance|quota|limit|remaining|currency|roundingMode)\b"
    ),
    "logic_pagination": re.compile(
        r"\b(?:pageToken|nextToken|nextCursor|cursor|offset|hasMore|loadMore|dedup)\b"
    ),
    "logic_temporal": re.compile(
        r"\b(?:Instant|LocalDate|ZonedDateTime|Calendar|TimeZone|expiresAt|ttl|deadline)\b|"
        r"currentTimeMillis|elapsedRealtime"
    ),
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

_MARKER_CHUNK_CHARS = 256_000
_MARKER_OVERLAP_CHARS = 4_096


# ──────────────────────────────────────────────────────────────────────────────
# 狩猎视角 → 门控技术（None = 始终过）。用于「多视角覆盖」事后断言：
# 本脚本据每批 tech_present 算出 expected_perspectives；hunter 在结果中回传
# perspectives_covered 与逐文件读取证据，check_hunt_coverage.py 交叉核对。
# 视角 id 必须与 agents/hunter.md、check_hunt_coverage.py 三处保持一致。
# ──────────────────────────────────────────────────────────────────────────────
PERSPECTIVES: list[tuple[str, str | None]] = [
    ("auth_dataflow", None),
    # Business invariants are often expressed without distinctive API names.
    # Keep this perspective unconditional so a marker miss cannot suppress the
    # state/identity/numeric/pagination/time review requested by the user.
    ("business_logic", None),
    ("platform_ipc", "platform_ipc"),
    ("permissions_platform", "permissions_platform"),
    ("lifecycle_concurrency", None),
    ("state_consistency", "state_consistency"),
    ("failure_reliability", None),
    ("storage_privacy", "storage_privacy"),
    ("privacy_consent", "privacy_consent"),
    ("network_crypto", "network_crypto"),
    ("performance", None),
    ("modern_runtime", "modern_runtime"),
    ("webview", "webview"),
    ("native_dependency", "native"),
    ("sdk_integration", "sdk_integration"),
    ("free", None),
]

# Every batch carries a deterministic case checklist.  Hunter receipts must
# cover these ids, so "perspective covered" is no longer a single coarse flag.
PERSPECTIVE_CASES: dict[str, tuple[str, ...]] = {
    "auth_dataflow": ("R-AI-001", "R-AI-002", "R-AI-003", "R-AI-004", "R-AI-012", "R-AI-013", "R-AI-068", "R-AI-069"),
    "business_logic": tuple(f"R-AI-{n:03d}" for n in range(67, 73)),
    "platform_ipc": ("R-AI-026", "R-AI-027", "R-AI-028", "R-AI-029", "R-AI-030", "R-AI-044", "R-AI-047", "R-AI-049", "R-AI-060", "R-AI-063", "R-AI-066"),
    "permissions_platform": ("R-AI-046", "R-AI-051", "R-AI-052", "R-AI-061", "R-AI-062", "R-AI-065"),
    "lifecycle_concurrency": ("R-AI-005", "R-AI-006", "R-AI-007", "R-AI-008", "R-AI-014", "R-AI-015", "R-AI-016", "R-AI-017", "R-AI-039", "R-AI-040"),
    "state_consistency": ("R-AI-054", "R-AI-056", "R-AI-057", "R-AI-067", "R-AI-070", "R-AI-071", "R-AI-072"),
    "failure_reliability": ("R-AI-041", "R-AI-043", "R-AI-055", "R-AI-061", "R-AI-067", "R-AI-070"),
    "storage_privacy": ("R-AI-031", "R-AI-032", "R-AI-035", "R-AI-036"),
    "privacy_consent": ("R-AI-046", "R-AI-059"),
    "network_crypto": ("R-AI-003", "R-AI-033", "R-AI-034", "R-AI-050", "R-AI-058", "R-AI-062"),
    "performance": ("R-AI-009", "R-AI-010", "R-AI-011"),
    "modern_runtime": ("R-AI-041", "R-AI-042", "R-AI-043", "R-AI-045"),
    "webview": tuple(f"R-AI-{n:03d}" for n in range(18, 26)) + ("R-AI-048",),
    "native_dependency": ("R-AI-037", "R-AI-038", "R-AI-058", "R-AI-064"),
    "sdk_integration": ("R-AI-038", "R-AI-053", "R-AI-054", "R-AI-061", "R-AI-064"),
    "free": (),
}


def _expected_perspectives(tech_present: list[str]) -> list[str]:
    tp = set(tech_present)
    capability_gates = {
        "platform_ipc": {"ipc_aidl", "content_provider", "exported", "deeplink", "platform_surface"},
        "permissions_platform": {"permissions", "hidden_api"},
        "storage_privacy": {"storage_privacy", "content_provider", "serialization"},
        "privacy_consent": {"privacy_identity", "permissions"},
        "network_crypto": {"network", "crypto", "long_conn"},
        "modern_runtime": {"compose", "room", "work_background"},
        "state_consistency": {"state_snapshot", "concurrency"},
        "sdk_integration": {"sdk_library", "native"},
    }
    return [
        name for name, gate in PERSPECTIVES
        if gate is None
        or gate in tp
        or bool(capability_gates.get(gate, set()) & tp)
    ]


def _is_generated(rel: str) -> bool:
    return any(rx.search(rel) for rx in _GENERATED_RES)


def _snapshot(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    line_count = 0
    last = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            line_count += chunk.count(b"\n")
            last = chunk[-1:]
    if path.stat().st_size and last != b"\n":
        line_count += 1
    return digest.hexdigest(), line_count


def _path_tech(rel: str) -> set[str]:
    path = Path(rel)
    suffix = path.suffix.lower()
    result: set[str] = set()
    if suffix in {".c", ".cc", ".cpp", ".h", ".hpp", ".rs"}:
        result.add("native")
    if path.name in {"CMakeLists.txt", "Android.mk", "Application.mk", "Android.bp"}:
        result.update({"native", "sdk_library"})
    if path.name == "AndroidManifest.xml":
        result.add("platform_surface")
    if suffix in {".gradle", ".kts", ".pro"} or path.name.startswith("build.gradle"):
        result.add("sdk_library")
    return result


def _analyze(text: str, rel: str = "") -> tuple[int, list[str], int]:
    """返回 (risk_score, tech_list, estimated_tokens)。"""
    risk = sum(w for rx, w in RISK_SIGNALS if rx.search(text))
    if text.count("\n") > 600:
        risk += 1
    tech = {name for name, rx in TECH_MARKERS.items() if rx.search(text)}
    tech.update(_path_tech(rel))
    # Prompt overhead and code fences make char/4 optimistic; char/3 is safer.
    estimated_tokens = max(64, (len(text) + 2) // 3)
    return risk, sorted(tech), estimated_tokens


def _analyze_file(path: Path, rel: str) -> tuple[int, list[str], int] | None:
    """Scan markers across the full file without loading an unbounded file at once."""
    risk_hits: set[int] = set()
    tech_hits = _path_tech(rel)
    char_count = 0
    newline_count = 0
    overlap = ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            while True:
                chunk = stream.read(_MARKER_CHUNK_CHARS)
                if not chunk:
                    break
                char_count += len(chunk)
                newline_count += chunk.count("\n")
                window = overlap + chunk
                for index, (rx, _weight) in enumerate(RISK_SIGNALS):
                    if index not in risk_hits and rx.search(window):
                        risk_hits.add(index)
                for name, rx in TECH_MARKERS.items():
                    if name not in tech_hits and rx.search(window):
                        tech_hits.add(name)
                overlap = window[-_MARKER_OVERLAP_CHARS:]
    except OSError:
        return None
    risk = sum(RISK_SIGNALS[index][1] for index in risk_hits)
    if newline_count > 600:
        risk += 1
    return risk, sorted(tech_hits), max(64, (char_count + 2) // 3)


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


def _repo_rel(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def _input_receipt(repo_root: Path, path: Path) -> dict:
    return {
        "file": _repo_rel(repo_root, path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def build_batches(
    repo_root: Path, scope_path: Path, out_dir: Path, batch_size: int,
    token_budget: int = 24_000,
    context_path: Path | None = None,
) -> dict:
    inputs = _read_scope(scope_path, repo_root)
    context_path = context_path or (repo_root / ".scan" / "tmp" / "context_scope.txt")
    context_files = _read_scope(context_path, repo_root) if context_path.is_file() else []

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
        analysis = _analyze_file(p, rel)
        if analysis is None:
            missing.append(rel)
            continue
        risk, tech, estimated_tokens = analysis
        sha256, line_count = _snapshot(p)
        analyzed.append({
            "file": rel,
            "risk_score": risk,
            "tech": tech,
            "estimated_tokens": estimated_tokens,
            "marker_scan_truncated": False,
            "sha256": sha256,
            "line_count": line_count,
        })

    # 风险降序、路径升序：决定每个关系子图的新种子，保证确定性。
    analyzed.sort(key=lambda d: (-d["risk_score"], d["file"]))

    # 确定性切批
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("hunt_batch_*.json"):
        stale.unlink()
    for pattern in (
        "hunt_result_*.json", "hunt_attest_*.json", "repo_map_*.md",
        "repo_map_*.meta.json", "gap_audit_batch_*.json", "gap_prior_*.json",
        "hunt_gap_result_*.json",
    ):
        for stale in out_dir.glob(pattern):
            stale.unlink()
    for stale_name in (
        "hunt_perspective_coverage.json", "relation_graph.json",
        "gap_audit_plan.json", "gap_audit_coverage.json",
    ):
        stale = out_dir / stale_name
        if stale.exists():
            stale.unlink()
    # Rebuilding hunter inputs invalidates every downstream adjudication receipt.
    for pattern in ("verify_batch_*.json", "verified_batch_*.json"):
        for stale in out_dir.glob(pattern):
            stale.unlink()
    for stale_name in ("verify_coverage.json", "merge_receipt.json"):
        stale = out_dir / stale_name
        if stale.exists():
            stale.unlink()
    batch_files: list[str] = []
    batches_detail: list[dict] = []
    batched_set: set[str] = set()
    relation_graph = build_relation_graph(repo_root, [d["file"] for d in analyzed])
    (out_dir / "relation_graph.json").write_text(
        json.dumps(relation_graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    chunks = cluster_items(analyzed, relation_graph, batch_size, token_budget)

    for idx, chunk in enumerate(chunks):
        tech_union = sorted({t for d in chunk for t in d["tech"]})
        expected = _expected_perspectives(tech_union)
        expected_cases = sorted({
            case for perspective in expected
            for case in PERSPECTIVE_CASES.get(perspective, ())
        })
        batch_tokens = sum(int(d["estimated_tokens"]) for d in chunk)
        chunk_names = [d["file"] for d in chunk]
        internal_edges, boundary_edges = edges_for_batch(relation_graph, chunk_names)
        batch_obj = {
            "schema_version": 2,
            "batch": idx,
            "file_count": len(chunk),
            "estimated_tokens": batch_tokens,
            "token_budget": token_budget,
            "batching_strategy": "relation-clustered",
            "tech_present": tech_union,
            "expected_perspectives": expected,
            "expected_case_ids": expected_cases,
            "files": chunk,
            "relation_edges": internal_edges,
            "boundary_relations": boundary_edges,
            # Tests/specs/docs are optional read-only clues for deriving business
            # invariants.  They are never part of finding/file coverage scope.
            "context_scope_path": _repo_rel(repo_root, context_path) if context_files else None,
            "context_file_count": len(context_files),
        }
        bf = out_dir / f"hunt_batch_{idx}.json"
        bf.write_text(json.dumps(batch_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        batch_files.append(_repo_rel(repo_root, bf))
        batches_detail.append({
            "batch": idx,
            "file_count": len(chunk),
            "estimated_tokens": batch_tokens,
            "tech_present": tech_union,
            "expected_perspectives": expected,
            "expected_case_ids": expected_cases,
            "files": chunk_names,
            "relation_edges": len(internal_edges),
            "boundary_relations": len(boundary_edges),
        })
        batched_set.update(d["file"] for d in chunk)
    n_batches = len(chunks)

    # ── 覆盖率断言：每个「存在且非生成」的文件必须恰好进一个批次 ──
    expected = {d["file"] for d in analyzed}
    uncovered = sorted(expected - batched_set)
    graph_gaps = list(relation_graph.get("stats", {}).get("files_not_fully_indexed", []))
    oversized_batches = [
        detail["batch"] for detail in batches_detail
        if int(detail["estimated_tokens"]) > token_budget
    ]
    analysis_gaps: list[dict] = []
    if graph_gaps:
        analysis_gaps.append({
            "kind": "relation_graph_not_fully_indexed",
            "files": graph_gaps,
            "remediation": "拆分/缩小超大源文件，或提升关系索引能力后重跑",
        })
    if oversized_batches:
        analysis_gaps.append({
            "kind": "batch_token_budget_exceeded",
            "batches": oversized_batches,
            "remediation": "提高 --token-budget 或先拆分超大文件；不得把超限批次宣称为已完整通读",
        })
    coverage_ok = not uncovered and not missing and not analysis_gaps

    tech_present_all = sorted({t for d in analyzed for t in d["tech"]})
    marker_scan_truncated = sorted(d["file"] for d in analyzed if d["marker_scan_truncated"])

    coverage = {
        "schema_version": 3,
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
        "batching_strategy": "relation-clustered",
        "relation_graph_path": _repo_rel(repo_root, out_dir / "relation_graph.json"),
        "map_receipts_required": True,
        "relation_graph_stats": relation_graph.get("stats", {}),
        "tech_present": tech_present_all,
        "marker_scan_truncated": marker_scan_truncated,
        "analysis_gaps": analysis_gaps,
        "batch_files": batch_files,
        "batches_detail": batches_detail,
        "scope_receipt": _input_receipt(repo_root, scope_path),
        "context_scope_receipt": (
            _input_receipt(repo_root, context_path) if context_path.is_file() else None
        ),
        "context_scope_path": _repo_rel(repo_root, context_path) if context_files else None,
        "context_files": len(context_files),
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
        "--context-files", default=".scan/tmp/context_scope.txt",
        help="只读逻辑上下文清单（测试/规格/文档）；不进入 finding 作用域",
    )
    ap.add_argument(
        "--batch-size", type=int, default=10,
        help="每批文件数上限（默认 10；hunter 子代理逐文件通读）",
    )
    ap.add_argument(
        "--token-budget", type=int, default=24_000,
        help="每批源码估算 token 上限（默认 24000；单个超大文件允许独占一批并超限）",
    )
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    try:
        scope_path = resolve_repo_path(repo_root, args.scope_files, label="hunt scope")
        out_dir = resolve_repo_path(repo_root, args.out_dir, label="hunt output directory")
        context_path = resolve_repo_path(repo_root, args.context_files, label="context scope")
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1

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
        cov = build_batches(
            repo_root, scope_path, out_dir, args.batch_size, args.token_budget,
            context_path=context_path,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "coverage_ok": False}, ensure_ascii=False))
        return 1

    # stderr 人类可读小结
    print(
        f"[build_hunt_batches] 输入 {cov['total_input']} → 分析 {cov['analyzed']} 文件，"
        f"关系聚类为 {cov['batches']} 批（每批≤{cov['batch_size']} 文件 / 约 {cov['token_budget']} tokens）；"
        f"生成码剔除 {len(cov['generated_excluded'])}，缺失 {len(cov['missing'])}。",
        file=sys.stderr,
    )
    if cov["tech_present"]:
        print(f"[build_hunt_batches] 技术存在: {', '.join(cov['tech_present'])}", file=sys.stderr)
    graph_stats = cov.get("relation_graph_stats", {})
    print(
        f"[build_hunt_batches] 关系图: {graph_stats.get('files', 0)} 节点 / "
        f"{graph_stats.get('edges', 0)} 边",
        file=sys.stderr,
    )
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
