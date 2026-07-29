#!/usr/bin/env python3
"""
check_hunt_coverage.py — AI 狩猎支线「多视角覆盖」的事后断言。

`build_hunt_batches.py` 保证了【文件不漏分批】（确定性 + 覆盖率断言）；但「每批是否真的
把每个该过的狩猎视角都过了」是 hunter 子代理的编排约定，脚本管不到。本脚本把它也变成
【事后可机械核对】：

  - 期望（expected）：`hunt_coverage.json` 的 `batches_detail[*].expected_perspectives`
    —— 由 build_hunt_batches 据每批 tech_present 确定性算出（无 WebView 就不期望 webview 视角）。
  - 实际（covered）：每个 hunter 回执 `hunt_attest_*.json` 的 `perspectives_covered`
    —— hunter 跑完一批后上报它实际过了哪些视角（多次采样则取各回执并集）。

断言（任一不满足 → 退出码 1）：
  1. 每个批次都至少有一份回执（缺回执 = hunter 未上报 = 视为未覆盖，必须排查）；
  2. 每个批次 expected ⊆ covered（少过任一期望视角即失败，列出缺哪个）；
  3. 可选 --min-samples：每批回执数 ≥ N（self-consistency 多采样时核对真的跑了 N 次）。

回执文件约定：out-dir 下任意 `hunt_attest_*.json`，每份至少含
    {"batch": <int>, "perspectives_covered": [<str>, ...]}
（一个 (batch,sample) 一份；命名随意，只要带 batch 字段。视角 id 见 build_hunt_batches.PERSPECTIVES。）

仅用 Python 标准库。只读 .scan/tmp，产物写 hunt_perspective_coverage.json。

退出码：0 = 全部视角已覆盖；1 = 有批次漏视角 / 缺回执 / 采样不足 / 输入缺失。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"__error__": str(e)}


def check(out_dir: Path, coverage_path: Path, min_samples: int) -> dict:
    cov = _load_json(coverage_path)
    if not isinstance(cov, dict) or "batches_detail" not in cov:
        return {"ok": False, "error": f"覆盖率清单无效或缺 batches_detail: {coverage_path}"}

    expected_by_batch: dict[int, set[str]] = {
        int(b["batch"]): set(b.get("expected_perspectives", []))
        for b in cov.get("batches_detail", [])
    }

    # 汇总回执（每份一个 (batch,sample)）
    covered_by_batch: dict[int, set[str]] = {}
    samples_by_batch: dict[int, int] = {}
    bad_attest: list[str] = []
    for ap in sorted(out_dir.glob("hunt_attest_*.json")):
        obj = _load_json(ap)
        if not isinstance(obj, dict) or "batch" not in obj or "__error__" in obj:
            bad_attest.append(ap.name)
            continue
        try:
            b = int(obj["batch"])
        except (TypeError, ValueError):
            bad_attest.append(ap.name)
            continue
        covered_by_batch.setdefault(b, set()).update(obj.get("perspectives_covered", []))
        samples_by_batch[b] = samples_by_batch.get(b, 0) + 1

    batches: list[dict] = []
    all_ok = True
    for b in sorted(expected_by_batch):
        expected = expected_by_batch[b]
        covered = covered_by_batch.get(b, set())
        n_samples = samples_by_batch.get(b, 0)
        missing = sorted(expected - covered)
        problems: list[str] = []
        if n_samples == 0:
            problems.append("无回执（hunter 未上报覆盖）")
        if missing:
            problems.append("漏视角: " + ", ".join(missing))
        if min_samples > 1 and 0 < n_samples < min_samples:
            problems.append(f"采样不足: {n_samples} < {min_samples}")
        ok = not problems
        all_ok = all_ok and ok
        batches.append({
            "batch": b,
            "expected": sorted(expected),
            "covered": sorted(covered),
            "missing": missing,
            "samples": n_samples,
            "ok": ok,
            "problems": problems,
        })

    # 指向不存在批次的游离回执
    stray = sorted(set(covered_by_batch) - set(expected_by_batch))

    return {
        "ok": all_ok and not bad_attest,
        "min_samples": min_samples,
        "batches_total": len(expected_by_batch),
        "batches": batches,
        "stray_attest_batches": stray,
        "unparseable_attest": bad_attest,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repo-root", default=".", help="被扫描仓库根目录（默认 .）")
    ap.add_argument("--out-dir", default=".scan/tmp", help="回执与清单目录（默认 .scan/tmp）")
    ap.add_argument(
        "--coverage", default=None,
        help="覆盖率清单路径（默认 <out-dir>/hunt_coverage.json）",
    )
    ap.add_argument(
        "--min-samples", type=int, default=1,
        help="每批期望回执数（= hunt_samples；>1 时核对多采样真的跑够次数）",
    )
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir
    coverage_path = Path(args.coverage) if args.coverage else out_dir / "hunt_coverage.json"
    if not coverage_path.is_absolute():
        coverage_path = repo_root / coverage_path

    if not coverage_path.is_file():
        print(json.dumps(
            {"ok": False, "error": f"覆盖率清单不存在: {coverage_path}（先跑 build_hunt_batches.py）"},
            ensure_ascii=False,
        ))
        return 1

    result = check(out_dir, coverage_path, args.min_samples)
    (out_dir / "hunt_perspective_coverage.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # stderr 人类可读
    if result.get("error"):
        print(f"[check_hunt_coverage] ❌ {result['error']}", file=sys.stderr)
    else:
        bad = [b for b in result["batches"] if not b["ok"]]
        if result["ok"]:
            print(
                f"[check_hunt_coverage] ✅ {result['batches_total']} 批次视角全部覆盖",
                file=sys.stderr,
            )
        else:
            print(
                f"[check_hunt_coverage] ❌ {len(bad)}/{result['batches_total']} 批次视角覆盖不全：",
                file=sys.stderr,
            )
            for b in bad:
                print(f"   • batch {b['batch']}: {'; '.join(b['problems'])}", file=sys.stderr)
        if result["unparseable_attest"]:
            print(f"   ⚠ 无法解析的回执: {', '.join(result['unparseable_attest'])}", file=sys.stderr)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
