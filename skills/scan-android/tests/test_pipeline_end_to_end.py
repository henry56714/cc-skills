import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from lib_scan import current_skill_fingerprint  # noqa: E402


class PipelineEndToEndTests(unittest.TestCase):
    def test_empty_scope_pipeline_can_only_complete_with_all_receipts(self):
        skill = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            scan_tmp = repo / ".scan/tmp"
            scan_tmp.mkdir(parents=True)
            run_id = "e2e-run"
            (scan_tmp / "run_manifest.json").write_text(json.dumps({
                "schema_version": 1, "source_only": True,
                "run_id": run_id, "language": "en",
                "skill_fingerprint": current_skill_fingerprint(),
                "config_trusted": False,
                "config_fingerprint": hashlib.sha256(b"{}").hexdigest(),
                "effective_hunt_policy": {
                    "samples": 2, "batch_size": 10, "token_budget": 24000,
                },
                "effective_excluded_engines": [],
            }))
            (scan_tmp / "project.json").write_text('{"config": {}}')
            (scan_tmp / "scope.txt").write_text("")
            (scan_tmp / "hunt_scope.txt").write_text("")
            (scan_tmp / "context_scope.txt").write_text("")
            (scan_tmp / "scope_meta.json").write_text("{}")
            (scan_tmp / "engine-results.json").write_text(json.dumps({
                "status": "complete", "scan_complete": True,
                "configured_complete": True, "coverage_complete": True,
                "incomplete_engines": [], "coverage_gaps": [],
                "engines_used": ["semgrep"], "candidates": [],
                "scope_snapshot": [], "scope_changed_during_scan": False,
                "engine_stats": [
                    {
                        "engine": "semgrep", "status": "complete",
                        "rules_run": 0, "rules_triggered": 0,
                        "rules_configured": 83, "candidates": 0, "truncated": 0,
                    },
                    {"engine": "detekt", "status": "not_applicable"},
                    {"engine": "pmd", "status": "not_applicable"},
                    {"engine": "lint", "status": "not_applicable"},
                ],
                "config_fingerprint": hashlib.sha256(b"{}").hexdigest(),
                "config_trusted": False,
                "effective_excluded_engines": [],
            }))
            subprocess.run([
                "python3", str(skill / "scripts/build_verify_batches.py"),
                "--repo-root", ".", "--input", ".scan/tmp/engine-results.json",
            ], cwd=repo, check=True, capture_output=True, text=True)
            (scan_tmp / "verified_batch_0.json").write_text(json.dumps({
                "batch": 0, "candidates_input": 0, "candidates_adjudicated": 0,
                "false_positive_count": 0, "duplicates_merged_count": 0,
                "false_positive_ids": [],
                "confirmed": [], "needs_review": [],
            }))
            merge_proc = subprocess.run([
                "python3", str(skill / "scripts/merge_findings.py"),
                "--verified-glob", ".scan/tmp/verified_batch_*.json",
            ], cwd=repo, check=True, capture_output=True, text=True)
            self.assertTrue(
                (scan_tmp / "merge_receipt.json").is_file(),
                {
                    "stdout": merge_proc.stdout,
                    "stderr": merge_proc.stderr,
                    "files": [str(path.relative_to(repo)) for path in repo.rglob("*")],
                },
            )
            subprocess.run([
                "python3", str(skill / "scripts/render_report.py"),
                "--repo-root", ".", "--engine-results", ".scan/tmp/engine-results.json",
                "--language", "en",
            ], cwd=repo, check=True, capture_output=True, text=True)
            manifest = json.loads((scan_tmp / "run_manifest.json").read_text())
            self.assertEqual(manifest["coverage_status"], "complete")
            self.assertEqual(manifest["models"], ["unknown"])

            # A post-merge verifier mutation invalidates the receipt on rerender.
            verified = scan_tmp / "verified_batch_0.json"
            verified.write_text(verified.read_text() + "\n")
            subprocess.run([
                "python3", str(skill / "scripts/render_report.py"),
                "--repo-root", ".", "--engine-results", ".scan/tmp/engine-results.json",
                "--language", "en",
            ], cwd=repo, check=True, capture_output=True, text=True)
            manifest = json.loads((scan_tmp / "run_manifest.json").read_text())
            self.assertEqual(manifest["coverage_status"], "incomplete")
            merge = next(s for s in manifest["pipeline_stats"] if s["engine"] == "merge")
            self.assertIn("changed after verification", merge["reason"])

    def test_gap_auditor_logic_candidate_flows_through_verifier_and_receipt(self):
        skill = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            scan_tmp = repo / ".scan/tmp"
            scan_tmp.mkdir(parents=True)
            source = repo / "app/Foo.kt"
            source.parent.mkdir()
            source.write_text("fun refresh() {\n  state = load()\n}\n")
            run_id = "logic-gap-e2e"
            effective_config = {"hunt_samples": 1}
            (scan_tmp / "run_manifest.json").write_text(json.dumps({
                "schema_version": 1,
                "source_only": True,
                "run_id": run_id,
                "language": "en",
                "skill_fingerprint": current_skill_fingerprint(),
                "config_trusted": True,
                "effective_excluded_engines": [],
                "effective_hunt_policy": {
                    "samples": 1, "batch_size": 10, "token_budget": 24000,
                },
                "config_fingerprint": hashlib.sha256(
                    json.dumps(effective_config, sort_keys=True).encode()
                ).hexdigest(),
            }))
            (scan_tmp / "project.json").write_text(json.dumps({"config": effective_config}))
            (scan_tmp / "scope.txt").write_text("app/Foo.kt\n")
            (scan_tmp / "hunt_scope.txt").write_text("app/Foo.kt\n")
            (scan_tmp / "context_scope.txt").write_text("")
            (scan_tmp / "scope_meta.json").write_text("{}")
            (scan_tmp / "engine-results.json").write_text(json.dumps({
                "status": "complete",
                "scan_complete": True,
                "configured_complete": True,
                "coverage_complete": True,
                "incomplete_engines": [],
                "coverage_gaps": [],
                "engines_used": ["semgrep"],
                "candidates": [],
                "scope_snapshot": [{
                    "file": "app/Foo.kt",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "bytes": len(source.read_bytes()),
                }],
                "scope_changed_during_scan": False,
                "engine_stats": [
                    {
                        "engine": "semgrep", "status": "complete",
                        "rules_run": 0, "rules_triggered": 0,
                        "rules_configured": 83, "candidates": 0, "truncated": 0,
                    },
                    {"engine": "detekt", "status": "not_applicable"},
                    {"engine": "pmd", "status": "not_applicable"},
                    {"engine": "lint", "status": "not_applicable"},
                ],
                "config_fingerprint": hashlib.sha256(
                    json.dumps(effective_config, sort_keys=True).encode()
                ).hexdigest(),
                "config_trusted": True,
                "effective_excluded_engines": [],
            }))
            subprocess.run([
                "python3", str(skill / "scripts/build_hunt_batches.py"),
                "--repo-root", ".", "--scope-files", ".scan/tmp/hunt_scope.txt",
                "--context-files", ".scan/tmp/context_scope.txt",
                "--batch-size", "10", "--token-budget", "24000",
            ], cwd=repo, check=True, capture_output=True, text=True)
            hunt_batch = scan_tmp / "hunt_batch_0.json"
            batch_obj = json.loads(hunt_batch.read_text())
            expected_perspectives = batch_obj["expected_perspectives"]
            expected_cases = batch_obj["expected_case_ids"]
            code_map = scan_tmp / "repo_map_0.md"
            code_map.write_text("# complete map\n")
            (scan_tmp / "repo_map_0.meta.json").write_text(json.dumps({
                "schema_version": 2,
                "backend": "treesitter",
                "degraded": False,
                "files_not_indexed": {},
                "map_truncated": False,
                "batch_sha256": hashlib.sha256(hunt_batch.read_bytes()).hexdigest(),
                "map_sha256": hashlib.sha256(code_map.read_bytes()).hexdigest(),
            }))
            (scan_tmp / "hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "sample": 0,
                "perspectives_covered": expected_perspectives,
                "case_ids_checked": expected_cases,
                "case_assessments": [{
                    "case_id": case,
                    "status": "no_signal",
                    "signals_checked": [
                        "refresh state transition and callback ordering"
                        if case == "R-AI-067" else "applicable source invariant"
                    ],
                    "evidence": [],
                    "conclusion": (
                        "first pass did not identify a stale callback"
                        if case == "R-AI-067" else "no matching signal in this source"
                    ),
                } for case in expected_cases],
                "files_reviewed": [{
                    "file": "app/Foo.kt",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "line_count": 3,
                    "ranges": [{"start": 1, "end": 3}],
                }],
                "candidates": [],
            }))
            subprocess.run([
                "python3", str(skill / "scripts/check_hunt_coverage.py"),
                "--repo-root", ".", "--out-dir", ".scan/tmp", "--min-samples", "1",
            ], cwd=repo, check=True, capture_output=True, text=True)
            subprocess.run([
                "python3", str(skill / "scripts/build_gap_audit_batches.py"),
                "--repo-root", ".", "--out-dir", ".scan/tmp",
            ], cwd=repo, check=True, capture_output=True, text=True)
            (scan_tmp / "hunt_gap_result_0.json").write_text(json.dumps({
                "batch": 0,
                "independent_pass": True,
                "prior_results_compared_after_pass": True,
                "perspectives_audited": expected_perspectives,
                "files_reviewed": [{
                    "file": "app/Foo.kt",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "line_count": 3,
                    "ranges": [{"start": 1, "end": 3}],
                }],
                "case_audits": [{
                    "case_id": case,
                    "disposition": "new_candidate" if case == "R-AI-067" else "agree_no_signal",
                    "signals_checked": [
                        "two refresh callbacks completing out of order"
                        if case == "R-AI-067" else "independent source invariant review"
                    ],
                    "evidence": (
                        [{"file": "app/Foo.kt", "line": 2}]
                        if case == "R-AI-067" else []
                    ),
                    "conclusion": (
                        "an older refresh can overwrite the newer generation"
                        if case == "R-AI-067" else "independent pass found no matching signal"
                    ),
                } for case in expected_cases],
                "candidates": [{
                    "file": "app/Foo.kt",
                    "line": 2,
                    "rule_id": "R-AI-067",
                    "category": "logic/stale-async-state",
                    "severity": "major",
                    "snippet": "state = load()",
                    "why": "an older request may overwrite newer state",
                    "root_cause_hint": {
                        "primary_file": "app/Foo.kt",
                        "symbol": "refresh",
                        "failure_mode": "stale-response-overwrite",
                    },
                }],
            }))
            subprocess.run([
                "python3", str(skill / "scripts/check_gap_audit_coverage.py"),
                "--repo-root", ".", "--out-dir", ".scan/tmp",
            ], cwd=repo, check=True, capture_output=True, text=True)

            subprocess.run([
                "python3", str(skill / "scripts/build_verify_batches.py"),
                "--repo-root", ".",
                "--input", ".scan/tmp/engine-results.json",
                "--input-glob", ".scan/tmp/hunt_result_*.json",
                "--input-glob", ".scan/tmp/hunt_gap_result_*.json",
            ], cwd=repo, check=True, capture_output=True, text=True)
            candidate = json.loads((scan_tmp / "verify_batch_0.json").read_text())[0]
            (scan_tmp / "verified_batch_0.json").write_text(json.dumps({
                "batch": 0,
                "candidates_input": 1,
                "candidates_adjudicated": 1,
                "false_positive_count": 0,
                "false_positive_ids": [],
                "duplicates_merged_count": 0,
                "confirmed": [{
                    "file": "app/Foo.kt",
                    "line": 2,
                    "rule_id": "R-AI-067",
                    "category": "logic/stale-async-state",
                    "severity": "major",
                    "title": "Stale refresh can overwrite newer state",
                    "evidence": "state = load()",
                    "why": "parallel refreshes have no generation fence",
                    "repro": "complete the older request after the newer request",
                    "suggestion": "discard responses from older generations",
                    "root_cause": candidate["root_cause_hint"],
                    "source_candidate_ids": [candidate["candidate_id"]],
                    "provenance": candidate["provenance"],
                }],
                "needs_review": [],
            }))
            merge_proc = subprocess.run([
                "python3", str(skill / "scripts/merge_findings.py"),
                "--verified-glob", ".scan/tmp/verified_batch_*.json",
            ], cwd=repo, check=True, capture_output=True, text=True)
            self.assertTrue(
                (scan_tmp / "merge_receipt.json").is_file(),
                {
                    "stdout": merge_proc.stdout,
                    "stderr": merge_proc.stderr,
                    "files": [str(path.relative_to(repo)) for path in repo.rglob("*")],
                },
            )
            subprocess.run([
                "python3", str(skill / "scripts/render_report.py"),
                "--repo-root", ".", "--engine-results", ".scan/tmp/engine-results.json",
                "--language", "en",
            ], cwd=repo, check=True, capture_output=True, text=True)

            manifest = json.loads((scan_tmp / "run_manifest.json").read_text())
            finding = json.loads((repo / ".scan/findings.json").read_text())["findings"][0]
            receipt = json.loads((scan_tmp / "merge_receipt.json").read_text())
            bound_paths = {item["path"] for item in receipt["artifacts_sha256"]}
            self.assertEqual(manifest["coverage_status"], "complete")
            self.assertEqual(finding["rule_id"], "R-AI-067")
            self.assertEqual(finding["provenance"][0]["source_kind"], "ai_gap_auditor")
            self.assertIn(".scan/tmp/gap_audit_coverage.json", bound_paths)
            self.assertIn(".scan/tmp/gap_prior_0.json", bound_paths)
            self.assertIn(".scan/tmp/relation_graph.json", bound_paths)
            self.assertIn("app/Foo.kt", bound_paths)
            self.assertEqual(receipt["skill_fingerprint"], current_skill_fingerprint())

            # The merge gate must not trust a post-hoc --min-samples=1 receipt
            # when this run's effective policy says that two samples were due.
            saved_manifest = dict(manifest)
            lowered_policy_manifest = dict(manifest)
            lowered_policy_manifest["config_fingerprint"] = hashlib.sha256(b"{}").hexdigest()
            lowered_policy_manifest["effective_hunt_policy"] = {
                "samples": 2, "batch_size": 10, "token_budget": 24000,
            }
            (scan_tmp / "run_manifest.json").write_text(json.dumps(lowered_policy_manifest))
            (scan_tmp / "project.json").write_text('{"config": {}}')
            lowered_samples = subprocess.run([
                "python3", str(skill / "scripts/merge_findings.py"),
                "--verified-glob", ".scan/tmp/verified_batch_*.json",
            ], cwd=repo, capture_output=True, text=True)
            self.assertEqual(lowered_samples.returncode, 2)
            self.assertIn("Hunter sample count does not match run_manifest", lowered_samples.stderr)

            (scan_tmp / "run_manifest.json").write_text(json.dumps(saved_manifest))
            (scan_tmp / "project.json").write_text(json.dumps({"config": effective_config}))

            source.write_text("fun refresh() = Unit\n")
            stale_merge = subprocess.run([
                "python3", str(skill / "scripts/merge_findings.py"),
                "--verified-glob", ".scan/tmp/verified_batch_*.json",
            ], cwd=repo, capture_output=True, text=True)
            self.assertEqual(stale_merge.returncode, 2)
            self.assertIn("engine scope source changed", stale_merge.stderr)


if __name__ == "__main__":
    unittest.main()
