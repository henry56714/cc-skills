import json
import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from source_nav import SourceNav  # noqa: E402
from render_report import (  # noqa: E402
    _coverage_status, _engine_stats_banner, _load_engine_stats,
    _pipeline_stats, _render, _render_needs_review,
)


class SourceNavTests(unittest.TestCase):
    def test_class_method_definition_filters_same_named_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "A.kt").write_text("class Alpha {\n  fun save() {}\n}\n")
            (repo / "B.kt").write_text("class Beta {\n  fun save() {}\n}\n")
            result = SourceNav(repo).get_definition("Alpha#save")
            self.assertEqual([item["file"] for item in result], ["A.kt"])

    def test_no_callers_is_not_automatically_an_entry_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "A.kt").write_text("fun orphan() {}\n")
            result = SourceNav(repo).trace_origin("A#orphan")
            terminal = result["chains"][0]["callers"][0]
            self.assertTrue(terminal["terminal_no_callers"])
            self.assertFalse(terminal["entry_point"])

    def test_path_local_cycle_detection_keeps_sibling_branches(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "A.kt").write_text("fun target() {}\n")
            (repo / "B.kt").write_text("fun left() { target() }\nfun right() { target() }\n")
            result = SourceNav(repo).trace_origin("A#target", max_depth=3)
            callers = result["chains"][0]["callers"]
            self.assertEqual({c.get("enclosing_symbol") for c in callers}, {"left", "right"})

    def test_receiver_type_inference_and_ambiguous_edges_do_not_recurse(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "WorkerPool.java").write_text(
                "class WorkerPool {\n  void start() {}\n}\n"
            )
            (repo / "Caller.java").write_text(
                "class Caller {\n"
                "  WorkerPool networkPool;\n"
                "  Thread cleanupThread;\n"
                "  void launch() {\n"
                "    networkPool.start();\n"
                "    cleanupThread.start();\n"
                "  }\n"
                "}\n"
            )
            nav = SourceNav(repo)
            callers = nav.get_callers("WorkerPool#start")
            by_receiver = {item["receiver"]: item for item in callers}
            self.assertEqual(by_receiver["networkPool"]["confidence"], "high")
            self.assertEqual(by_receiver["networkPool"]["matched_by"], "inferred-receiver-type")
            self.assertEqual(by_receiver["cleanupThread"]["confidence"], "ambiguous")
            trace = nav.trace_origin("WorkerPool#start", max_depth=4)
            ambiguous = next(
                item for item in trace["chains"][0]["callers"]
                if item.get("receiver") == "cleanupThread"
            )
            self.assertTrue(ambiguous["not_expanded"])
            self.assertNotIn("callers", ambiguous)


class ReportTests(unittest.TestCase):
    def test_incomplete_banner_and_statuses(self):
        lines = _engine_stats_banner([
            {"engine": "semgrep", "status": "partial", "rules_run": 2,
             "candidates": 3, "truncated": 1},
            {"engine": "lint", "status": "skipped", "rules_run": 0,
             "candidates": 0, "reason": "not authorized"},
        ])
        text = "\n".join(lines)
        self.assertIn("扫描不完整", text)
        self.assertIn("partial", text)
        self.assertIn("skipped", text)

    def test_skipped_engine_is_a_visible_coverage_gap(self):
        lines = _engine_stats_banner([
            {"engine": "lint", "status": "skipped", "rules_triggered": 0,
             "candidates": 0, "reason": "not authorized"},
        ])
        self.assertIn("覆盖受限", "\n".join(lines))
        self.assertEqual(_coverage_status([{"status": "skipped"}]), "complete_with_skips")

    def test_not_applicable_is_not_a_coverage_gap(self):
        self.assertEqual(_coverage_status([{"status": "not_applicable"}]), "complete")

    def test_english_report_has_english_static_labels(self):
        md = _render([], language="en", run_manifest={"run_id": "abc"})
        self.assertIn("# Scan results", md)
        self.assertIn("Run ID", md)
        self.assertIn("Findings", md)

    def test_needs_review_report_explains_missing_evidence(self):
        md = _render_needs_review([{
            "file": "A.kt", "line": 1, "rule_id": "R-AI-1", "category": "security/x",
            "severity": "major", "title": "x", "evidence": "code",
            "review_reason": "unknown dispatch", "missing_evidence": ["implementation"],
        }])
        self.assertIn("待复核项", md)
        self.assertIn("unknown dispatch", md)
        self.assertIn("implementation", md)

    def test_missing_ai_coverage_forces_incomplete_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            scan_tmp = repo / ".scan/tmp"
            scan_tmp.mkdir(parents=True)
            (scan_tmp / "hunt_scope.txt").write_text("A.kt\n")
            (scan_tmp / "verify_coverage.json").write_text(json.dumps({
                "coverage_ok": True, "candidates_input": 0,
                "candidates_batched": 0, "batches": 1,
                "batch_files": [str(scan_tmp / "verify_batch_0.json")],
            }))
            (repo / ".scan/findings.json").write_text('{"findings": []}')
            (repo / ".scan/needs-review.json").write_text('{"needs_review": []}')
            (scan_tmp / "merge_receipt.json").write_text(json.dumps({
                "ok": True, "run_id": "r1",
                "results": {"confirmed": 0, "needs_review": 0},
            }))
            stats = _pipeline_stats(
                repo=repo,
                hunt_result=scan_tmp / "hunt_perspective_coverage.json",
                verify_coverage=scan_tmp / "verify_coverage.json",
                merge_receipt=scan_tmp / "merge_receipt.json",
                findings_path=repo / ".scan/findings.json",
                needs_review_path=repo / ".scan/needs-review.json",
                findings_count=0, needs_review_count=0,
                run_manifest={"run_id": "r1"},
            )
            self.assertEqual(next(s for s in stats if s["engine"] == "ai_hunter")["status"], "failed")
            self.assertEqual(_coverage_status(stats), "incomplete")

    def test_engine_stats_file_is_required_for_complete_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"
            stats, gate = _load_engine_stats(path, '[{"status":"complete"}]')
            self.assertEqual(len(stats), 1)
            self.assertEqual(gate["status"], "failed")


if __name__ == "__main__":
    unittest.main()
