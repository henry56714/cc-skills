import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from source_nav import SourceNav  # noqa: E402
from render_report import _coverage_status, _engine_stats_banner, _render, _render_needs_review  # noqa: E402


class SourceNavTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
