import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from adapters.semgrep_adapter import SemgrepAdapter, _contextual_suppression, _extract_dataflow_path  # noqa: E402
from adapters.base import ScanContext  # noqa: E402
from adapters.lint_adapter import LintAdapter, _parse_lint_xml  # noqa: E402
from adapters.pmd_adapter import _parse_violation, _should_emit  # noqa: E402
from run_engines import _overall_status  # noqa: E402
from lib_scan import Candidate  # noqa: E402


class SemgrepDataflowTests(unittest.TestCase):
    def test_adapter_does_not_install_without_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = ScanContext(repo=Path(tmp), scope_files=[], rules_dir=Path(tmp))
            with mock.patch("adapters.semgrep_adapter._find_semgrep", return_value=None):
                with mock.patch("tools.installer.ensure_semgrep") as install:
                    available, reason = SemgrepAdapter().is_available(ctx)
        install.assert_not_called()
        self.assertFalse(available)
        self.assertIn("--install-missing", reason)

    def test_extracts_source_intermediate_sink_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            trace = {"dataflow_trace": {
                "taint_source": ["source", {"path": str(repo / "A.kt"), "start": {"line": 2}}],
                "intermediate_vars": [{"location": {"path": str(repo / "B.kt"), "start": {"line": 5}},
                                       "content": "propagated"}],
                "taint_sink": ["sink", {"path": str(repo / "C.kt"), "start": {"line": 8}}],
            }}
            path = _extract_dataflow_path(trace, repo)
            self.assertEqual([p["file"] for p in path], ["A.kt", "B.kt", "C.kt"])
            self.assertEqual([p["line"] for p in path], [2, 5, 8])

    def test_sticky_broadcast_and_finally_release_are_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.java"
            source.write_text(
                "class A { void f() { try { manager.registerListener(listener, sensor, 1); "
                "} finally { manager.unregisterListener(listener); } } }"
            )
            sticky = Candidate(
                engine="semgrep", rule_id="R-SG-017", file="A.java", line=1,
                category="security/x", severity="major",
                snippet="context.registerReceiver(null, filter)",
            )
            paired = Candidate(
                engine="semgrep", rule_id="R-SG-023", file="A.java", line=1,
                category="stability/x", severity="major",
                snippet="manager.registerListener(listener, sensor, 1)",
            )
            self.assertEqual(_contextual_suppression(sticky, repo), "sticky-broadcast-null-receiver")
            self.assertEqual(_contextual_suppression(paired, repo), "paired-release-in-finally")


class LintParserTests(unittest.TestCase):
    def test_unmapped_warning_is_not_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            src = repo / "app/src/main/Foo.kt"
            src.parent.mkdir(parents=True)
            src.write_text("fun x() {}")
            report = repo / "lint.xml"
            report.write_text(
                '<issues><issue id="NewLintRule" severity="Warning" message="m">'
                f'<location file="{src}" line="1"/></issue></issues>'
            )
            candidates, issues = _parse_lint_xml(report, repo, {"app/src/main/Foo.kt"})
            self.assertEqual(len(candidates), 1)
            self.assertIn("NewLintRule", issues)
            self.assertEqual(candidates[0].category, "lint/newlintrule")

    def test_success_without_fresh_report_does_not_reuse_stale_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            gradlew = repo / "gradlew"
            gradlew.write_text("#!/bin/sh\nexit 0\n")
            (repo / "lint-results.xml").write_text(
                '<issues><issue id="OldIssue" severity="Warning" message="stale"/></issues>'
            )
            ctx = ScanContext(
                repo=repo,
                scope_files=[],
                rules_dir=repo,
                detect_info={"suggested_lint_tasks": ["lint"]},
                allow_build_execution=True,
            )
            result = LintAdapter().run(ctx)
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.available)
            self.assertEqual(result.candidates, [])
            self.assertIn("未产生新的 XML", result.unavailable_reason)

    def test_existing_report_is_ingested_without_gradle_and_marked_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            src = repo / "app/src/main/Foo.java"
            src.parent.mkdir(parents=True)
            src.write_text("class Foo {}")
            report = repo / "app/build/reports/lint-results-debug.xml"
            report.parent.mkdir(parents=True)
            report.write_text(
                '<issues><issue id="SoonBlockedPrivateApi" severity="Error" message="blocked">'
                f'<location file="{src}" line="1"/></issue></issues>'
            )
            ctx = ScanContext(
                repo=repo, scope_files=["app/src/main/Foo.java"], rules_dir=repo,
                detect_info={"config": {}}, allow_build_execution=False,
            )
            adapter = LintAdapter()
            self.assertTrue(adapter.is_available(ctx)[0])
            result = adapter.run(ctx)
            self.assertEqual(result.status, "partial")
            self.assertEqual(len(result.candidates), 1)
            self.assertEqual(result.candidates[0].native_rule_id, "SoonBlockedPrivateApi")


class PMDParserTests(unittest.TestCase):
    def test_generic_priority_one_is_not_critical(self):
        candidate = _parse_violation({
            "rule": "SomeBestPractice",
            "ruleset": "Best Practices",
            "beginline": 3,
            "endline": 3,
            "priority": 1,
            "description": "advice",
        }, "A.java")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.severity, "major")

    def test_avoid_file_stream_has_calibrated_severity(self):
        candidate = _parse_violation({
            "rule": "AvoidFileStream",
            "ruleset": "Performance",
            "beginline": 3,
            "endline": 3,
            "priority": 1,
            "description": "advice",
        }, "A.java")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.severity, "minor")

    def test_default_profile_only_emits_high_signal_rules(self):
        self.assertTrue(_should_emit("CloseResource"))
        self.assertTrue(_should_emit("HardCodedCryptoKey"))
        self.assertFalse(_should_emit("AvoidSynchronizedAtMethodLevel"))
        self.assertFalse(_should_emit("DoNotUseThreads"))
        self.assertTrue(_should_emit("AvoidSynchronizedAtMethodLevel", include_advisories=True))


class EngineStatusTests(unittest.TestCase):
    def test_skipped_is_not_reported_as_complete(self):
        self.assertEqual(_overall_status([
            {"status": "complete"}, {"status": "skipped"},
        ]), "complete_with_skips")

    def test_not_applicable_is_neutral(self):
        self.assertEqual(_overall_status([
            {"status": "complete"}, {"status": "not_applicable"},
        ]), "complete")


if __name__ == "__main__":
    unittest.main()
