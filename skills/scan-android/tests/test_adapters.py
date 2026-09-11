import json
import tempfile
import unittest
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from adapters.semgrep_adapter import SemgrepAdapter, _contextual_suppression, _extract_dataflow_path  # noqa: E402
from adapters.base import ScanContext  # noqa: E402
from adapters.lint_adapter import LintAdapter, _parse_lint_xml  # noqa: E402
from adapters.pmd_adapter import _parse_violation, _should_emit  # noqa: E402
from run_engines import _overall_status, _select_engines, _unselected_engine_gaps  # noqa: E402
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

    def test_repository_registry_config_cannot_enable_or_inject_network_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".scan").mkdir()
            (repo / ".scan/config.json").write_text(json.dumps({
                "semgrep_use_registry": True,
                "semgrep_registry_packs": ["p/attacker-controlled"],
            }))
            rules = repo / "rules"
            rules.mkdir()
            (rules / "local.yaml").write_text("rules:\n  - id: local-rule\n")
            ctx = ScanContext(
                repo=repo, scope_files=[], rules_dir=rules,
                allow_network_rules=False, trust_project_config=True,
            )
            completed = SimpleNamespace(
                returncode=0, stdout='{"results": [], "errors": []}', stderr="",
            )
            with mock.patch("adapters.semgrep_adapter._find_semgrep", return_value="semgrep"):
                with mock.patch("adapters.semgrep_adapter._QUERIES_DIR", rules):
                    with mock.patch(
                        "adapters.semgrep_adapter.subprocess.run", return_value=completed,
                    ) as run:
                        result = SemgrepAdapter().run(ctx)
            command = run.call_args.args[0]
            self.assertNotIn("p/attacker-controlled", command)
            self.assertFalse(any(arg.startswith("p/") for arg in command))
            self.assertTrue(any("未获调用方" in note.get("note", "") for note in result.notes))

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
    def test_discovered_report_symlink_outside_repo_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "lint-results-outside.xml"
            outside.write_text("<issues/>")
            try:
                (repo / "lint-results.xml").symlink_to(outside)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            ctx = ScanContext(
                repo=repo, scope_files=[], rules_dir=repo,
                detect_info={"config": {}}, allow_build_execution=False,
            )
            available, _reason = LintAdapter().is_available(ctx)
            self.assertFalse(available)

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

    def test_every_shipping_lint_task_is_run_and_accounted_for(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "app/src/main/Foo.kt"
            source.parent.mkdir(parents=True)
            source.write_text("fun x() = Unit\n")
            gradlew = repo / "gradlew"
            gradlew.write_text("#!/bin/sh\nexit 0\n")
            ctx = ScanContext(
                repo=repo,
                scope_files=["app/src/main/Foo.kt"],
                rules_dir=repo,
                detect_info={
                    "suggested_lint_tasks": ["lintPaidRelease", "lintFreeRelease"],
                },
                allow_build_execution=True,
            )
            calls = []

            def run_lint(command, **_kwargs):
                calls.append(command[2])
                index = len(calls)
                report = repo / f"app/build/reports/lint-results-{index}.xml"
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(
                    f'<issues><issue id="VariantRule{index}" severity="Warning" message="m">'
                    f'<location file="{source}" line="1"/></issue></issues>'
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with mock.patch("adapters.lint_adapter.subprocess.run", side_effect=run_lint):
                result = LintAdapter().run(ctx)
            self.assertEqual(calls, ["lintPaidRelease", "lintFreeRelease"])
            self.assertEqual(result.status, "complete")
            self.assertEqual(len(result.candidates), 2)
            coverage_note = result.notes[-1]
            self.assertEqual(
                coverage_note["tasks_with_fresh_reports"],
                ["lintPaidRelease", "lintFreeRelease"],
            )


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

    def test_default_profile_emits_correctness_and_concurrency_rules(self):
        self.assertTrue(_should_emit("CloseResource"))
        self.assertTrue(_should_emit("HardCodedCryptoKey"))
        self.assertFalse(_should_emit("AvoidSynchronizedAtMethodLevel"))
        self.assertFalse(_should_emit("DoNotUseThreads"))
        self.assertTrue(_should_emit("BrokenNullCheck", ruleset="Error Prone"))
        self.assertTrue(_should_emit("DoubleCheckedLocking", ruleset="Multithreading"))
        self.assertTrue(_should_emit("AvoidSynchronizedAtMethodLevel", include_advisories=True))


class EngineStatusTests(unittest.TestCase):
    def test_duplicate_explicit_engine_name_is_run_once(self):
        selected = _select_engines("semgrep,semgrep,pmd,semgrep")
        self.assertEqual([adapter.name for adapter in selected], ["semgrep", "pmd"])

    def test_explicit_engine_subset_records_every_omitted_engine_as_skipped(self):
        gaps = dict(_unselected_engine_gaps({"semgrep"}, set()))
        self.assertEqual(set(gaps), {"detekt", "pmd", "lint"})
        self.assertTrue(all("--engines" in reason for reason in gaps.values()))

    def test_skipped_is_not_reported_as_complete(self):
        self.assertEqual(_overall_status([
            {"status": "complete"}, {"status": "skipped"},
        ]), "complete_with_skips")

    def test_not_applicable_is_neutral(self):
        self.assertEqual(_overall_status([
            {"status": "complete"}, {"status": "not_applicable"},
        ]), "complete")

    def test_unknown_adapter_status_fails_closed(self):
        self.assertEqual(_overall_status([{"status": "invented"}]), "incomplete")


if __name__ == "__main__":
    unittest.main()
