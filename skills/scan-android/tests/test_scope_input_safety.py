import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
import sys
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import run_engines  # noqa: E402
from adapters.base import AdapterResult  # noqa: E402
from build_hunt_batches import _read_scope as read_hunt_scope  # noqa: E402
from lib_scan import Candidate  # noqa: E402


class ScopeInputSafetyTests(unittest.TestCase):
    def test_engine_scope_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            outside = Path(tmp) / "outside.kt"
            outside.write_text("fun secret() {}")
            scope = Path(tmp) / "scope.txt"
            scope.write_text("../outside.kt\n")
            with self.assertRaises(ValueError):
                run_engines._read_scope(str(scope), repo)

    def test_hunt_scope_rejects_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            scope = Path(tmp) / "scope.txt"
            scope.write_text(str(Path(tmp) / "outside.kt") + "\n")
            with self.assertRaises(ValueError):
                read_hunt_scope(scope, repo)

    def test_engine_scope_normalizes_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            source = repo / "app" / "A.kt"
            source.parent.mkdir(parents=True)
            source.write_text("fun ok() {}")
            scope = Path(tmp) / "scope.txt"
            scope.write_text("app/A.kt\napp/./A.kt\n")
            self.assertEqual(run_engines._read_scope(str(scope), repo), ["app/A.kt"])


class EngineIsolationTests(unittest.TestCase):
    def test_non_object_engine_config_uses_safe_defaults_and_reports_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".scan").mkdir()
            (repo / ".scan/config.json").write_text("[]")
            excluded, config = run_engines._load_engine_config(repo)
            self.assertEqual(excluded, [])
            self.assertIn("__config_error__", config)

    def test_overlapping_same_rule_candidates_keep_richer_evidence(self):
        short = Candidate(
            engine="semgrep", rule_id="R-X", file="A.kt", line=3,
            category="security/x", severity="major", snippet="x",
        )
        rich = Candidate(
            engine="semgrep", rule_id="R-X", file="A.kt", line=3,
            category="security/x", severity="major", snippet="x\ny", end_line=4,
        )
        other = Candidate(
            engine="semgrep", rule_id="R-Y", file="A.kt", line=3,
            category="security/x", severity="major", snippet="z",
        )
        result = run_engines._dedupe_candidates([short, rich, other])
        self.assertEqual(len(result), 2)
        self.assertIn(rich, result)
        self.assertIn(other, result)

    def test_one_adapter_exception_does_not_discard_other_results(self):
        class Good:
            name = "good"

            def is_available(self, ctx):
                return True, ""

            def run(self, ctx):
                return AdapterResult(engine=self.name)

        class Broken:
            name = "broken"

            def is_available(self, ctx):
                return True, ""

            def run(self, ctx):
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("fun ok() {}")
            scope = repo / "scope.txt"
            scope.write_text("A.kt\n")
            argv = [
                "run_engines.py", "--repo-root", str(repo),
                "--scope-files", str(scope),
            ]
            output = io.StringIO()
            with mock.patch.object(run_engines, "_REGISTRY", [Good(), Broken()]):
                with mock.patch.object(sys, "argv", argv), redirect_stdout(output):
                    rc = run_engines.main()
            result = json.loads(output.getvalue())
            self.assertEqual(rc, 0)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["engines_used"], ["good"])
            self.assertEqual(result["incomplete_engines"], ["broken"])


if __name__ == "__main__":
    unittest.main()
