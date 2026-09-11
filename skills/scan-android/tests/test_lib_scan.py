"""Unit tests for scripts/lib_scan.py (id calc, severity rank, glob expansion, JSON I/O, Candidate).

Runs with both `python3 -m unittest` (zero deps) and `pytest`.
"""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import lib_scan  # noqa: E402  (after sys.path tweak)


class FindingId(unittest.TestCase):
    def test_matches_sha1_of_canonical_string(self):
        fid = lib_scan.finding_id("app/Foo.java", 42, "security/hardcoded-secret", "R-1")
        expected = hashlib.sha1(b"app/Foo.java:42:security/hardcoded-secret:R-1").hexdigest()
        self.assertEqual(fid, expected)

    def test_deterministic(self):
        self.assertEqual(
            lib_scan.finding_id("a", 1, "c"), lib_scan.finding_id("a", 1, "c")
        )

    def test_distinct_on_each_component(self):
        base = lib_scan.finding_id("a", 1, "c")
        self.assertNotEqual(base, lib_scan.finding_id("b", 1, "c"))
        self.assertNotEqual(base, lib_scan.finding_id("a", 2, "c"))
        self.assertNotEqual(base, lib_scan.finding_id("a", 1, "d"))

    def test_rule_id_prevents_same_line_rule_collapse(self):
        self.assertNotEqual(
            lib_scan.finding_id("a", 1, "c", "R-1"),
            lib_scan.finding_id("a", 1, "c", "R-2"),
        )

    def test_root_cause_id_is_case_and_separator_stable(self):
        self.assertEqual(
            lib_scan.root_cause_id("app\\Foo.kt", "Foo.Report ", "Cleartext_Report"),
            lib_scan.root_cause_id("APP/Foo.kt", "foo.report", "cleartext-report"),
        )


class SeverityRank(unittest.TestCase):
    def test_canonical_order_is_ascending(self):
        ranks = [lib_scan.severity_rank(s) for s in ("critical", "major", "minor", "info")]
        self.assertEqual(ranks, sorted(ranks))
        self.assertLess(ranks[0], ranks[-1])

    def test_unknown_sorts_after_info(self):
        self.assertEqual(lib_scan.severity_rank("bogus"), 99)
        self.assertGreater(lib_scan.severity_rank("bogus"), lib_scan.severity_rank("info"))


class BraceGlobs(unittest.TestCase):
    def test_expands_single_brace(self):
        self.assertEqual(
            lib_scan.expand_brace_globs(["**/*.{java,kt}"]), ["**/*.java", "**/*.kt"]
        )

    def test_passthrough_without_brace(self):
        self.assertEqual(lib_scan.expand_brace_globs(["**/*.java"]), ["**/*.java"])

    def test_strips_inner_whitespace(self):
        self.assertEqual(lib_scan._expand_one("a.{x, y}"), ["a.x", "a.y"])


class JsonRoundTrip(unittest.TestCase):
    def test_atomic_write_creates_parent_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "nested" / "f.json"  # parent missing -> exercises mkdir
            data = {"k": "值", "n": 1, "list": [1, 2]}
            lib_scan.atomic_write_json(p, data)
            self.assertEqual(lib_scan.load_json(p), data)

    def test_unicode_written_raw(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.json"
            lib_scan.atomic_write_json(p, {"title": "硬编码密钥"})
            self.assertIn("硬编码密钥", p.read_text(encoding="utf-8"))  # ensure_ascii=False

    def test_load_missing_returns_default(self):
        self.assertEqual(
            lib_scan.load_json("/no/such/path.json", default={"x": 1}), {"x": 1}
        )

    def test_no_partial_or_tmp_file_on_serialization_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.json"
            with self.assertRaises(TypeError):
                lib_scan.atomic_write_json(p, {"bad": object()})  # not JSON-serializable
            self.assertFalse(p.exists())          # atomic: target never half-written
            self.assertEqual(list(Path(d).glob("*.tmp")), [])  # temp cleaned up


class HuntPolicy(unittest.TestCase):
    def test_engine_exclusions_accept_only_known_string_names(self):
        self.assertEqual(lib_scan.effective_excluded_engines({
            "excluded_engines": [" AI ", "semgrep", "unknown", 7, "ai"],
        }), ["ai", "semgrep"])

    def test_defaults_and_rejects_bool_or_too_small_values(self):
        self.assertEqual(lib_scan.effective_hunt_policy({}), {
            "samples": 2, "batch_size": 10, "token_budget": 24000,
        })
        self.assertEqual(lib_scan.effective_hunt_policy({
            "hunt_samples": True,
            "hunt_batch_size": 0,
            "hunt_token_budget": 999,
        }), {
            "samples": 2, "batch_size": 10, "token_budget": 24000,
        })

    def test_accepts_valid_explicit_values(self):
        self.assertEqual(lib_scan.effective_hunt_policy({
            "hunt_samples": 1,
            "hunt_batch_size": 7,
            "hunt_token_budget": 12000,
        }), {
            "samples": 1, "batch_size": 7, "token_budget": 12000,
        })


class StrictJsonEquality(unittest.TestCase):
    def test_boolean_does_not_equal_integer(self):
        self.assertFalse(lib_scan.strict_json_equal({"batch": True}, {"batch": 1}))
        self.assertTrue(lib_scan.strict_json_equal({"batch": 1}, {"batch": 1}))


class CliPathSafety(unittest.TestCase):
    def test_relative_scan_symlink_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            repo = root / "repo"
            outside = root / "outside"
            repo.mkdir()
            outside.mkdir()
            try:
                (repo / ".scan").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "符号链接越出仓库"):
                lib_scan.resolve_cli_path(repo, ".scan/tmp", label="output")

    def test_artifact_absolute_path_must_still_stay_in_repository(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            repo = root / "repo"
            outside = root / "outside.json"
            repo.mkdir()
            outside.write_text("secret")
            with self.assertRaisesRegex(ValueError, "越出仓库"):
                lib_scan.resolve_repo_path(repo, outside, label="artifact")

    def test_relative_glob_cannot_follow_symlink_outside_repository(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            repo = root / "repo"
            outside = root / "outside"
            repo.mkdir()
            outside.mkdir()
            (outside / "verified_batch_0.json").write_text("{}")
            try:
                (repo / "results").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "符号链接越出仓库"):
                lib_scan.expand_cli_glob(repo, "results/*.json", label="results")


class CandidateContract(unittest.TestCase):
    def test_minimal_emits_core_keys_and_omits_empty_optionals(self):
        d = lib_scan.Candidate(
            engine="semgrep", rule_id="R-SEC-001", file="A.java", line=10
        ).to_dict()
        for key in (
            "engine", "rule_id", "file", "line", "category",
            "severity", "native_rule_id", "snippet", "message",
        ):
            self.assertIn(key, d)
        self.assertNotIn("end_line", d)        # None -> omitted
        self.assertNotIn("dataflow_path", d)   # empty -> omitted

    def test_optional_fields_included_when_set(self):
        d = lib_scan.Candidate(
            engine="semgrep", rule_id="R", file="A", line=1,
            end_line=5, dataflow_path=[{"file": "A", "line": 1, "message": "m"}],
        ).to_dict()
        self.assertEqual(d["end_line"], 5)
        self.assertEqual(len(d["dataflow_path"]), 1)


if __name__ == "__main__":
    unittest.main()
