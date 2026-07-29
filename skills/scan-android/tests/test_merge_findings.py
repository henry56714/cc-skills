"""Tests for scripts/merge_findings.py — within-scan dedup, schema, origin gate, exit codes.

Predicate helpers are tested by import; end-to-end behavior is driven through the
script's stdin/stdout contract via subprocess (how the workflow actually calls it).

Runs with both `python3 -m unittest` (zero deps) and `pytest`.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import merge_findings as mf  # noqa: E402  (after sys.path tweak)

MERGE_SCRIPT = SCRIPTS / "merge_findings.py"


def _run_merge(candidates, extra_args=()):
    """Run merge_findings.py with candidates on stdin; return (proc, written_json_or_None)."""
    with tempfile.TemporaryDirectory() as d:
        out_path = Path(d) / "findings.json"
        proc = subprocess.run(
            [sys.executable, str(MERGE_SCRIPT), "--findings", str(out_path), *extra_args],
            input=json.dumps(candidates),
            capture_output=True,
            text=True,
        )
        written = (
            json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else None
        )
    return proc, written


def _candidate(**override):
    base = {
        "file": "app/Foo.java",
        "line": 42,
        "rule_id": "R-SEC-001",
        "category": "security/hardcoded-secret",
        "severity": "critical",
        "title": "t", "evidence": "e", "why": "w", "repro": "r", "suggestion": "s",
    }
    base.update(override)
    return base


class OriginGatePredicates(unittest.TestCase):
    def test_needs_origin_by_prefix(self):
        self.assertTrue(mf._needs_origin("perf/main-thread"))
        self.assertTrue(mf._needs_origin("stability/static-context-leak"))
        self.assertFalse(mf._needs_origin("security/hardcoded-secret"))

    def test_needs_origin_by_substring(self):
        self.assertTrue(mf._needs_origin("security/something-data-flow"))
        self.assertTrue(mf._needs_origin("security/越权-call"))

    def test_has_origin(self):
        self.assertTrue(mf._has_origin({"dataflow_path": [{"file": "a"}]}))
        self.assertTrue(mf._has_origin({"origin_trace": [1]}))
        self.assertFalse(mf._has_origin({}))
        self.assertFalse(mf._has_origin({"dataflow_path": []}))


class MergeEndToEnd(unittest.TestCase):
    def test_schema_id_and_defaults(self):
        proc, written = _run_merge([_candidate()])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(written["schema_version"], 2)
        self.assertEqual(len(written["findings"]), 1)
        f = written["findings"][0]
        self.assertEqual(
            f["id"],
            hashlib.sha1(b"app/Foo.java:42:security/hardcoded-secret").hexdigest(),
        )
        self.assertEqual(f["status"], "open")
        self.assertEqual(f["end_line"], 42)  # defaults to line when absent
        stats = json.loads(proc.stdout.strip())
        self.assertEqual(stats["findings_total"], 1)
        self.assertEqual(stats["findings_duplicate"], 0)

    def test_dedup_keeps_first_of_same_file_line_category(self):
        proc, written = _run_merge([_candidate(title="first"), _candidate(title="second")])
        self.assertEqual(len(written["findings"]), 1)
        self.assertEqual(written["findings"][0]["title"], "first")
        self.assertEqual(json.loads(proc.stdout.strip())["findings_duplicate"], 1)

    def test_different_category_not_deduped(self):
        proc, written = _run_merge([_candidate(), _candidate(category="perf/algo")])
        self.assertEqual(len(written["findings"]), 2)

    def test_missing_required_field_exits_2(self):
        bad = _candidate()
        del bad["why"]
        proc, _ = _run_merge([bad])
        self.assertEqual(proc.returncode, 2)

    def test_origin_gate_drops_unproven_conditional_finding(self):
        proc, written = _run_merge([_candidate(category="perf/main-thread")])
        self.assertEqual(len(written["findings"]), 0)
        self.assertEqual(
            json.loads(proc.stdout.strip())["findings_dropped_no_origin"], 1
        )

    def test_origin_gate_keeps_finding_with_dataflow_path(self):
        proc, written = _run_merge(
            [_candidate(
                category="perf/main-thread",
                dataflow_path=[{"file": "A", "line": 1, "message": "src"}],
            )]
        )
        self.assertEqual(len(written["findings"]), 1)
        self.assertIn("dataflow_path", written["findings"][0])

    def test_empty_input_writes_empty_findings(self):
        proc, written = _run_merge([])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(written, {"schema_version": 2, "findings": []})


if __name__ == "__main__":
    unittest.main()
