"""End-to-end tests for confirmed/needs-review merge behavior."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import merge_findings as mf  # noqa: E402

MERGE_SCRIPT = SCRIPTS / "merge_findings.py"


def _candidate(**override):
    item = {
        "file": "app/Foo.java", "line": 42, "rule_id": "R-SEC-001",
        "category": "security/hardcoded-secret", "severity": "critical",
        "title": "t", "evidence": "e", "why": "w", "repro": "r", "suggestion": "s",
    }
    item.update(override)
    return item


def _root(failure_mode="hardcoded-client-secret"):
    return {
        "primary_file": "app/Foo.java",
        "symbol": "Foo.report",
        "failure_mode": failure_mode,
    }


def _run(payload):
    with tempfile.TemporaryDirectory() as tmp:
        findings = Path(tmp) / "findings.json"
        review = Path(tmp) / "review.json"
        proc = subprocess.run(
            [sys.executable, str(MERGE_SCRIPT), "--findings", str(findings),
             "--needs-review", str(review)],
            input=json.dumps(payload), capture_output=True, text=True,
        )
        found_obj = json.loads(findings.read_text()) if findings.exists() else None
        review_obj = json.loads(review.read_text()) if review.exists() else None
        return proc, found_obj, review_obj


def _run_verified_glob(batch_count: int, verified_indices: list[int]):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        out = root / ".scan/tmp"
        out.mkdir(parents=True)
        batch_files = []
        for index in range(batch_count):
            batch = out / f"verify_batch_{index}.json"
            batch.write_text("[]")
            batch_files.append(str(batch))
        (out / "verify_coverage.json").write_text(json.dumps({
            "coverage_ok": True,
            "candidates_input": 0,
            "candidates_batched": 0,
            "batches": batch_count,
            "batch_files": batch_files,
        }))
        for index in verified_indices:
            (out / f"verified_batch_{index}.json").write_text(
                json.dumps({
                    "batch": index,
                    "candidates_input": 0,
                    "candidates_adjudicated": 0,
                    "false_positive_count": 0,
                    "duplicates_merged_count": 0,
                    "confirmed": [],
                    "needs_review": [],
                })
            )
        findings = root / ".scan/findings.json"
        review = root / ".scan/needs-review.json"
        proc = subprocess.run(
            [sys.executable, str(MERGE_SCRIPT),
             "--verified-glob", ".scan/tmp/verified_batch_*.json",
             "--findings", str(findings), "--needs-review", str(review)],
            cwd=root, capture_output=True, text=True,
        )
        return proc, findings.exists(), review.exists()


class Predicates(unittest.TestCase):
    def test_origin_predicates(self):
        self.assertTrue(mf._needs_origin("perf/main-thread"))
        self.assertTrue(mf._needs_origin("security/sql-injection-data-flow"))
        self.assertTrue(mf._needs_origin("security/exported-unprotected"))
        self.assertFalse(mf._needs_origin("security/hardcoded-secret"))
        self.assertTrue(mf._has_origin({"dataflow_path": [{"line": 1}]}))
        self.assertFalse(mf._has_origin({"dataflow_path": []}))


class MergeEndToEnd(unittest.TestCase):
    def test_verified_glob_rejects_missing_batch(self):
        proc, findings_exists, review_exists = _run_verified_glob(2, [0])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("verifier 批次不完整", proc.stderr)
        self.assertFalse(findings_exists)
        self.assertFalse(review_exists)

    def test_verified_glob_accepts_exact_coverage(self):
        proc, findings_exists, review_exists = _run_verified_glob(2, [0, 1])
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(findings_exists)
        self.assertTrue(review_exists)

    def test_adjudication_receipt_rejects_unaccounted_candidates(self):
        with self.assertRaises(ValueError):
            mf._validate_adjudication({
                "batch": 0,
                "candidates_input": 2,
                "candidates_adjudicated": 2,
                "false_positive_count": 0,
                "duplicates_merged_count": 0,
                "confirmed": [],
                "needs_review": [],
            }, Path("verified_batch_0.json"), 0, 2)

    def test_schema_id_and_bare_array_compatibility(self):
        proc, found, review = _run([_candidate()])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(found["schema_version"], 4)
        f = found["findings"][0]
        expected = hashlib.sha1(
            b"app/Foo.java:42:security/hardcoded-secret:R-SEC-001"
        ).hexdigest()
        self.assertEqual(f["id"], expected)
        self.assertEqual(f["end_line"], 42)
        self.assertEqual(review, {"schema_version": 2, "needs_review": []})

    def test_same_line_category_different_rule_is_preserved(self):
        _, found, _ = _run({"confirmed": [
            _candidate(rule_id="R-A"), _candidate(rule_id="R-B")
        ], "needs_review": []})
        self.assertEqual(len(found["findings"]), 2)

    def test_exact_duplicate_keeps_richer_evidence(self):
        _, found, _ = _run({"confirmed": [
            _candidate(evidence="x"), _candidate(evidence="much richer evidence")
        ], "needs_review": []})
        self.assertEqual(len(found["findings"]), 1)
        self.assertEqual(found["findings"][0]["evidence"], "much richer evidence")

    def test_cross_file_same_root_cause_merges_and_keeps_locations(self):
        first = _candidate(root_cause=_root(), source_candidate_ids=["a"],
                           provenance=[{"source_kind": "ai_hunter", "hunter_sample": 0}])
        second = _candidate(
            file="app/network_security_config.xml", line=8,
            category="security/cleartext-transport", rule_id="R-AI-034",
            root_cause=_root(), source_candidate_ids=["b"],
            provenance=[{"source_kind": "ai_hunter", "hunter_sample": 1}],
        )
        proc, found, _ = _run({"confirmed": [first, second], "needs_review": []})
        self.assertEqual(len(found["findings"]), 1)
        merged = found["findings"][0]
        self.assertEqual(merged["dedup_scope"], "root_cause")
        self.assertEqual(set(merged["source_candidate_ids"]), {"a", "b"})
        self.assertEqual(len(merged["related_locations"]), 2)
        self.assertEqual(json.loads(proc.stdout)["semantic_duplicates_merged"], 1)

    def test_missing_origin_moves_to_review(self):
        proc, found, review = _run({
            "confirmed": [_candidate(category="perf/main-thread")], "needs_review": []
        })
        self.assertEqual(found["findings"], [])
        self.assertEqual(len(review["needs_review"]), 1)
        stats = json.loads(proc.stdout)
        self.assertEqual(stats["moved_to_review_no_origin"], 1)

    def test_needs_review_accepts_relaxed_explanatory_fields(self):
        item = _candidate()
        item.pop("why")
        item.pop("repro")
        item.pop("suggestion")
        item["review_reason"] = "merged manifest unavailable"
        proc, _, review = _run({"confirmed": [], "needs_review": [item]})
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(review["needs_review"][0]["review_reason"], "merged manifest unavailable")

    def test_confirmed_wins_over_same_needs_review_item(self):
        confirmed = _candidate(dataflow_path=[{"file": "app/Foo.java", "line": 42}])
        review_item = _candidate(review_reason="uncertain")
        _, found, review = _run({
            "confirmed": [confirmed],
            "needs_review": [review_item],
        })
        self.assertEqual(len(found["findings"]), 1)
        self.assertEqual(review["needs_review"], [])

    def test_confirmed_wins_over_cross_file_review_with_same_root(self):
        confirmed = _candidate(root_cause=_root())
        review_item = _candidate(
            file="app/Config.xml", line=9, category="security/cleartext",
            rule_id="R-AI-034", root_cause=_root(), review_reason="uncertain",
        )
        proc, found, review = _run({"confirmed": [confirmed], "needs_review": [review_item]})
        self.assertEqual(len(found["findings"]), 1)
        self.assertEqual(review["needs_review"], [])
        self.assertEqual(json.loads(proc.stdout)["confirmed_review_conflicts_resolved"], 1)

    def test_bad_confirmed_rejected(self):
        bad = _candidate()
        bad.pop("why")
        proc, found, _ = _run({"confirmed": [bad], "needs_review": []})
        self.assertEqual(proc.returncode, 2)
        self.assertIsNone(found)

    def test_empty_input_writes_both_outputs(self):
        proc, found, review = _run({"confirmed": [], "needs_review": []})
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(found, {"schema_version": 4, "findings": []})
        self.assertEqual(review, {"schema_version": 2, "needs_review": []})

    def test_verified_output_requires_root_cause_and_provenance(self):
        input_items = [{"candidate_id": "c1"}]
        with self.assertRaisesRegex(ValueError, "root_cause"):
            mf._validate_adjudication({
                "batch": 0, "candidates_input": 1, "candidates_adjudicated": 1,
                "false_positive_count": 0, "duplicates_merged_count": 0,
                "confirmed": [_candidate()], "needs_review": [],
            }, Path("verified_batch_0.json"), 0, input_items)

    def test_verified_provenance_count_is_conserved(self):
        item = _candidate(
            root_cause=_root(), source_candidate_ids=["c1", "c2"],
            provenance=[{"source_kind": "ai_hunter"}],
        )
        mf._validate_adjudication({
            "batch": 0, "candidates_input": 2, "candidates_adjudicated": 2,
            "false_positive_count": 0, "duplicates_merged_count": 1,
            "confirmed": [item], "needs_review": [],
        }, Path("verified_batch_0.json"), 0, [{"candidate_id": "c1"}, {"candidate_id": "c2"}])


if __name__ == "__main__":
    unittest.main()
