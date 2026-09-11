import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_gap_audit_batches as gb  # noqa: E402
import check_gap_audit_coverage as gc  # noqa: E402


class GapAuditCoverageTests(unittest.TestCase):
    def _pipeline_inputs(self, repo: Path) -> tuple[Path, Path]:
        out = repo / ".scan/tmp"
        out.mkdir(parents=True)
        source = repo / "app/src/main/Foo.kt"
        source.parent.mkdir(parents=True)
        source.write_text("fun refresh() {\n  state = load()\n}\n")
        expected_perspectives = ["auth_dataflow", "business_logic", "free"]
        expected_cases = ["R-AI-067", "R-AI-069"]
        (out / "hunt_batch_0.json").write_text(json.dumps({
            "batch": 0,
            "expected_perspectives": expected_perspectives,
            "expected_case_ids": expected_cases,
            "files": [{
                "file": "app/src/main/Foo.kt",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "line_count": 3,
            }],
        }))
        (out / "hunt_coverage.json").write_text(json.dumps({
            "schema_version": 3,
            "coverage_ok": True,
            "batches_detail": [{
                "batch": 0,
                "expected_perspectives": expected_perspectives,
                "expected_case_ids": expected_cases,
                "files": ["app/src/main/Foo.kt"],
            }],
        }))
        (out / "hunt_perspective_coverage.json").write_text(
            '{"schema_version": 3, "ok": true}'
        )
        (out / "hunt_result_0_0.json").write_text(json.dumps({
            "batch": 0,
            "sample": 0,
            "case_assessments": [{
                "case_id": case,
                "status": "no_signal",
                "signals_checked": ["relevant invariant"],
                "evidence": [],
                "conclusion": "no candidate in first pass",
            } for case in expected_cases],
            "candidates": [],
        }))
        return out, source

    @staticmethod
    def _audit_result(source: Path) -> dict:
        return {
            "batch": 0,
            "independent_pass": True,
            "prior_results_compared_after_pass": True,
            "perspectives_audited": ["auth_dataflow", "business_logic", "free"],
            "files_reviewed": [{
                "file": "app/src/main/Foo.kt",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "line_count": 3,
                "ranges": [{"start": 1, "end": 3}],
            }],
            "case_audits": [{
                "case_id": case,
                "disposition": "agree_no_signal",
                "signals_checked": ["relevant invariant"],
                "evidence": [],
                "conclusion": "independent pass found no candidate",
            } for case in ("R-AI-067", "R-AI-069")],
            "candidates": [],
        }

    def test_build_separates_prior_conclusions_and_complete_audit_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            plan = gb.build(repo, out)
            audit_input = json.loads((out / "gap_audit_batch_0.json").read_text())
            self.assertTrue(plan["coverage_ok"])
            self.assertNotIn("prior_hunter_results", audit_input)
            self.assertTrue((out / "gap_prior_0.json").is_file())
            self.assertFalse(Path(audit_input["source_batch_file"]).is_absolute())
            self.assertFalse(Path(audit_input["prior_hunter_results_file"]).is_absolute())
            self.assertFalse(Path(plan["source_hunter_coverage"]).is_absolute())
            self.assertEqual(
                plan["batches_detail"][0]["negative_cases"],
                ["R-AI-067", "R-AI-069"],
            )
            (out / "hunt_gap_result_0.json").write_text(
                json.dumps(self._audit_result(source))
            )
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertTrue(result["ok"])

    def test_missing_planned_perspective_rejects_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            audit = self._audit_result(source)
            audit["perspectives_audited"].remove("business_logic")
            (out / "hunt_gap_result_0.json").write_text(json.dumps(audit))
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertFalse(result["ok"])
            self.assertIn("视角", " ".join(result["batches"][0]["problems"]))

    def test_out_of_range_mitigation_evidence_rejects_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            audit = self._audit_result(source)
            audit["case_audits"][0].update({
                "disposition": "agree_mitigated",
                "evidence": [{"file": "app/src/main/Foo.kt", "line": 999}],
            })
            (out / "hunt_gap_result_0.json").write_text(json.dumps(audit))
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertFalse(result["ok"])
            self.assertIn("行号超出", " ".join(result["batches"][0]["problems"]))

    def test_prior_results_changed_after_plan_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            (out / "gap_prior_0.json").write_text('{"batch": 0, "tampered": true}')
            (out / "hunt_gap_result_0.json").write_text(
                json.dumps(self._audit_result(source))
            )
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertFalse(result["ok"])
            self.assertIn("prior results", " ".join(result["plan_integrity_problems"]))

    def test_coordinated_case_subset_cannot_fake_complete_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            plan_path = out / "gap_audit_plan.json"
            plan = json.loads(plan_path.read_text())
            plan["batches_detail"][0]["expected_case_ids"] = ["R-AI-067"]
            plan_path.write_text(json.dumps(plan))
            audit = self._audit_result(source)
            audit["case_audits"] = [audit["case_audits"][0]]
            (out / "hunt_gap_result_0.json").write_text(json.dumps(audit))
            result = gc.check(repo, out, plan_path)
            self.assertFalse(result["ok"])
            self.assertIn("确定性重建", " ".join(result["plan_integrity_problems"]))

    def test_boolean_batch_id_is_not_accepted_as_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            audit = self._audit_result(source)
            audit["batch"] = False
            (out / "hunt_gap_result_0.json").write_text(json.dumps(audit))
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertFalse(result["ok"])
            self.assertEqual(result["stray_or_invalid_results"], ["hunt_gap_result_0.json"])

    def test_non_array_candidates_is_reported_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            out, source = self._pipeline_inputs(repo)
            gb.build(repo, out)
            audit = self._audit_result(source)
            audit["candidates"] = None
            (out / "hunt_gap_result_0.json").write_text(json.dumps(audit))
            result = gc.check(repo, out, out / "gap_audit_plan.json")
            self.assertFalse(result["ok"])
            self.assertIn("candidates", " ".join(result["batches"][0]["problems"]))


if __name__ == "__main__":
    unittest.main()
