import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class PipelineEndToEndTests(unittest.TestCase):
    def test_empty_scope_pipeline_can_only_complete_with_all_receipts(self):
        skill = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            scan_tmp = repo / ".scan/tmp"
            scan_tmp.mkdir(parents=True)
            run_id = "e2e-run"
            (scan_tmp / "run_manifest.json").write_text(json.dumps({
                "run_id": run_id, "language": "en",
            }))
            (scan_tmp / "hunt_scope.txt").write_text("")
            (scan_tmp / "engine-results.json").write_text(json.dumps({
                "status": "complete", "candidates": [],
                "engine_stats": [{
                    "engine": "semgrep", "status": "complete",
                    "rules_run": 0, "rules_triggered": 0,
                    "rules_configured": 83, "candidates": 0, "truncated": 0,
                }],
            }))
            verify_batch = scan_tmp / "verify_batch_0.json"
            verify_batch.write_text("[]")
            (scan_tmp / "verify_coverage.json").write_text(json.dumps({
                "coverage_ok": True, "candidates_input": 0,
                "candidates_batched": 0, "batches": 1,
                "batch_files": [str(verify_batch)],
            }))
            (scan_tmp / "verified_batch_0.json").write_text(json.dumps({
                "batch": 0, "candidates_input": 0, "candidates_adjudicated": 0,
                "false_positive_count": 0, "duplicates_merged_count": 0,
                "confirmed": [], "needs_review": [],
            }))
            subprocess.run([
                "python3", str(skill / "scripts/merge_findings.py"),
                "--verified-glob", ".scan/tmp/verified_batch_*.json",
            ], cwd=repo, check=True, capture_output=True, text=True)
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


if __name__ == "__main__":
    unittest.main()
