import json
import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_hunt_batches as hb  # noqa: E402
import build_verify_batches as vb  # noqa: E402
import check_hunt_coverage as hc  # noqa: E402


class HuntBatchTests(unittest.TestCase):
    def test_plain_local_binder_does_not_claim_aidl_ipc(self):
        _, tech, _ = hb._analyze(
            "class S : Service() { val b = Binder(); fun onBind(): IBinder = b }"
        )
        self.assertNotIn("ipc_aidl", tech)

    def test_transaction_binder_is_marked_as_ipc(self):
        _, tech, _ = hb._analyze("override fun onTransact(code: Int) = true")
        self.assertIn("ipc_aidl", tech)

    def test_token_budget_splits_and_marks_perspectives(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "src").mkdir()
            (repo / "src/A.kt").write_text("WebView\n" + "x" * 1800)
            (repo / "src/B.kt").write_text("RoomDatabase\n" + "y" * 1800)
            scope = repo / "scope.txt"
            scope.write_text("src/A.kt\nsrc/B.kt\n")
            result = hb.build_batches(repo, scope, repo / "out", 10, token_budget=700)
            self.assertTrue(result["coverage_ok"])
            self.assertEqual(result["batches"], 2)
            first = json.loads((repo / "out/hunt_batch_0.json").read_text())
            self.assertIn("auth_dataflow", first["expected_perspectives"])
            self.assertIn("webview", first["expected_perspectives"])

    def test_missing_file_fails_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            scope = repo / "scope.txt"
            scope.write_text("missing.kt\n")
            result = hb.build_batches(repo, scope, repo / "out", 10)
            self.assertFalse(result["coverage_ok"])
            self.assertEqual(result["missing"], ["missing.kt"])

    def test_cxx_and_cmake_artifacts_are_defensively_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            generated = repo / "sdk/.cxx/Debug/CMakeFiles/compiler-id/CMakeCXXCompilerId.cpp"
            generated.parent.mkdir(parents=True)
            generated.write_text("int main() {}")
            real = repo / "sdk/src/main/cpp/secrets.cpp"
            real.parent.mkdir(parents=True)
            real.write_text("int secret() { return 1; }")
            scope = repo / "scope.txt"
            scope.write_text(
                "sdk/.cxx/Debug/CMakeFiles/compiler-id/CMakeCXXCompilerId.cpp\n"
                "sdk/src/main/cpp/secrets.cpp\n"
            )
            result = hb.build_batches(repo, scope, repo / "out", 15)
            self.assertEqual(result["generated_excluded"], [
                "sdk/.cxx/Debug/CMakeFiles/compiler-id/CMakeCXXCompilerId.cpp"
            ])
            self.assertEqual(result["analyzed"], 1)

    def test_optional_perspectives_are_technology_gated(self):
        base = hb._expected_perspectives([])
        self.assertEqual(base, [
            "auth_dataflow", "lifecycle_concurrency", "performance", "free"
        ])
        network = hb._expected_perspectives(["network"])
        self.assertIn("network_crypto", network)
        self.assertNotIn("platform_ipc", network)


class VerifyBatchTests(unittest.TestCase):
    def test_all_candidates_are_batched_without_fixed_batch_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "engine.json"
            source.write_text(json.dumps({"candidates": [
                {"file": f"F{i}.kt", "line": i} for i in range(47)
            ]}))
            result = vb.build(repo, [source], repo / "out", max_candidates=20, token_budget=100000)
            self.assertTrue(result["coverage_ok"])
            self.assertEqual(result["batches"], 3)
            self.assertEqual(result["candidates_batched"], 47)

    def test_empty_candidate_set_still_produces_deterministic_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "engine.json"
            source.write_text('{"candidates": []}')
            result = vb.build(repo, [source], repo / "out")
            self.assertTrue(result["coverage_ok"])
            self.assertEqual(result["batches"], 1)
            self.assertEqual(json.loads((repo / "out/verify_batch_0.json").read_text()), [])

    def test_candidates_gain_stable_provenance_and_duplicate_affinity(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source0 = repo / "hunt_result_2_0.json"
            source1 = repo / "hunt_result_2_1.json"
            candidate = {"file": "A.kt", "line": 7, "rule_id": "R-AI-1"}
            source0.write_text(json.dumps({"batch": 2, "candidates": [candidate]}))
            source1.write_text(json.dumps({"batch": 2, "candidates": [candidate]}))
            result = vb.build(repo, [source0, source1], repo / "out", max_candidates=20)
            batch = json.loads((repo / "out/verify_batch_0.json").read_text())
            self.assertEqual(len(batch), 2)
            self.assertEqual(len({item["candidate_id"] for item in batch}), 2)
            self.assertTrue(all(item["engine"] == "ai" for item in batch))
            self.assertEqual(batch[0]["provenance"][0]["hunter_sample"], 0)
            self.assertEqual(batch[1]["provenance"][0]["hunter_sample"], 1)
            self.assertEqual(result["candidate_ids_unique"], 2)


class HuntCoverageTests(unittest.TestCase):
    def _coverage(self, root: Path) -> Path:
        path = root / "hunt_coverage.json"
        path.write_text(json.dumps({
            "batches_detail": [
                {"batch": 0, "expected_perspectives": ["auth_dataflow", "free"]}
            ]
        }))
        return path

    def test_requires_result_as_well_as_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            coverage = self._coverage(out)
            (out / "hunt_attest_0_0.json").write_text(json.dumps({
                "batch": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
            }))
            result = hc.check(out, coverage, 1)
            self.assertFalse(result["ok"])
            self.assertIn("无候选结果文件", result["batches"][0]["problems"][0])

    def test_valid_result_and_attestation_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            coverage = self._coverage(out)
            (out / "hunt_attest_0_0.json").write_text(json.dumps({
                "batch": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
            }))
            (out / "hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "candidates": [],
            }))
            result = hc.check(out, coverage, 1)
            self.assertTrue(result["ok"])

    def test_rejects_string_perspectives(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            coverage = self._coverage(out)
            (out / "hunt_attest_0_0.json").write_text(json.dumps({
                "batch": 0,
                "perspectives_covered": "auth_dataflow",
            }))
            (out / "hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "candidates": [],
            }))
            result = hc.check(out, coverage, 1)
            self.assertFalse(result["ok"])
            self.assertEqual(result["unparseable_attest"], ["hunt_attest_0_0.json"])


if __name__ == "__main__":
    unittest.main()
