import json
import hashlib
import tempfile
import unittest
import re
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_hunt_batches as hb  # noqa: E402
import build_verify_batches as vb  # noqa: E402
import check_hunt_coverage as hc  # noqa: E402
from fallback_verify import build_fallback  # noqa: E402


class HuntBatchTests(unittest.TestCase):
    def test_every_expected_case_is_documented(self):
        rules = (Path(__file__).resolve().parent.parent / "rules/ai/hunting.md").read_text()
        expected = {case for cases in hb.PERSPECTIVE_CASES.values() for case in cases}
        self.assertTrue(expected <= set(re.findall(r"R-AI-\d{3}", rules)))

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

    def test_rebuilding_hunter_batches_invalidates_downstream_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "A.kt").write_text("fun x() {}")
            scope = repo / "scope.txt"
            scope.write_text("A.kt\n")
            out = repo / "out"
            out.mkdir()
            for name in ("verify_coverage.json", "merge_receipt.json", "verified_batch_0.json"):
                (out / name).write_text("{}")
            hb.build_batches(repo, scope, out, 10)
            self.assertFalse((out / "verify_coverage.json").exists())
            self.assertFalse((out / "merge_receipt.json").exists())
            self.assertFalse((out / "verified_batch_0.json").exists())

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
            "auth_dataflow", "lifecycle_concurrency", "failure_reliability",
            "performance", "free"
        ])
        network = hb._expected_perspectives(["network"])
        self.assertIn("network_crypto", network)
        self.assertNotIn("platform_ipc", network)

    def test_permissions_and_sdk_markers_enable_dedicated_perspectives_and_cases(self):
        _, tech, _ = hb._analyze(
            '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />\n'
            'plugins { id("com.android.library") }\nSystem.loadLibrary("x")'
        )
        expected = hb._expected_perspectives(tech)
        self.assertIn("permissions_platform", expected)
        self.assertIn("sdk_integration", expected)
        cases = {case for perspective in expected for case in hb.PERSPECTIVE_CASES[perspective]}
        self.assertIn("R-AI-051", cases)
        self.assertIn("R-AI-053", cases)

    def test_all_numbered_ai_cases_are_assigned_to_a_perspective(self):
        mapped = {case for cases in hb.PERSPECTIVE_CASES.values() for case in cases}
        self.assertEqual(mapped, {f"R-AI-{index:03d}" for index in range(1, 61)})

    def test_related_files_stay_together_before_unrelated_high_risk_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            src = repo / "app/src/main/java/p"
            src.mkdir(parents=True)
            (src / "Api.kt").write_text("package p\nclass Api { fun load() = WebView }\n")
            (src / "Caller.kt").write_text("package p\nimport p.Api\nclass Caller { val api = Api() }\n")
            (src / "Other.kt").write_text("package p\nclass Other { val view = WebView }\n")
            scope = repo / "scope.txt"
            scope.write_text(
                "app/src/main/java/p/Api.kt\n"
                "app/src/main/java/p/Caller.kt\n"
                "app/src/main/java/p/Other.kt\n"
            )
            result = hb.build_batches(repo, scope, repo / "out", 2, token_budget=5000)
            first = json.loads((repo / "out/hunt_batch_0.json").read_text())
            self.assertEqual(first["batching_strategy"], "relation-clustered")
            self.assertEqual(
                {item["file"] for item in first["files"]},
                {"app/src/main/java/p/Api.kt", "app/src/main/java/p/Caller.kt"},
            )
            self.assertGreater(result["relation_graph_stats"]["edges"], 0)


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

    def test_root_cause_hints_keep_cross_rule_duplicates_in_one_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "engine.json"
            hint = {
                "primary_file": "A.java", "symbol": "A.start",
                "failure_mode": "worker-overlap",
            }
            source.write_text(json.dumps({"candidates": [
                {"file": "A.java", "line": 10, "rule_id": "R-AI-005", "root_cause_hint": hint},
                {"file": "B.java", "line": 30, "rule_id": "R-AI-057", "root_cause_hint": hint},
            ]}))
            result = vb.build(repo, [source], repo / "out", max_candidates=2)
            self.assertEqual(result["batches"], 1)
            batch = json.loads((repo / "out/verify_batch_0.json").read_text())
            self.assertEqual({item["rule_id"] for item in batch}, {"R-AI-005", "R-AI-057"})


class FallbackVerifierTests(unittest.TestCase):
    def test_failure_fallback_preserves_every_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            batch = Path(tmp) / "verify_batch_3.json"
            batch.write_text(json.dumps([
                {"candidate_id": "a", "file": "A.java", "line": 1},
                {"candidate_id": "b", "file": "B.java", "line": 2},
            ]))
            result = build_fallback(batch, "model unavailable")
            self.assertEqual(result["batch"], 3)
            self.assertEqual(result["candidates_adjudicated"], 2)
            self.assertEqual(len(result["needs_review"]), 2)
            self.assertEqual(
                {item["source_candidate_ids"][0] for item in result["needs_review"]},
                {"a", "b"},
            )


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


class HuntCoverageV2Tests(unittest.TestCase):
    def _coverage(self, root: Path) -> Path:
        path = root / "out/hunt_coverage.json"
        path.parent.mkdir()
        path.write_text(json.dumps({
            "schema_version": 2,
            "batches_detail": [{
                "batch": 0,
                "expected_perspectives": ["auth_dataflow", "free"],
                "files": ["A.kt"],
            }],
        }))
        return path

    @staticmethod
    def _receipt(path: Path, ranges=None) -> dict:
        data = path.read_bytes()
        return {
            "file": path.name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "line_count": len(data.decode("utf-8").splitlines()),
            "ranges": ranges if ranges is not None else [{"start": 1, "end": 3}],
        }

    def test_v2_validates_file_hash_lines_and_full_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            (repo / "out/hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "sample": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
                "files_reviewed": [self._receipt(source)],
                "candidates": [],
            }))
            result = hc.check(repo / "out", coverage, 1, repo_root=repo)
            self.assertTrue(result["ok"])
            self.assertEqual(result["coverage_evidence"], "file-hash-line-range-receipt")

    def test_v2_rejects_partial_read_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            (repo / "out/hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "sample": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
                "files_reviewed": [self._receipt(source, [{"start": 1, "end": 2}])],
                "candidates": [],
            }))
            result = hc.check(repo / "out", coverage, 1, repo_root=repo)
            self.assertFalse(result["ok"])
            self.assertIn("读取范围未覆盖完整文件", " ".join(result["batches"][0]["problems"]))

    def test_v2_rejects_stale_file_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            receipt = self._receipt(source)
            source.write_text("one\nchanged\nthree\n")
            (repo / "out/hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "sample": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
                "files_reviewed": [receipt],
                "candidates": [],
            }))
            result = hc.check(repo / "out", coverage, 1, repo_root=repo)
            self.assertFalse(result["ok"])
            self.assertIn("文件哈希不匹配", " ".join(result["batches"][0]["problems"]))

    def test_v2_each_sample_must_cover_all_perspectives(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            for sample, perspective in enumerate(("auth_dataflow", "free")):
                (repo / f"out/hunt_result_0_{sample}.json").write_text(json.dumps({
                    "batch": 0,
                    "sample": sample,
                    "perspectives_covered": [perspective],
                    "files_reviewed": [self._receipt(source)],
                    "candidates": [],
                }))
            result = hc.check(repo / "out", coverage, 2, repo_root=repo)
            self.assertFalse(result["ok"])
            self.assertIn("漏视角", " ".join(result["batches"][0]["problems"]))

    def test_v2_requires_every_expected_case_id_per_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            obj = json.loads(coverage.read_text())
            obj["batches_detail"][0]["expected_case_ids"] = ["R-AI-001", "R-AI-055"]
            coverage.write_text(json.dumps(obj))
            (repo / "out/hunt_result_0_0.json").write_text(json.dumps({
                "batch": 0,
                "sample": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
                "case_ids_checked": ["R-AI-001"],
                "files_reviewed": [self._receipt(source)],
                "candidates": [],
            }))
            result = hc.check(repo / "out", coverage, 1, repo_root=repo)
            self.assertFalse(result["ok"])
            self.assertIn("R-AI-055", " ".join(result["batches"][0]["problems"]))

    def test_v2_rejects_filename_batch_sample_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "A.kt"
            source.write_text("one\ntwo\nthree\n")
            coverage = self._coverage(repo)
            (repo / "out/hunt_result_0_0.json").write_text(json.dumps({
                "batch": 9, "sample": 0,
                "perspectives_covered": ["auth_dataflow", "free"],
                "files_reviewed": [self._receipt(source)], "candidates": [],
            }))
            result = hc.check(repo / "out", coverage, 1, repo_root=repo)
            self.assertFalse(result["ok"])
            self.assertEqual(result["unparseable_results"], ["hunt_result_0_0.json"])


if __name__ == "__main__":
    unittest.main()
