import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import prepare_scope as ps  # noqa: E402


class PrepareScopeTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "app/src/main/java/x").mkdir(parents=True)
        (root / "app/src/main/AndroidManifest.xml").write_text("<manifest/>")
        (root / "app/build.gradle").write_text("plugins {}")
        (root / "settings.gradle").write_text("include ':app'\n")
        (root / "app/src/main/java/x/A.kt").write_text("fun target() { helper() }\n")
        (root / "app/src/main/java/x/B.kt").write_text("fun use() { target() }\n")
        (root / "app/src/main/java/x/C.kt").write_text("fun top() { use() }\n")
        (root / "app/src/main/java/x/H.kt").write_text("fun helper() {}\n")
        (root / "shared-native").mkdir()
        (root / "shared-native/core.cpp").write_text("int parse() { return 0; }\n")
        (root / "sdk/.cxx/Debug/arm64-v8a/CMakeFiles/compiler-id").mkdir(parents=True)
        (root / "sdk/.cxx/Debug/arm64-v8a/CMakeFiles/compiler-id/CMakeCXXCompilerId.cpp").write_text("int main() {}")
        (root / "sdk/.cxx/Debug/arm64-v8a/compile_commands.json").write_text("[]")
        (root / "docs").mkdir()
        (root / "docs/AESUtil.java").write_text("class AESUtil {}")
        (root / ".vscode").mkdir()
        (root / ".vscode/settings.json").write_text("{}")
        (root / "local.properties").write_text("sdk.dir=/private/android")
        (root / "app/build/generated/X.kt").parent.mkdir(parents=True)
        (root / "app/build/generated/X.kt").write_text("fun generated() {}")

    def test_full_includes_source_types_and_excludes_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._repo(repo)
            result = ps.prepare_scope(
                repo, diff_ref=None, full=True, module=None, globs=[], impact_depth=2,
                impact=True, out_dir=repo / ".scan/tmp",
            )
            scope = (repo / ".scan/tmp/scope.txt").read_text().splitlines()
            self.assertIn("app/src/main/AndroidManifest.xml", scope)
            self.assertIn("settings.gradle", scope)
            self.assertIn("shared-native/core.cpp", scope)
            self.assertFalse(any("/build/" in f for f in scope))
            self.assertFalse(any("/.cxx/" in "/" + f for f in scope))
            self.assertNotIn("docs/AESUtil.java", scope)
            self.assertNotIn(".vscode/settings.json", scope)
            self.assertNotIn("local.properties", scope)
            self.assertEqual(result["mode"], "full")

    def test_documentation_can_be_explicitly_included_for_tool_scope_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._repo(repo)
            (repo / ".scan").mkdir(exist_ok=True)
            (repo / ".scan/config.json").write_text('{"include_documentation": true}')
            ps.prepare_scope(
                repo, diff_ref=None, full=True, module=None, globs=[], impact_depth=2,
                impact=True, out_dir=repo / ".scan/tmp",
            )
            scope = (repo / ".scan/tmp/scope.txt").read_text().splitlines()
            hunt = (repo / ".scan/tmp/hunt_scope.txt").read_text().splitlines()
            self.assertIn("docs/AESUtil.java", scope)
            self.assertNotIn("docs/AESUtil.java", hunt)

    def test_run_manifest_records_reproducibility_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._repo(repo)
            ps.prepare_scope(
                repo, diff_ref=None, full=True, module=None, globs=[], impact_depth=2,
                impact=True, out_dir=repo / ".scan/tmp", language="zh",
            )
            import json
            manifest = json.loads((repo / ".scan/tmp/run_manifest.json").read_text())
            self.assertTrue(manifest["source_only"])
            self.assertEqual(manifest["language"], "zh")
            self.assertEqual(manifest["scope"]["scope_files"], 8)
            self.assertEqual(len(manifest["skill_fingerprint"]), 64)

    def test_impact_slice_adds_callee_and_recursive_callers(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._repo(repo)
            all_files = set(ps._iter_source_files(
                repo, ["app"], {".kt", ".xml", ".gradle"}, []
            ))
            impact = ps._impact_expand(
                repo, {"app/src/main/java/x/A.kt"}, all_files, ["app"], depth=2
            )
            self.assertIn("app/src/main/java/x/H.kt", impact)  # callee definition
            self.assertIn("app/src/main/java/x/B.kt", impact)  # direct caller
            self.assertIn("app/src/main/java/x/C.kt", impact)  # caller of caller

    def test_manifest_change_expands_entire_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._repo(repo)
            all_files = set(ps._iter_source_files(
                repo, ["app"], {".kt", ".xml", ".gradle"}, []
            ))
            impact = ps._impact_expand(
                repo, {"app/src/main/AndroidManifest.xml"}, all_files, ["app"], depth=2
            )
            self.assertTrue(all_files <= impact)


if __name__ == "__main__":
    unittest.main()
