import json
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from adapters.base import ScanContext  # noqa: E402
from adapters.semgrep_adapter import SemgrepAdapter, _find_semgrep  # noqa: E402


class SemgrepGoldenCorpusTests(unittest.TestCase):
    def test_hidden_bug_sdk_required_rules_and_negative_fixture(self):
        if not _find_semgrep():
            self.skipTest("pinned Semgrep is not installed")
        fixture = Path(__file__).resolve().parent / "fixtures" / "hidden-bug-sdk"
        golden = json.loads((fixture / "golden.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "fixture"
            shutil.copytree(fixture, repo)
            (repo / ".scan/tmp").mkdir(parents=True)
            scope = sorted(
                path.relative_to(repo).as_posix()
                for path in repo.rglob("*")
                if path.suffix in {".java", ".kt", ".xml"}
            )
            ctx = ScanContext(repo=repo, scope_files=scope, rules_dir=repo)
            result = SemgrepAdapter().run(ctx)

        self.assertEqual(result.status, "complete", result.notes)
        actual = {(item.rule_id, item.file) for item in result.candidates}
        self.assertTrue(set(golden["required_rule_ids"]) <= {rule for rule, _ in actual})
        for forbidden in golden["forbidden"]:
            self.assertNotIn((forbidden["rule_id"], forbidden["file"]), actual)


if __name__ == "__main__":
    unittest.main()
