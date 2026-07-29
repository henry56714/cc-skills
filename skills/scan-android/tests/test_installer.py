import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent.parent / "scripts" / "tools"
sys.path.insert(0, str(TOOLS))
import installer  # noqa: E402


class SafeZipTests(unittest.TestCase):
    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape", "x")
            with zipfile.ZipFile(archive) as zf:
                with self.assertRaises(RuntimeError):
                    installer._safe_extract_zip(zf, Path(tmp) / "out")

    def test_extracts_normal_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "ok.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("bin/tool", "x")
            out = Path(tmp) / "out"
            with zipfile.ZipFile(archive) as zf:
                installer._safe_extract_zip(zf, out)
            self.assertEqual((out / "bin/tool").read_text(), "x")


class PinnedToolTests(unittest.TestCase):
    def test_find_pmd_ignores_other_cached_versions_and_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = installer.TOOLS_DIR
            try:
                installer.TOOLS_DIR = Path(tmp)
                wrong = Path(tmp) / "pmd" / "pmd-bin-99.0.0" / "bin" / "pmd"
                wrong.parent.mkdir(parents=True)
                wrong.write_text("wrong")
                self.assertIsNone(installer.find_pmd())

                exact = (
                    Path(tmp) / "pmd" /
                    f"pmd-bin-{installer._PMD_VERSION}" / "bin" / "pmd"
                )
                exact.parent.mkdir(parents=True)
                exact.write_text("exact")
                self.assertEqual(installer.find_pmd(), str(exact))
            finally:
                installer.TOOLS_DIR = original


if __name__ == "__main__":
    unittest.main()
