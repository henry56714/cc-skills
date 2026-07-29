"""Unit tests for scripts/detect_project.py (module/flavor detection, lint tasks, language, config).

Runs with both `python3 -m unittest` (zero deps) and `pytest`.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import detect_project as dp  # noqa: E402  (after sys.path tweak)


class ExtractBlock(unittest.TestCase):
    def test_returns_balanced_inner_content(self):
        block = dp._extract_block(
            "android { productFlavors { paid { } free { } } }", "productFlavors"
        )
        self.assertIsNotNone(block)
        self.assertIn("paid", block)
        self.assertIn("free", block)
        self.assertNotIn("android", block)  # stops at the matching brace

    def test_missing_keyword_returns_none(self):
        self.assertIsNone(dp._extract_block("android { }", "productFlavors"))


class SuggestLintTasks(unittest.TestCase):
    def test_no_flavors_defaults(self):
        self.assertEqual(dp._suggest_lint_tasks([]), ["lintDebug", "lint"])

    def test_flavor_capitalized_and_appended_before_defaults(self):
        tasks = dp._suggest_lint_tasks(["paid"])
        self.assertEqual(tasks[0], "lintPaidDebug")
        self.assertEqual(tasks[-2:], ["lintDebug", "lint"])

    def test_dedups_repeated_flavor(self):
        self.assertEqual(dp._suggest_lint_tasks(["paid", "paid"]).count("lintPaidDebug"), 1)


class DetectLanguage(unittest.TestCase):
    def test_config_takes_priority(self):
        self.assertEqual(dp._detect_language({"language": "zh-CN"}), "zh")
        self.assertEqual(dp._detect_language({"language": "en-US"}), "en")

    def test_env_used_when_no_config(self):
        with mock.patch.dict(os.environ, {"LANG": "zh_CN.UTF-8"}, clear=True):
            self.assertEqual(dp._detect_language({}), "zh")
        with mock.patch.dict(os.environ, {"LANG": "en_US.UTF-8"}, clear=True):
            self.assertEqual(dp._detect_language({}), "en")

    def test_lc_all_overrides_lang(self):
        with mock.patch.dict(os.environ, {"LC_ALL": "zh_CN.UTF-8", "LANG": "en_US.UTF-8"}, clear=True):
            self.assertEqual(dp._detect_language({}), "zh")


class DetectModules(unittest.TestCase):
    def _repo(self, d, settings, dirs):
        repo = Path(d)
        for m in dirs:
            (repo / m).mkdir(parents=True, exist_ok=True)
        (repo / "settings.gradle").write_text(settings, encoding="utf-8")
        return repo

    def test_parses_groovy_and_kotlin_includes_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(
                d,
                "include ':app', ':core'\ninclude(':feature:login')\n",
                ["app", "core", "feature/login"],
            )
            self.assertEqual(
                dp._detect_modules(repo, []), ["app", "core", "feature/login"]
            )

    def test_skips_commented_include_even_if_dir_exists(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(
                d, "include ':app'\n// include ':ignored'\n", ["app", "ignored"]
            )
            mods = dp._detect_modules(repo, [])
            self.assertEqual(mods, ["app"])

    def test_skips_include_whose_dir_is_absent(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo(d, "include ':app', ':ghost'\n", ["app"])
            self.assertEqual(dp._detect_modules(repo, []), ["app"])

    def test_falls_back_to_build_gradle_scan(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "app").mkdir()
            (repo / "app" / "build.gradle").write_text("", encoding="utf-8")
            (repo / "buildSrc").mkdir()
            (repo / "buildSrc" / "build.gradle").write_text("", encoding="utf-8")
            mods = dp._detect_modules(repo, [])
            self.assertIn("app", mods)
            self.assertNotIn("buildSrc", mods)  # buildSrc explicitly excluded


class DetectFlavors(unittest.TestCase):
    def _module_with_gradle(self, d, body):
        repo = Path(d)
        (repo / "app").mkdir()
        (repo / "app" / "build.gradle").write_text(body, encoding="utf-8")
        return repo

    def test_groovy_flavors(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._module_with_gradle(
                d, "android {\n  productFlavors {\n    paid { }\n    free { }\n  }\n}\n"
            )
            self.assertEqual(dp._detect_flavors(repo, ["app"]), ["paid", "free"])

    def test_kotlin_dsl_flavors(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._module_with_gradle(
                d, 'android {\n  productFlavors {\n    create("paid") { }\n  }\n}\n'
            )
            self.assertEqual(dp._detect_flavors(repo, ["app"]), ["paid"])

    def test_no_flavors_block(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._module_with_gradle(d, "android {\n  defaultConfig { }\n}\n")
            self.assertEqual(dp._detect_flavors(repo, ["app"]), [])


class LoadConfig(unittest.TestCase):
    def test_missing_returns_empty(self):
        self.assertEqual(dp._load_config(Path("/no/such/config.json")), {})

    def test_valid_dict(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"language": "en"}), encoding="utf-8")
            self.assertEqual(dp._load_config(p), {"language": "en"})

    def test_malformed_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text("{not valid json", encoding="utf-8")
            self.assertEqual(dp._load_config(p), {})

    def test_non_dict_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text("[1, 2, 3]", encoding="utf-8")
            self.assertEqual(dp._load_config(p), {})

    def test_invalid_existing_config_is_reported_in_project_notes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / ".scan").mkdir()
            (repo / ".scan/config.json").write_text("[]", encoding="utf-8")
            info = dp.detect_project(repo)
            self.assertEqual(info["config"], {})
            self.assertTrue(any("invalid project config" in note for note in info["notes"]))


class SampleRepoIntegration(unittest.TestCase):
    """Smoke test against the real sample repo; skipped when it isn't present."""

    SAMPLE = Path("/path/to/sample/android-project")

    @unittest.skipUnless(SAMPLE.is_dir(), "sample repo not present")
    def test_detect_modules_finds_app(self):
        mods = dp._detect_modules(self.SAMPLE, [])
        self.assertTrue(mods)            # non-empty
        self.assertIn("app", mods)


if __name__ == "__main__":
    unittest.main()
