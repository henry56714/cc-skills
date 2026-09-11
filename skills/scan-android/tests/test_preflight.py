import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import preflight  # noqa: E402


class PreflightAuthorizationTests(unittest.TestCase):
    def test_default_preflight_never_installs_missing_tools(self):
        missing = preflight.CheckResult(
            "semgrep", "missing", "not installed",
            can_auto_install=True, is_hard_required=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(preflight, "_read_scan_config", return_value={}):
                with mock.patch.object(preflight, "_detect_all", return_value=[missing]):
                    with mock.patch.object(preflight, "_try_install") as install:
                        result = preflight.run_preflight(Path(tmp))
        install.assert_not_called()
        self.assertTrue(result["ready"])
        self.assertTrue(result["warnings"])

    def test_even_trusted_config_cannot_authorize_gradle_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                preflight, "_read_scan_config",
                return_value={"allow_gradle_execution": True},
            ):
                with mock.patch.object(preflight, "_detect_all", return_value=[]) as detect:
                    result = preflight.run_preflight(
                        Path(tmp), trust_project_config=True,
                    )
            self.assertTrue(result["ready"])
            self.assertFalse(detect.call_args.kwargs["gradle_needed"])
            self.assertTrue(any("仅命令行" in warning for warning in result["warnings"]))

    def test_repository_nav_backend_cannot_force_semantic_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_venv = Path(tmp) / "missing-repomap-venv"
            with mock.patch.dict(
                preflight.os.environ, {"SCAN_ANDROID_NAV_BACKEND": ""}, clear=False,
            ):
                with mock.patch.object(
                    preflight, "_read_scan_config", return_value={"nav_backend": "source"},
                ) as read_config:
                    with mock.patch.object(preflight, "REPOMAP_VENV_DIR", missing_venv):
                        result = preflight._detect_repomap_venv(Path(tmp))
            read_config.assert_not_called()
            self.assertEqual(result.status, "missing")


if __name__ == "__main__":
    unittest.main()
