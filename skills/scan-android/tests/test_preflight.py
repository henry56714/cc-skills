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


if __name__ == "__main__":
    unittest.main()
