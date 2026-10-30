import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

import pthguard_lite as pg


def run_main(argv):
    """Call main with stdout/stderr silenced (reports still exercised)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        return pg.main(argv)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_site_packages(self):
        (self.root / "normal.pth").write_text("/some/extra/path\n", encoding="utf-8")
        (self.root / "pkg.py").write_text("x = 1\n", encoding="utf-8")
        rc = run_main([str(self.root)])
        self.assertEqual(rc, 0)

    def test_malicious_pth_exec_and_base64(self):
        bad = self.root / "evil.pth"
        bad.write_text(
            "# path line\n"
            "/usr/local/lib/dummy\n"
            "import os, base64, subprocess; os.system('echo pwned')\n",
            encoding="utf-8",
        )
        results = pg.LiteScanner(str(self.root)).run()
        cats = {f["category"] for f in results["findings"]}
        self.assertIn("MALICIOUS_PTH_HOOK", cats)
        self.assertGreaterEqual(results["summary"]["threats_detected"], 1)
        self.assertEqual(run_main([str(self.root)]), 1)

    def test_benign_virtualenv_pth_ignored(self):
        (self.root / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
        results = pg.LiteScanner(str(self.root)).run()
        self.assertEqual(results["findings"], [])
        self.assertEqual(results["summary"]["pth_files"], 1)

    def test_unrecognised_import_line_is_medium(self):
        (self.root / "odd.pth").write_text("import something_custom\n", encoding="utf-8")
        results = pg.LiteScanner(str(self.root)).run()
        self.assertEqual(len(results["findings"]), 1)
        self.assertEqual(results["findings"][0]["severity"], "MEDIUM")
        self.assertEqual(results["findings"][0]["category"], "EXECUTABLE_PTH_LINE")
        # MEDIUM alone must not flip exit code
        self.assertEqual(run_main([str(self.root)]), 0)

    def test_sitecustomize_credential_hook(self):
        (self.root / "sitecustomize.py").write_text(
            "import os\nkey = os.environ.get('AWS_SECRET_ACCESS_KEY')\n",
            encoding="utf-8",
        )
        results = pg.LiteScanner(str(self.root)).run()
        cats = {f["category"] for f in results["findings"]}
        self.assertIn("SUSPICIOUS_CUSTOMIZE_HOOK", cats)
        self.assertEqual(run_main([str(self.root)]), 1)

    def test_usercustomize_subprocess(self):
        (self.root / "usercustomize.py").write_text(
            "import subprocess\nsubprocess.Popen(['id'])\n",
            encoding="utf-8",
        )
        results = pg.LiteScanner(str(self.root)).run()
        self.assertTrue(any(f["severity"] == "HIGH" for f in results["findings"]))

    def test_single_file_pth_target(self):
        f = self.root / "one.pth"
        f.write_text("import base64; base64.b64decode('YQ==')\n", encoding="utf-8")
        results = pg.LiteScanner(str(f)).run()
        self.assertEqual(results["summary"]["pth_files"], 1)
        self.assertIn("MALICIOUS_PTH_HOOK", {x["category"] for x in results["findings"]})

    def test_missing_path(self):
        missing = self.root / "nope"
        results = pg.LiteScanner(str(missing)).run()
        self.assertEqual(results["findings"][0]["category"], "PATH_NOT_FOUND")
        self.assertEqual(run_main([str(missing)]), 0)

    def test_no_target_exits_2(self):
        self.assertEqual(run_main([]), 2)

    def test_report_contains_header(self):
        report = pg.format_text_report(
            {
                "summary": {
                    "target": "/tmp/x",
                    "pth_files": 0,
                    "customize_files": 0,
                    "findings": 0,
                    "threats_detected": 0,
                },
                "findings": [],
            }
        )
        self.assertIn("PTHGUARD-LITE SCAN REPORT", report)
        self.assertIn("CLEAN", report)


if __name__ == "__main__":
    unittest.main()
