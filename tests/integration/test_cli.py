import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from hashvault import __version__
from hashvault.cli import main
from tests.helpers import TempDirTestCase, sha256


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class HashCommandTests(TempDirTestCase):
    def test_hash_default_sha256(self):
        p = self.write("f", b"abc")
        code, out, _ = run("hash", str(p))
        self.assertEqual(code, 0)
        self.assertEqual(out.split()[0], sha256(b"abc"))

    def test_generate_alias_still_works(self):
        p = self.write("f", b"abc")
        code, out, _ = run("generate", str(p))
        self.assertEqual((code, out.split()[0]), (0, sha256(b"abc")))

    def test_algorithm_and_chunk_size(self):
        p = self.write("f", b"abc" * 1000)
        code, out, _ = run("hash", str(p), "-a", "sha512", "--chunk-size", "1KB", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["results"][0]["algorithm"], "sha512")
        self.assertEqual(data["results"][0]["size"], 3000)

    def test_legacy_warning(self):
        p = self.write("f", b"abc")
        code, _, err = run("hash", str(p), "-a", "md5")
        self.assertEqual(code, 0)
        self.assertIn("legacy", err)

    def test_missing_file_exit_3(self):
        code, _, err = run("hash", str(self.tmp / "nope"))
        self.assertEqual(code, 3)
        self.assertIn("error:", err)

    def test_bad_algorithm_exit_2(self):
        p = self.write("f", b"abc")
        self.assertEqual(run("hash", str(p), "-a", "nope")[0], 2)

    def test_bad_chunk_size_exit_2(self):
        p = self.write("f", b"abc")
        self.assertEqual(run("hash", str(p), "--chunk-size", "zzz")[0], 2)

    def test_quiet_suppresses_output(self):
        p = self.write("f", b"abc")
        code, out, _ = run("hash", str(p), "-q")
        self.assertEqual((code, out), (0, ""))


class VerifyCommandTests(TempDirTestCase):
    def test_verified_exit_0(self):
        p = self.write("f", b"abc")
        code, out, _ = run("verify", str(p), sha256(b"abc"), "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED", out)
        self.assertIn("INTACT", out)

    def test_mismatch_exit_1(self):
        p = self.write("f", b"abc")
        code, out, _ = run("verify", str(p), sha256(b"zzz"), "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out)
        self.assertIn("COMPROMISED", out)

    def test_json(self):
        p = self.write("f", b"abc")
        code, out, _ = run("verify", str(p), sha256(b"abc"), "--json")
        self.assertEqual((code, json.loads(out)["status"]), (0, "verified"))

    def test_malformed_hash_exit_2(self):
        p = self.write("f", b"abc")
        self.assertEqual(run("verify", str(p), "nothex")[0], 2)

    def test_json_error_shape(self):
        code, out, _ = run("verify", str(self.tmp / "nope"), sha256(b""), "--json")
        data = json.loads(out)
        self.assertEqual((code, data["status"], data["exit_code"]), (3, "error", 3))


class ScanAndManifestTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.write("README.md", "readme")
        self.write("src/main.py", "print(1)")
        self.write("src/auth.py", "x = 1")
        self.write("config/settings.json", "{}")
        self.d = str(self.tmp)

    def test_scan_without_baseline_is_inventory(self):
        code, out, _ = run("scan", self.d, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("INVENTORY", out)
        self.assertIn("4 files hashed", out)

    def test_manifest_create_then_clean_scan(self):
        code, out, _ = run("manifest", "create", self.d)
        self.assertEqual(code, 0)
        self.assertTrue((self.tmp / "hashvault.manifest.json").is_file())
        self.assertIn("4 files", out)
        code, out, _ = run("scan", self.d, "--json")
        data = json.loads(out)
        self.assertEqual((code, data["status"]), (0, "clean"))
        self.assertEqual(data["summary"]["unchanged"], 4)

    def test_detects_modified_added_deleted_renamed(self):
        run("manifest", "create", self.d)
        self.write("src/main.py", "print(2)")
        self.write("src/logger.py", "new")
        (self.tmp / "config/settings.json").unlink()
        (self.tmp / "src/auth.py").rename(self.tmp / "src/authn.py")
        code, out, _ = run("scan", self.d, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["status"], "changes_detected")
        self.assertEqual(
            data["summary"],
            {"unchanged": 1, "modified": 1, "added": 1, "deleted": 1, "renamed": 1},
        )

    def test_text_report_lists_changes(self):
        run("manifest", "create", self.d)
        self.write("README.md", "tampered")
        code, out, _ = run("scan", self.d, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("README.md  (modified)", out)
        self.assertIn("CHANGES DETECTED", out)
        self.assertNotIn("src/main.py", out)  # unchanged hidden unless --verbose
        _, verbose, _ = run("scan", self.d, "--no-color", "-v")
        self.assertIn("src/main.py", verbose)

    def test_manifest_verify_command(self):
        m = self.tmp / "hashvault.manifest.json"
        run("manifest", "create", self.d)
        self.assertEqual(run("manifest", "verify", str(m))[0], 0)
        self.write("README.md", "tampered")
        self.assertEqual(run("manifest", "verify", str(m))[0], 1)

    def test_manifest_stored_outside_directory(self):
        out = self.tmp.parent / (self.tmp.name + ".manifest.json")
        self.addCleanup(lambda: out.unlink(missing_ok=True))
        self.assertEqual(run("manifest", "create", self.d, "-o", str(out))[0], 0)
        self.assertEqual(run("manifest", "verify", str(out), "--root", self.d)[0], 0)
        self.assertEqual(run("scan", self.d, "--baseline", str(out))[0], 0)

    def test_create_refuses_overwrite_without_force(self):
        run("manifest", "create", self.d)
        self.assertEqual(run("manifest", "create", self.d)[0], 4)
        self.assertEqual(run("manifest", "create", self.d, "--force")[0], 0)

    def test_exclude_recorded_in_manifest_and_applied_on_verify(self):
        self.write("debug.log", "noise")
        run("manifest", "create", self.d, "--exclude", "*.log")
        self.write("debug.log", "different noise")
        self.assertEqual(run("scan", self.d)[0], 0)

    def test_default_excludes(self):
        self.write(".git/HEAD", "ref")
        self.write("__pycache__/x.pyc", "b")
        _, out, _ = run("manifest", "create", self.d, "--json")
        self.assertEqual(json.loads(out)["file_count"], 4)

    def test_algorithm_mismatch_with_manifest_exit_2(self):
        run("manifest", "create", self.d, "-a", "sha512")
        self.assertEqual(run("scan", self.d, "-a", "sha256")[0], 2)
        self.assertEqual(run("scan", self.d)[0], 0)  # uses manifest's algorithm

    def test_corrupt_manifest_exit_4(self):
        m = self.write("hashvault.manifest.json", "{broken")
        self.assertEqual(run("manifest", "verify", str(m))[0], 4)
        self.assertEqual(run("scan", self.d)[0], 4)

    def test_missing_manifest_exit_4(self):
        self.assertEqual(run("manifest", "verify", str(self.tmp / "none.json"))[0], 4)

    def test_missing_directory_exit_3(self):
        self.assertEqual(run("scan", str(self.tmp / "nope"))[0], 3)
        self.assertEqual(run("manifest", "create", str(self.tmp / "nope"))[0], 3)

    def test_config_file_is_honoured(self):
        cfg = self.write("hv.toml", 'algorithm = "blake2b"\n[scan]\nexclude = ["config"]\n')
        code, out, _ = run("manifest", "create", self.d, "--config", str(cfg), "--json")
        data = json.loads(out)
        # README, src/main.py, src/auth.py and hv.toml itself; config/ is excluded
        self.assertEqual((code, data["algorithm"], data["file_count"]), (0, "blake2b", 4))
        manifest = json.loads((self.tmp / "hashvault.manifest.json").read_text())
        self.assertNotIn("config/settings.json", manifest["files"])

    def test_unicode_and_spaced_filenames(self):
        self.write("dossier été/naïve file.txt", "é")
        run("manifest", "create", self.d)
        self.assertEqual(run("scan", self.d)[0], 0)


class MiscCommandTests(unittest.TestCase):
    def test_version(self):
        code, out, _ = run("version")
        self.assertEqual((code, out.strip()), (0, f"hashvault {__version__}"))

    def test_config_command(self):
        code, out, _ = run("config", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["algorithm"], "sha256")

    def test_no_command_is_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 2)

    def test_help_exits_zero(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--help"]), 0)

    def test_python_dash_m_entrypoint_propagates_exit_code(self):
        src = str(Path(__file__).resolve().parents[2] / "src")
        env = {**os.environ, "PYTHONPATH": src}
        r = subprocess.run(
            [sys.executable, "-m", "hashvault", "hash", "definitely-missing-file"],
            capture_output=True, text=True, env=env,
        )  # fmt: skip
        self.assertEqual(r.returncode, 3)
        self.assertIn("error:", r.stderr)


if __name__ == "__main__":
    unittest.main()
