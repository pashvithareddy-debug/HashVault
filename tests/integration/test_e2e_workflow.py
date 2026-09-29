"""End-to-end tests that run the real CLI in separate processes (no in-process shortcuts)."""

import json
import os
import subprocess
import sys
import unittest
from importlib.util import find_spec
from pathlib import Path

from tests.helpers import TempDirTestCase, sha256

SRC = str(Path(__file__).resolve().parents[2] / "src")


def hv(*args: str, cwd=None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC, "NO_COLOR": "1"}

    result = subprocess.run(
        [sys.executable, "-m", "hashvault", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )

    if result.returncode != 0:
        print(
            "\n--- HASHVAULT SUBPROCESS FAILURE ---\n"
            f"command: {args!r}\n"
            f"returncode: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
            "--- END HASHVAULT SUBPROCESS FAILURE ---",
            flush=True,
        )

    return result

class FullWorkflowTests(TempDirTestCase):
    def test_hash_verify_manifest_modify_detect(self):
        project = self.tmp / "project"
        (project / "src").mkdir(parents=True)
        (project / "README.md").write_text("hello")
        (project / "src" / "app.py").write_text("print('v1')")

        # hash → verify
        r = hv("hash", str(project / "README.md"))
        self.assertEqual(r.returncode, 0)
        digest = r.stdout.split()[0]
        self.assertEqual(digest, sha256(b"hello"))
        self.assertEqual(hv("verify", str(project / "README.md"), digest).returncode, 0)
        self.assertEqual(hv("verify", str(project / "README.md"), "0" * 64).returncode, 1)

        # manifest create → verify clean
        self.assertEqual(hv("manifest", "create", str(project)).returncode, 0)
        manifest = project / "hashvault.manifest.json"
        self.assertEqual(hv("manifest", "verify", str(manifest)).returncode, 0)

        # modify a file → detected, exit 1, correct classification
        (project / "src" / "app.py").write_text("print('TAMPERED')")
        r = hv("manifest", "verify", str(manifest), "--json")
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertEqual(data["status"], "changes_detected")
        changed = {f["path"]: f["status"] for f in data["files"] if f["status"] != "unchanged"}
        self.assertEqual(changed, {"src/app.py": "modified"})

        # add + delete + rename on top
        (project / "new.txt").write_text("n")
        (project / "README.md").rename(project / "README.txt")
        r = hv("scan", str(project), "--json")
        summary = json.loads(r.stdout)["summary"]
        self.assertEqual((summary["modified"], summary["added"], summary["renamed"]), (1, 1, 1))

        # regenerate baseline → clean again
        self.assertEqual(hv("manifest", "create", str(project), "--force").returncode, 0)
        self.assertEqual(hv("scan", str(project)).returncode, 0)

    def test_manifest_stored_elsewhere_is_the_recommended_mode(self):
        project = self.tmp / "project"
        project.mkdir()
        (project / "a.txt").write_text("a")
        safe = self.tmp / "safe" / "m.json"
        safe.parent.mkdir()
        self.assertEqual(hv("manifest", "create", str(project), "-o", str(safe)).returncode, 0)
        self.assertEqual(hv("manifest", "verify", str(safe), "--root", str(project)).returncode, 0)
        (project / "a.txt").write_text("evil")
        self.assertEqual(hv("manifest", "verify", str(safe), "--root", str(project)).returncode, 1)

    def test_stdout_stderr_separation_and_quiet_mode(self):
        f = self.tmp / "f"
        f.write_text("x")
        r = hv("hash", str(f), "-a", "md5")
        self.assertIn("legacy", r.stderr)
        self.assertNotIn("legacy", r.stdout)
        r = hv("verify", str(f), "0" * 64, "-q")
        self.assertEqual((r.returncode, r.stdout), (1, ""))


@unittest.skipUnless(find_spec("cryptography"), "needs the optional 'cryptography' package")
class SignedWorkflowTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.project = self.tmp / "project"
        self.project.mkdir()
        (self.project / "a.txt").write_text("a")
        (self.project / "b.txt").write_text("b")
        self.keys = self.tmp / "keys"
        self.keys.mkdir()
        self.assertEqual(hv("keygen", str(self.keys / "vault")).returncode, 0)
        self.priv, self.pub = str(self.keys / "vault.key"), str(self.keys / "vault.pub")
        self.m = str(self.project / "hashvault.manifest.json")
        self.assertEqual(hv("manifest", "create", str(self.project)).returncode, 0)
        self.assertEqual(hv("manifest", "sign", self.m, "--key", self.priv).returncode, 0)

    def test_signed_manifest_verifies_and_signature_file_is_not_a_change(self):
        self.assertEqual(hv("manifest", "verify-signature", self.m, "--public-key", self.pub).returncode, 0)
        r = hv("manifest", "verify", self.m, "--public-key", self.pub, "--json")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["status"], "clean")  # .sig not reported as "added"

    def test_file_tampering_still_detected_under_valid_signature(self):
        (self.project / "a.txt").write_text("evil")
        r = hv("manifest", "verify", self.m, "--public-key", self.pub, "--json")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["summary"]["modified"], 1)

    def test_attacker_who_rewrites_file_and_manifest_is_caught_by_signature(self):
        # Attacker tampers with a file, then regenerates the manifest to hide it.
        (self.project / "a.txt").write_text("evil")
        self.assertEqual(hv("manifest", "create", str(self.project), "--force").returncode, 0)
        # Without a signature check the forgery passes...
        self.assertEqual(hv("manifest", "verify", self.m).returncode, 0)
        # ...but the signature no longer matches, so the trusted check fails.
        r = hv("manifest", "verify", self.m, "--public-key", self.pub, "--no-color")
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALID", r.stdout)
        self.assertIn("DO NOT TRUST", r.stdout)

    def test_wrong_public_key_rejected(self):
        self.assertEqual(hv("keygen", str(self.keys / "attacker")).returncode, 0)
        r = hv("manifest", "verify-signature", self.m, "--public-key", str(self.keys / "attacker.pub"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("different key", r.stdout)

    def test_missing_signature_file_exit_4(self):
        os.remove(self.m + ".sig")
        r = hv("manifest", "verify", self.m, "--public-key", self.pub)
        self.assertEqual(r.returncode, 4)

    def test_public_key_without_manifest_is_usage_error(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertEqual(hv("scan", str(empty), "--public-key", self.pub).returncode, 2)

    def test_sign_refuses_invalid_manifest_and_overwrite(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{nope")
        self.assertEqual(hv("manifest", "sign", str(bad), "--key", self.priv).returncode, 4)
        self.assertEqual(hv("manifest", "sign", self.m, "--key", self.priv).returncode, 4)  # .sig exists
        self.assertEqual(hv("manifest", "sign", self.m, "--key", self.priv, "--force").returncode, 0)

    def test_scan_with_baseline_and_public_key(self):
        r = hv("scan", str(self.project), "--baseline", self.m, "--public-key", self.pub)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
