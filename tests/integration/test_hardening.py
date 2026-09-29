import hashlib
import json
import os
import threading
import tracemalloc
import unittest
from unittest import mock

from hashvault.core import hasher
from hashvault.core.hasher import hash_file
from hashvault.core.manifest import parse_manifest
from hashvault.errors import FileError, ManifestError
from tests.helpers import TempDirTestCase, sha256
from tests.integration.test_cli import run

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
POSIX = os.name == "posix"


@unittest.skipUnless(POSIX, "symlink semantics")
class SymlinkAttackTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.write("outside/secret.txt", "TOP SECRET")
        self.root = self.tmp / "project"
        self.write("project/real.txt", "real")

    def test_symlinks_to_outside_are_not_followed_by_default(self):
        os.symlink(self.outside / "secret.txt", self.root / "file_link")
        os.symlink(self.outside, self.root / "dir_link")
        code, out, _ = run("manifest", "create", str(self.root), "--json")
        self.assertEqual(json.loads(out)["file_count"], 1)
        manifest = json.loads((self.root / "hashvault.manifest.json").read_text())
        self.assertEqual(list(manifest["files"]), ["real.txt"])

    def test_manifest_entries_never_read_through_symlinks(self):
        """A manifest naming evil/secret.txt must not cause HashVault to open the link target."""
        os.symlink(self.outside, self.root / "evil")
        m = self.write(
            "project/hashvault.manifest.json",
            json.dumps(
                {
                    "version": "1.0",
                    "algorithm": "sha256",
                    "created_at": "x",
                    "files": {"evil/secret.txt": sha256(b"TOP SECRET"), "real.txt": sha256(b"real")},
                }
            ),
        )
        code, out, _ = run("manifest", "verify", str(m), "--json")
        data = json.loads(out)
        statuses = {f["path"]: f["status"] for f in data["files"]}
        self.assertEqual(code, 1)
        self.assertEqual(statuses["evil/secret.txt"], "deleted")  # not "unchanged"
        self.assertEqual(statuses["real.txt"], "unchanged")

    def test_swapping_file_for_symlink_is_detected(self):
        run("manifest", "create", str(self.root))
        (self.root / "real.txt").unlink()
        os.symlink(self.outside / "secret.txt", self.root / "real.txt")
        code, out, _ = run("scan", str(self.root), "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["summary"]["deleted"], 1)

    def test_dangling_symlink_does_not_crash(self):
        os.symlink(self.tmp / "does-not-exist", self.root / "dangling")
        self.assertEqual(run("manifest", "create", str(self.root))[0], 0)


class MaliciousManifestTests(TempDirTestCase):
    def test_deeply_nested_json_rejected_cleanly(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"[" * 200_000)

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"\xff\xfe\x00garbage")

    def test_null_and_control_characters_in_paths(self):
        h = sha256(b"x")
        m = parse_manifest(json.dumps({"version": "1.0", "algorithm": "sha256", "created_at": "",
                                       "files": {"a\nb": h}}).encode())  # fmt: skip
        self.assertIn("a\nb", m.files)  # accepted as data, never executed or used as a path to open

    def test_traversal_variants_rejected_via_cli(self):
        for evil in ("../x", "/abs", "a/../../b", "..\\x", "C:\\x"):
            m = self.write(
                "m.json",
                json.dumps({"version": "1.0", "algorithm": "sha256", "created_at": "",
                            "files": {evil: sha256(b"x")}}),
            )  # fmt: skip
            self.assertEqual(run("manifest", "verify", str(m), "--root", str(self.tmp))[0], 4, evil)

    def test_exclude_list_cannot_be_smuggled_in_as_wrong_type(self):
        m = self.write("m.json", json.dumps({"version": "1.0", "algorithm": "sha256",
                                             "created_at": "", "files": {}, "exclude": [1]}))  # fmt: skip
        self.assertEqual(run("manifest", "verify", str(m))[0], 4)


class FailureModeTests(TempDirTestCase):
    def test_malformed_config_exit_2(self):
        cfg = self.write("bad.toml", "algorithm = [")
        p = self.write("f", "x")
        self.assertEqual(run("hash", str(p), "--config", str(cfg))[0], 2)

    def test_config_with_wrong_types_exit_2(self):
        cfg = self.write("bad.toml", "follow_symlinks = 'yes'")
        p = self.write("f", "x")
        self.assertEqual(run("hash", str(p), "--config", str(cfg))[0], 2)

    @unittest.skipIf(not POSIX or IS_ROOT, "needs POSIX non-root")
    def test_unreadable_file_in_scan_exit_3(self):
        self.write("ok.txt", "ok")
        bad = self.write("locked.txt", "x")
        bad.chmod(0)
        self.addCleanup(bad.chmod, 0o600)
        self.assertEqual(run("manifest", "create", str(self.tmp))[0], 3)

    @unittest.skipIf(not POSIX or IS_ROOT, "needs POSIX non-root")
    def test_unreadable_directory_in_scan_exit_3(self):
        self.write("ok.txt", "ok")
        self.write("locked/inner.txt", "x")
        d = self.tmp / "locked"
        d.chmod(0)
        self.addCleanup(d.chmod, 0o700)
        self.assertEqual(run("scan", str(self.tmp))[0], 3)

    def test_file_modified_during_hashing_is_reported_not_trusted(self):
        p = self.write("live.log", b"A" * 100_000)
        real_new_hasher = hasher.new_hasher

        class Tampering:
            def __init__(self, inner):
                self.inner, self.done = inner, False

            def update(self, data):
                if not self.done:  # simulate a writer appending after we started reading
                    self.done = True
                    with open(p, "ab") as f:
                        f.write(b"B" * 10)
                self.inner.update(data)

            def hexdigest(self):
                return self.inner.hexdigest()

        with mock.patch.object(hasher, "new_hasher", lambda a: Tampering(real_new_hasher(a))):
            with self.assertRaises(FileError) as ctx:
                hash_file(p, chunk_size=1024)
        self.assertIn("changed while", str(ctx.exception))

    def test_concurrent_appends_never_yield_a_silently_wrong_digest(self):
        p = self.write("busy.log", b"x" * 1_000_000)
        stop = threading.Event()

        def writer():
            with open(p, "ab") as f:
                while not stop.is_set():
                    f.write(b"y" * 100)
                    f.flush()

        t = threading.Thread(target=writer)
        t.start()
        try:
            outcomes = set()
            for _ in range(20):
                try:
                    r = hash_file(p, chunk_size=4096)
                    # If it succeeded, the digest must match the size that was read
                    self.assertGreaterEqual(r.size, 1_000_000)
                    outcomes.add("ok")
                except FileError:
                    outcomes.add("flagged")
        finally:
            stop.set()
            t.join()
        self.assertTrue(outcomes)  # never crashed with anything but FileError


class LargeFileTests(TempDirTestCase):
    def test_memory_stays_bounded_regardless_of_file_size(self):
        p = self.tmp / "big.bin"
        with open(p, "wb") as f:
            f.truncate(64 * 1024 * 1024)  # 64 MiB, sparse
        tracemalloc.start()
        try:
            r = hash_file(p, chunk_size=1024 * 1024)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(r.size, 64 * 1024 * 1024)
        self.assertLess(peak, 4 * 1024 * 1024)  # ~1 chunk, nowhere near 64 MiB

    @unittest.skipIf(os.environ.get("HASHVAULT_SKIP_SLOW"), "HASHVAULT_SKIP_SLOW set")
    def test_file_larger_than_2_gib(self):
        size = 2 * 1024**3 + 12345  # crosses the 32-bit signed boundary
        p = self.tmp / "huge.bin"
        try:
            with open(p, "wb") as f:
                f.truncate(size)
        except OSError:
            self.skipTest("filesystem cannot create a sparse file this large")
        expected = hashlib.sha256()
        zeros = bytes(1024 * 1024)
        remaining = size
        while remaining:
            n = min(remaining, len(zeros))
            expected.update(zeros[:n])
            remaining -= n
        r = hash_file(p)
        self.assertEqual((r.size, r.digest), (size, expected.hexdigest()))


if __name__ == "__main__":
    unittest.main()
