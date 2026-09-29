import json
import os
import unittest

from hashvault.core.manifest import (
    DEFAULT_MANIFEST_NAME,
    create_manifest,
    load_manifest,
    write_manifest,
)
from hashvault.errors import ManifestError
from tests.helpers import TempDirTestCase, sha256


class ManifestTests(TempDirTestCase):
    def _valid(self, **over):
        data = {
            "version": "1.0",
            "algorithm": "sha256",
            "created_at": "2026-01-01T00:00:00+00:00",
            "files": {"a.txt": sha256(b"a")},
        }
        data.update(over)
        return self.write("m.json", json.dumps(data))

    def test_create_write_load_roundtrip(self):
        self.write("a.txt", "a")
        self.write("sub/b.txt", "b")
        out = self.tmp / DEFAULT_MANIFEST_NAME
        m = create_manifest(self.tmp, "sha512", exclude=[".git"], skip=[out])
        write_manifest(m, out)
        loaded = load_manifest(out)
        self.assertEqual(loaded.algorithm, "sha512")
        self.assertEqual(loaded.files, m.files)
        self.assertEqual(sorted(loaded.files), ["a.txt", "sub/b.txt"])
        self.assertEqual(loaded.exclude, (".git",))

    def test_manifest_does_not_contain_itself(self):
        self.write("a.txt", "a")
        out = self.tmp / DEFAULT_MANIFEST_NAME
        write_manifest(create_manifest(self.tmp, "sha256", skip=[out]), out)
        m2 = create_manifest(self.tmp, "sha256", skip=[out])  # existing manifest present
        self.assertNotIn(DEFAULT_MANIFEST_NAME, m2.files)

    def test_no_overwrite_without_force(self):
        out = self.write("m.json", "{}")
        m = create_manifest(self.tmp, "sha256", skip=[out])
        with self.assertRaises(ManifestError):
            write_manifest(m, out)
        write_manifest(m, out, overwrite=True)
        self.assertEqual(json.loads(out.read_text())["version"], "1.0")
        self.assertEqual([p.name for p in self.tmp.iterdir()], ["m.json"])  # no temp litter

    def test_valid_manifest_loads(self):
        self.assertEqual(load_manifest(self._valid()).files["a.txt"], sha256(b"a"))

    def test_missing(self):
        with self.assertRaises(ManifestError):
            load_manifest(self.tmp / "nope.json")

    def test_corrupt_json(self):
        with self.assertRaises(ManifestError):
            load_manifest(self.write("bad.json", "{not json"))

    def test_not_an_object(self):
        with self.assertRaises(ManifestError):
            load_manifest(self.write("bad.json", "[]"))

    def test_bad_version_and_algorithm(self):
        with self.assertRaises(ManifestError):
            load_manifest(self._valid(version="9.9"))
        with self.assertRaises(ManifestError):
            load_manifest(self._valid(algorithm="rot13"))

    def test_bad_digest(self):
        for bad in ("short", "z" * 64, 123, None):
            with self.assertRaises(ManifestError, msg=repr(bad)):
                load_manifest(self._valid(files={"a.txt": bad}))

    def test_path_traversal_rejected(self):
        h = sha256(b"a")
        for evil in ("../secret", "/etc/passwd", "a/../../b", "C:\\x", "a\\b", ""):
            with self.assertRaises(ManifestError, msg=repr(evil)):
                load_manifest(self._valid(files={evil: h}))

    def test_bad_optional_fields(self):
        with self.assertRaises(ManifestError):
            load_manifest(self._valid(exclude="nope"))
        with self.assertRaises(ManifestError):
            load_manifest(self._valid(follow_symlinks="yes"))

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_unwritable_directory(self):
        d = self.tmp / "ro"
        d.mkdir()
        d.chmod(0o500)
        self.addCleanup(d.chmod, 0o700)
        if os.access(d, os.W_OK):
            self.skipTest("running with permission overrides (root)")
        m = create_manifest(self.tmp, "sha256", skip=[])
        with self.assertRaises(ManifestError):
            write_manifest(m, d / "m.json")
