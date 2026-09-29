from pathlib import Path

from hashvault.core.scanner import compare, scan_directory, snapshot
from hashvault.errors import FileError
from hashvault.models import ChangeStatus as S
from tests.helpers import TempDirTestCase, sha256


def statuses(changes):
    return {c.path: c.status for c in changes}


class CompareTests(TempDirTestCase):
    def test_classification(self):
        base = {"same": "1", "mod": "2", "gone": "3"}
        cur = {"same": "1", "mod": "9", "new": "4"}
        self.assertEqual(
            statuses(compare(base, cur)),
            {"same": S.UNCHANGED, "mod": S.MODIFIED, "gone": S.DELETED, "new": S.ADDED},
        )

    def test_rename_detected_when_unambiguous(self):
        changes = compare({"old.txt": "h"}, {"new.txt": "h"})
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].status, S.RENAMED)
        self.assertEqual((changes[0].previous_path, changes[0].path), ("old.txt", "new.txt"))

    def test_ambiguous_duplicates_not_treated_as_rename(self):
        changes = compare({"a": "h", "b": "h"}, {"c": "h", "d": "h"})
        self.assertEqual({c.status for c in changes}, {S.DELETED, S.ADDED})

    def test_empty(self):
        self.assertEqual(compare({}, {}), [])


class ScanTests(TempDirTestCase):
    def test_inventory_without_baseline(self):
        self.write("a.txt", "a")
        self.write("sub/b.txt", "b")
        r = scan_directory(self.tmp, "sha256")
        self.assertFalse(r.has_baseline)
        self.assertEqual(r.status, "inventory")
        self.assertEqual([c.path for c in r.changes], ["a.txt", "sub/b.txt"])
        self.assertEqual(r.changes[0].actual, sha256(b"a"))

    def test_full_cycle(self):
        self.write("keep.txt", "k")
        self.write("edit.txt", "v1")
        self.write("remove.txt", "r")
        base = snapshot(self.tmp, "sha256")

        self.write("edit.txt", "v2")
        (self.tmp / "remove.txt").unlink()
        self.write("sub/added.txt", "n")

        r = scan_directory(self.tmp, "sha256", baseline=base)
        self.assertEqual(r.status, "changes_detected")
        self.assertEqual(r.summary, {"unchanged": 1, "modified": 1, "added": 1, "deleted": 1, "renamed": 0})

    def test_clean(self):
        self.write("a", "a")
        base = snapshot(self.tmp, "sha256")
        r = scan_directory(self.tmp, "sha256", baseline=base)
        self.assertEqual(r.status, "clean")
        self.assertTrue(r.clean)

    def test_skip_paths(self):
        f = self.write("a", "a")
        self.write("manifest.json", "{}")
        got = snapshot(self.tmp, "sha256", skip=[self.tmp / "manifest.json"])
        self.assertEqual(list(got), [f.name])

    def test_missing_directory(self):
        with self.assertRaises(FileError):
            scan_directory(Path(self.tmp / "nope"), "sha256")

    def test_file_instead_of_directory(self):
        f = self.write("a", "a")
        with self.assertRaises(FileError):
            scan_directory(f, "sha256")
