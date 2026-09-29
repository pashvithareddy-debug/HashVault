import os
import unittest

from hashvault.utils.filesystem import DEFAULT_EXCLUDES, is_excluded, walk_files
from tests.helpers import TempDirTestCase


class ExclusionTests(unittest.TestCase):
    def test_component_match(self):
        self.assertTrue(is_excluded(".git/config", [".git"]))
        self.assertTrue(is_excluded("a/b/__pycache__/x.pyc", ["__pycache__"]))
        self.assertFalse(is_excluded("gitignore.txt", [".git"]))

    def test_glob(self):
        self.assertTrue(is_excluded("a/b/x.log", ["*.log"]))
        self.assertFalse(is_excluded("a/b/x.txt", ["*.log"]))

    def test_path_pattern(self):
        self.assertTrue(is_excluded("build/out.bin", ["build/*"]))
        self.assertFalse(is_excluded("src/build/out.bin", ["build/*"]))

    def test_defaults_cover_common_junk(self):
        for name in (".git", ".venv", "__pycache__", "node_modules", ".DS_Store"):
            self.assertIn(name, DEFAULT_EXCLUDES)


class WalkTests(TempDirTestCase):
    def test_sorted_recursive_and_pruned(self):
        self.write("b.txt")
        self.write("a.txt")
        self.write("src/z.py")
        self.write(".git/HEAD")
        self.write("node_modules/pkg/index.js")
        got = [rel for rel, _ in walk_files(self.tmp, DEFAULT_EXCLUDES)]
        self.assertEqual(got, ["a.txt", "b.txt", "src/z.py"])

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlinks_ignored_by_default(self):
        target = self.write("real.txt", "x")
        os.symlink(target, self.tmp / "link.txt")
        self.assertEqual([r for r, _ in walk_files(self.tmp)], ["real.txt"])
        self.assertEqual([r for r, _ in walk_files(self.tmp, follow_symlinks=True)], ["link.txt", "real.txt"])

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlink_loop_terminates(self):
        self.write("d/file.txt", "x")
        os.symlink(self.tmp, self.tmp / "d" / "loop")
        files = [r for r, _ in walk_files(self.tmp, follow_symlinks=True)]
        self.assertIn("d/file.txt", files)
