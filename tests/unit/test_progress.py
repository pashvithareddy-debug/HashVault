import io
import unittest

from hashvault.core.scanner import snapshot
from hashvault.utils.output import Progress
from tests.helpers import TempDirTestCase


class ProgressTests(TempDirTestCase):
    def test_disabled_writes_nothing(self):
        buf = io.StringIO()
        p = Progress(buf, enabled=False)
        p(1, 2, "a")
        p.clear()
        self.assertEqual(buf.getvalue(), "")

    def test_enabled_shows_counts_and_clears(self):
        buf = io.StringIO()
        with Progress(buf, enabled=True, min_interval=0) as p:
            p(1, 3, "a.txt")
            p(3, 3, "c.txt")
        out = buf.getvalue()
        self.assertIn("Hashing 1/3 files  a.txt", out)
        self.assertIn("Hashing 3/3 files  c.txt", out)
        self.assertTrue(out.endswith("\r"))  # line erased on exit

    def test_throttled_but_final_update_always_shown(self):
        buf = io.StringIO()
        p = Progress(buf, enabled=True, min_interval=3600)
        p(1, 100, "first")
        p(2, 100, "second")  # throttled
        p(100, 100, "last")  # completion always drawn
        out = buf.getvalue()
        self.assertIn("first", out)
        self.assertNotIn("second", out)
        self.assertIn("last", out)

    def test_long_names_are_truncated(self):
        buf = io.StringIO()
        Progress(buf, enabled=True, min_interval=0)(1, 1, "x" * 500)
        self.assertLess(len(buf.getvalue()), 200)

    def test_snapshot_reports_progress(self):
        for n in "abc":
            self.write(n, n)
        calls = []
        snapshot(self.tmp, "sha256", progress=lambda d, t, n: calls.append((d, t, n)))
        self.assertEqual(calls, [(1, 3, "a"), (2, 3, "b"), (3, 3, "c")])


if __name__ == "__main__":
    unittest.main()
