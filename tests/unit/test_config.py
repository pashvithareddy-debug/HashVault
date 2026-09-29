from hashvault.config import Settings, load_settings
from hashvault.errors import FileError, UsageError
from tests.helpers import TempDirTestCase


class ConfigTests(TempDirTestCase):
    def test_defaults(self):
        s = Settings()
        self.assertEqual(s.algorithm, "sha256")
        self.assertIn(".git", s.effective_excludes())

    def test_load_full(self):
        p = self.write(
            "c.toml",
            'algorithm = "SHA3-256"\nchunk_size = "64KB"\nfollow_symlinks = true\n'
            '[scan]\nexclude = ["*.log", ".git"]\n',
        )
        s = load_settings(p)
        self.assertEqual(s.algorithm, "sha3-256")
        self.assertEqual(s.chunk_size, 64 * 1024)
        self.assertTrue(s.follow_symlinks)
        ex = s.effective_excludes(["extra"])
        self.assertIn("*.log", ex)
        self.assertIn("extra", ex)
        self.assertEqual(len(ex), len(set(ex)))  # de-duplicated

    def test_disable_default_excludes(self):
        p = self.write("c.toml", "[scan]\nuse_default_excludes = false\nexclude = ['x']\n")
        self.assertEqual(load_settings(p).effective_excludes(), ("x",))

    def test_explicit_missing_is_error(self):
        with self.assertRaises(FileError):
            load_settings(self.tmp / "nope.toml")

    def test_invalid_values(self):
        for body in ("algorithm = 5", "algorithm = 'x'", "chunk_size = true", "scan = 3",
                     "[scan]\nexclude = [1]", "not toml ["):  # fmt: skip
            with self.assertRaises(UsageError, msg=body):
                load_settings(self.write("c.toml", body))
