import hashlib
import tempfile
import unittest
from pathlib import Path


class TempDirTestCase(unittest.TestCase):
    """Gives each test a fresh temporary directory at self.tmp."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)

    def write(self, rel: str, data: bytes | str = b"") -> Path:
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        return p


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
