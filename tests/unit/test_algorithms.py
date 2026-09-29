import hashlib
import unittest

from hashvault.algorithms import available_algorithms, get_algorithm, new_hasher
from hashvault.errors import UsageError


class AlgorithmTests(unittest.TestCase):
    def test_name_normalization(self):
        for name in ("SHA-256", "sha256", "Sha_256", " sha256 "):
            self.assertEqual(get_algorithm(name).name, "sha256")
        self.assertEqual(get_algorithm("SHA3_512").name, "sha3-512")

    def test_unknown_algorithm(self):
        with self.assertRaises(UsageError):
            get_algorithm("crc32")

    def test_legacy_flagged(self):
        self.assertTrue(get_algorithm("md5").legacy)
        self.assertTrue(get_algorithm("sha1").legacy)
        self.assertFalse(get_algorithm("sha256").legacy)
        self.assertNotIn("md5", [a.name for a in available_algorithms(include_legacy=False)])

    def test_digest_sizes_match_hashlib(self):
        for alg in available_algorithms():
            h = new_hasher(alg)
            h.update(b"x")
            self.assertEqual(len(h.hexdigest()), alg.hex_length, alg.name)
            self.assertEqual(h.digest_size, alg.digest_size, alg.name)

    def test_known_vector(self):
        h = new_hasher(get_algorithm("sha3-256"))
        h.update(b"abc")
        self.assertEqual(h.hexdigest(), hashlib.sha3_256(b"abc").hexdigest())
