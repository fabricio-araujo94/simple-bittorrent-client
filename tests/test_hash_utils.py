"""
Testes unitários para utilitários de hash SHA-1.
"""

import hashlib
import unittest
from src.hash_utils import compute_sha1, verify_sha1


class TestHashUtils(unittest.TestCase):

    def test_compute_sha1_known_vectors(self):
        # Test vector SHA-1 de string vazia: da39a3ee5e6b4b0d3255bfef95601890afd80709
        expected_empty = bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(compute_sha1(b""), expected_empty)

        # Test vector SHA-1 de "abc": a9993e364706816aba3e25717850c26c9cd0d89d
        expected_abc = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(compute_sha1(b"abc"), expected_abc)

    def test_verify_sha1(self):
        data = b"bittorrent_piece_data"
        expected = hashlib.sha1(data).digest()
        self.assertTrue(verify_sha1(data, expected))

        wrong_hash = bytes([0] * 20)
        self.assertFalse(verify_sha1(data, wrong_hash))

    def test_verify_sha1_invalid_length(self):
        with self.assertRaises(ValueError):
            verify_sha1(b"data", b"short_hash")


if __name__ == "__main__":
    unittest.main()
