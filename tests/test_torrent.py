"""
Testes unitários para a camada de metadados .torrent e extração do info_hash.
"""

import hashlib
import unittest
from src.bencode import encode_bencode
from src.torrent import load_torrent_bytes, TorrentParseError


class TestTorrent(unittest.TestCase):

    def setUp(self):
        # Hash de teste de 20 bytes (2 peças fictícias)
        self.piece1_hash = hashlib.sha1(b"piece_1_content").digest()
        self.piece2_hash = hashlib.sha1(b"piece_2_content").digest()
        self.pieces_bytes = self.piece1_hash + self.piece2_hash

        # Monta um dicionário 'info' válido
        self.info_dict = {
            b"length": 524288,
            b"name": b"ubuntu-test.iso",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
        }

        # Serializa o dicionário info
        self.info_bencoded = encode_bencode(self.info_dict)

        # Monta a estrutura completa do torrent
        self.torrent_dict = {
            b"announce": b"http://tracker.ubuntu.com/announce",
            b"created by": b"mktorrent 1.1",
            b"info": self.info_dict,
        }
        self.torrent_bytes = encode_bencode(self.torrent_dict)

    def test_load_torrent_bytes_success(self):
        metadata = load_torrent_bytes(self.torrent_bytes)

        self.assertEqual(metadata.announce, "http://tracker.ubuntu.com/announce")
        self.assertEqual(metadata.name, "ubuntu-test.iso")
        self.assertEqual(metadata.piece_length, 262144)
        self.assertEqual(metadata.total_length, 524288)
        self.assertEqual(metadata.num_pieces, 2)
        self.assertEqual(metadata.piece_hashes, [self.piece1_hash, self.piece2_hash])

        # Teste crítico: info_hash DEVE ser idêntico ao SHA-1 da fatia bruta da seção info
        expected_info_hash = hashlib.sha1(self.info_bencoded).digest()
        self.assertEqual(metadata.info_hash, expected_info_hash)
        self.assertEqual(metadata.info_hash_hex, expected_info_hash.hex())
        self.assertEqual(metadata.raw_info_bytes, self.info_bencoded)

    def test_load_torrent_missing_info(self):
        invalid_torrent = encode_bencode({b"announce": b"http://example.com"})
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(invalid_torrent)

    def test_load_torrent_missing_piece_length(self):
        bad_info = {
            b"length": 100,
            b"name": b"file.txt",
            b"pieces": b"12345678901234567890",
        }
        bad_torrent = encode_bencode({b"info": bad_info})
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(bad_torrent)

    def test_load_torrent_invalid_pieces_length(self):
        bad_info = {
            b"length": 100,
            b"name": b"file.txt",
            b"piece length": 50,
            b"pieces": b"short_pieces_hash",  # Não é múltiplo de 20 bytes
        }
        bad_torrent = encode_bencode({b"info": bad_info})
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(bad_torrent)

    def test_load_torrent_not_a_dict(self):
        not_a_dict = encode_bencode([1, 2, 3])
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(not_a_dict)


if __name__ == "__main__":
    unittest.main()
