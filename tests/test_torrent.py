"""
Comprehensive unit tests for .torrent file parsing layer.

Covers:
- Loading torrents from raw bytes and disk files;
- Parsing single-file and multi-file torrents;
- Extraction of announce, announce-list (BEP 0012 tiers) and aggregated tracker list;
- Accurate extraction of info section and SHA-1 info_hash calculation;
- Extraction of name, piece length, pieces, and 20-byte hash splitting;
- Piece helper methods (get_piece_length, get_piece_hash, verify_piece);
- Strict validation of required fields and data types;
- Mathematical consistency validation (pieces vs total size vs piece length);
- Rejection of malformed, inconsistent, or incomplete torrents.
"""

import hashlib
import math
import os
import tempfile
import unittest
from pathlib import Path

from src.bencode import encode_bencode
from src.torrent import (
    FileInfo,
    TorrentMetadata,
    TorrentParseError,
    TorrentValidationError,
    load_torrent_bytes,
    load_torrent_file,
)


class TestTorrentParser(unittest.TestCase):
    """Primary tests for .torrent metadata parsing and validation."""

    def setUp(self):
        # Create simulated data of 2 pieces (500 KB total, piece_length of 256 KB)
        self.piece_data_0 = b"A" * 262144
        self.piece_data_1 = b"B" * (512000 - 262144)  # 249856 bytes
        self.piece0_hash = hashlib.sha1(self.piece_data_0).digest()
        self.piece1_hash = hashlib.sha1(self.piece_data_1).digest()
        self.pieces_bytes = self.piece0_hash + self.piece1_hash

        # Single-file 'info' dictionary
        self.single_info_dict = {
            b"length": 512000,
            b"name": b"debian-live.iso",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
        }
        self.single_info_bencoded = encode_bencode(self.single_info_dict)
        self.expected_single_info_hash = hashlib.sha1(self.single_info_bencoded).digest()

        # Complete single-file torrent dictionary with optional metadata
        self.single_torrent_dict = {
            b"announce": b"http://tracker.debian.org:6969/announce",
            b"announce-list": [
                [b"http://tracker.debian.org:6969/announce", b"http://backup.debian.org/announce"],
                [b"udp://tracker.openbittorrent.com:80/announce"],
            ],
            b"comment": b"Debian Live Image",
            b"created by": b"mktorrent 1.1",
            b"creation date": 1672531199,
            b"info": self.single_info_dict,
        }
        self.single_torrent_bytes = encode_bencode(self.single_torrent_dict)

    # --- Success Tests (Single-file and Multi-file) ---

    def test_load_single_file_torrent_success(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # Basic metadata validation
        self.assertEqual(metadata.announce, "http://tracker.debian.org:6969/announce")
        self.assertEqual(metadata.name, "debian-live.iso")
        self.assertEqual(metadata.piece_length, 262144)
        self.assertEqual(metadata.total_length, 512000)
        self.assertFalse(metadata.is_multi_file)
        self.assertEqual(len(metadata.files), 1)
        self.assertEqual(metadata.files[0].length, 512000)
        self.assertEqual(metadata.files[0].full_path, "debian-live.iso")

        # Trackers and tiers validation (BEP 0012)
        expected_announce_list = [
            ["http://tracker.debian.org:6969/announce", "http://backup.debian.org/announce"],
            ["udp://tracker.openbittorrent.com:80/announce"],
        ]
        self.assertEqual(metadata.announce_list, expected_announce_list)
        expected_trackers = [
            "http://tracker.debian.org:6969/announce",
            "http://backup.debian.org/announce",
            "udp://tracker.openbittorrent.com:80/announce",
        ]
        self.assertEqual(metadata.trackers, expected_trackers)

        # Hashes and info section integrity validation
        self.assertEqual(metadata.info_hash, self.expected_single_info_hash)
        self.assertEqual(metadata.info_hash_hex, self.expected_single_info_hash.hex())
        self.assertEqual(metadata.raw_info_bytes, self.single_info_bencoded)

        # Piece division validation
        self.assertEqual(metadata.num_pieces, 2)
        self.assertEqual(metadata.piece_hashes, [self.piece0_hash, self.piece1_hash])
        self.assertEqual(metadata.pieces, self.pieces_bytes)

        # Optional metadata validation
        self.assertEqual(metadata.comment, "Debian Live Image")
        self.assertEqual(metadata.created_by, "mktorrent 1.1")
        self.assertEqual(metadata.creation_date, 1672531199)
        self.assertFalse(metadata.private)

    def test_load_multi_file_torrent_success(self):
        # 3 files summing to 512,000 bytes
        file1_len = 200000
        file2_len = 100000
        file3_len = 212000

        multi_info_dict = {
            b"files": [
                {b"length": file1_len, b"path": [b"docs", b"manual.pdf"]},
                {b"length": file2_len, b"path": [b"docs", b"changelog.txt"]},
                {b"length": file3_len, b"path": [b"bin", b"app.exe"]},
            ],
            b"name": b"my_bundle",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
            b"private": 1,
        }
        multi_torrent_dict = {
            b"announce": b"http://tracker.private.org/announce",
            b"info": multi_info_dict,
        }
        raw_multi = encode_bencode(multi_torrent_dict)
        metadata = load_torrent_bytes(raw_multi)

        self.assertTrue(metadata.is_multi_file)
        self.assertEqual(metadata.name, "my_bundle")
        self.assertEqual(metadata.total_length, 512000)
        self.assertEqual(len(metadata.files), 3)

        self.assertEqual(metadata.files[0], FileInfo(length=200000, path=["docs", "manual.pdf"], full_path="docs/manual.pdf"))
        self.assertEqual(metadata.files[1], FileInfo(length=100000, path=["docs", "changelog.txt"], full_path="docs/changelog.txt"))
        self.assertEqual(metadata.files[2], FileInfo(length=212000, path=["bin", "app.exe"], full_path="bin/app.exe"))
        self.assertTrue(metadata.private)

    def test_load_torrent_file_from_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.torrent"
            file_path.write_bytes(self.single_torrent_bytes)

            metadata = load_torrent_file(file_path)
            self.assertEqual(metadata.name, "debian-live.iso")
            self.assertEqual(metadata.info_hash, self.expected_single_info_hash)

            # Test passing as string
            metadata_str = load_torrent_file(str(file_path))
            self.assertEqual(metadata_str.info_hash, self.expected_single_info_hash)

    # --- Piece Helper Methods Tests ---

    def test_piece_length_helpers(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # First piece: standard full size (262144)
        self.assertEqual(metadata.get_piece_length(0), 262144)
        # Second (last) piece: remainder of division (512000 - 262144 = 249856)
        self.assertEqual(metadata.get_piece_length(1), 249856)

        # Index out of range
        with self.assertRaises(IndexError):
            metadata.get_piece_length(-1)
        with self.assertRaises(IndexError):
            metadata.get_piece_length(2)

    def test_get_piece_hash(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)
        self.assertEqual(metadata.get_piece_hash(0), self.piece0_hash)
        self.assertEqual(metadata.get_piece_hash(1), self.piece1_hash)

        with self.assertRaises(IndexError):
            metadata.get_piece_hash(5)

    def test_verify_piece(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # Valid piece 0
        self.assertTrue(metadata.verify_piece(0, self.piece_data_0))
        # Valid piece 1
        self.assertTrue(metadata.verify_piece(1, self.piece_data_1))

        # Data with incorrect hash
        corrupted_data = b"Z" * 262144
        self.assertFalse(metadata.verify_piece(0, corrupted_data))

        # Data with incorrect size (smaller or larger)
        self.assertFalse(metadata.verify_piece(0, b"short_data"))

        # Invalid type
        with self.assertRaises(TypeError):
            metadata.verify_piece(0, "not_bytes")  # type: ignore

        # Invalid index
        with self.assertRaises(IndexError):
            metadata.verify_piece(99, self.piece_data_0)

    # --- Validation and Error Handling Tests ---

    def test_load_torrent_invalid_inputs(self):
        # Input that is not bytes
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes("string_data")  # type: ignore
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(12345)  # type: ignore
        # Empty buffer
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(b"")

    def test_load_torrent_file_errors(self):
        # Non-existent file
        with self.assertRaises(FileNotFoundError):
            load_torrent_file("non_existent_file.torrent")

        # Path is a directory
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(TorrentParseError):
                load_torrent_file(tmpdir)

    def test_missing_or_invalid_root_structure(self):
        # Root is not a dictionary
        not_a_dict = encode_bencode([1, 2, 3])
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(not_a_dict)

        # Absence of info section
        no_info = encode_bencode({b"announce": b"http://tracker.com"})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(no_info)

        # Info section is not a dictionary
        bad_info_type = encode_bencode({b"announce": b"http://tracker.com", b"info": b"not_a_dict"})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_info_type)

    def test_missing_or_invalid_trackers(self):
        # Neither announce nor announce-list
        no_trackers = encode_bencode({b"info": self.single_info_dict})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(no_trackers)

        # Announce with invalid type
        bad_announce = encode_bencode({b"announce": 12345, b"info": self.single_info_dict})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_announce)

        # Announce-list with invalid type
        bad_announce_list = encode_bencode({
            b"announce-list": b"not_a_list",
            b"info": self.single_info_dict,
        })
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_announce_list)

    def test_missing_or_invalid_name(self):
        # Missing name field
        bad_info = dict(self.single_info_dict)
        del bad_info[b"name"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # Name with empty string
        bad_info[b"name"] = b""
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_missing_or_invalid_piece_length(self):
        bad_info = dict(self.single_info_dict)
        # Missing piece length
        del bad_info[b"piece length"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # Zero or negative piece length
        bad_info[b"piece length"] = 0
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        bad_info[b"piece length"] = -262144
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_missing_or_invalid_pieces(self):
        bad_info = dict(self.single_info_dict)
        # Missing pieces
        del bad_info[b"pieces"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # pieces is not a multiple of 20 bytes
        bad_info[b"pieces"] = b"1234567890"  # 10 bytes
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_single_and_multi_file_conflicts(self):
        # Both 'length' and 'files' present simultaneously
        conflicted_info = dict(self.single_info_dict)
        conflicted_info[b"files"] = [{b"length": 512000, b"path": [b"file.bin"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": conflicted_info}))

        # Neither 'length' nor 'files' present
        empty_files_info = dict(self.single_info_dict)
        del empty_files_info[b"length"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": empty_files_info}))

    def test_multi_file_validation_errors(self):
        # Empty files
        bad_multi_info = {
            b"files": [],
            b"name": b"bundle",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
        }
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # File without 'length' field
        bad_multi_info[b"files"] = [{b"path": [b"file.txt"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # File with negative length
        bad_multi_info[b"files"] = [{b"length": -10, b"path": [b"file.txt"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # File without 'path' field
        bad_multi_info[b"files"] = [{b"length": 100}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # File with empty path
        bad_multi_info[b"files"] = [{b"length": 100, b"path": []}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

    def test_mathematical_piece_count_inconsistency(self):
        # total_length = 512000, piece_length = 262144 -> math.ceil(512000 / 262144) = 2 pieces
        # Passing only 1 hash of 20 bytes causes inconsistency error
        bad_info = dict(self.single_info_dict)
        bad_info[b"pieces"] = self.piece0_hash  # 1 piece instead of 2
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # Passing 3 hashes of 20 bytes causes inconsistency error
        bad_info[b"pieces"] = self.pieces_bytes + self.piece0_hash  # 3 pieces
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))


if __name__ == "__main__":
    unittest.main()

