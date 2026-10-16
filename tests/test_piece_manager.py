"""
Comprehensive unit tests for PieceManager (piece and block manager).

Covers:
- Division of pieces into blocks and exact size calculations;
- Accurate handling and sizing of last piece and its last block;
- Lifecycle and states of blocks (MISSING, REQUESTED, RECEIVED);
- Lifecycle and states of pieces (MISSING, DOWNLOADING, COMPLETED);
- Out-of-order block reception;
- Graceful handling of duplicate blocks;
- Strict SHA-1 integrity validation (correct hash);
- Rejection, data discard, and reset on incorrect hash (corrupted data);
- Synchronization and concurrent requests across multiple peers (Multi-threading / Thread-Safety);
- Ordered reconstruction of complete file data and disk storage.
"""

import hashlib
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest

from src.hash_utils import compute_sha1
from src.peer import Bitfield
from src.piece_manager import (
    Block,
    BlockState,
    Piece,
    PieceManager,
    PieceState,
)
from src.torrent import TorrentMetadata


class TestPiece(unittest.TestCase):
    """Unit tests for Piece class and its individual blocks."""

    def setUp(self):
        # 32 KB piece (32,768 bytes) divided into 2 blocks of 16 KB (16,384 bytes)
        self.piece_data = b"A" * 16384 + b"B" * 16384
        self.expected_hash = compute_sha1(self.piece_data)
        self.piece = Piece(
            index=0,
            length=32768,
            expected_hash=self.expected_hash,
            block_size=16384,
        )

    def test_piece_initial_state(self):
        self.assertEqual(self.piece.index, 0)
        self.assertEqual(self.piece.length, 32768)
        self.assertEqual(self.piece.state, PieceState.MISSING)
        self.assertEqual(self.piece.num_blocks, 2)
        self.assertFalse(self.piece.is_completed())
        self.assertIsNone(self.piece.get_data())

        # Blocks
        self.assertEqual(self.piece.blocks[0].begin, 0)
        self.assertEqual(self.piece.blocks[0].length, 16384)
        self.assertEqual(self.piece.blocks[0].state, BlockState.MISSING)

        self.assertEqual(self.piece.blocks[1].begin, 16384)
        self.assertEqual(self.piece.blocks[1].length, 16384)
        self.assertEqual(self.piece.blocks[1].state, BlockState.MISSING)

    def test_piece_blocks_in_order(self):
        # 1. Add first block
        added1, completed1 = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added1)
        self.assertFalse(completed1)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)
        self.assertTrue(self.piece.blocks[0].is_received)
        self.assertFalse(self.piece.blocks[1].is_received)

        # 2. Add second block (completes piece with correct hash)
        added2, completed2 = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added2)
        self.assertTrue(completed2)
        self.assertEqual(self.piece.state, PieceState.COMPLETED)
        self.assertTrue(self.piece.is_completed())
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_blocks_out_of_order(self):
        # Add block 1 before block 0
        added1, completed1 = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added1)
        self.assertFalse(completed1)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)

        # Now add block 0
        added0, completed0 = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added0)
        self.assertTrue(completed0)
        self.assertEqual(self.piece.state, PieceState.COMPLETED)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_duplicate_blocks(self):
        # Add block 0
        added1, _ = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added1)

        # Redeliver block 0 (duplicate)
        added_dup, _ = self.piece.add_block(0, b"A" * 16384)
        self.assertFalse(added_dup)  # Do not add again

        # Complete with block 1
        added2, completed = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added2)
        self.assertTrue(completed)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_corrupt_hash_rejection_and_reset(self):
        # Deliver corrupted data (block 1 corrupted with 'Z')
        corrupted_block1 = b"Z" * 16384
        self.piece.add_block(0, b"A" * 16384)
        added2, completed = self.piece.add_block(16384, corrupted_block1)

        self.assertTrue(added2)
        self.assertFalse(completed)  # SHA-1 failed!

        # Must have reset state to MISSING and discarded blocks for redownload
        self.assertEqual(self.piece.state, PieceState.MISSING)
        self.assertFalse(self.piece.is_completed())
        self.assertIsNone(self.piece.get_data())
        self.assertFalse(self.piece.blocks[0].is_received)
        self.assertFalse(self.piece.blocks[1].is_received)

        # Now deliver correct data and should complete normally
        self.piece.add_block(0, b"A" * 16384)
        _, completed_now = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(completed_now)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_invalid_offsets_and_sizes(self):
        # Non-existent offset
        with self.assertRaises(ValueError):
            self.piece.add_block(500, b"A" * 16384)

        # Incompatible block size (smaller or larger)
        with self.assertRaises(ValueError):
            self.piece.add_block(0, b"A" * 100)
        with self.assertRaises(ValueError):
            self.piece.add_block(0, b"A" * 20000)

    def test_piece_get_next_missing_block_and_reset(self):
        b0 = self.piece.get_next_missing_block(mark_requested=True)
        self.assertIsNotNone(b0)
        self.assertEqual(b0.begin, 0)
        self.assertEqual(b0.state, BlockState.REQUESTED)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)

        b1 = self.piece.get_next_missing_block(mark_requested=True)
        self.assertIsNotNone(b1)
        self.assertEqual(b1.begin, 16384)
        self.assertEqual(b1.state, BlockState.REQUESTED)

        # No pending blocks remaining
        b_none = self.piece.get_next_missing_block()
        self.assertIsNone(b_none)

        # Reset pending requests (e.g. peer disconnected)
        self.piece.reset_pending_blocks()
        self.assertEqual(self.piece.blocks[0].state, BlockState.MISSING)
        self.assertEqual(self.piece.blocks[1].state, BlockState.MISSING)
        self.assertEqual(self.piece.state, PieceState.MISSING)


class TestPieceManager(unittest.TestCase):
    """Unit and integration tests for PieceManager."""

    def setUp(self):
        # Torrent with 3 pieces (50,000 bytes total, piece_length=20,000 bytes, block_size=8,192 bytes)
        # Piece 0: 20,000 bytes (blocks: 8192, 8192, 3616)
        # Piece 1: 20,000 bytes (blocks: 8192, 8192, 3616)
        # Piece 2 (last piece): 10,000 bytes (50000 % 20000) (blocks: 8192, 1808)
        self.p0_data = b"0" * 20000
        self.p1_data = b"1" * 20000
        self.p2_data = b"2" * 10000
        self.full_torrent_data = self.p0_data + self.p1_data + self.p2_data  # 50.000 bytes

        self.p0_hash = compute_sha1(self.p0_data)
        self.p1_hash = compute_sha1(self.p1_data)
        self.p2_hash = compute_sha1(self.p2_data)
        self.piece_hashes = [self.p0_hash, self.p1_hash, self.p2_hash]

        self.pm = PieceManager(
            total_length=50000,
            piece_length=20000,
            piece_hashes=self.piece_hashes,
            block_size=8192,
        )

    def test_piece_manager_initialization_and_sizes(self):
        self.assertEqual(self.pm.total_length, 50000)
        self.assertEqual(self.pm.piece_length, 20000)
        self.assertEqual(self.pm.num_pieces, 3)
        self.assertEqual(self.pm.block_size, 8192)
        self.assertEqual(self.pm.completed_pieces_count(), 0)
        self.assertEqual(self.pm.missing_pieces_count(), 3)
        self.assertEqual(self.pm.bytes_downloaded(), 0)
        self.assertEqual(self.pm.bytes_left(), 50000)
        self.assertEqual(self.pm.progress, 0.0)
        self.assertFalse(self.pm.is_complete)

        # Verification of exact piece sizes
        self.assertEqual(self.pm.get_piece_length(0), 20000)
        self.assertEqual(self.pm.get_piece_length(1), 20000)
        self.assertEqual(self.pm.get_piece_length(2), 10000)  # Last piece

        # Verification of last piece blocks (10000 = 8192 + 1808)
        p2 = self.pm.get_piece(2)
        self.assertEqual(p2.num_blocks, 2)
        self.assertEqual(p2.blocks[0].begin, 0)
        self.assertEqual(p2.blocks[0].length, 8192)
        self.assertEqual(p2.blocks[1].begin, 8192)
        self.assertEqual(p2.blocks[1].length, 1808)

    def test_complete_piece_download_and_bitfield(self):
        # Download piece 0 completely
        # Blocks: (0, 8192), (8192, 8192), (16384, 3616)
        self.pm.add_block(0, 0, self.p0_data[0:8192])
        self.pm.add_block(0, 8192, self.p0_data[8192:16384])
        added, completed = self.pm.add_block(0, 16384, self.p0_data[16384:20000])

        self.assertTrue(added)
        self.assertTrue(completed)
        self.assertTrue(self.pm.is_piece_complete(0))
        self.assertTrue(self.pm.bitfield.has_piece(0))
        self.assertFalse(self.pm.bitfield.has_piece(1))
        self.assertEqual(self.pm.completed_pieces_count(), 1)
        self.assertEqual(self.pm.bytes_downloaded(), 20000)
        self.assertEqual(self.pm.bytes_left(), 30000)
        self.assertEqual(self.pm.progress, 20000 / 50000)
        self.assertEqual(self.pm.get_piece_data(0), self.p0_data)

    def test_download_all_pieces_and_reconstruct(self):
        # 1. Download piece 2 (last piece) first
        self.pm.add_block(2, 0, self.p2_data[0:8192])
        self.pm.add_block(2, 8192, self.p2_data[8192:10000])
        self.assertTrue(self.pm.is_piece_complete(2))

        # 2. Download piece 0
        self.pm.add_block(0, 0, self.p0_data[0:8192])
        self.pm.add_block(0, 8192, self.p0_data[8192:16384])
        self.pm.add_block(0, 16384, self.p0_data[16384:20000])
        self.assertTrue(self.pm.is_piece_complete(0))

        # Attempted reconstruction before completion -> ValueError
        with self.assertRaises(ValueError):
            self.pm.get_all_data()

        # 3. Download piece 1
        self.pm.add_block(1, 0, self.p1_data[0:8192])
        self.pm.add_block(1, 8192, self.p1_data[8192:16384])
        self.pm.add_block(1, 16384, self.p1_data[16384:20000])
        self.assertTrue(self.pm.is_piece_complete(1))

        # Now 100% completed
        self.assertTrue(self.pm.is_complete)
        self.assertEqual(self.pm.completed_pieces_count(), 3)
        self.assertEqual(self.pm.bytes_downloaded(), 50000)
        self.assertEqual(self.pm.bytes_left(), 0)
        self.assertEqual(self.pm.progress, 1.0)
        self.assertTrue(self.pm.bitfield.is_complete)

        # Perfect ordered reconstruction
        reconstructed = self.pm.get_all_data()
        self.assertEqual(reconstructed, self.full_torrent_data)

    def test_save_to_file(self):
        # Download everything
        for p_idx, p_data in enumerate([self.p0_data, self.p1_data, self.p2_data]):
            piece = self.pm.get_piece(p_idx)
            for block in piece.blocks:
                b_data = p_data[block.begin : block.begin + block.length]
                self.pm.add_block(p_idx, block.begin, b_data)

        self.assertTrue(self.pm.is_complete)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "downloads" / "output.bin"
            self.pm.save_to_file(out_file)

            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.read_bytes(), self.full_torrent_data)

    def test_get_next_block_to_request_with_peer_bitfield(self):
        # Peer possesses only pieces 1 and 2 (Bitfield: [0b01100000])
        peer_bf = Bitfield(num_pieces=3)
        peer_bf.set_piece(1, True)
        peer_bf.set_piece(2, True)

        # First request: must pick block from piece 1 (first piece peer has)
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertIsNotNone(req1)
        self.assertEqual(req1, (1, 0, 8192))

        # Second request: next block of piece 1
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2, (1, 8192, 8192))

        # Third request: last block of piece 1
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3, (1, 16384, 3616))

        # Fourth request: advance to piece 2
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4, (2, 0, 8192))

        # Reset piece 1 requests (piece 2 continues DOWNLOADING)
        self.pm.reset_pending_requests(piece_index=1)
        # Next request prioritizes completing piece 2 which is already DOWNLOADING
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5, (2, 8192, 1808))

        # Now that piece 2 is fully requested, return to piece 1 (MISSING)
        req6 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req6, (1, 0, 8192))

        # Reset all pending pieces globally
        self.pm.reset_pending_requests()
        req_restart = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req_restart, (1, 0, 8192))

    def test_concurrent_multi_peer_block_downloads(self):
        """
        Simulates multiple concurrent peers (threads) downloading blocks simultaneously.
        Ensures absence of race conditions and final integrity.
        """
        num_workers = 8
        errors = []

        def worker_task(worker_id: int):
            try:
                while True:
                    req = self.pm.get_next_block_to_request()
                    if req is None:
                        # No pending blocks
                        break

                    piece_idx, begin, length = req
                    # Simulate receiving correct data for that block
                    if piece_idx == 0:
                        block_data = self.p0_data[begin : begin + length]
                    elif piece_idx == 1:
                        block_data = self.p1_data[begin : begin + length]
                    else:
                        block_data = self.p2_data[begin : begin + length]

                    # Add block to PieceManager
                    self.pm.add_block(piece_idx, begin, block_data)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_workers):
            t = threading.Thread(target=worker_task, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertTrue(self.pm.is_complete)
        self.assertEqual(self.pm.completed_pieces_count(), 3)
        self.assertEqual(self.pm.get_all_data(), self.full_torrent_data)

    def test_granular_reset_block_and_reset_blocks(self):
        """Tests atomic reset of individual and multiple blocks."""
        # 1. Request piece 0 blocks: (0, 0), (0, 8192), (0, 16384)
        r0 = self.pm.get_next_block_to_request()
        r1 = self.pm.get_next_block_to_request()
        r2 = self.pm.get_next_block_to_request()

        self.assertEqual(r0, (0, 0, 8192))
        self.assertEqual(r1, (0, 8192, 8192))
        self.assertEqual(r2, (0, 16384, 3616))

        # Piece 0 now has no more MISSING blocks
        r_p1 = self.pm.get_next_block_to_request()
        self.assertEqual(r_p1, (1, 0, 8192))

        # 2. Reset only block (0, 8192)
        res = self.pm.reset_block(0, 8192)
        self.assertTrue(res)

        # Next requested block must be re-available block (0, 8192)!
        r_retried = self.pm.get_next_block_to_request()
        self.assertEqual(r_retried, (0, 8192, 8192))

        # 3. Reset multiple blocks via reset_blocks
        self.pm.reset_blocks([(0, 0), (0, 16384)])
        # Must re-offer (0, 0)
        r_re0 = self.pm.get_next_block_to_request()
        self.assertEqual(r_re0, (0, 0, 8192))

    def test_reset_block_invalid_index(self):
        """Tests reset_block with out-of-range indices."""
        self.assertFalse(self.pm.reset_block(-1, 0))
        self.assertFalse(self.pm.reset_block(999, 0))
        self.assertFalse(self.pm.reset_block(0, 999999))

    def test_save_to_file_multi_file_torrent(self):
        """Tests save_to_file preserving directory hierarchy in multi-file torrents."""
        from src.bencode import encode_bencode
        from src.torrent import load_torrent_bytes

        file1_data = b"Hello from file 1! " * 500  # 9500 bytes
        file2_data = b"Nested file 2 data! " * 600  # 12000 bytes
        total_data = file1_data + file2_data       # 21500 bytes
        piece_len = 8192

        p0 = total_data[0:8192]
        p1 = total_data[8192:16384]
        p2 = total_data[16384:21500]
        pieces_hashes = compute_sha1(p0) + compute_sha1(p1) + compute_sha1(p2)

        meta_dict = {
            b"announce": b"http://tracker.local/announce",
            b"info": {
                b"name": b"my_multi_package",
                b"piece length": piece_len,
                b"pieces": pieces_hashes,
                b"files": [
                    {b"length": len(file1_data), b"path": [b"docs", b"file1.txt"]},
                    {b"length": len(file2_data), b"path": [b"media", b"video", b"file2.bin"]},
                ],
            },
        }
        torrent_bytes = encode_bencode(meta_dict)
        meta = load_torrent_bytes(torrent_bytes)

        pm = PieceManager(meta, block_size=4096)

        # Populate pieces
        for p_idx, p_data in enumerate([p0, p1, p2]):
            piece = pm.get_piece(p_idx)
            for block in piece.blocks:
                b_data = p_data[block.begin : block.begin + block.length]
                pm.add_block(p_idx, block.begin, b_data)

        self.assertTrue(pm.is_complete)

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "output_dir"
            pm.save_to_file(dest)

            # Check files at destination
            out_file1 = dest / "my_multi_package" / "docs" / "file1.txt"
            out_file2 = dest / "my_multi_package" / "media" / "video" / "file2.bin"

            self.assertTrue(out_file1.exists())
            self.assertTrue(out_file2.exists())
            self.assertEqual(out_file1.read_bytes(), file1_data)
            self.assertEqual(out_file2.read_bytes(), file2_data)


if __name__ == "__main__":
    unittest.main()

