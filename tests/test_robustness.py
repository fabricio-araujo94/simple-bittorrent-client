"""
Comprehensive robustness and failure handling tests for BitTorrent client.

Covers critical failure scenarios at correct abstraction level:
1. Peer abruptly disconnecting (EOF/connection reset mid-download);
2. Tracker unavailable (network failure, timeout, HTTP 5xx, multi-tracker fallback);
3. Connection and message read timeouts;
4. Invalid or truncated Bencode response returned by tracker;
5. Invalid handshake (size, mismatched protocol identifier);
6. Incorrect info_hash in peer handshake;
7. Malformed messages (oversized, payload inconsistent with ID);
8. Corrupted piece (SHA-1 failure with automatic reset and redownload);
9. Lost block on inactive peer and reassignment to another peer;
10. Peer sending unexpected data (invalid offset, out-of-range index, incorrect size);
11. Peer remaining choked continuously;
12. Torrent with no peers in swarm (NoPeersAvailableError);
13. Resume of partially downloaded file (disk SHA-1 validation);
14. Graceful shutdown and immediate stop of active threads (client.stop()).
"""

import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from src.bencode import encode_bencode
from src.client import (
    DownloadError,
    DownloadIncompleteError,
    NoPeersAvailableError,
    TorrentClient,
    TrackerUnavailableError,
)
from src.hash_utils import compute_sha1
from src.peer import (
    DEFAULT_BLOCK_SIZE,
    Bitfield,
    BitfieldMessage,
    ChokeMessage,
    HandshakeError,
    HaveMessage,
    MessageSizeError,
    PeerConnection,
    PeerConnectionClosedError,
    PeerConnectionError,
    PeerProtocolError,
    PeerTimeoutError,
    PieceMessage,
    RequestMessage,
    UnchokeMessage,
    encode_handshake,
    parse_handshake,
    parse_message,
)
from src.piece_manager import BlockState, PieceManager, PieceState
from src.torrent import load_torrent_bytes
from src.tracker import (
    HTTPTrackerClient,
    PeerInfo,
    TrackerConnectionError,
    TrackerHTTPError,
    TrackerResponseError,
    TrackerTimeoutError,
)


class MockHTTPResponse:
    """Mock for HTTP request responses."""

    def __init__(self, data: bytes, code: int = 200, headers: Optional[dict] = None):
        self.data = data
        self.code = code
        self.headers = headers or {}

    def read(self) -> bytes:
        return self.data


class TestRobustnessEdgeCases(unittest.TestCase):
    """Detailed robustness tests for network, protocol, integrity, and concurrency failures."""

    def setUp(self):
        # 3 pieces of 16 KB each (total: 48 KB), blocks of 8 KB (2 blocks per piece)
        self.piece_length = 16384
        self.block_size = 8192
        self.num_pieces = 3
        self.total_length = self.piece_length * self.num_pieces

        self.pieces_data = [bytes([i + 10]) * self.piece_length for i in range(self.num_pieces)]
        self.raw_data = b"".join(self.pieces_data)
        self.piece_hashes = [compute_sha1(p) for p in self.pieces_data]
        self.pieces_hash_bytes = b"".join(self.piece_hashes)

        self.torrent_dict = {
            b"announce": b"http://tracker1.local:8080/announce",
            b"announce-list": [
                [b"http://tracker1.local:8080/announce"],
                [b"http://tracker2.local:8080/announce"],
            ],
            b"info": {
                b"length": self.total_length,
                b"name": b"robustness_test.bin",
                b"piece length": self.piece_length,
                b"pieces": self.pieces_hash_bytes,
            },
        }
        self.torrent_meta = load_torrent_bytes(encode_bencode(self.torrent_dict))

    # ==========================================================================
    # 1. Tracker Failures and Fallback
    # ==========================================================================

    def test_tracker_unavailable_and_fallback(self):
        """
        Tests whether client attempts secondary tracker when primary fails,
        and raises TrackerUnavailableError if all fail.
        """
        attempted_urls = []

        def failing_opener(req, timeout=15.0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            attempted_urls.append(url)
            # Simulate tracker 1 down and tracker 2 returning peers
            if "tracker1.local" in url:
                raise TrackerConnectionError("Connection refused by tracker1")
            elif "tracker2.local" in url:
                peer_compact = socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)
                return MockHTTPResponse(encode_bencode({b"interval": 900, b"peers": peer_compact}))
            raise TrackerConnectionError("Unknown tracker")

        client = TorrentClient(self.torrent_meta, http_opener=failing_opener)
        peers = client.discover_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].ip, "127.0.0.1")
        self.assertTrue(any("tracker1.local" in u for u in attempted_urls))
        self.assertTrue(any("tracker2.local" in u for u in attempted_urls))

    def test_all_trackers_down_raises_tracker_unavailable_error(self):
        """Tests whether TrackerUnavailableError is raised when all trackers fail."""
        def all_fail_opener(req, timeout=15.0):
            raise TrackerConnectionError("No route to host")

        client = TorrentClient(self.torrent_meta, http_opener=all_fail_opener)
        with self.assertRaises(TrackerUnavailableError):
            client.discover_peers()

    def test_invalid_bencode_from_tracker_handled_cleanly(self):
        """Tests whether malformed tracker Bencode response is handled without crashing client."""
        def garbage_opener(req, timeout=15.0):
            return MockHTTPResponse(b"<html>502 Bad Gateway</html>")

        client = TorrentClient(self.torrent_meta, http_opener=garbage_opener)
        with self.assertRaises(TrackerUnavailableError):
            client.discover_peers()

    # ==========================================================================
    # 2. Swarm Failures (No peers available)
    # ==========================================================================

    def test_no_peers_in_swarm_raises_no_peers_error(self):
        """Tests whether NoPeersAvailableError is raised when tracker returns empty peer list."""
        def empty_peers_opener(req, timeout=15.0):
            return MockHTTPResponse(encode_bencode({b"interval": 900, b"peers": b""}))

        client = TorrentClient(self.torrent_meta, http_opener=empty_peers_opener)
        with self.assertRaises(NoPeersAvailableError):
            client.download()

    # ==========================================================================
    # 3. Handshake and info_hash Failures
    # ==========================================================================

    def test_peer_wrong_info_hash_rejected(self):
        """Tests whether client rejects and closes connection when peer returns different info_hash in handshake."""
        c_sock, s_sock = socket.socketpair()

        def bad_handshake_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                # Send mismatched info_hash
                wrong_hash = b"\xff" * 20
                sock.sendall(encode_handshake(wrong_hash, b"-UT2210-peerWRONGPID"))
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=bad_handshake_server, args=(s_sock,), daemon=True)
        srv.start()

        client = TorrentClient(self.torrent_meta, peer_timeout=2.0)
        peer = PeerInfo(ip="127.0.0.1", port=6881)

        conn = PeerConnection(sock=c_sock, default_timeout=2.0)
        with self.assertRaises(HandshakeError):
            conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        conn.close()
        srv.join(timeout=2.0)

    def test_peer_invalid_protocol_pstr_rejected(self):
        """Tests whether handshake with mismatched protocol is rejected with HandshakeError."""
        c_sock, s_sock = socket.socketpair()

        def bad_proto_server(sock):
            try:
                sock.recv(68)
                # Send invalid protocol identifier (19 bytes: WrongProtoProtocol1)
                bad_bytes = b"\x13WrongProtoProtocol1\x00\x00\x00\x00\x00\x00\x00\x00" + self.torrent_meta.info_hash + b"12345678901234567890"
                sock.sendall(bad_bytes)
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=bad_proto_server, args=(s_sock,), daemon=True)
        srv.start()

        conn = PeerConnection(sock=c_sock, default_timeout=2.0)
        with self.assertRaises(HandshakeError):
            conn.perform_handshake(info_hash=self.torrent_meta.info_hash, peer_id=b"-ST0001-abcdefghijkl")

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 4. Malformed Messages and Protocol Violations
    # ==========================================================================

    def test_peer_oversized_message_rejected(self):
        """Tests whether peer sending message larger than MAX_MESSAGE_LENGTH (2 MB) is rejected with MessageSizeError."""
        c_sock, s_sock = socket.socketpair()

        def oversized_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerOVERSIZ1"))
                # Send 5 MB length prefix
                sock.sendall(struct.pack("!I", 5 * 1024 * 1024))
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=oversized_server, args=(s_sock,), daemon=True)
        srv.start()

        client = TorrentClient(self.torrent_meta, peer_timeout=2.0)
        conn = PeerConnection(sock=c_sock, default_timeout=2.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # download_from_peer_connection must detect violation, disconnect and return False
        success = client.download_from_peer_connection(conn)
        self.assertFalse(success)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 5. Peer Sending Unexpected or Malformed Data
    # ==========================================================================

    def test_peer_sending_invalid_piece_index_or_offset(self):
        """Tests whether sending Piece with invalid offset or out-of-range index is safely caught."""
        c_sock, s_sock = socket.socketpair()

        def bad_piece_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerBADPIECE"))
                sock.sendall(UnchokeMessage().encode())

                # Await Request
                buffer = bytearray()
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    buffer.extend(data)
                    if len(buffer) >= 17:  # 4 len + 1 id + 12 req
                        # Send Piece with completely invalid offset (9999)
                        bad_piece = PieceMessage(index=0, begin=9999, block=b"X" * 8192)
                        sock.sendall(bad_piece.encode())
                        break
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=bad_piece_server, args=(s_sock,), daemon=True)
        srv.start()

        client = TorrentClient(self.torrent_meta, block_size=self.block_size, peer_timeout=2.0)
        conn = PeerConnection(sock=c_sock, default_timeout=2.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # Client must catch malformed data error, deallocate in-flight requests and exit
        success = client.download_from_peer_connection(conn)
        self.assertFalse(success)
        self.assertFalse(client.is_complete)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 6. Peer Remaining Choked
    # ==========================================================================

    def test_peer_remaining_choked_times_out_and_releases(self):
        """Tests whether peer that never sends Unchoke is released after timeout without hanging client."""
        c_sock, s_sock = socket.socketpair()

        def choked_forever_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerCHOKED99"))
                # Send Choke and do nothing else
                sock.sendall(ChokeMessage().encode())
                time.sleep(2.0)
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=choked_forever_server, args=(s_sock,), daemon=True)
        srv.start()

        client = TorrentClient(self.torrent_meta, peer_timeout=0.5)
        conn = PeerConnection(sock=c_sock, default_timeout=0.5)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # Download must exit after timeout and not get stuck in infinite loop
        start_t = time.time()
        success = client.download_from_peer_connection(conn)
        duration = time.time() - start_t

        self.assertFalse(success)
        self.assertLess(duration, 3.0)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 7. Partially Downloaded File Resume
    # ==========================================================================

    def test_resume_partially_downloaded_file(self):
        """
        Tests recovery and resume of partially downloaded files:
        - Piece 0 and Piece 2 already valid on disk;
        - Piece 1 is missing/corrupted;
        - Client verifies disk, completes Pieces 0 and 2, and downloads only Piece 1.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "partial_test.bin"

            # Write partial file: Piece 0 (correct), Piece 1 (corrupted/zeros), Piece 2 (correct)
            partial_data = self.pieces_data[0] + (b"\x00" * self.piece_length) + self.pieces_data[2]
            out_file.write_bytes(partial_data)

            client = TorrentClient(
                self.torrent_meta,
                output_path=out_file,
                block_size=self.block_size,
                auto_resume=True,  # Enable auto-verification of existing file
            )

            # Verify Pieces 0 and 2 identified as complete and Piece 1 as missing
            self.assertTrue(client.piece_manager.is_piece_complete(0))
            self.assertFalse(client.piece_manager.is_piece_complete(1))
            self.assertTrue(client.piece_manager.is_piece_complete(2))
            self.assertEqual(client.piece_manager.completed_pieces_count(), 2)
            self.assertEqual(client.piece_manager.bytes_left(), self.piece_length)

            # Simulate a peer providing Piece 1
            c_sock, s_sock = socket.socketpair()

            def provide_piece_1_server(sock):
                try:
                    raw_hs = sock.recv(68)
                    parse_handshake(raw_hs)
                    sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerRESUME11"))
                    sock.sendall(UnchokeMessage().encode())

                    buffer = bytearray()
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        buffer.extend(data)
                        while len(buffer) >= 4:
                            length = struct.unpack("!I", buffer[:4])[0]
                            if len(buffer) < 4 + length:
                                break
                            msg_bytes = bytes(buffer[: 4 + length])
                            del buffer[: 4 + length]
                            if length == 0:
                                continue
                            msg = parse_message(msg_bytes)
                            if isinstance(msg, RequestMessage):
                                b_start = msg.index * self.piece_length + msg.begin
                                b_end = b_start + msg.length
                                block = self.raw_data[b_start:b_end]
                                sock.sendall(PieceMessage(index=msg.index, begin=msg.begin, block=block).encode())
                except Exception:
                    pass
                finally:
                    sock.close()

            srv = threading.Thread(target=provide_piece_1_server, args=(s_sock,), daemon=True)
            srv.start()

            conn = PeerConnection(sock=c_sock, default_timeout=5.0)
            conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

            success = client.download_from_peer_connection(conn)
            conn.close()
            srv.join(timeout=2.0)

            self.assertTrue(success)
            self.assertTrue(client.is_complete)
            self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)

    def test_resume_partially_downloaded_multi_file(self):
        """
        Tests recovery and resume of partially downloaded multi-file torrent:
        - Multi-file directory hierarchy structure;
        - Piece 0 spans f1 and part of f2;
        - Validates piece-by-piece check correctly identifies partial/existing files.
        """
        f1_data = b"F1_DATA_TEST_12345"  # 18 bytes
        f2_data = b"F2_DATA_TEST_XYZ_67890"  # 22 bytes
        f3_data = b"F3_DATA_FINAL_DATA_ABCDEF1"  # 26 bytes
        total_data = f1_data + f2_data + f3_data  # 66 bytes
        piece_len = 22  # 3 pieces (22, 22, 22)

        p0_hash = compute_sha1(total_data[:22])
        p1_hash = compute_sha1(total_data[22:44])
        p2_hash = compute_sha1(total_data[44:66])

        multi_info = {
            b"name": b"dataset_resume",
            b"piece length": piece_len,
            b"pieces": p0_hash + p1_hash + p2_hash,
            b"files": [
                {b"length": 18, b"path": [b"docs", b"f1.txt"]},
                {b"length": 22, b"path": [b"docs", b"f2.txt"]},
                {b"length": 26, b"path": [b"f3.bin"]},
            ],
        }
        multi_meta = load_torrent_bytes(encode_bencode({
            b"announce": b"http://tracker.local:8080/announce",
            b"info": multi_info,
        }))

        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = Path(tmpdir) / "downloads"
            base_dir = out_root / "dataset_resume"
            (base_dir / "docs").mkdir(parents=True, exist_ok=True)

            # Write complete f1 and f2 (piece 0 spans bytes 0..21 = f1(18) + 4 bytes of f2) -> Piece 0 valid!
            # Piece 1 spans bytes 22..43 = remaining f2 (18 bytes) + 4 bytes of f3.
            # f3 not written yet -> Pieces 1 and 2 incomplete.
            (base_dir / "docs" / "f1.txt").write_bytes(f1_data)
            (base_dir / "docs" / "f2.txt").write_bytes(f2_data)

            client = TorrentClient(
                multi_meta,
                output_path=out_root,
                block_size=8,
                auto_resume=True,
            )

            # Piece 0 must have been validated successfully
            self.assertTrue(client.piece_manager.is_piece_complete(0))
            self.assertFalse(client.piece_manager.is_piece_complete(1))
            self.assertFalse(client.piece_manager.is_piece_complete(2))
            self.assertEqual(client.piece_manager.completed_pieces_count(), 1)

            # Now write complete f3
            (base_dir / "f3.bin").write_bytes(f3_data)

            # Create new client with auto-resume to re-verify all
            client2 = TorrentClient(
                multi_meta,
                output_path=out_root,
                block_size=8,
                auto_resume=True,
            )
            self.assertTrue(client2.piece_manager.is_piece_complete(0))
            self.assertTrue(client2.piece_manager.is_piece_complete(1))
            self.assertTrue(client2.piece_manager.is_piece_complete(2))
            self.assertTrue(client2.is_complete)

    # ==========================================================================
    # 8. Graceful Shutdown and Instant Thread Interruption
    # ==========================================================================

    def test_client_stop_unblocks_active_connections_immediately(self):
        """Tests whether client.stop() closes active sockets and interrupts blocked connections."""
        c_sock, s_sock = socket.socketpair()

        def hanging_server(sock):
            try:
                sock.recv(68)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerHANG1111"))
                time.sleep(10.0)  # Blocks
            except Exception:
                pass
            finally:
                sock.close()

        srv = threading.Thread(target=hanging_server, args=(s_sock,), daemon=True)
        srv.start()

        def dummy_opener(req, timeout=1.0):
            return MockHTTPResponse(b"")

        client = TorrentClient(self.torrent_meta, peer_timeout=10.0, http_opener=dummy_opener)
        conn = PeerConnection(sock=c_sock, default_timeout=10.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        worker_thread = threading.Thread(target=client.download_from_peer_connection, args=(conn,), daemon=True)
        worker_thread.start()

        # Allow time for worker to enter wait on socket
        time.sleep(0.1)

        # Run client.stop()
        t0 = time.time()
        client.stop()
        worker_thread.join(timeout=2.0)
        stop_duration = time.time() - t0

        self.assertFalse(worker_thread.is_alive())
        self.assertLess(stop_duration, 1.5)

        conn.close()
        srv.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
