"""
Dedicated tests for Rarest First strategy (BEP 0003) in PieceManager and TorrentClient.

Covers:
1. Rare pieces receive selection priority over common pieces;
2. Already completed pieces are ignored and not selected;
3. HAVE messages increment individual piece availability;
4. Arrival of new peers (Bitfield) increments availability of possessed pieces;
5. Departure/disconnection of peers decrements availability of possessed pieces;
6. Tie-breaking among pieces with identical availability (deterministic lowest index tie-break and priority for DOWNLOADING pieces);
7. End-to-end integration test with multiple peers where request order strictly follows rarity.
"""

import socket
import struct
import threading
import time
import unittest
from typing import List, Optional, Set, Tuple

from src.bencode import encode_bencode
from src.client import TorrentClient
from src.hash_utils import compute_sha1
from src.peer import (
    Bitfield,
    BitfieldMessage,
    HaveMessage,
    PeerConnection,
    PieceMessage,
    RequestMessage,
    UnchokeMessage,
    encode_handshake,
    parse_handshake,
    parse_message,
)
from src.piece_manager import BlockState, PieceManager, PieceState
from src.torrent import load_torrent_bytes


class TestRarestFirstPieceManager(unittest.TestCase):
    """Unit tests for Rarest First logic in PieceManager."""

    def setUp(self):
        # 5 pieces (0, 1, 2, 3, 4) of 16,384 bytes each
        self.piece_length = 16384
        self.block_size = 8192
        self.num_pieces = 5
        self.total_length = self.piece_length * self.num_pieces

        self.pieces_data = [bytes([i]) * self.piece_length for i in range(self.num_pieces)]
        self.piece_hashes = [compute_sha1(p) for p in self.pieces_data]

        self.pm = PieceManager(
            total_length=self.total_length,
            piece_length=self.piece_length,
            piece_hashes=self.piece_hashes,
            block_size=self.block_size,
        )

    def test_initial_availability_all_zero(self):
        """Verifies initial availability of all pieces is 0."""
        self.assertEqual(self.pm.get_all_availabilities(), [0, 0, 0, 0, 0])
        for i in range(self.num_pieces):
            self.assertEqual(self.pm.get_piece_availability(i), 0)

    def test_new_peers_alter_availability(self):
        """Tests whether new peers with bitfields update piece availability."""
        # Peer 1 possesses pieces {0, 2, 4}
        bf1 = Bitfield(num_pieces=self.num_pieces)
        bf1.set_piece(0, True)
        bf1.set_piece(2, True)
        bf1.set_piece(4, True)

        self.pm.add_peer_bitfield(bf1)
        self.assertEqual(self.pm.get_all_availabilities(), [1, 0, 1, 0, 1])

        # Peer 2 possesses pieces {0, 1, 2}
        bf2 = Bitfield(num_pieces=self.num_pieces)
        bf2.set_piece(0, True)
        bf2.set_piece(1, True)
        bf2.set_piece(2, True)

        self.pm.add_peer_bitfield(bf2)
        # Piece 0: 2 peers, Piece 1: 1 peer, Piece 2: 2 peers, Piece 3: 0 peers, Piece 4: 1 peer
        self.assertEqual(self.pm.get_all_availabilities(), [2, 1, 2, 0, 1])

    def test_peer_disconnect_alters_availability(self):
        """Tests whether peer disconnection reduces piece availability."""
        bf1 = Bitfield(num_pieces=self.num_pieces)
        bf1.set_piece(0, True)
        bf1.set_piece(1, True)

        bf2 = Bitfield(num_pieces=self.num_pieces)
        bf2.set_piece(1, True)
        bf2.set_piece(2, True)

        self.pm.add_peer_bitfield(bf1)
        self.pm.add_peer_bitfield(bf2)
        self.assertEqual(self.pm.get_all_availabilities(), [1, 2, 1, 0, 0])

        # Peer 1 disconnects
        self.pm.remove_peer_bitfield(bf1)
        self.assertEqual(self.pm.get_all_availabilities(), [0, 1, 1, 0, 0])

        # Peer 2 disconnects
        self.pm.remove_peer_bitfield(bf2)
        self.assertEqual(self.pm.get_all_availabilities(), [0, 0, 0, 0, 0])

    def test_have_alters_availability(self):
        """Tests whether HAVE messages alter piece availability."""
        self.assertEqual(self.pm.get_piece_availability(3), 0)

        # Peer A announces Have for piece 3
        self.pm.update_peer_have(3)
        self.assertEqual(self.pm.get_piece_availability(3), 1)

        # Peer B announces Have for piece 3
        self.pm.update_peer_have(3)
        self.assertEqual(self.pm.get_piece_availability(3), 2)

        # Piece 1 remains 0
        self.assertEqual(self.pm.get_piece_availability(1), 0)

    def test_rare_pieces_receive_priority(self):
        """
        Tests whether rarer pieces (lower availability) are selected before common pieces.
        Configured availabilities:
        - Piece 0: 3 peers (common)
        - Piece 1: 1 peer  (RARE)
        - Piece 2: 2 peers (medium)
        - Piece 3: 4 peers (very common)
        - Piece 4: 1 peer  (RARE)
        """
        # Configure bitfields simulating the count above
        bf_common = Bitfield(num_pieces=self.num_pieces)
        for i in [0, 1, 2, 3, 4]:
            bf_common.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_common)  # [1, 1, 1, 1, 1]

        bf_extra1 = Bitfield(num_pieces=self.num_pieces)
        for i in [0, 2, 3]:
            bf_extra1.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_extra1)  # [2, 1, 2, 2, 1]

        bf_extra2 = Bitfield(num_pieces=self.num_pieces)
        for i in [0, 3]:
            bf_extra2.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_extra2)  # [3, 1, 2, 3, 1]

        bf_extra3 = Bitfield(num_pieces=self.num_pieces)
        bf_extra3.set_piece(3, True)
        self.pm.add_peer_bitfield(bf_extra3)  # [3, 1, 2, 4, 1]

        self.assertEqual(self.pm.get_all_availabilities(), [3, 1, 2, 4, 1])

        # Connected peer possesses all pieces
        peer_bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            peer_bf.set_piece(i, True)

        # 1st and 2nd requests: must be the 2 blocks of Piece 1 (Rarity = 1, lower index than 4)
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req1, (1, 0, 8192))
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2, (1, 8192, 8192))

        # 3rd and 4th requests: must be for Piece 4 (Rarity = 1)
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3, (4, 0, 8192))
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4, (4, 8192, 8192))

        # 5th and 6th requests: must be for Piece 2 (Rarity = 2)
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5, (2, 0, 8192))
        req6 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req6, (2, 8192, 8192))

        # 7th and 8th requests: must be for Piece 0 (Rarity = 3)
        req7 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req7, (0, 0, 8192))
        req8 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req8, (0, 8192, 8192))

        # 9th and 10th requests: must be for Piece 3 (Rarity = 4, the most common)
        req9 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req9, (3, 0, 8192))
        req10 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req10, (3, 8192, 8192))

        # No remaining blocks
        req_none = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertIsNone(req_none)

    def test_completed_pieces_ignored(self):
        """Tests whether pieces that are already downloaded and completed are ignored."""
        # Piece 1 is the rarest (disp=1), Piece 0 has disp=2
        bf = Bitfield(num_pieces=self.num_pieces)
        bf.set_piece(0, True)
        self.pm.add_peer_bitfield(bf)
        bf_all = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf_all.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_all)

        # Availabilities: [2, 1, 1, 1, 1]
        # Complete Piece 1 with valid data
        self.pm.add_block(1, 0, self.pieces_data[1][:8192])
        self.pm.add_block(1, 8192, self.pieces_data[1][8192:])
        self.assertTrue(self.pm.is_piece_complete(1))

        # When requesting next block, COMPLETED Piece 1 must be completely ignored
        # and next rarest piece (Piece 2) must be selected
        req = self.pm.get_next_block_to_request(peer_bitfield=bf_all)
        self.assertIsNotNone(req)
        piece_idx, begin, _ = req
        self.assertNotEqual(piece_idx, 1)  # Piece 1 ignored
        self.assertEqual(piece_idx, 2)     # Piece 2 selected

    def test_tie_breaking_deterministic_lowest_index(self):
        """
        Tests tie-breaking strategy:
        When multiple pieces have the same rarity (e.g. pieces 1, 3, 4 all with disp=1
        while pieces 0 and 2 have disp=2), deterministic tie-break must select
        in ascending index order (1, then 3, then 4).
        """
        # Base: all have disp=1
        bf_base = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf_base.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_base)  # [1, 1, 1, 1, 1]

        # Pieces 0 and 2 have more peers (disp=2), pieces 1, 3, 4 remain rarest (disp=1)
        bf_extra = Bitfield(num_pieces=self.num_pieces)
        bf_extra.set_piece(0, True)
        bf_extra.set_piece(2, True)
        self.pm.add_peer_bitfield(bf_extra)  # [2, 1, 2, 1, 1]

        self.assertEqual(self.pm.get_all_availabilities(), [2, 1, 2, 1, 1])

        peer_bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            peer_bf.set_piece(i, True)

        # Among rarest pieces (1, 3, 4 with disp=1), Piece 1 has lowest index
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req1[0], 1)
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2[0], 1)

        # Next rarest must be Piece 3 (3 < 4)
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3[0], 3)
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4[0], 3)

        # Next rarest must be Piece 4
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5[0], 4)

    def test_tie_breaking_downloading_state_priority(self):
        """
        Tests whether pieces already in DOWNLOADING state have priority over MISSING pieces,
        even with identical availability, to finish blocks and free memory.
        """
        # All pieces with same availability (disp=1)
        bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf.set_piece(i, True)
        self.pm.add_peer_bitfield(bf)

        # Start Piece 4 (request block 0) -> Piece 4 goes to DOWNLOADING
        p4 = self.pm.get_piece(4)
        p4.blocks[0].state = BlockState.REQUESTED
        p4.state = PieceState.DOWNLOADING

        # Next request must prioritize second block of Piece 4 (DOWNLOADING)
        # instead of starting Piece 0 (MISSING)
        req = self.pm.get_next_block_to_request(peer_bitfield=bf)
        self.assertEqual(req, (4, 8192, 8192))


class TestRarestFirstClientIntegration(unittest.TestCase):
    """End-to-end integration tests of Rarest First with TorrentClient."""

    def test_client_requests_rarest_piece_first_from_swarm(self):
        """
        Creates a scenario with 3 peers:
        - Peer A has pieces {0, 1, 2}
        - Peer B has pieces {0, 2}
        - Peer C has pieces {0, 2}
        In this scenario:
        - Piece 0: 3 peers (common)
        - Piece 2: 3 peers (common)
        - Piece 1: 1 peer (RARE - available only on Peer A)

        Client connected to Peer A must immediately prioritize Piece 1.
        """
        piece_len = 16384
        num_pieces = 3
        total_len = piece_len * num_pieces
        pieces_data = [bytes([i + 1]) * piece_len for i in range(num_pieces)]
        pieces_hash = b"".join(compute_sha1(p) for p in pieces_data)

        torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": {
                b"length": total_len,
                b"name": b"rarest_test.bin",
                b"piece length": piece_len,
                b"pieces": pieces_hash,
            },
        }
        meta = load_torrent_bytes(encode_bencode(torrent_dict))

        c_sock, s_sock = socket.socketpair()

        # Peer A (servidor)
        def run_peer_server(sock):
            try:
                # 1. Handshake
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(meta.info_hash, b"-UT2210-peerA1234567"))

                # 2. Bitfield (possesses pieces 0, 1, 2)
                bf = Bitfield(num_pieces=3)
                bf.set_piece(0, True)
                bf.set_piece(1, True)
                bf.set_piece(2, True)
                sock.sendall(BitfieldMessage(bitfield=bf.to_bytes()).encode())

                # 3. Unchoke
                sock.sendall(UnchokeMessage().encode())

                # Read requests
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
                            p_idx = msg.index
                            b_start = p_idx * piece_len + msg.begin
                            b_end = b_start + msg.length
                            sock.sendall(
                                PieceMessage(
                                    index=msg.index,
                                    begin=msg.begin,
                                    block=b"".join(pieces_data)[b_start:b_end],
                                ).encode()
                            )
            except Exception:
                pass
            finally:
                sock.close()

        srv_thread = threading.Thread(target=run_peer_server, args=(s_sock,), daemon=True)
        srv_thread.start()

        client = TorrentClient(meta, block_size=8192, max_in_flight=1)

        # Simulate client has learned about other peers (Peer B and Peer C) possessing {0, 2}
        bf_other = Bitfield(num_pieces=3)
        bf_other.set_piece(0, True)
        bf_other.set_piece(2, True)
        client.piece_manager.add_peer_bitfield(bf_other)  # Peer B
        client.piece_manager.add_peer_bitfield(bf_other)  # Peer C

        # Availabilities before connecting to Peer A:
        # Piece 0: 2, Piece 1: 0, Piece 2: 2
        self.assertEqual(client.piece_manager.get_all_availabilities(), [2, 0, 2])

        conn = PeerConnection(sock=c_sock, default_timeout=5.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # When running download, Piece 1 must be requested and downloaded first
        first_piece_completed = []

        def on_progress(p):
            if p.completed_pieces == 1 and not first_piece_completed:
                # Record which piece was completed first
                for i in range(3):
                    if client.piece_manager.is_piece_complete(i):
                        first_piece_completed.append(i)

        success = client.download_from_peer_connection(conn, on_progress=on_progress)
        conn.close()
        srv_thread.join(timeout=2.0)

        self.assertTrue(success)
        self.assertTrue(client.is_complete)
        # Proves that rarest piece (index 1) was completed first!
        self.assertEqual(first_piece_completed, [1])


if __name__ == "__main__":
    unittest.main()
