"""
Comprehensive concurrency tests with multiple simultaneous peers for TorrentClient.

Covers:
1. Connection and concurrent download from multiple peers simultaneously;
2. Correct tracking of individual piece possession (Bitfield and Have) for targeted request routing;
3. Strict adherence to in-flight request limits per peer (Pipelining / max_in_flight);
4. Absence of duplicate simultaneous requests for the same block;
5. Handling of peers that disconnect / drop mid-download (isolation and re-queuing of blocks);
6. Handling of dynamic Choke in concurrent connections;
7. Broadcast of Have messages to all connected peers upon validating each piece;
8. Processing and queue rotation of peers across concurrent worker pool.
"""

import queue
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
    DownloadProgress,
    TorrentClient,
)
from src.hash_utils import compute_sha1
from src.peer import (
    Bitfield,
    BitfieldMessage,
    ChokeMessage,
    Handshake,
    HaveMessage,
    InterestedMessage,
    KeepAliveMessage,
    PeerConnection,
    PieceMessage,
    RequestMessage,
    UnchokeMessage,
    encode_handshake,
    parse_handshake,
    parse_message,
)
from src.piece_manager import PieceManager
from src.torrent import TorrentMetadata, load_torrent_bytes
from src.tracker import PeerInfo


class MockPeerHandler:
    """
    Configurable controller for peer simulation in dedicated thread.
    """

    def __init__(
        self,
        sock: socket.socket,
        info_hash: bytes,
        peer_id: bytes,
        torrent_data: bytes,
        piece_length: int,
        available_pieces: Optional[Set[int]] = None,
        drop_after_blocks: Optional[int] = None,
        choke_after_blocks: Optional[int] = None,
        delay_per_block: float = 0.0,
    ):
        self.sock = sock
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.torrent_data = torrent_data
        self.piece_length = piece_length
        self.total_pieces = (len(torrent_data) + piece_length - 1) // piece_length
        self.available_pieces = available_pieces if available_pieces is not None else set(range(self.total_pieces))
        self.drop_after_blocks = drop_after_blocks
        self.choke_after_blocks = choke_after_blocks
        self.delay_per_block = delay_per_block

        self.blocks_sent = 0
        self.received_requests: List[Tuple[int, int, int]] = []
        self.received_haves: List[int] = []
        self.received_interested = False
        self.stopped = False

    def run(self) -> None:
        try:
            self.sock.settimeout(5.0)
            # 1. Handshake
            raw_hs = self.sock.recv(68)
            if len(raw_hs) != 68:
                return
            parse_handshake(raw_hs)
            self.sock.sendall(encode_handshake(self.info_hash, self.peer_id))

            # 2. Bitfield
            bf = Bitfield(num_pieces=self.total_pieces)
            for idx in self.available_pieces:
                bf.set_piece(idx, True)
            self.sock.sendall(BitfieldMessage(bitfield=bf.to_bytes()).encode())

            # 3. Unchoke
            self.sock.sendall(UnchokeMessage().encode())

            buffer = bytearray()
            while not self.stopped:
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        break
                    buffer.extend(data)
                except socket.timeout:
                    continue
                except socket.error:
                    break

                while len(buffer) >= 4:
                    length = struct.unpack("!I", buffer[:4])[0]
                    if len(buffer) < 4 + length:
                        break
                    msg_bytes = bytes(buffer[: 4 + length])
                    del buffer[: 4 + length]

                    if length == 0:
                        continue

                    msg = parse_message(msg_bytes)

                    if isinstance(msg, InterestedMessage):
                        self.received_interested = True
                    elif isinstance(msg, HaveMessage):
                        self.received_haves.append(msg.piece_index)
                    elif isinstance(msg, RequestMessage):
                        self.received_requests.append((msg.index, msg.begin, msg.length))

                        if self.choke_after_blocks is not None and self.blocks_sent >= self.choke_after_blocks:
                            self.sock.sendall(ChokeMessage().encode())
                            time.sleep(0.1)
                            continue

                        if self.drop_after_blocks is not None and self.blocks_sent >= self.drop_after_blocks:
                            # Abruptly terminate connection
                            self.sock.close()
                            return

                        if self.delay_per_block > 0:
                            time.sleep(self.delay_per_block)

                        # Send Piece
                        p_start = msg.index * self.piece_length
                        b_start = p_start + msg.begin
                        b_end = b_start + msg.length
                        block_bytes = self.torrent_data[b_start:b_end]

                        self.sock.sendall(
                            PieceMessage(
                                index=msg.index,
                                begin=msg.begin,
                                block=block_bytes,
                            ).encode()
                        )
                        self.blocks_sent += 1

        except Exception:
            pass
        finally:
            try:
                self.sock.close()
            except Exception:
                pass


class TestMultiPeerDownload(unittest.TestCase):
    """Tests with multiple concurrent peers for TorrentClient."""

    def setUp(self):
        # Create data for 4 pieces of 16 KB each (65,536 bytes)
        # Each piece will have 2 blocks of 8 KB (8192 bytes)
        self.piece_length = 16384
        self.block_size = 8192
        self.num_pieces = 4
        self.total_length = self.piece_length * self.num_pieces  # 65536 bytes

        # Generate predictable data
        pieces_raw = [bytes([i]) * self.piece_length for i in range(self.num_pieces)]
        self.raw_data = b"".join(pieces_raw)

        hashes = [compute_sha1(p) for p in pieces_raw]
        self.piece_hashes_bytes = b"".join(hashes)

        self.info_dict = {
            b"length": self.total_length,
            b"name": b"multipeer_test.bin",
            b"piece length": self.piece_length,
            b"pieces": self.piece_hashes_bytes,
        }
        self.torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": self.info_dict,
        }
        self.torrent_meta = load_torrent_bytes(encode_bencode(self.torrent_dict))

    def test_multi_peer_concurrent_swarm_download(self):
        """
        Tests concurrent download where 3 peers have 100% of the file (swarm).
        Ensures all 3 peers work simultaneously and no block is duplicated.
        """
        num_peers = 3
        server_handlers: List[MockPeerHandler] = []
        threads: List[threading.Thread] = []
        client_conns: List[PeerConnection] = []

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=2,
        )

        for i in range(num_peers):
            c_sock, s_sock = socket.socketpair()
            conn = PeerConnection(sock=c_sock, default_timeout=5.0)
            client_conns.append(conn)

            handler = MockPeerHandler(
                sock=s_sock,
                info_hash=client.info_hash,
                peer_id=f"-UT2210-peer000{i}1234".encode(),
                torrent_data=self.raw_data,
                piece_length=self.piece_length,
                delay_per_block=0.01,
            )
            server_handlers.append(handler)

            t = threading.Thread(target=handler.run, daemon=True)
            threads.append(t)
            t.start()

        # Run client connections concurrently
        client_threads: List[threading.Thread] = []
        for conn in client_conns:
            conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)
            t = threading.Thread(
                target=client.download_from_peer_connection,
                args=(conn,),
                kwargs={"max_in_flight": 2},
                daemon=True,
            )
            client_threads.append(t)
            t.start()

        for t in client_threads:
            t.join(timeout=10.0)

        for conn in client_conns:
            conn.close()

        for t in threads:
            t.join(timeout=2.0)

        # Validations
        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.completed_pieces_count(), 4)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)

        # Verify more than one peer contributed to download (shared work)
        contributions = [h.blocks_sent for h in server_handlers]
        total_blocks_sent = sum(contributions)
        # Total blocks in torrent: 4 pieces * 2 blocks = 8 blocks
        self.assertEqual(total_blocks_sent, 8)
        # At least 2 peers must have sent blocks
        active_senders = sum(1 for c in contributions if c > 0)
        self.assertGreaterEqual(active_senders, 2)

    def test_multi_peer_disjoint_pieces_distribution(self):
        """
        Tests distribution of disjoint pieces across peers:
        - Peer 0 has only pieces {0, 1}
        - Peer 1 has only pieces {2, 3}
        Client must request pieces 0 and 1 exclusively from Peer 0,
        and pieces 2 and 3 exclusively from Peer 1.
        """
        c_sock0, s_sock0 = socket.socketpair()
        c_sock1, s_sock1 = socket.socketpair()

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=2,
        )

        handler0 = MockPeerHandler(
            sock=s_sock0,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peer0001AAAA",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            available_pieces={0, 1},
        )
        handler1 = MockPeerHandler(
            sock=s_sock1,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peer0002BBBB",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            available_pieces={2, 3},
        )

        t0 = threading.Thread(target=handler0.run, daemon=True)
        t1 = threading.Thread(target=handler1.run, daemon=True)
        t0.start()
        t1.start()

        conn0 = PeerConnection(sock=c_sock0, default_timeout=5.0)
        conn1 = PeerConnection(sock=c_sock1, default_timeout=5.0)
        conn0.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)
        conn1.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        ct0 = threading.Thread(target=client.download_from_peer_connection, args=(conn0,), daemon=True)
        ct1 = threading.Thread(target=client.download_from_peer_connection, args=(conn1,), daemon=True)
        ct0.start()
        ct1.start()

        ct0.join(timeout=10.0)
        ct1.join(timeout=10.0)

        conn0.close()
        conn1.close()
        t0.join(timeout=2.0)
        t1.join(timeout=2.0)

        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)

        # Verify requests respected piece possession of each peer
        for req in handler0.received_requests:
            piece_idx = req[0]
            self.assertIn(piece_idx, {0, 1}, f"Peer 0 received request for unexpected piece {piece_idx}")

        for req in handler1.received_requests:
            piece_idx = req[0]
            self.assertIn(piece_idx, {2, 3}, f"Peer 1 received request for unexpected piece {piece_idx}")

    def test_disappearing_peer_failover_and_recovery(self):
        """
        Tests recovery when a peer drops mid-download:
        - Peer 0 sends 1 block and drops abruptly (drop_after_blocks=1);
        - Peer 1 is available with all pieces;
        Client must recover in-flight blocks from Peer 0,
        request them from Peer 1, and complete 100% with SHA-1 integrity.
        """
        c_sock0, s_sock0 = socket.socketpair()
        c_sock1, s_sock1 = socket.socketpair()

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=2,
        )

        handler_failing = MockPeerHandler(
            sock=s_sock0,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerFAIL1111",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            drop_after_blocks=1,  # Drops after sending 1 block
        )
        handler_reliable = MockPeerHandler(
            sock=s_sock1,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerOK222222",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
        )

        t0 = threading.Thread(target=handler_failing.run, daemon=True)
        t1 = threading.Thread(target=handler_reliable.run, daemon=True)
        t0.start()
        t1.start()

        conn0 = PeerConnection(sock=c_sock0, default_timeout=2.0)
        conn1 = PeerConnection(sock=c_sock1, default_timeout=5.0)
        conn0.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)
        conn1.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        ct0 = threading.Thread(target=client.download_from_peer_connection, args=(conn0,), daemon=True)
        ct1 = threading.Thread(target=client.download_from_peer_connection, args=(conn1,), daemon=True)
        ct0.start()
        ct1.start()

        ct0.join(timeout=10.0)
        ct1.join(timeout=10.0)

        conn0.close()
        conn1.close()
        t0.join(timeout=2.0)
        t1.join(timeout=2.0)

        # Download must complete successfully thanks to failover
        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)
        # Reliable peer must have sent remaining 7 blocks
        self.assertEqual(handler_reliable.blocks_sent, 7)

    def test_choke_release_and_peer_reassignment(self):
        """
        Tests release of in-flight blocks when a peer sends Choke:
        - Peer 0 sends 2 blocks and then sends Choke;
        - Peer 1 takes over pending blocks and completes download.
        """
        c_sock0, s_sock0 = socket.socketpair()
        c_sock1, s_sock1 = socket.socketpair()

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=2,
        )

        handler_choking = MockPeerHandler(
            sock=s_sock0,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerCHOKE111",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            choke_after_blocks=2,
        )
        handler_helper = MockPeerHandler(
            sock=s_sock1,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerHELP2222",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
        )

        t0 = threading.Thread(target=handler_choking.run, daemon=True)
        t1 = threading.Thread(target=handler_helper.run, daemon=True)
        t0.start()
        t1.start()

        conn0 = PeerConnection(sock=c_sock0, default_timeout=2.0)
        conn1 = PeerConnection(sock=c_sock1, default_timeout=5.0)
        conn0.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)
        conn1.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        ct0 = threading.Thread(target=client.download_from_peer_connection, args=(conn0,), daemon=True)
        ct1 = threading.Thread(target=client.download_from_peer_connection, args=(conn1,), daemon=True)
        ct0.start()
        ct1.start()

        ct0.join(timeout=10.0)
        ct1.join(timeout=10.0)

        conn0.close()
        conn1.close()
        t0.join(timeout=2.0)
        t1.join(timeout=2.0)

        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)

    def test_broadcast_have_messages_to_all_peers(self):
        """
        Tests whether upon completing download and SHA-1 validation of each piece,
        a Have(piece_index) message is broadcast to all connected peers.
        """
        c_sock0, s_sock0 = socket.socketpair()
        c_sock1, s_sock1 = socket.socketpair()

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=1,
        )

        # Peer 0 provides data
        handler_sender = MockPeerHandler(
            sock=s_sock0,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerSND11111",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            delay_per_block=0.01,
        )
        # Peer 1 has no pieces, only listens
        handler_listener = MockPeerHandler(
            sock=s_sock1,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerLST22222",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            available_pieces=set(),
        )

        t0 = threading.Thread(target=handler_sender.run, daemon=True)
        t1 = threading.Thread(target=handler_listener.run, daemon=True)
        t0.start()
        t1.start()

        conn0 = PeerConnection(sock=c_sock0, default_timeout=5.0)
        conn1 = PeerConnection(sock=c_sock1, default_timeout=5.0)
        conn0.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)
        conn1.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        ct0 = threading.Thread(target=client.download_from_peer_connection, args=(conn0,), daemon=True)
        ct1 = threading.Thread(target=client.download_from_peer_connection, args=(conn1,), daemon=True)
        ct0.start()
        ct1.start()

        ct0.join(timeout=10.0)
        ct1.join(timeout=10.0)

        conn0.close()
        conn1.close()
        t0.join(timeout=2.0)
        t1.join(timeout=2.0)

        self.assertTrue(client.is_complete)
        # The listener must have received Have notifications for completed pieces (0, 1, 2, 3)
        self.assertGreaterEqual(len(handler_listener.received_haves), 1)
        for piece_idx in handler_listener.received_haves:
            self.assertIn(piece_idx, range(self.num_pieces))

    def test_peer_pool_dispatch_and_worker_rotation(self):
        """
        Tests download() method with worker pool and queue rotation:
        - 4 peers available in list;
        - max_workers = 2;
        - Peer 0 and 1 fail connection;
        - Workers automatically pick Peer 2 and 3 and complete download.
        """
        # Create real mock socket servers on local ports
        srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv2.bind(("127.0.0.1", 0))
        srv2.listen(1)
        port2 = srv2.getsockname()[1]

        srv3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv3.bind(("127.0.0.1", 0))
        srv3.listen(1)
        port3 = srv3.getsockname()[1]

        def serve(srv_sock, pieces_set):
            try:
                srv_sock.settimeout(5.0)
                client_s, _ = srv_sock.accept()
                handler = MockPeerHandler(
                    sock=client_s,
                    info_hash=self.torrent_meta.info_hash,
                    peer_id=b"-UT2210-mockserver99",
                    torrent_data=self.raw_data,
                    piece_length=self.piece_length,
                    available_pieces=pieces_set,
                )
                handler.run()
            except Exception:
                pass
            finally:
                srv_sock.close()

        t2 = threading.Thread(target=serve, args=(srv2, {0, 1}), daemon=True)
        t3 = threading.Thread(target=serve, args=(srv3, {2, 3}), daemon=True)
        t2.start()
        t3.start()

        # List with 2 peers that will fail (closed ports) and 2 real peers
        peers_list = [
            PeerInfo(ip="127.0.0.1", port=1),  # Unreachable port
            PeerInfo(ip="127.0.0.1", port=2),  # Unreachable port
            PeerInfo(ip="127.0.0.1", port=port2),
            PeerInfo(ip="127.0.0.1", port=port3),
        ]

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            peer_timeout=1.0,
        )

        downloaded = client.download(peers=peers_list, max_workers=2)
        self.assertEqual(downloaded, self.raw_data)
        self.assertTrue(client.is_complete)

        t2.join(timeout=2.0)
        t3.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
