"""
Complete End-to-End Integration Test Suite for Simple BitTorrent Client.

Tests the full pipeline without relying on public Internet trackers or peers:
.torrent
  -> parser (TorrentMetadata)
  -> info_hash calculation
  -> local HTTP tracker query and announce
  -> peer discovery
  -> 68-byte TCP handshake
  -> bitfield / have exchange
  -> unchoke / interested management
  -> in-flight request pipelining
  -> block reception (PieceMessage)
  -> strict per-piece SHA-1 integrity validation
  -> resilience against corrupted pieces and disconnects
  -> final file reconstruction (single-file and multi-file).
"""

import dataclasses
import hashlib
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from typing import List

from src.client import (
    DownloadError,
    DownloadIncompleteError,
    DownloadProgress,
    NoPeersAvailableError,
    TorrentClient,
    TrackerUnavailableError,
)
from src.hash_utils import compute_sha1
from src.peer import Bitfield
from src.torrent import load_torrent_file
from tests.simulators import (
    PeerBehavior,
    SimulatedPeerServer,
    SimulatedSwarm,
    SimulatedTrackerServer,
    TorrentFixtureBuilder,
)


class TestFullPipelineIntegration(unittest.TestCase):
    """
    Testes do fluxo completo ponta a ponta (.torrent -> tracker -> peers -> arquivo final).
    """

    def test_e2e_single_file_complete_download_flow(self):
        """
        Tests complete download flow for a single-file torrent:
        1. Creation and parsing of .torrent from physical file;
        2. Local HTTP tracker announcing start and recording statistics;
        3. Local TCP peer performing handshake, bitfield, and unchoke;
        4. Request pipelining and block reception;
        5. SHA-1 validation on all pieces;
        6. Saving to disk and byte-by-byte validation of saved file;
        7. Final 'completed' announce to tracker.
        """
        file_size = 48 * 1024  # 48 KB
        piece_length = 16 * 1024  # 16 KB (3 pieces)

        with SimulatedSwarm() as swarm:
            # 1. Create fixture with local tracker URL
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="ubuntu_test_iso.iso",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # 2. Create a Peer with 100% of pieces
            peer = swarm.spawn_peer(PeerBehavior(peer_id=b"-ST0001-goodpeer0001"))

            # 3. Configure output directory
            with tempfile.TemporaryDirectory() as out_dir:
                out_path = Path(out_dir)
                target_file = out_path / "ubuntu_test_iso.iso"

                progress_snapshots: List[DownloadProgress] = []

                def track_progress(p: DownloadProgress):
                    progress_snapshots.append(p)

                # 4. Instantiate BitTorrent client pointing to .torrent file on disk
                client = TorrentClient(
                    torrent=fixture.torrent_file_path,
                    output_path=out_path,
                    peer_timeout=3.0,
                    tracker_timeout=3.0,
                )

                # 5. Execute end-to-end download
                downloaded_data = client.download(on_progress=track_progress)

                # 6. Validations
                # A. Returned in-memory data matches original exactly
                self.assertEqual(downloaded_data, fixture.total_data)
                self.assertEqual(len(downloaded_data), file_size)

                # B. File written to disk matches byte-for-byte
                self.assertTrue(target_file.exists())
                self.assertEqual(target_file.read_bytes(), fixture.total_data)

                # C. Validate progress
                self.assertTrue(client.piece_manager.is_complete)
                self.assertEqual(client.piece_manager.completed_pieces_count(), 3)
                self.assertEqual(client.piece_manager.bytes_downloaded(), file_size)
                self.assertEqual(client.piece_manager.bytes_left(), 0)
                self.assertTrue(len(progress_snapshots) > 0)
                self.assertTrue(progress_snapshots[-1].is_complete)

                # D. Validate statistics recorded by HTTP Tracker
                announces = swarm.tracker.get_announces()
                self.assertTrue(len(announces) >= 2)
                started_event = [a for a in announces if a.event == "started"]
                completed_event = [a for a in announces if a.event == "completed"]
                self.assertEqual(len(started_event), 1)
                self.assertEqual(len(completed_event), 1)
                self.assertEqual(started_event[0].info_hash, fixture.info_hash)
                self.assertEqual(completed_event[0].downloaded, file_size)

                # E. Validate peer served all blocks
                self.assertEqual(peer.blocks_served, 3)
                self.assertIn("InterestedMessage", peer.received_messages)
                self.assertIn("RequestMessage", peer.received_messages)

    def test_e2e_multi_file_download_and_directory_tree_reconstruction(self):
        """
        Tests complete flow for multi-file torrents with multiple files and nested directories:
        - Verifies data integrity across piece and file boundaries;
        - Validates correct creation of subdirectories and files on disk.
        """
        files_spec = [
            (["manual", "intro.txt"], 1500),
            (["bin", "app.exe"], 25000),
            (["assets", "images", "logo.png"], 18500),
        ]
        piece_length = 16 * 1024  # 16 KB

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_multi_file_torrent(
                root_dir_name="sample_package",
                files_spec=files_spec,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            peer = swarm.spawn_peer(PeerBehavior(peer_id=b"-ST0001-multifile001"))

            with tempfile.TemporaryDirectory() as out_dir:
                out_path = Path(out_dir)

                client = TorrentClient(
                    torrent=fixture.torrent_file_path,
                    output_path=out_path,
                    peer_timeout=3.0,
                )

                downloaded_data = client.download()

                # 1. Validate continuous torrent data
                self.assertEqual(downloaded_data, fixture.total_data)

                # 2. Validate each file individually in directory tree
                root_target = out_path / "sample_package"
                self.assertTrue(root_target.is_dir())

                for rel_path, expected_bytes in fixture.file_map.items():
                    disk_file = root_target / Path(rel_path)
                    self.assertTrue(disk_file.exists(), f"File not found on disk: {disk_file}")
                    self.assertEqual(
                        disk_file.read_bytes(),
                        expected_bytes,
                        f"Divergent content for file: {rel_path}",
                    )


class TestMultiPeerAndSwarmDynamicsIntegration(unittest.TestCase):
    """
    Integration tests for swarm dynamics (multiple simultaneous peers, distributed pieces).
    """

    def test_multi_peer_disjoint_pieces_swarm_assembly(self):
        """
        Tests concurrent download from 3 peers, where each possesses only a slice of pieces:
        - Peer 1 possesses pieces [0, 1]
        - Peer 2 possesses pieces [2, 3]
        - Peer 3 possesses pieces [4, 5]
        Client must connect to all 3 peers, route requests based on Bitfield, and assemble full file.
        """
        piece_length = 16 * 1024
        file_size = 6 * piece_length  # 6 pieces of 16 KB = 96 KB

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="distributed_archive.tar",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Create 3 peers with disjoint sets of pieces
            peer1 = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-peer_part1___",
                pieces_possessed={0, 1},
            ))
            peer2 = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-peer_part2___",
                pieces_possessed={2, 3},
            ))
            peer3 = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-peer_part3___",
                pieces_possessed={4, 5},
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
                max_in_flight=4,
            )

            # Run with multiple concurrent workers
            downloaded = client.download(max_workers=3)

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertEqual(client.piece_manager.completed_pieces_count(), 6)

            # Validate all 3 peers were contacted for their respective pieces
            self.assertGreaterEqual(peer1.blocks_served, 2)
            self.assertGreaterEqual(peer2.blocks_served, 2)
            self.assertGreaterEqual(peer3.blocks_served, 2)
            self.assertEqual(peer1.blocks_served + peer2.blocks_served + peer3.blocks_served, 6)

    def test_slow_unchoke_and_dynamic_have_messages(self):
        """
        Tests interaction when peer starts Choked and sends Have progressively:
        1. Peer connects choked;
        2. Peer sends unchoke after brief delay (50ms);
        3. Peer sends no initial bitfield, but announces pieces dynamically via HaveMessage.
        """
        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="dynamic_test.bin",
                file_size=32 * 1024,
                piece_length=16 * 1024,  # 2 pieces
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-dynamicpeer01",
                pieces_possessed={0, 1},
                send_bitfield=False,  # Announce via Have
                choke_first=True,     # Start choked
                choke_delay=0.05,
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
            )

            downloaded = client.download()
            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)


class TestCorruptionAndFaultToleranceIntegration(unittest.TestCase):
    """
    Integration tests for fault tolerance, poisoned pieces, and peer disconnection.
    """

    def test_corrupted_piece_discard_and_failover_recovery(self):
        """
        Tests scenario where a peer intentionally sends corrupted blocks:
        - Peer 1 (Malicious) possesses piece 0, but sends data with invalid SHA-1 hash;
        - Peer 2 (Genuine) possesses piece 0 and valid data;
        - Client must detect SHA-1 error upon finishing piece, discard corrupted blocks,
          reset piece to MISSING, and download it successfully from Peer 2.
        """
        piece_length = 16 * 1024
        file_size = 32 * 1024  # 2 pieces

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="poison_test.dat",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Peer 1: corrupts piece 0
            bad_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-bad_peer_00001",
                pieces_possessed={0, 1},
                corrupt_pieces={0},
            ))

            # Peer 2: reliable and intact
            good_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-good_peer_0001",
                pieces_possessed={0, 1},
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
            )

            # Execute download with both peers in pool
            downloaded = client.download(max_workers=2)

            # Validate final result is 100% intact and matches legitimate data
            self.assertEqual(downloaded, fixture.total_data)
            self.assertEqual(compute_sha1(downloaded), compute_sha1(fixture.total_data))
            self.assertTrue(client.piece_manager.is_complete)

    def test_peer_abrupt_disconnect_mid_stream_failover(self):
        """
        Tests resilience against sudden TCP connection drop:
        - Peer 1 serves 1 block and drops (disconnect_after_blocks=1);
        - Peer 2 remains active;
        - Client must capture disconnection, re-queue in-flight blocks, and complete download via Peer 2.
        """
        piece_length = 16 * 1024
        file_size = 48 * 1024  # 3 pieces

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="disconnect_test.dat",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Peer that drops immediately after first block
            flaky_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-flakypeer0001",
                pieces_possessed={0, 1, 2},
                disconnect_after_blocks=1,
            ))

            # Resilient peer
            solid_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-solidpeer0001",
                pieces_possessed={0, 1, 2},
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
            )

            downloaded = client.download(max_workers=2)

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertGreaterEqual(solid_peer.blocks_served, 1)

    def test_handshake_rejection_and_peer_recovery(self):
        """
        Tests resilience when a peer responds to handshake with invalid info_hash:
        - Peer 1 (Tampered): sends incorrect info_hash in handshake;
        - Peer 2 (Valid): responds with correct handshake;
        - Client rejects Peer 1 (HandshakeError), attempts Peer 2, and completes download.
        """
        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="bad_hs_test.dat",
                file_size=16 * 1024,
                piece_length=16 * 1024,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            bad_hs_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-bad_hs_peer01",
                send_bad_handshake_hash=True,
            ))
            good_hs_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-good_hs_peer1",
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=1.0,
            )

            downloaded = client.download(max_workers=2)
            time.sleep(0.05)

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertGreaterEqual(good_hs_peer.blocks_served, 1)

    def test_peer_never_unchoking_timeout_and_worker_rotation(self):
        """
        Tests worker rotation when a peer connects but never unchokes (remains choked):
        - Peer 1: responds to handshake and bitfield but never sends Unchoke;
        - Peer 2: responds normally;
        - Client detects choke timeout on Peer 1, terminates session, and completes via Peer 2.
        """
        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="choke_timeout.dat",
                file_size=16 * 1024,
                piece_length=16 * 1024,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            stubborn_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-stubbornpeer1",
                never_unchoke=True,
            ))
            cooperative_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-cooppeer00001",
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=0.5,
            )

            downloaded = client.download(max_workers=2)
            time.sleep(0.05)

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertGreaterEqual(cooperative_peer.blocks_served, 1)

    def test_multi_block_pipelining_with_large_pieces(self):
        """
        Tests intensive pipelining of multiple blocks per piece:
        - 1 piece of 64 KB containing 4 blocks of 16 KB;
        - max_in_flight=4 for simultaneous request dispatch without individual waiting.
        """
        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="pipelined_file.bin",
                file_size=64 * 1024,
                piece_length=64 * 1024,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-pipelinepeer1",
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                max_in_flight=4,
                peer_timeout=3.0,
            )

            downloaded = client.download(max_workers=1)
            time.sleep(0.05)  # Allow final synchronization of peer thread

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertGreaterEqual(peer.blocks_served, 4)


class TestTrackerFailoverAndResilienceIntegration(unittest.TestCase):
    """
    Integration tests for Tracker communication fallback and resilience.
    """

    def test_tracker_tier_fallback_on_primary_failure(self):
        """
        Tests tracker selection when primary fails (e.g. HTTP 500 or unavailable):
        - Primary Tracker: returns HTTP 500;
        - Secondary Tracker: responds normally with peer list;
        - Client must attempt primary, catch failure, advance to secondary, and finish download.
        """
        # Start Tracker 1 (Failing)
        broken_tracker = SimulatedTrackerServer()
        broken_tracker.set_http_error(500)
        broken_url = broken_tracker.start()

        # Start Tracker 2 (Operational)
        good_tracker = SimulatedTrackerServer()
        good_url = good_tracker.start()

        fixture = TorrentFixtureBuilder.create_single_file_torrent(
            filename="tier_fallback.dat",
            file_size=16 * 1024,
            piece_length=16 * 1024,
            announce_url=broken_url,
            announce_list=[[broken_url], [good_url]],
        )

        try:
            # Create Peer registered on functional tracker
            peer_server = SimulatedPeerServer(fixture, behavior=PeerBehavior())
            peer_info = peer_server.start()
            good_tracker.add_peer(peer_info)

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
                tracker_timeout=3.0,
            )

            downloaded = client.download()

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            # Verify functional tracker received queries
            self.assertTrue(len(good_tracker.get_announces()) >= 1)

        finally:
            broken_tracker.stop()
            good_tracker.stop()
            peer_server.stop()
            fixture.temp_dir.cleanup()

    def test_no_peers_available_in_swarm_raises_error(self):
        """
        Testa o tratamento quando o tracker responde com uma lista vazia de peers.
        """
        tracker = SimulatedTrackerServer()
        tracker_url = tracker.start()

        fixture = TorrentFixtureBuilder.create_single_file_torrent(
            filename="empty_swarm.dat",
            file_size=16 * 1024,
            announce_url=tracker_url,
        )

        try:
            client = TorrentClient(
                torrent=fixture.torrent_meta,
                tracker_timeout=3.0,
            )

            with self.assertRaises(NoPeersAvailableError):
                client.download()

        finally:
            tracker.stop()
            fixture.temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
