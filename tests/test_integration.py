"""
Suíte Completa de Testes de Integração de Ponta a Ponta para o Simple BitTorrent Client.

Testa o pipeline completo sem depender de trackers ou peers públicos na Internet:
.torrent
  -> parser (TorrentMetadata)
  -> cálculo do info_hash
  -> consulta e anúncio ao tracker HTTP local
  -> descoberta de peers
  -> handshake TCP de 68 bytes
  -> troca de bitfield / have
  -> gerenciamento de unchoke / interested
  -> envio de requests em voo (pipelining)
  -> recepção de blocos (PieceMessage)
  -> validação rigorosa de integridade SHA-1 por peça
  -> resiliência contra peças corrompidas e desconexões
  -> reconstrução dos arquivos finais (single-file e multi-file).
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
        Testa o fluxo integral de download para um arquivo único (single-file):
        1. Criação e parsing do .torrent a partir de arquivo físico;
        2. Tracker HTTP local anunciando início e registrando estatísticas;
        3. Peer TCP local efetuando handshake, bitfield e unchoke;
        4. Pipelining de requisições e recepção de blocos;
        5. Validação de SHA-1 em todas as peças;
        6. Gravação em disco e validação byte a byte do arquivo salvo;
        7. Anúncio final de 'completed' no tracker.
        """
        file_size = 48 * 1024  # 48 KB
        piece_length = 16 * 1024  # 16 KB (3 peças)

        with SimulatedSwarm() as swarm:
            # 1. Cria fixture com a URL do tracker local
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="ubuntu_test_iso.iso",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # 2. Cria um Peer com 100% das peças
            peer = swarm.spawn_peer(PeerBehavior(peer_id=b"-ST0001-goodpeer0001"))

            # 3. Configura diretório de saída
            with tempfile.TemporaryDirectory() as out_dir:
                out_path = Path(out_dir)
                target_file = out_path / "ubuntu_test_iso.iso"

                progress_snapshots: List[DownloadProgress] = []

                def track_progress(p: DownloadProgress):
                    progress_snapshots.append(p)

                # 4. Instancia o cliente BitTorrent apontando para o arquivo .torrent em disco
                client = TorrentClient(
                    torrent=fixture.torrent_file_path,
                    output_path=out_path,
                    peer_timeout=3.0,
                    tracker_timeout=3.0,
                )

                # 5. Executa o download de ponta a ponta
                downloaded_data = client.download(on_progress=track_progress)

                # 6. Validações
                # A. Dados retornados em memória coincidem exatamente com o original
                self.assertEqual(downloaded_data, fixture.total_data)
                self.assertEqual(len(downloaded_data), file_size)

                # B. Arquivo gravado em disco confere byte a byte
                self.assertTrue(target_file.exists())
                self.assertEqual(target_file.read_bytes(), fixture.total_data)

                # C. Valida progresso
                self.assertTrue(client.piece_manager.is_complete)
                self.assertEqual(client.piece_manager.completed_pieces_count(), 3)
                self.assertEqual(client.piece_manager.bytes_downloaded(), file_size)
                self.assertEqual(client.piece_manager.bytes_left(), 0)
                self.assertTrue(len(progress_snapshots) > 0)
                self.assertTrue(progress_snapshots[-1].is_complete)

                # D. Valida estatísticas registradas pelo Tracker HTTP
                announces = swarm.tracker.get_announces()
                self.assertTrue(len(announces) >= 2)
                started_event = [a for a in announces if a.event == "started"]
                completed_event = [a for a in announces if a.event == "completed"]
                self.assertEqual(len(started_event), 1)
                self.assertEqual(len(completed_event), 1)
                self.assertEqual(started_event[0].info_hash, fixture.info_hash)
                self.assertEqual(completed_event[0].downloaded, file_size)

                # E. Valida que o peer atendeu todos os blocos
                self.assertEqual(peer.blocks_served, 3)
                self.assertIn("InterestedMessage", peer.received_messages)
                self.assertIn("RequestMessage", peer.received_messages)

    def test_e2e_multi_file_download_and_directory_tree_reconstruction(self):
        """
        Testa o fluxo completo para torrents multi-file com múltiplos arquivos e pastas aninhadas:
        - Verifica integridade dos dados através das fronteiras de peças e arquivos;
        - Valida a criação correta de subdiretórios e arquivos no disco.
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

                # 1. Valida dados contínuos do torrent
                self.assertEqual(downloaded_data, fixture.total_data)

                # 2. Valida cada arquivo individualmente na árvore de diretórios
                root_target = out_path / "sample_package"
                self.assertTrue(root_target.is_dir())

                for rel_path, expected_bytes in fixture.file_map.items():
                    disk_file = root_target / Path(rel_path)
                    self.assertTrue(disk_file.exists(), f"Arquivo não encontrado no disco: {disk_file}")
                    self.assertEqual(
                        disk_file.read_bytes(),
                        expected_bytes,
                        f"Conteúdo divergente para o arquivo: {rel_path}",
                    )


class TestMultiPeerAndSwarmDynamicsIntegration(unittest.TestCase):
    """
    Testes de integração para dinâmicas de enxame (múltiplos peers simultâneos, peças divididas).
    """

    def test_multi_peer_disjoint_pieces_swarm_assembly(self):
        """
        Testa o download concorrente a partir de 3 peers, onde cada um possui apenas uma fatia das peças:
        - Peer 1 possui peças [0, 1]
        - Peer 2 possui peças [2, 3]
        - Peer 3 possui peças [4, 5]
        O cliente deve conectar nos 3 peers, rotear requisições com base no Bitfield e montar o arquivo completo.
        """
        piece_length = 16 * 1024
        file_size = 6 * piece_length  # 6 peças de 16 KB = 96 KB

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="distributed_archive.tar",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Cria 3 peers com fatias disjuntas de peças
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

            # Executa com múltiplos workers simultâneos
            downloaded = client.download(max_workers=3)

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertEqual(client.piece_manager.completed_pieces_count(), 6)

            # Valida que todos os 3 peers foram acionados para suas respectivas peças
            self.assertGreaterEqual(peer1.blocks_served, 2)
            self.assertGreaterEqual(peer2.blocks_served, 2)
            self.assertGreaterEqual(peer3.blocks_served, 2)
            self.assertEqual(peer1.blocks_served + peer2.blocks_served + peer3.blocks_served, 6)

    def test_slow_unchoke_and_dynamic_have_messages(self):
        """
        Testa a interação quando o peer inicia em estado Choked e envia Have progressivamente:
        1. Peer conecta choked;
        2. Peer envia unchoke após breve atraso (50ms);
        3. Peer não envia bitfield inicial, mas anuncia peças via HaveMessage dinamicamente.
        """
        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="dynamic_test.bin",
                file_size=32 * 1024,
                piece_length=16 * 1024,  # 2 peças
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-dynamicpeer01",
                pieces_possessed={0, 1},
                send_bitfield=False,  # Anuncia via Have
                choke_first=True,     # Inicia choked
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
    Testes de integração para tolerância a falhas, peças envenenadas e desconexão de peers.
    """

    def test_corrupted_piece_discard_and_failover_recovery(self):
        """
        Testa o cenário onde um peer envia blocos corrompidos propositalmente:
        - Peer 1 (Malicioso) possui a peça 0, mas envia dados com hash SHA-1 inválido;
        - Peer 2 (Genuíno) possui a peça 0 e dados válidos;
        - O cliente deve detectar o erro de SHA-1 ao finalizar a peça, descartar os blocos corrompidos,
          resetar a peça para MISSING e baixá-la com sucesso a partir do Peer 2.
        """
        piece_length = 16 * 1024
        file_size = 32 * 1024  # 2 peças

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="poison_test.dat",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Peer 1: corrompe a peça 0
            bad_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-bad_peer_00001",
                pieces_possessed={0, 1},
                corrupt_pieces={0},
            ))

            # Peer 2: confiável e íntegro
            good_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-good_peer_0001",
                pieces_possessed={0, 1},
            ))

            client = TorrentClient(
                torrent=fixture.torrent_meta,
                peer_timeout=3.0,
            )

            # Executa o download com ambos os peers no pool
            downloaded = client.download(max_workers=2)

            # Valida que o resultado final é 100% íntegro e confere com os dados legítimos
            self.assertEqual(downloaded, fixture.total_data)
            self.assertEqual(compute_sha1(downloaded), compute_sha1(fixture.total_data))
            self.assertTrue(client.piece_manager.is_complete)

    def test_peer_abrupt_disconnect_mid_stream_failover(self):
        """
        Testa resiliência contra queda súbita de conexão TCP:
        - Peer 1 atende 1 bloco e cai (disconnect_after_blocks=1);
        - Peer 2 permanece ativo;
        - O cliente deve capturar a queda, re-enfileirar os blocos em voo e concluir o download via Peer 2.
        """
        piece_length = 16 * 1024
        file_size = 48 * 1024  # 3 peças

        with SimulatedSwarm() as swarm:
            fixture = TorrentFixtureBuilder.create_single_file_torrent(
                filename="disconnect_test.dat",
                file_size=file_size,
                piece_length=piece_length,
                announce_url=swarm.tracker_url,
            )
            swarm.set_fixture(fixture)

            # Peer que cai logo após o primeiro bloco
            flaky_peer = swarm.spawn_peer(PeerBehavior(
                peer_id=b"-ST0001-flakypeer0001",
                pieces_possessed={0, 1, 2},
                disconnect_after_blocks=1,
            ))

            # Peer resiliente
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
        Testa resiliência quando um peer responde ao handshake com info_hash inválido:
        - Peer 1 (Adulterado): envia info_hash incorreto no handshake;
        - Peer 2 (Válido): responde com handshake correto;
        - O cliente rejeita o Peer 1 (HandshakeError), tenta o Peer 2 e completa o download.
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
        Testa a rotação de worker quando um peer conecta mas nunca desbloqueia (permanece choked):
        - Peer 1: responde handshake e bitfield mas nunca envia Unchoke;
        - Peer 2: responde normalmente;
        - O cliente detecta o timeout de choke no Peer 1, encerra a sessão com ele e conclui via Peer 2.
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
        Testa o pipelining intensivo de múltiplos blocos por peça:
        - 1 peça de 64 KB contendo 4 blocos de 16 KB;
        - max_in_flight=4 para envio simultâneo de requisições sem espera individual.
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
            time.sleep(0.05)  # Permite sincronização final da thread do peer

            self.assertEqual(downloaded, fixture.total_data)
            self.assertTrue(client.piece_manager.is_complete)
            self.assertGreaterEqual(peer.blocks_served, 4)


class TestTrackerFailoverAndResilienceIntegration(unittest.TestCase):
    """
    Testes de integração para fallback e resiliência de comunicação com Trackers.
    """

    def test_tracker_tier_fallback_on_primary_failure(self):
        """
        Testa a seleção de trackers quando o primário falha (ex: HTTP 500 ou indisponível):
        - Tracker Primário: retorna HTTP 500;
        - Tracker Secundário: responde normalmente com a lista de peers;
        - O cliente deve tentar o primário, capturar a falha, avançar para o secundário e concluir o download.
        """
        # Inicia Tracker 1 (Falho)
        broken_tracker = SimulatedTrackerServer()
        broken_tracker.set_http_error(500)
        broken_url = broken_tracker.start()

        # Inicia Tracker 2 (Operacional)
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
            # Cria Peer registrado no tracker funcional
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
            # Verifica que o tracker funcional recebeu as consultas
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
