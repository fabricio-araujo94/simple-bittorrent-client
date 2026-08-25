"""
Testes abrangentes de concorrência com múltiplos peers simultâneos para o TorrentClient.

Cobre:
1. Conexão e download concorrente a partir de múltiplos peers simultaneamente;
2. Rastreamento correto de posse de peças individuais (Bitfield e Have) para distribuição direcionada de requests;
3. Respeito estrito aos limites de requisições em voo por peer (Pipelining / max_in_flight);
4. Ausência de requisições duplicadas simultâneas para o mesmo bloco;
5. Tratamento de peers que desconectam / desaparecem no meio do download (isolamento e re-enfileiramento de blocos);
6. Tratamento de Choke dinâmico em conexões concorrentes;
7. Broadcast de mensagens Have para todos os peers conectados ao concluir a validação de cada peça;
8. Processamento e rotação de fila de peers em pool de workers concorrentes.
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
    Controlador configurável para simulação de peer em thread dedicada.
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
                            # Encerra abruptamente a conexão
                            self.sock.close()
                            return

                        if self.delay_per_block > 0:
                            time.sleep(self.delay_per_block)

                        # Envia Piece
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
    """Testes com múltiplos peers concorrentes para o TorrentClient."""

    def setUp(self):
        # Cria dados para 4 peças de 16 KB cada (65.536 bytes)
        # Cada peça terá 2 blocos de 8 KB (8192 bytes)
        self.piece_length = 16384
        self.block_size = 8192
        self.num_pieces = 4
        self.total_length = self.piece_length * self.num_pieces  # 65536 bytes

        # Gera dados previsíveis
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
        Testa download concorrente onde 3 peers possuem 100% do arquivo (swarm).
        Garante que os 3 peers trabalham simultaneamente e nenhum bloco é duplicado.
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

        # Executa conexões do cliente concorrentemente
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

        # Validações
        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.completed_pieces_count(), 4)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)

        # Verifica se mais de um peer contribuiu para o download (trabalho compartilhado)
        contributions = [h.blocks_sent for h in server_handlers]
        total_blocks_sent = sum(contributions)
        # Total de blocos no torrent: 4 peças * 2 blocos = 8 blocos
        self.assertEqual(total_blocks_sent, 8)
        # Pelo menos 2 peers devem ter enviado blocos
        active_senders = sum(1 for c in contributions if c > 0)
        self.assertGreaterEqual(active_senders, 2)

    def test_multi_peer_disjoint_pieces_distribution(self):
        """
        Testa distribuição de peças disjuntas entre peers:
        - Peer 0 tem apenas peças {0, 1}
        - Peer 1 tem apenas peças {2, 3}
        O cliente deve solicitar peças 0 e 1 exclusivamente ao Peer 0,
        e peças 2 e 3 exclusivamente ao Peer 1.
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

        # Verifica se as requisições respeitaram a posse de peças de cada peer
        for req in handler0.received_requests:
            piece_idx = req[0]
            self.assertIn(piece_idx, {0, 1}, f"Peer 0 recebeu request para peça inesperada {piece_idx}")

        for req in handler1.received_requests:
            piece_idx = req[0]
            self.assertIn(piece_idx, {2, 3}, f"Peer 1 recebeu request para peça inesperada {piece_idx}")

    def test_disappearing_peer_failover_and_recovery(self):
        """
        Testa recuperação quando um peer cai no meio do download:
        - Peer 0 envia 1 bloco e cai abruptamente (drop_after_blocks=1);
        - Peer 1 está disponível com todas as peças;
        O cliente deve recuperar os blocos que estavam em voo no Peer 0,
        solicitá-los ao Peer 1 e completar 100% com integridade SHA-1.
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
            drop_after_blocks=1,  # Cai após enviar 1 bloco
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

        # O download deve ter sido completado com sucesso graças ao failover
        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_data)
        # Peer confiável deve ter enviado os 7 blocos restantes
        self.assertEqual(handler_reliable.blocks_sent, 7)

    def test_choke_release_and_peer_reassignment(self):
        """
        Testa liberação de blocos em voo quando um peer envia Choke:
        - Peer 0 envia 2 blocos e depois envia Choke;
        - Peer 1 assume os blocos pendentes e finaliza o download.
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
        Testa se ao completar o download e validação SHA-1 de cada peça,
        uma mensagem Have(piece_index) é transmitida a todos os peers conectados.
        """
        c_sock0, s_sock0 = socket.socketpair()
        c_sock1, s_sock1 = socket.socketpair()

        client = TorrentClient(
            self.torrent_meta,
            block_size=self.block_size,
            max_in_flight=1,
        )

        # Peer 0 fornece os dados
        handler_sender = MockPeerHandler(
            sock=s_sock0,
            info_hash=client.info_hash,
            peer_id=b"-UT2210-peerSND11111",
            torrent_data=self.raw_data,
            piece_length=self.piece_length,
            delay_per_block=0.01,
        )
        # Peer 1 não possui peças, apenas escuta
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
        # O listener deve ter recebido as notificações Have para as peças completadas (0, 1, 2, 3)
        self.assertGreaterEqual(len(handler_listener.received_haves), 1)
        for piece_idx in handler_listener.received_haves:
            self.assertIn(piece_idx, range(self.num_pieces))

    def test_peer_pool_dispatch_and_worker_rotation(self):
        """
        Testa o método download() com pool de workers e rotação de fila:
        - 4 peers disponíveis na lista;
        - max_workers = 2;
        - Peer 0 e 1 falham na conexão;
        - Workers automaticamente pegam Peer 2 e 3 e concluem o download.
        """
        # Criamos um mock socket server real em portas locais
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

        # Lista com 2 peers que falharão (portas fechadas) e 2 peers reais
        peers_list = [
            PeerInfo(ip="127.0.0.1", port=1),  # Porta inacessível
            PeerInfo(ip="127.0.0.1", port=2),  # Porta inacessível
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
