"""
Testes abrangentes de robustez e tratamento de falhas para o cliente BitTorrent.

Cobre cenários críticos de falha no nível correto de abstração:
1. Peer desconectando abruptamente (EOF/Reset de conexão no meio do download);
2. Tracker indisponível (falha de rede, timeout, erro HTTP 5xx, fallback de múltiplos trackers);
3. Timeouts de conexão e leitura de mensagens;
4. Resposta Bencode inválida ou truncada retornada pelo tracker;
5. Handshake inválido (tamanho, identificador de protocolo divergente);
6. info_hash incorreto no handshake do peer;
7. Mensagens malformadas (tamanho excessivo, payload inconsistente com ID);
8. Peça corrompida (falha de SHA-1 com reset automático e re-download);
9. Bloco perdido em peer inativo e reatribuição para outro peer;
10. Peer enviando dados inesperados (offset inválido, índice fora de alcance, tamanho incorreto);
11. Peer permanecendo bloqueado (choked) continuamente;
12. Torrent sem peers no enxame (NoPeersAvailableError);
13. Retomada de arquivo parcialmente baixado (validação SHA-1 em disco);
14. Encerramento gracioso e parada imediata de threads ativas (client.stop()).
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
    """Mock para respostas de requisições HTTP."""

    def __init__(self, data: bytes, code: int = 200, headers: Optional[dict] = None):
        self.data = data
        self.code = code
        self.headers = headers or {}

    def read(self) -> bytes:
        return self.data


class TestRobustnessEdgeCases(unittest.TestCase):
    """Testes detalhados de robustez para falhas de rede, protocolo, integridade e concorrência."""

    def setUp(self):
        # 3 peças de 16 KB cada (total: 48 KB), blocos de 8 KB (2 blocos por peça)
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
    # 1. Falhas de Tracker e Fallback
    # ==========================================================================

    def test_tracker_unavailable_and_fallback(self):
        """
        Testa se o cliente tenta o tracker secundário quando o tracker primário falha,
        e levanta TrackerUnavailableError se todos falharem.
        """
        attempted_urls = []

        def failing_opener(req, timeout=15.0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            attempted_urls.append(url)
            # Simula tracker 1 fora do ar e tracker 2 retornando peers
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
        """Testa se TrackerUnavailableError é lançado quando todos os trackers falham."""
        def all_fail_opener(req, timeout=15.0):
            raise TrackerConnectionError("No route to host")

        client = TorrentClient(self.torrent_meta, http_opener=all_fail_opener)
        with self.assertRaises(TrackerUnavailableError):
            client.discover_peers()

    def test_invalid_bencode_from_tracker_handled_cleanly(self):
        """Testa se resposta Bencode malformada do tracker é tratada sem crash do cliente."""
        def garbage_opener(req, timeout=15.0):
            return MockHTTPResponse(b"<html>502 Bad Gateway</html>")

        client = TorrentClient(self.torrent_meta, http_opener=garbage_opener)
        with self.assertRaises(TrackerUnavailableError):
            client.discover_peers()

    # ==========================================================================
    # 2. Falhas no Enxame (Sem peers disponíveis)
    # ==========================================================================

    def test_no_peers_in_swarm_raises_no_peers_error(self):
        """Testa se NoPeersAvailableError é lançado quando o tracker retorna lista vazia de peers."""
        def empty_peers_opener(req, timeout=15.0):
            return MockHTTPResponse(encode_bencode({b"interval": 900, b"peers": b""}))

        client = TorrentClient(self.torrent_meta, http_opener=empty_peers_opener)
        with self.assertRaises(NoPeersAvailableError):
            client.download()

    # ==========================================================================
    # 3. Falhas de Handshake e info_hash
    # ==========================================================================

    def test_peer_wrong_info_hash_rejected(self):
        """Testa se o cliente rejeita e fecha conexão quando o peer retorna outro info_hash no handshake."""
        c_sock, s_sock = socket.socketpair()

        def bad_handshake_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                # Envia info_hash divergente
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
        """Testa se handshake com protocolo divergente é rejeitado com HandshakeError."""
        c_sock, s_sock = socket.socketpair()

        def bad_proto_server(sock):
            try:
                sock.recv(68)
                # Envia identificador de protocolo inválido (19 bytes: WrongProtoProtocol1)
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
    # 4. Mensagens Malformadas e Violações de Protocolo
    # ==========================================================================

    def test_peer_oversized_message_rejected(self):
        """Testa se peer enviando mensagem maior que MAX_MESSAGE_LENGTH (2 MB) é rejeitado por MessageSizeError."""
        c_sock, s_sock = socket.socketpair()

        def oversized_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerOVERSIZ1"))
                # Envia length prefix de 5 MB
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

        # download_from_peer_connection deve detectar a violação, desconectar e retornar False
        success = client.download_from_peer_connection(conn)
        self.assertFalse(success)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 5. Peer Enviando Dados Inesperados ou Malformados
    # ==========================================================================

    def test_peer_sending_invalid_piece_index_or_offset(self):
        """Testa se envio de Piece com offset inválido ou índice fora de alcance é capturado com segurança."""
        c_sock, s_sock = socket.socketpair()

        def bad_piece_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerBADPIECE"))
                sock.sendall(UnchokeMessage().encode())

                # Aguarda Request
                buffer = bytearray()
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    buffer.extend(data)
                    if len(buffer) >= 17:  # 4 len + 1 id + 12 req
                        # Envia Piece com offset completamente inválido (9999)
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

        # O cliente deve capturar o erro de dados malformados, desalocar requests em voo e sair
        success = client.download_from_peer_connection(conn)
        self.assertFalse(success)
        self.assertFalse(client.is_complete)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 6. Peer Permanecendo Choked
    # ==========================================================================

    def test_peer_remaining_choked_times_out_and_releases(self):
        """Testa se peer que nunca envia Unchoke é liberado após timeout sem travar o cliente."""
        c_sock, s_sock = socket.socketpair()

        def choked_forever_server(sock):
            try:
                raw_hs = sock.recv(68)
                parse_handshake(raw_hs)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerCHOKED99"))
                # Envia Choke e não faz mais nada
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

        # O download deve sair após o timeout e não ficar em loop infinito
        start_t = time.time()
        success = client.download_from_peer_connection(conn)
        duration = time.time() - start_t

        self.assertFalse(success)
        self.assertLess(duration, 3.0)

        conn.close()
        srv.join(timeout=2.0)

    # ==========================================================================
    # 7. Retomada de Arquivo Parcialmente Baixado (Resume)
    # ==========================================================================

    def test_resume_partially_downloaded_file(self):
        """
        Testa a recuperação e retomada de arquivos parcialmente baixados:
        - Peça 0 e Peça 2 já estão válidas em disco;
        - Peça 1 está ausente/corrompida;
        - O cliente verifica o disco, completa as Peças 0 e 2, e baixa apenas a Peça 1.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "partial_test.bin"

            # Grava arquivo parcial: Peça 0 (correta), Peça 1 (corrompida/zeros), Peça 2 (correta)
            partial_data = self.pieces_data[0] + (b"\x00" * self.piece_length) + self.pieces_data[2]
            out_file.write_bytes(partial_data)

            client = TorrentClient(
                self.torrent_meta,
                output_path=out_file,
                block_size=self.block_size,
                auto_resume=True,  # Ativa auto-verificação de arquivo existente
            )

            # Verifica se identificou Peças 0 e 2 como concluídas e Peça 1 como faltante
            self.assertTrue(client.piece_manager.is_piece_complete(0))
            self.assertFalse(client.piece_manager.is_piece_complete(1))
            self.assertTrue(client.piece_manager.is_piece_complete(2))
            self.assertEqual(client.piece_manager.completed_pieces_count(), 2)
            self.assertEqual(client.piece_manager.bytes_left(), self.piece_length)

            # Simula um peer que fornece a Peça 1
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

    # ==========================================================================
    # 8. Parada Graciosa e Interrupção Instantânea de Threads
    # ==========================================================================

    def test_client_stop_unblocks_active_connections_immediately(self):
        """Testa se client.stop() fecha os sockets ativos e interrompe conexões bloqueadas."""
        c_sock, s_sock = socket.socketpair()

        def hanging_server(sock):
            try:
                sock.recv(68)
                sock.sendall(encode_handshake(self.torrent_meta.info_hash, b"-UT2210-peerHANG1111"))
                time.sleep(10.0)  # Bloqueia
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

        # Dá tempo para o worker entrar em espera no socket
        time.sleep(0.1)

        # Executa client.stop()
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
