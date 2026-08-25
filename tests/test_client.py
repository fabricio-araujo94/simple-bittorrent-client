"""
Testes de integração de ponta a ponta para o fluxo completo de download (TorrentClient).

Cobre o fluxo completo de 17 etapas:
1. Carregar .torrent;
2. Calcular info_hash;
3. Anunciar ao tracker;
4. Obter peers;
5. Conectar aos peers;
6. Realizar handshake;
7. Receber bitfield/have;
8. Enviar interested quando apropriado;
9. Aguardar unchoke;
10. Selecionar uma peça disponível;
11. Solicitar blocos;
12. Receber piece;
13. Reconstruir a peça;
14. Validar SHA-1;
15. Marcar peça como concluída;
16. Repetir até concluir o torrent;
17. Montar e gravar o arquivo final (single-file e multi-file).
"""

import hashlib
import io
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import List, Optional

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
from src.torrent import FileInfo, TorrentMetadata, load_torrent_bytes
from src.tracker import PeerInfo


class MockHTTPResponse:
    """Mock para respostas do urllib HTTP Tracker."""

    def __init__(self, data: bytes, code: int = 200):
        self.data = data
        self.code = code
        self.headers = {}

    def read(self) -> bytes:
        return self.data


def run_mock_peer_server(
    server_sock: socket.socket,
    expected_info_hash: bytes,
    server_peer_id: bytes,
    torrent_data: bytes,
    piece_length: int,
    send_bitfield_first: bool = True,
    choke_first: bool = False,
    corrupt_first_piece: bool = False,
) -> None:
    """
    Simula o comportamento de um peer BitTorrent completo em uma thread de teste.
    """
    try:
        # 1. Recebe o handshake do cliente
        client_hs_raw = server_sock.recv(68)
        if len(client_hs_raw) != 68:
            return
        client_hs = parse_handshake(client_hs_raw)

        # 2. Envia o handshake do servidor
        server_hs = encode_handshake(expected_info_hash, server_peer_id)
        server_sock.sendall(server_hs)

        total_length = len(torrent_data)
        num_pieces = (total_length + piece_length - 1) // piece_length

        # 3. Envia Bitfield ou Have
        if send_bitfield_first:
            bf = Bitfield(num_pieces=num_pieces)
            for i in range(num_pieces):
                bf.set_piece(i, True)
            server_sock.sendall(BitfieldMessage(bitfield=bf.to_bytes()).encode())

        # 4. Envia Choke ou Unchoke
        if choke_first:
            server_sock.sendall(ChokeMessage().encode())
            time.sleep(0.02)
            server_sock.sendall(UnchokeMessage().encode())
        else:
            server_sock.sendall(UnchokeMessage().encode())

        # Buffer para ler mensagens do cliente
        buffer = bytearray()
        first_piece_sent = False

        while True:
            data = server_sock.recv(4096)
            if not data:
                break
            buffer.extend(data)

            # Processa mensagens completas
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
                    # Garante que o cliente está unchoked
                    server_sock.sendall(UnchokeMessage().encode())

                elif isinstance(msg, RequestMessage):
                    # Calcula o offset absoluto nos dados do torrent
                    piece_start = msg.index * piece_length
                    block_start = piece_start + msg.begin
                    block_end = block_start + msg.length

                    if corrupt_first_piece and not first_piece_sent and msg.index == 0:
                        # Envia bloco propositalmente corrompido na primeira vez
                        block_data = b"Z" * msg.length
                        first_piece_sent = True
                    else:
                        block_data = torrent_data[block_start:block_end]

                    # Envia a resposta Piece
                    resp_piece = PieceMessage(
                        index=msg.index,
                        begin=msg.begin,
                        block=block_data,
                    ).encode()
                    server_sock.sendall(resp_piece)

    except Exception:
        pass
    finally:
        try:
            server_sock.close()
        except Exception:
            pass


class TestTorrentClientIntegration(unittest.TestCase):
    """Testes de integração ponta a ponta do fluxo de download do cliente."""

    def setUp(self):
        # Cria dados simulados de um arquivo de 65.000 bytes (~64 KB)
        # Dividido em 3 peças (peças de 24.000 bytes cada, última de 17.000 bytes)
        self.raw_file_content = b"".join(bytes([i % 256]) * 1000 for i in range(65))  # 65000 bytes
        self.piece_length = 24000
        self.block_size = 8192

        p0 = self.raw_file_content[0:24000]
        p1 = self.raw_file_content[24000:48000]
        p2 = self.raw_file_content[48000:65000]

        self.p0_hash = compute_sha1(p0)
        self.p1_hash = compute_sha1(p1)
        self.p2_hash = compute_sha1(p2)
        self.pieces_bytes = self.p0_hash + self.p1_hash + self.p2_hash

        # Metadados .torrent Single-File
        self.single_info_dict = {
            b"length": 65000,
            b"name": b"test_payload.bin",
            b"piece length": self.piece_length,
            b"pieces": self.pieces_bytes,
        }
        self.single_torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": self.single_info_dict,
        }
        self.single_torrent_bytes = encode_bencode(self.single_torrent_dict)
        self.single_torrent_meta = load_torrent_bytes(self.single_torrent_bytes)

    def test_full_download_flow_single_file(self):
        """
        Testa o fluxo funcional completo de ponta a ponta (17 etapas):
        Tracker -> Handshake -> Bitfield -> Interested -> Unchoke -> Request -> Piece -> SHA1 -> Save File
        """
        s_client, s_server = socket.socketpair()

        # Inicia thread do peer simulado
        peer_thread = threading.Thread(
            target=run_mock_peer_server,
            kwargs={
                "server_sock": s_server,
                "expected_info_hash": self.single_torrent_meta.info_hash,
                "server_peer_id": b"-UT2210-peer12345678",
                "torrent_data": self.raw_file_content,
                "piece_length": self.piece_length,
            },
        )
        peer_thread.daemon = True
        peer_thread.start()

        # Configura Mock do Tracker HTTP para retornar o IP/porta do peer
        peer_compact = socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)
        tracker_response_bencoded = encode_bencode({
            b"interval": 1800,
            b"peers": peer_compact,
        })

        def mock_tracker_opener(req, timeout=15.0):
            return MockHTTPResponse(tracker_response_bencoded)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "downloaded_test_payload.bin"

            client = TorrentClient(
                self.single_torrent_meta,
                output_path=out_file,
                block_size=self.block_size,
                http_opener=mock_tracker_opener,
            )

            progress_updates: List[DownloadProgress] = []

            def on_progress(p: DownloadProgress):
                progress_updates.append(p)

            # Usa conexão direta de socketpair
            conn = PeerConnection(sock=s_client, default_timeout=5.0)
            conn.perform_handshake(
                info_hash=client.info_hash,
                peer_id=client.peer_id,
            )

            # Executa o ciclo de download
            success = client.download_from_peer_connection(conn, on_progress=on_progress)
            conn.close()

            # Finaliza o download (grava em disco e valida)
            downloaded_bytes = client._finalize_download()

            self.assertTrue(success)
            self.assertTrue(client.is_complete)
            self.assertEqual(downloaded_bytes, self.raw_file_content)

            # Valida gravação do arquivo em disco
            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.read_bytes(), self.raw_file_content)

            # Valida progresso
            self.assertTrue(len(progress_updates) > 0)
            last_p = client.get_progress()
            self.assertTrue(last_p.is_complete)
            self.assertEqual(last_p.completed_pieces, 3)
            self.assertEqual(last_p.bytes_downloaded, 65000)
            self.assertEqual(last_p.bytes_left, 0)
            self.assertEqual(last_p.progress_percentage, 100.0)

        peer_thread.join(timeout=2.0)

    def test_full_download_flow_multi_file(self):
        """
        Testa o fluxo funcional de download e reconstrução de um torrent multi-file
        com subdiretórios e múltiplos arquivos.
        """
        f1_content = b"FILE_ONE_DATA_123456"  # 20 bytes
        f2_content = b"FILE_TWO_DATA_7890123456789012"  # 30 bytes
        f3_content = b"FILE_THREE_CONTENT_XYZ"  # 22 bytes
        multi_content = f1_content + f2_content + f3_content  # 72 bytes total

        piece_len = 36  # 2 peças de 36 bytes
        p0_hash = compute_sha1(multi_content[:36])
        p1_hash = compute_sha1(multi_content[36:])

        multi_info = {
            b"name": b"my_dataset",
            b"piece length": piece_len,
            b"pieces": p0_hash + p1_hash,
            b"files": [
                {b"length": 20, b"path": [b"docs", b"file1.txt"]},
                {b"length": 30, b"path": [b"docs", b"file2.txt"]},
                {b"length": 22, b"path": [b"bin", b"file3.bin"]},
            ],
        }
        multi_torrent_bytes = encode_bencode({
            b"announce": b"http://tracker.local:8080/announce",
            b"info": multi_info,
        })
        multi_meta = load_torrent_bytes(multi_torrent_bytes)

        s_client, s_server = socket.socketpair()

        peer_thread = threading.Thread(
            target=run_mock_peer_server,
            kwargs={
                "server_sock": s_server,
                "expected_info_hash": multi_meta.info_hash,
                "server_peer_id": b"-UT2210-peer12345678",
                "torrent_data": multi_content,
                "piece_length": piece_len,
            },
        )
        peer_thread.daemon = True
        peer_thread.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "output_root"

            client = TorrentClient(
                multi_meta,
                output_path=out_dir,
                block_size=16,
            )

            conn = PeerConnection(sock=s_client, default_timeout=5.0)
            conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

            success = client.download_from_peer_connection(conn)
            conn.close()

            all_data = client._finalize_download()
            self.assertTrue(success)
            self.assertEqual(all_data, multi_content)

            # Verifica se cada arquivo individual foi escrito na estrutura correta de diretórios
            base_dir = out_dir / "my_dataset"
            file1_path = base_dir / "docs" / "file1.txt"
            file2_path = base_dir / "docs" / "file2.txt"
            file3_path = base_dir / "bin" / "file3.bin"

            self.assertTrue(file1_path.exists())
            self.assertEqual(file1_path.read_bytes(), f1_content)

            self.assertTrue(file2_path.exists())
            self.assertEqual(file2_path.read_bytes(), f2_content)

            self.assertTrue(file3_path.exists())
            self.assertEqual(file3_path.read_bytes(), f3_content)

        peer_thread.join(timeout=2.0)

    def test_corrupted_piece_retry_and_recovery(self):
        """
        Testa recuperação automática quando um peer envia um bloco corrompido.
        O PieceManager descarta a peça, o TorrentClient re-solicita os blocos
        e conclui com sucesso quando o dado correto é entregue.
        """
        s_client, s_server = socket.socketpair()

        peer_thread = threading.Thread(
            target=run_mock_peer_server,
            kwargs={
                "server_sock": s_server,
                "expected_info_hash": self.single_torrent_meta.info_hash,
                "server_peer_id": b"-UT2210-peer12345678",
                "torrent_data": self.raw_file_content,
                "piece_length": self.piece_length,
                "corrupt_first_piece": True,  # Envia bloco inválido na 1ª tentativa
            },
        )
        peer_thread.daemon = True
        peer_thread.start()

        client = TorrentClient(
            self.single_torrent_meta,
            block_size=self.block_size,
        )

        conn = PeerConnection(sock=s_client, default_timeout=5.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # O ciclo deve re-solicitar a peça corrompida e concluir 100%
        success = client.download_from_peer_connection(conn)
        conn.close()

        self.assertTrue(success)
        self.assertTrue(client.is_complete)
        self.assertEqual(client.piece_manager.get_all_data(), self.raw_file_content)

        peer_thread.join(timeout=2.0)

    def test_choke_and_unchoke_during_download(self):
        """
        Testa comportamento quando o peer envia Choke inicialmente e depois Unchoke.
        """
        s_client, s_server = socket.socketpair()

        peer_thread = threading.Thread(
            target=run_mock_peer_server,
            kwargs={
                "server_sock": s_server,
                "expected_info_hash": self.single_torrent_meta.info_hash,
                "server_peer_id": b"-UT2210-peer12345678",
                "torrent_data": self.raw_file_content,
                "piece_length": self.piece_length,
                "choke_first": True,
            },
        )
        peer_thread.daemon = True
        peer_thread.start()

        client = TorrentClient(
            self.single_torrent_meta,
            block_size=self.block_size,
        )

        conn = PeerConnection(sock=s_client, default_timeout=5.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        success = client.download_from_peer_connection(conn)
        conn.close()

        self.assertTrue(success)
        self.assertTrue(client.is_complete)

        peer_thread.join(timeout=2.0)

    def test_discover_peers_success_and_error(self):
        # 1. Tracker retorna peers válidos
        peer_compact = socket.inet_aton("192.168.1.100") + struct.pack("!H", 6881)
        resp_bencoded = encode_bencode({b"interval": 900, b"peers": peer_compact})

        def mock_opener_ok(req, timeout=15.0):
            return MockHTTPResponse(resp_bencoded)

        client = TorrentClient(self.single_torrent_meta, http_opener=mock_opener_ok)
        peers = client.discover_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].ip, "192.168.1.100")
        self.assertEqual(peers[0].port, 6881)

        # 2. Tracker retorna erro
        fail_bencoded = encode_bencode({b"failure reason": b"unregistered torrent"})

        def mock_opener_fail(req, timeout=15.0):
            return MockHTTPResponse(fail_bencoded)

        client_fail = TorrentClient(self.single_torrent_meta, http_opener=mock_opener_fail)
        with self.assertRaises(DownloadError):
            client_fail.discover_peers()

    def test_download_incomplete_error(self):
        # Nenhum peer disponível
        client = TorrentClient(self.single_torrent_meta)
        with self.assertRaises(DownloadError):
            client.download(peers=[])

    def test_client_stop_signal(self):
        client = TorrentClient(self.single_torrent_meta)
        self.assertFalse(client._stop_requested)
        client.stop()
        self.assertTrue(client._stop_requested)


if __name__ == "__main__":
    unittest.main()
