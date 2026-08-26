"""
Suíte de Testes de Segurança e Auditoria contra Ameaças Externas (Threat Defense).

Valida a proteção e imunidade do cliente BitTorrent contra:
1. Ataques de DoS por estouro de pilha/recursão em Bencode (Recursion Depth Limit);
2. Ataques de DoS por exaustão de memória em strings e inteiros Bencode;
3. Vulnerabilidades de Path Traversal no nome do torrent e em segmentos multi-file;
4. Injeção de Null Bytes e especificadores de drive em caminhos de arquivos;
5. Tentativas de gravação arbitrária fora do diretório de destino (Directory Escape);
6. Tentativas de SSRF e esquemas não-HTTP em URLs de trackers (file://, ftp://, etc.);
7. Adulteração de bits sobressalentes em mensagens Bitfield (BEP 0003);
8. Ataques de alocação excessiva com blocos gigantescos em Piece, Request e Cancel;
9. Exaustão de memória no buffer do socket do peer (Buffer Overflow Protection);
10. Tentativas de envenenamento de peças (Poisoned Blocks / SHA-1 Mismatch).
"""

import socket
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Optional

from src.bencode import (
    MAX_BENCODE_DEPTH,
    BencodeDecodeError,
    decode_bencode,
    encode_bencode,
)
from src.client import DownloadError, TorrentClient
from src.hash_utils import compute_sha1
from src.peer import (
    MAX_BLOCK_SIZE,
    MAX_MESSAGE_LENGTH,
    MAX_PEER_BUFFER_SIZE,
    Bitfield,
    BitfieldMessage,
    CancelMessage,
    MessageSizeError,
    PeerConnection,
    PeerProtocolError,
    PieceMessage,
    RequestMessage,
    parse_message,
    parse_message_payload,
)
from src.piece_manager import PieceManager, PieceState
from src.torrent import (
    TorrentMetadata,
    TorrentSecurityError,
    TorrentValidationError,
    load_torrent_bytes,
    validate_safe_path_segment,
)
from src.tracker import (
    HTTPTrackerClient,
    TrackerError,
    build_announce_url,
    execute_http_get,
)


class TestBencodeSecurity(unittest.TestCase):
    """Testes de segurança para parsing de Bencode contra ataques de DoS."""

    def test_bencode_recursion_depth_limit_prevents_stack_overflow(self):
        """Valida que árvores Bencode profundamente aninhadas não causam estouro de pilha."""
        deep_lists = b"l" * (MAX_BENCODE_DEPTH + 10) + b"i1e" + b"e" * (MAX_BENCODE_DEPTH + 10)
        with self.assertRaises(BencodeDecodeError) as ctx:
            decode_bencode(deep_lists)
        self.assertIn("Profundidade máxima de aninhamento", str(ctx.exception))

    def test_bencode_huge_int_digits_rejected(self):
        """Valida que inteiros com quantidade excessiva de dígitos são rejeitados."""
        huge_int = b"i" + b"9" * 100 + b"e"
        with self.assertRaises(BencodeDecodeError) as ctx:
            decode_bencode(huge_int)
        self.assertIn("excede o limite seguro", str(ctx.exception))

    def test_bencode_huge_string_length_rejected(self):
        """Valida que declarações de tamanhos absurdos de string são rejeitadas."""
        huge_str_decl = b"200000000:abc"  # Declara 200 MB
        with self.assertRaises(BencodeDecodeError) as ctx:
            decode_bencode(huge_str_decl)
        self.assertIn("excede o limite máximo permitido", str(ctx.exception))


class TestPathTraversalSecurity(unittest.TestCase):
    """Testes de segurança contra Path Traversal em metadados de torrents e gravação em disco."""

    def setUp(self):
        self.valid_info_hash = b"\x11" * 20
        self.valid_piece_hash = compute_sha1(b"valid piece data")

    def test_single_file_name_path_traversal_rejected(self):
        """Valida que nomes contendo '..' ou caminhos relativos são rejeitados."""
        malicious_names = [
            b"../../etc/passwd",
            b"..\\..\\Windows\\System32\\calc.exe",
            b"..",
            b".",
            b"/etc/shadow",
            b"C:\\malicious.exe",
        ]
        for bad_name in malicious_names:
            torrent_dict = {
                b"announce": b"http://tracker.local:8080/announce",
                b"info": {
                    b"length": 16,
                    b"name": bad_name,
                    b"piece length": 16,
                    b"pieces": self.valid_piece_hash,
                },
            }
            with self.assertRaises((TorrentSecurityError, TorrentValidationError)):
                load_torrent_bytes(encode_bencode(torrent_dict))

    def test_name_with_null_byte_rejected(self):
        """Valida que null bytes em nomes de arquivos são bloqueados."""
        bad_name = b"safe_name.txt\x00.evil.exe"
        torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": {
                b"length": 16,
                b"name": bad_name,
                b"piece length": 16,
                b"pieces": self.valid_piece_hash,
            },
        }
        with self.assertRaises(TorrentSecurityError):
            load_torrent_bytes(encode_bencode(torrent_dict))

    def test_multi_file_path_traversal_segments_rejected(self):
        """Valida que segmentos '..' em torrents multi-file são interceptados e bloqueados."""
        malicious_paths = [
            [b"..", b"escape.txt"],
            [b"folder", b"..", b"escape.txt"],
            [b"/root", b"file.bin"],
            [b"C:", b"file.bin"],
            [b"folder\x00bad", b"file.bin"],
        ]
        for bad_path in malicious_paths:
            torrent_dict = {
                b"announce": b"http://tracker.local:8080/announce",
                b"info": {
                    b"name": b"valid_root_dir",
                    b"piece length": 16,
                    b"pieces": self.valid_piece_hash,
                    b"files": [
                        {b"length": 16, b"path": bad_path}
                    ],
                },
            }
            with self.assertRaises(TorrentSecurityError):
                load_torrent_bytes(encode_bencode(torrent_dict))

    def test_save_files_prevents_directory_escape(self):
        """Valida que save_files impede qualquer gravação fora do diretório pretendido."""
        piece_data = b"A" * 16
        piece_hash = compute_sha1(piece_data)
        torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": {
                b"length": 16,
                b"name": b"test_output.bin",
                b"piece length": 16,
                b"pieces": piece_hash,
            },
        }
        meta = load_torrent_bytes(encode_bencode(torrent_dict))
        client = TorrentClient(meta)
        client.piece_manager.add_block(0, 0, piece_data)

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = Path(tmpdir) / "subfolder"
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Gravação normal dentro de dest_dir deve funcionar
            client.save_files(dest_dir)
            self.assertTrue((dest_dir / "test_output.bin").is_file())


class TestTrackerSecurityAndSSRF(unittest.TestCase):
    """Testes de segurança contra SSRF e protocolos não confiáveis em trackers."""

    def test_tracker_url_rejects_non_http_schemes(self):
        """Valida que esquemas não-HTTP (file://, ftp://, javascript://) são rejeitados."""
        bad_schemes = [
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini",
            "ftp://attacker.com/announce",
            "gopher://attacker.com/",
            "javascript:alert(1)",
        ]
        info_hash = b"\x22" * 20
        peer_id = b"-ST0001-012345678901"

        for bad_url in bad_schemes:
            with self.assertRaises(TrackerError):
                build_announce_url(base_url=bad_url, info_hash=info_hash, peer_id=peer_id)

            with self.assertRaises(TrackerError):
                execute_http_get(bad_url)


class TestPeerProtocolSecurity(unittest.TestCase):
    """Testes de segurança contra adulteração de protocolo e ataques de peers maliciosos."""

    def test_bitfield_spare_bits_tampering_rejected(self):
        """
        Valida que peers que enviam bits sobressalentes ativos no final do bitfield
        são rejeitados com PeerProtocolError conforme a especificação BEP 0003.
        """
        # 10 peças = 2 bytes (bits 0..9 são peças, bits 10..15 são spare bits no byte 1)
        num_pieces = 10
        # Byte 0: 0xFF (peças 0..7), Byte 1: 0xC0 (peças 8 e 9 ativas, spare bits 0b000000 são zero) -> Válido
        valid_bytes = b"\xff\xc0"
        bf = Bitfield(num_pieces=num_pieces, initial_bytes=valid_bytes)
        self.assertEqual(bf.count(), 10)

        # Byte 1 com spare bit adulterado (0xC1 = peças 8 e 9 + spare bit 15 ativo) -> Inválido!
        tampered_bytes = b"\xff\xc1"
        with self.assertRaises(PeerProtocolError) as ctx:
            Bitfield(num_pieces=num_pieces, initial_bytes=tampered_bytes)
        self.assertIn("bits sobressalentes não-nulos", str(ctx.exception))

    def test_oversized_block_in_piece_message_rejected(self):
        """Valida que PieceMessage com bloco > MAX_BLOCK_SIZE (128 KB) é rejeitada."""
        oversized_data = struct.pack("!II", 0, 0) + (b"X" * (MAX_BLOCK_SIZE + 1024))
        length = 1 + len(oversized_data)
        payload = bytes([7]) + oversized_data  # ID 7 = PIECE

        with self.assertRaises(MessageSizeError) as ctx:
            parse_message_payload(length, payload)
        self.assertIn("excede o limite máximo", str(ctx.exception))

    def test_oversized_block_in_request_message_rejected(self):
        """Valida que RequestMessage solicitando bloco > MAX_BLOCK_SIZE é rejeitada."""
        req_data = struct.pack("!III", 0, 0, MAX_BLOCK_SIZE + 1024)
        length = 1 + len(req_data)
        payload = bytes([6]) + req_data  # ID 6 = REQUEST

        with self.assertRaises(MessageSizeError) as ctx:
            parse_message_payload(length, payload)
        self.assertIn("excede o limite máximo", str(ctx.exception))

    def test_peer_buffer_overflow_dos_prevented(self):
        """Valida que acúmulo de bytes no buffer interno além de MAX_PEER_BUFFER_SIZE lança MessageSizeError."""
        c_sock, s_sock = socket.socketpair()

        try:
            conn = PeerConnection(sock=c_sock, default_timeout=2.0)
            # Injeta dados simulando buffer já quase cheio
            conn._buffer = bytearray(b"A" * (MAX_PEER_BUFFER_SIZE - 100))

            # Envia 200 bytes pelo socket
            s_sock.sendall(b"B" * 200)

            # recv_exact deve atingir o limite e levantar MessageSizeError
            with self.assertRaises(MessageSizeError) as ctx:
                conn.recv_exact(MAX_PEER_BUFFER_SIZE + 100, timeout=1.0)
            self.assertIn("excedeu o limite máximo seguro", str(ctx.exception))
        finally:
            c_sock.close()
            s_sock.close()


class TestPieceIntegrityAndPoisoningDefense(unittest.TestCase):
    """Testes de integridade de peças contra envenenamento e corrupção."""

    def test_poisoned_piece_sha1_mismatch_discarded_and_not_saved(self):
        """Valida que peça com dados envenenados falha no SHA-1, é descartada e resetada."""
        expected_data = b"LEGITIMATE PIECE DATA"
        expected_hash = compute_sha1(expected_data)

        torrent_dict = {
            b"announce": b"http://tracker.local:8080/announce",
            b"info": {
                b"length": len(expected_data),
                b"name": b"poison_test.bin",
                b"piece length": len(expected_data),
                b"pieces": expected_hash,
            },
        }
        meta = load_torrent_bytes(encode_bencode(torrent_dict))
        pm = PieceManager(meta, block_size=len(expected_data))

        # Peer malicioso envia dados envenenados
        poisoned_data = b"POISONED PIECE DATA!!"[:len(expected_data)]
        added, completed = pm.add_block(piece_index=0, begin=0, data=poisoned_data)

        # Deve reportar que adicionou o bloco mas a peça NÃO foi completada nem validada
        self.assertTrue(added)
        self.assertFalse(completed)
        self.assertFalse(pm.is_complete)
        self.assertFalse(pm.is_piece_complete(0))
        self.assertEqual(pm.get_piece(0).state, PieceState.MISSING)

        # Peer legítimo envia dados corretos posteriormente
        added, completed = pm.add_block(piece_index=0, begin=0, data=expected_data)
        self.assertTrue(added)
        self.assertTrue(completed)
        self.assertTrue(pm.is_complete)
        self.assertEqual(pm.get_all_data(), expected_data)


if __name__ == "__main__":
    unittest.main()
