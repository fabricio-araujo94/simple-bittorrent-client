"""
Testes unitários abrangentes para a camada de protocolo de peers (Peer Wire Protocol - BEP 0003).

Cobre:
- Montagem, envio e validação do Handshake de 68 bytes;
- Codificação e decodificação precisa de todas as mensagens padrão (KeepAlive, Choke, Unchoke,
  Interested, NotInterested, Have, Bitfield, Request, Piece, Cancel, Port);
- Tratamento e manipulação de Bitfield por índice de bits e bytes;
- Proteção contra mensagens truncadas, malformadas e tamanhos excessivos (DoS);
- Parsing de streams com mensagens fragmentadas e múltiplas mensagens no mesmo buffer;
- Testes com sockets reais usando socket.socketpair() simulando fragmentação byte a byte,
  packet coalescing, timeouts de leitura/escrita e desconexões prematuras (EOF).
"""

import socket
import struct
import time
import unittest
from typing import List

from src.peer import (
    DEFAULT_BLOCK_SIZE,
    HANDSHAKE_LENGTH,
    HANDSHAKE_PSTR,
    HANDSHAKE_PSTRLEN,
    MAX_MESSAGE_LENGTH,
    Bitfield,
    BitfieldMessage,
    CancelMessage,
    ChokeMessage,
    Handshake,
    HandshakeError,
    HaveMessage,
    InterestedMessage,
    KeepAliveMessage,
    MessageID,
    MessageSizeError,
    NotInterestedMessage,
    PeerConnection,
    PeerConnectionClosedError,
    PeerConnectionError,
    PeerProtocolError,
    PeerTimeoutError,
    PieceMessage,
    PortMessage,
    RequestMessage,
    UnchokeMessage,
    UnknownMessage,
    encode_bitfield,
    encode_cancel,
    encode_choke,
    encode_handshake,
    encode_have,
    encode_interested,
    encode_keep_alive,
    encode_message,
    encode_not_interested,
    encode_piece,
    encode_port,
    encode_request,
    encode_unchoke,
    parse_handshake,
    parse_message,
    parse_message_payload,
    parse_messages_from_buffer,
)


class TestHandshake(unittest.TestCase):
    """Testes para codificação, decodificação e validação do Handshake de 68 bytes."""

    def setUp(self):
        self.info_hash = b"\x12" * 20
        self.peer_id = b"-ST0001-abcdefghijkl"
        self.reserved = b"\x00" * 8

    def test_encode_handshake_structure(self):
        encoded = encode_handshake(
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            reserved=self.reserved,
        )
        self.assertEqual(len(encoded), 68)
        self.assertEqual(encoded[0], 19)
        self.assertEqual(encoded[1:20], b"BitTorrent protocol")
        self.assertEqual(encoded[20:28], b"\x00" * 8)
        self.assertEqual(encoded[28:48], self.info_hash)
        self.assertEqual(encoded[48:68], self.peer_id)

    def test_handshake_dataclass_encode(self):
        hs = Handshake(info_hash=self.info_hash, peer_id=self.peer_id)
        self.assertEqual(hs.encode(), encode_handshake(self.info_hash, self.peer_id))

    def test_parse_valid_handshake(self):
        raw = encode_handshake(self.info_hash, self.peer_id, reserved=b"\x01" * 8)
        hs = parse_handshake(raw)
        self.assertEqual(hs.info_hash, self.info_hash)
        self.assertEqual(hs.peer_id, self.peer_id)
        self.assertEqual(hs.reserved, b"\x01" * 8)
        self.assertEqual(hs.pstr, b"BitTorrent protocol")

    def test_parse_handshake_with_expected_matching(self):
        raw = encode_handshake(self.info_hash, self.peer_id)
        hs = parse_handshake(
            raw,
            expected_info_hash=self.info_hash,
            expected_peer_id=self.peer_id,
        )
        self.assertEqual(hs.info_hash, self.info_hash)
        self.assertEqual(hs.peer_id, self.peer_id)

    def test_parse_handshake_validation_errors(self):
        valid_raw = encode_handshake(self.info_hash, self.peer_id)

        # Tamanho inválido (< 68 bytes ou > 68 bytes)
        with self.assertRaises(HandshakeError):
            parse_handshake(valid_raw[:60])
        with self.assertRaises(HandshakeError):
            parse_handshake(valid_raw + b"\x00")

        # pstrlen inválido (!= 19)
        bad_pstrlen = b"\x14" + valid_raw[1:]
        with self.assertRaises(HandshakeError):
            parse_handshake(bad_pstrlen)

        # pstr inválido
        bad_pstr = valid_raw[:1] + b"WrongProtoProtocol!" + valid_raw[20:]
        with self.assertRaises(HandshakeError):
            parse_handshake(bad_pstr)

        # info_hash divergente
        with self.assertRaises(HandshakeError) as ctx:
            parse_handshake(valid_raw, expected_info_hash=b"\x99" * 20)
        self.assertIn("info_hash divergente", str(ctx.exception))

        # peer_id divergente
        with self.assertRaises(HandshakeError) as ctx:
            parse_handshake(valid_raw, expected_peer_id=b"-XX0000-000000000000")
        self.assertIn("peer_id divergente", str(ctx.exception))

    def test_handshake_invalid_inputs(self):
        with self.assertRaises(ValueError):
            Handshake(info_hash=b"curto", peer_id=self.peer_id)
        with self.assertRaises(ValueError):
            Handshake(info_hash=self.info_hash, peer_id=b"curto")
        with self.assertRaises(ValueError):
            Handshake(info_hash=self.info_hash, peer_id=self.peer_id, reserved=b"curto")
        with self.assertRaises(ValueError):
            Handshake(info_hash=self.info_hash, peer_id=self.peer_id, pstr=b"wrong")


class TestBitfield(unittest.TestCase):
    """Testes para manipulação precisa da estrutura de Bitfield."""

    def test_bitfield_manipulation(self):
        # 10 peças -> 2 bytes necessários (16 bits, 6 spare bits)
        bf = Bitfield(num_pieces=10)
        self.assertEqual(len(bf.to_bytes()), 2)
        self.assertEqual(bf.count(), 0)
        self.assertFalse(bf.is_complete)

        # Seta peças 0, 7, 8
        # Peça 0: byte 0, bit 7 (0x80)
        # Peça 7: byte 0, bit 0 (0x01) -> byte 0 = 0x81
        # Peça 8: byte 1, bit 7 (0x80) -> byte 1 = 0x80
        bf.set_piece(0, True)
        bf.set_piece(7, True)
        bf.set_piece(8, True)

        self.assertTrue(bf.has_piece(0))
        self.assertTrue(bf.has_piece(7))
        self.assertTrue(bf.has_piece(8))
        self.assertFalse(bf.has_piece(1))
        self.assertFalse(bf.has_piece(9))
        self.assertEqual(bf.count(), 3)
        self.assertEqual(bf.to_bytes(), bytes([0x81, 0x80]))

        # Limpa peça 0
        bf.set_piece(0, False)
        self.assertFalse(bf.has_piece(0))
        self.assertEqual(bf.count(), 2)
        self.assertEqual(bf.to_bytes(), bytes([0x01, 0x80]))

    def test_bitfield_from_bytes(self):
        raw = bytes([0b11110000, 0b10000000])
        bf = Bitfield.from_bytes(raw, num_pieces=9)
        self.assertEqual(bf.num_pieces, 9)
        self.assertTrue(bf.has_piece(0))
        self.assertTrue(bf.has_piece(1))
        self.assertTrue(bf.has_piece(2))
        self.assertTrue(bf.has_piece(3))
        self.assertFalse(bf.has_piece(4))
        self.assertTrue(bf.has_piece(8))
        self.assertEqual(bf.count(), 5)

    def test_bitfield_out_of_bounds(self):
        bf = Bitfield(num_pieces=5)
        with self.assertRaises(IndexError):
            bf.has_piece(-1)
        with self.assertRaises(IndexError):
            bf.has_piece(5)
        with self.assertRaises(IndexError):
            bf.set_piece(5)


class TestMessageEncodingAndParsing(unittest.TestCase):
    """Testes para codificação, decodificação e round-trip de todas as mensagens."""

    def test_keep_alive_message(self):
        msg = KeepAliveMessage()
        encoded = msg.encode()
        self.assertEqual(encoded, b"\x00\x00\x00\x00")
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, KeepAliveMessage)

    def test_choke_message(self):
        msg = ChokeMessage()
        encoded = msg.encode()
        self.assertEqual(encoded, b"\x00\x00\x00\x01\x00")
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, ChokeMessage)
        self.assertEqual(parsed.msg_id, MessageID.CHOKE)

    def test_unchoke_message(self):
        msg = UnchokeMessage()
        encoded = msg.encode()
        self.assertEqual(encoded, b"\x00\x00\x00\x01\x01")
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, UnchokeMessage)
        self.assertEqual(parsed.msg_id, MessageID.UNCHOKE)

    def test_interested_message(self):
        msg = InterestedMessage()
        encoded = msg.encode()
        self.assertEqual(encoded, b"\x00\x00\x00\x01\x02")
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, InterestedMessage)
        self.assertEqual(parsed.msg_id, MessageID.INTERESTED)

    def test_not_interested_message(self):
        msg = NotInterestedMessage()
        encoded = msg.encode()
        self.assertEqual(encoded, b"\x00\x00\x00\x01\x03")
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, NotInterestedMessage)
        self.assertEqual(parsed.msg_id, MessageID.NOT_INTERESTED)

    def test_have_message(self):
        msg = HaveMessage(piece_index=42)
        encoded = msg.encode()
        expected = struct.pack("!IBI", 5, 4, 42)
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, HaveMessage)
        self.assertEqual(parsed.piece_index, 42)

    def test_bitfield_message(self):
        bf_bytes = bytes([0xFF, 0x80])
        msg = BitfieldMessage(bitfield=bf_bytes)
        encoded = msg.encode()
        expected = struct.pack("!IB", 3, 5) + bf_bytes
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, BitfieldMessage)
        self.assertEqual(parsed.bitfield, bf_bytes)
        bf_obj = parsed.to_bitfield(num_pieces=9)
        self.assertTrue(bf_obj.has_piece(0))
        self.assertTrue(bf_obj.has_piece(8))

    def test_request_message(self):
        msg = RequestMessage(index=3, begin=16384, length=16384)
        encoded = msg.encode()
        expected = struct.pack("!IBIII", 13, 6, 3, 16384, 16384)
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, RequestMessage)
        self.assertEqual(parsed.index, 3)
        self.assertEqual(parsed.begin, 16384)
        self.assertEqual(parsed.length, 16384)

    def test_piece_message(self):
        block_data = b"BLOCK_CONTENT_12345678"
        msg = PieceMessage(index=5, begin=32768, block=block_data)
        encoded = msg.encode()
        expected = struct.pack("!IBII", 9 + len(block_data), 7, 5, 32768) + block_data
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, PieceMessage)
        self.assertEqual(parsed.index, 5)
        self.assertEqual(parsed.begin, 32768)
        self.assertEqual(parsed.block, block_data)

    def test_cancel_message(self):
        msg = CancelMessage(index=2, begin=0, length=16384)
        encoded = msg.encode()
        expected = struct.pack("!IBIII", 13, 8, 2, 0, 16384)
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, CancelMessage)
        self.assertEqual(parsed.index, 2)
        self.assertEqual(parsed.begin, 0)
        self.assertEqual(parsed.length, 16384)

    def test_port_message(self):
        msg = PortMessage(listen_port=6881)
        encoded = msg.encode()
        expected = struct.pack("!IBH", 3, 9, 6881)
        self.assertEqual(encoded, expected)
        parsed = parse_message(encoded)
        self.assertIsInstance(parsed, PortMessage)
        self.assertEqual(parsed.listen_port, 6881)

    def test_unknown_message(self):
        # Mensagem com ID não-padrão (ex: ID 99)
        payload = bytes([99, 1, 2, 3])
        length = len(payload)
        raw = struct.pack("!I", length) + payload
        parsed = parse_message(raw)
        self.assertIsInstance(parsed, UnknownMessage)
        self.assertEqual(parsed.msg_id, 99)
        self.assertEqual(parsed.payload, b"\x01\x02\x03")


class TestMessageValidationAndErrors(unittest.TestCase):
    """Testes para rejeição de mensagens com tamanhos ou estruturas inválidas."""

    def test_buffer_too_short_for_length_prefix(self):
        with self.assertRaises(PeerProtocolError):
            parse_message(b"\x00\x00\x01")  # Apenas 3 bytes

    def test_payload_length_mismatch(self):
        # Prefix diz length=10, mas só fornece 4 bytes
        bad_msg = struct.pack("!I", 10) + b"\x00\x01\x02\x03"
        with self.assertRaises(PeerProtocolError):
            parse_message(bad_msg)

    def test_choke_with_extra_payload(self):
        bad_choke = struct.pack("!IBB", 2, MessageID.CHOKE, 0xFF)
        with self.assertRaises(MessageSizeError):
            parse_message(bad_choke)

    def test_have_with_invalid_length(self):
        # Have precisa de 4 bytes de índice (length=5)
        bad_have = struct.pack("!IB", 1, MessageID.HAVE)
        with self.assertRaises(MessageSizeError):
            parse_message(bad_have)

    def test_request_with_invalid_length(self):
        bad_request = struct.pack("!IBI", 5, MessageID.REQUEST, 0)
        with self.assertRaises(MessageSizeError):
            parse_message(bad_request)

    def test_piece_with_invalid_length(self):
        bad_piece = struct.pack("!IBI", 5, MessageID.PIECE, 0)
        with self.assertRaises(MessageSizeError):
            parse_message(bad_piece)

    def test_message_dataclass_validation(self):
        with self.assertRaises(ValueError):
            HaveMessage(piece_index=-1)
        with self.assertRaises(ValueError):
            RequestMessage(index=-1, begin=0, length=100)
        with self.assertRaises(ValueError):
            RequestMessage(index=0, begin=0, length=0)  # length zero
        with self.assertRaises(ValueError):
            PortMessage(listen_port=0)
        with self.assertRaises(ValueError):
            PortMessage(listen_port=70000)


class TestBufferStreamParsing(unittest.TestCase):
    """Testes para parsing contínuo a partir de streams/buffers mutáveis."""

    def test_parse_multiple_messages_in_buffer(self):
        m1 = ChokeMessage().encode()
        m2 = HaveMessage(piece_index=7).encode()
        m3 = UnchokeMessage().encode()
        m4 = KeepAliveMessage().encode()

        buffer = bytearray(m1 + m2 + m3 + m4)
        messages = parse_messages_from_buffer(buffer)

        self.assertEqual(len(messages), 4)
        self.assertIsInstance(messages[0], ChokeMessage)
        self.assertIsInstance(messages[1], HaveMessage)
        self.assertEqual(messages[1].piece_index, 7)
        self.assertIsInstance(messages[2], UnchokeMessage)
        self.assertIsInstance(messages[3], KeepAliveMessage)
        self.assertEqual(len(buffer), 0)

    def test_parse_fragmented_message_in_buffer(self):
        m1 = InterestedMessage().encode()  # 5 bytes
        m2_full = RequestMessage(index=1, begin=0, length=16384).encode()  # 17 bytes

        # Coloca m1 inteira e metade de m2 no buffer
        buffer = bytearray(m1 + m2_full[:10])
        messages = parse_messages_from_buffer(buffer)

        self.assertEqual(len(messages), 1)
        self.assertIsInstance(messages[0], InterestedMessage)
        # O fragmento de 10 bytes de m2 deve permanecer no buffer intacto
        self.assertEqual(len(buffer), 10)

        # Adiciona o restante de m2
        buffer.extend(m2_full[10:])
        messages2 = parse_messages_from_buffer(buffer)
        self.assertEqual(len(messages2), 1)
        self.assertIsInstance(messages2[0], RequestMessage)
        self.assertEqual(len(buffer), 0)

    def test_buffer_message_size_exceeded(self):
        huge_len_header = struct.pack("!I", MAX_MESSAGE_LENGTH + 1)
        buffer = bytearray(huge_len_header + b"\x00" * 10)
        with self.assertRaises(MessageSizeError):
            parse_messages_from_buffer(buffer)


class TestPeerConnectionWithSocketpair(unittest.TestCase):
    """Testes de integração de rede usando socket.socketpair()."""

    def setUp(self):
        self.s_client, self.s_server = socket.socketpair()
        self.info_hash = b"\xaa" * 20
        self.client_peer_id = b"-ST0001-client123456"
        self.server_peer_id = b"-UT2210-server123456"

    def tearDown(self):
        self.s_client.close()
        self.s_server.close()

    def test_handshake_exchange(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0)

        # Servidor envia seu handshake
        server_hs_bytes = encode_handshake(self.info_hash, self.server_peer_id)
        self.s_server.sendall(server_hs_bytes)

        # Cliente executa handshake
        handshake = conn.perform_handshake(
            info_hash=self.info_hash,
            peer_id=self.client_peer_id,
            expected_peer_id=self.server_peer_id,
        )

        self.assertEqual(handshake.info_hash, self.info_hash)
        self.assertEqual(handshake.peer_id, self.server_peer_id)

        # Servidor lê o handshake enviado pelo cliente
        received_by_server = self.s_server.recv(68)
        self.assertEqual(len(received_by_server), 68)
        server_parsed = parse_handshake(received_by_server)
        self.assertEqual(server_parsed.peer_id, self.client_peer_id)

    def test_fragmented_delivery(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0)

        # Monta mensagem Piece de 100 bytes
        block = b"X" * 100
        piece_msg = PieceMessage(index=2, begin=0, block=block).encode()

        # Envia 1 byte por vez para testar fragmentação extrema
        for b in piece_msg:
            self.s_server.sendall(bytes([b]))

        # Cliente deve remontar e decodificar com perfeição
        msg = conn.read_message()
        self.assertIsInstance(msg, PieceMessage)
        self.assertEqual(msg.index, 2)
        self.assertEqual(msg.begin, 0)
        self.assertEqual(msg.block, block)

    def test_packet_coalescing_multiple_messages_in_one_read(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0)

        m1 = UnchokeMessage().encode()
        m2 = HaveMessage(piece_index=99).encode()
        m3 = KeepAliveMessage().encode()

        # Envia todas de uma vez em um único pacote TCP
        self.s_server.sendall(m1 + m2 + m3)

        # Lê mensagens sequencialmente
        r1 = conn.read_message()
        self.assertIsInstance(r1, UnchokeMessage)
        self.assertFalse(conn.peer_choking)

        r2 = conn.read_message()
        self.assertIsInstance(r2, HaveMessage)
        self.assertEqual(r2.piece_index, 99)

        r3 = conn.read_message()
        self.assertIsInstance(r3, KeepAliveMessage)

    def test_state_tracking_and_helpers(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0, num_pieces=8)

        # Estado inicial
        self.assertTrue(conn.am_choking)
        self.assertFalse(conn.am_interested)
        self.assertTrue(conn.peer_choking)
        self.assertFalse(conn.peer_interested)

        # Cliente envia unchoke e interested
        conn.send_unchoke()
        self.assertFalse(conn.am_choking)

        conn.send_interested()
        self.assertTrue(conn.am_interested)

        # Servidor lê e valida
        data = self.s_server.recv(1024)
        self.assertEqual(data, UnchokeMessage().encode() + InterestedMessage().encode())

        # Servidor envia bitfield (8 peças: 11000000 -> peças 0 e 1)
        bf_msg = BitfieldMessage(bitfield=bytes([0b11000000])).encode()
        self.s_server.sendall(bf_msg)

        msg = conn.read_message()
        self.assertIsInstance(msg, BitfieldMessage)
        self.assertIsNotNone(conn.peer_bitfield)
        self.assertTrue(conn.peer_bitfield.has_piece(0))
        self.assertTrue(conn.peer_bitfield.has_piece(1))
        self.assertFalse(conn.peer_bitfield.has_piece(2))

        # Servidor envia have para peça 2
        self.s_server.sendall(HaveMessage(piece_index=2).encode())
        msg_have = conn.read_message()
        self.assertIsInstance(msg_have, HaveMessage)
        self.assertTrue(conn.peer_bitfield.has_piece(2))

    def test_bitfield_rejects_nonzero_spare_bits(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0, num_pieces=10)

        # Para 10 peças, os 6 bits inferiores do segundo byte são sobressalentes.
        invalid_bitfield = BitfieldMessage(bitfield=bytes([0x00, 0x01])).encode()
        self.s_server.sendall(invalid_bitfield)

        with self.assertRaises(PeerProtocolError):
            conn.read_message()

    def test_connection_closed_raises_error(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=5.0)

        # Fecha o lado do servidor
        self.s_server.close()

        with self.assertRaises(PeerConnectionClosedError):
            conn.recv_exact(10)

    def test_timeout_raises_error(self):
        conn = PeerConnection(sock=self.s_client, default_timeout=0.05)

        # Nenhum dado enviado pelo servidor -> deve estourar o timeout rápido
        with self.assertRaises(PeerTimeoutError):
            conn.read_message()

    def test_context_manager(self):
        with PeerConnection(sock=self.s_client) as conn:
            self.assertTrue(conn.is_connected)
        self.assertFalse(conn.is_connected)


if __name__ == "__main__":
    unittest.main()
