"""
Testes dedicados para a estratégia Rarest First (BEP 0003) no PieceManager e TorrentClient.

Cobre:
1. Peças raras recebem prioridade de seleção sobre peças comuns;
2. Peças já concluídas são ignoradas e não são selecionadas;
3. Mensagens HAVE incrementam a disponibilidade de peças individuais;
4. Entrada de novos peers (Bitfield) incrementa a disponibilidade das peças possuídas;
5. Saída/desconexão de peers decrementa a disponibilidade das peças possuídas;
6. Tratamento de empates entre peças com mesma disponibilidade (desempate determinístico por menor índice e prioridade para peças em DOWNLOADING);
7. Teste de integração de ponta a ponta com múltiplos peers onde a ordem de requisição segue estritamente a raridade.
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
    """Testes unitários da lógica Rarest First no PieceManager."""

    def setUp(self):
        # 5 peças (0, 1, 2, 3, 4) de 16.384 bytes cada
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
        """Verifica se a disponibilidade inicial de todas as peças é 0."""
        self.assertEqual(self.pm.get_all_availabilities(), [0, 0, 0, 0, 0])
        for i in range(self.num_pieces):
            self.assertEqual(self.pm.get_piece_availability(i), 0)

    def test_new_peers_alter_availability(self):
        """Testa se a entrada de novos peers com bitfields atualiza a disponibilidade das peças."""
        # Peer 1 possui peças {0, 2, 4}
        bf1 = Bitfield(num_pieces=self.num_pieces)
        bf1.set_piece(0, True)
        bf1.set_piece(2, True)
        bf1.set_piece(4, True)

        self.pm.add_peer_bitfield(bf1)
        self.assertEqual(self.pm.get_all_availabilities(), [1, 0, 1, 0, 1])

        # Peer 2 possui peças {0, 1, 2}
        bf2 = Bitfield(num_pieces=self.num_pieces)
        bf2.set_piece(0, True)
        bf2.set_piece(1, True)
        bf2.set_piece(2, True)

        self.pm.add_peer_bitfield(bf2)
        # Peça 0: 2 peers, Peça 1: 1 peer, Peça 2: 2 peers, Peça 3: 0 peers, Peça 4: 1 peer
        self.assertEqual(self.pm.get_all_availabilities(), [2, 1, 2, 0, 1])

    def test_peer_disconnect_alters_availability(self):
        """Testa se a desconexão de um peer reduz a disponibilidade de suas peças."""
        bf1 = Bitfield(num_pieces=self.num_pieces)
        bf1.set_piece(0, True)
        bf1.set_piece(1, True)

        bf2 = Bitfield(num_pieces=self.num_pieces)
        bf2.set_piece(1, True)
        bf2.set_piece(2, True)

        self.pm.add_peer_bitfield(bf1)
        self.pm.add_peer_bitfield(bf2)
        self.assertEqual(self.pm.get_all_availabilities(), [1, 2, 1, 0, 0])

        # Peer 1 desconecta
        self.pm.remove_peer_bitfield(bf1)
        self.assertEqual(self.pm.get_all_availabilities(), [0, 1, 1, 0, 0])

        # Peer 2 desconecta
        self.pm.remove_peer_bitfield(bf2)
        self.assertEqual(self.pm.get_all_availabilities(), [0, 0, 0, 0, 0])

    def test_have_alters_availability(self):
        """Testa se mensagens HAVE alteram a disponibilidade da peça."""
        self.assertEqual(self.pm.get_piece_availability(3), 0)

        # Peer A anuncia Have para peça 3
        self.pm.update_peer_have(3)
        self.assertEqual(self.pm.get_piece_availability(3), 1)

        # Peer B anuncia Have para peça 3
        self.pm.update_peer_have(3)
        self.assertEqual(self.pm.get_piece_availability(3), 2)

        # Peça 1 permanece 0
        self.assertEqual(self.pm.get_piece_availability(1), 0)

    def test_rare_pieces_receive_priority(self):
        """
        Testa se peças mais raras (menor disponibilidade) são selecionadas antes de peças comuns.
        Disponibilidades configuradas:
        - Peça 0: 3 peers (comum)
        - Peça 1: 1 peer  (RARA)
        - Peça 2: 2 peers (média)
        - Peça 3: 4 peers (muito comum)
        - Peça 4: 1 peer  (RARA)
        """
        # Configura bitfields simulando a contagem acima
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

        # Peer conectado possui todas as peças
        peer_bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            peer_bf.set_piece(i, True)

        # 1ª e 2ª solicitações: devem ser os 2 blocos da Peça 1 (Raridade = 1, menor índice que 4)
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req1, (1, 0, 8192))
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2, (1, 8192, 8192))

        # 3ª e 4ª solicitações: devem ser da Peça 4 (Raridade = 1)
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3, (4, 0, 8192))
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4, (4, 8192, 8192))

        # 5ª e 6ª solicitações: devem ser da Peça 2 (Raridade = 2)
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5, (2, 0, 8192))
        req6 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req6, (2, 8192, 8192))

        # 7ª e 8ª solicitações: devem ser da Peça 0 (Raridade = 3)
        req7 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req7, (0, 0, 8192))
        req8 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req8, (0, 8192, 8192))

        # 9ª e 10ª solicitações: devem ser da Peça 3 (Raridade = 4, a mais comum)
        req9 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req9, (3, 0, 8192))
        req10 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req10, (3, 8192, 8192))

        # Nenhum bloco restante
        req_none = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertIsNone(req_none)

    def test_completed_pieces_ignored(self):
        """Testa se peças que já foram baixadas e completadas são ignoradas."""
        # Peça 1 é a mais rara (disp=1), Peça 0 tem disp=2
        bf = Bitfield(num_pieces=self.num_pieces)
        bf.set_piece(0, True)
        self.pm.add_peer_bitfield(bf)
        bf_all = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf_all.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_all)

        # Disponibilidades: [2, 1, 1, 1, 1]
        # Completa a Peça 1 com dados válidos
        self.pm.add_block(1, 0, self.pieces_data[1][:8192])
        self.pm.add_block(1, 8192, self.pieces_data[1][8192:])
        self.assertTrue(self.pm.is_piece_complete(1))

        # Ao solicitar próximo bloco, a Peça 1 COMPLETED deve ser totalmente ignorada
        # e a próxima peça mais rara (Peça 2) deve ser selecionada
        req = self.pm.get_next_block_to_request(peer_bitfield=bf_all)
        self.assertIsNotNone(req)
        piece_idx, begin, _ = req
        self.assertNotEqual(piece_idx, 1)  # Peça 1 ignorada
        self.assertEqual(piece_idx, 2)     # Peça 2 selecionada

    def test_tie_breaking_deterministic_lowest_index(self):
        """
        Testa a estratégia de desempate:
        Quando múltiplas peças possuem a mesma raridade (ex: peças 1, 3, 4 todas com disp=1
        enquanto peças 0 e 2 possuem disp=2), o desempate determinístico deve selecionar
        na ordem crescente de índice (1, depois 3, depois 4).
        """
        # Base: todos têm disp=1
        bf_base = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf_base.set_piece(i, True)
        self.pm.add_peer_bitfield(bf_base)  # [1, 1, 1, 1, 1]

        # Peças 0 e 2 têm mais peers (disp=2), peças 1, 3, 4 permanecem as mais raras (disp=1)
        bf_extra = Bitfield(num_pieces=self.num_pieces)
        bf_extra.set_piece(0, True)
        bf_extra.set_piece(2, True)
        self.pm.add_peer_bitfield(bf_extra)  # [2, 1, 2, 1, 1]

        self.assertEqual(self.pm.get_all_availabilities(), [2, 1, 2, 1, 1])

        peer_bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            peer_bf.set_piece(i, True)

        # Entre as peças mais raras (1, 3, 4 com disp=1), a Peça 1 é a de menor índice
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req1[0], 1)
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2[0], 1)

        # Próxima mais rara deve ser a Peça 3 (3 < 4)
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3[0], 3)
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4[0], 3)

        # Próxima mais rara deve ser a Peça 4
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5[0], 4)

    def test_tie_breaking_downloading_state_priority(self):
        """
        Testa se peças que já estão em estado DOWNLOADING têm prioridade sobre peças MISSING,
        mesmo que possuam a mesma disponibilidade, para concluir blocos e liberar memória.
        """
        # Todas as peças com mesma disponibilidade (disp=1)
        bf = Bitfield(num_pieces=self.num_pieces)
        for i in range(self.num_pieces):
            bf.set_piece(i, True)
        self.pm.add_peer_bitfield(bf)

        # Inicia a Peça 4 (solicita bloco 0) -> Peça 4 vai para DOWNLOADING
        p4 = self.pm.get_piece(4)
        p4.blocks[0].state = BlockState.REQUESTED
        p4.state = PieceState.DOWNLOADING

        # Próxima requisição deve priorizar o segundo bloco da Peça 4 (DOWNLOADING)
        # ao invés de abrir a Peça 0 (MISSING)
        req = self.pm.get_next_block_to_request(peer_bitfield=bf)
        self.assertEqual(req, (4, 8192, 8192))


class TestRarestFirstClientIntegration(unittest.TestCase):
    """Testes de integração ponta a ponta do Rarest First com TorrentClient."""

    def test_client_requests_rarest_piece_first_from_swarm(self):
        """
        Cria um cenário com 3 peers:
        - Peer A tem peças {0, 1, 2}
        - Peer B tem peças {0, 2}
        - Peer C tem peças {0, 2}
        Nesse cenário:
        - Peça 0: 3 peers (comum)
        - Peça 2: 3 peers (comum)
        - Peça 1: 1 peer (RARA - disponível apenas no Peer A)

        O cliente conectado ao Peer A deve priorizar imediatamente a Peça 1.
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

                # 2. Bitfield (possui peças 0, 1, 2)
                bf = Bitfield(num_pieces=3)
                bf.set_piece(0, True)
                bf.set_piece(1, True)
                bf.set_piece(2, True)
                sock.sendall(BitfieldMessage(bitfield=bf.to_bytes()).encode())

                # 3. Unchoke
                sock.sendall(UnchokeMessage().encode())

                # Lê requests
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

        # Simula que o cliente já tomou conhecimento de outros peers (Peer B e Peer C) que possuem {0, 2}
        bf_other = Bitfield(num_pieces=3)
        bf_other.set_piece(0, True)
        bf_other.set_piece(2, True)
        client.piece_manager.add_peer_bitfield(bf_other)  # Peer B
        client.piece_manager.add_peer_bitfield(bf_other)  # Peer C

        # Disponibilidades antes de conectar ao Peer A:
        # Peça 0: 2, Peça 1: 0, Peça 2: 2
        self.assertEqual(client.piece_manager.get_all_availabilities(), [2, 0, 2])

        conn = PeerConnection(sock=c_sock, default_timeout=5.0)
        conn.perform_handshake(info_hash=client.info_hash, peer_id=client.peer_id)

        # Ao executar o download, a Peça 1 deve ser solicitada e baixada primeiro
        first_piece_completed = []

        def on_progress(p):
            if p.completed_pieces == 1 and not first_piece_completed:
                # Registra qual peça foi concluída primeiro
                for i in range(3):
                    if client.piece_manager.is_piece_complete(i):
                        first_piece_completed.append(i)

        success = client.download_from_peer_connection(conn, on_progress=on_progress)
        conn.close()
        srv_thread.join(timeout=2.0)

        self.assertTrue(success)
        self.assertTrue(client.is_complete)
        # Comprova que a peça mais rara (índice 1) foi completada primeiro!
        self.assertEqual(first_piece_completed, [1])


if __name__ == "__main__":
    unittest.main()
