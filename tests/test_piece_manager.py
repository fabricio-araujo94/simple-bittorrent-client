"""
Testes unitários abrangentes para o PieceManager (gerenciador de peças e blocos).

Cobre:
- Divisão de peças em blocos e cálculo exato de tamanhos;
- Tratamento e dimensionamento preciso da última peça e seu último bloco;
- Ciclo de vida e estados de blocos (MISSING, REQUESTED, RECEIVED);
- Ciclo de vida e estados de peças (MISSING, DOWNLOADING, COMPLETED);
- Recebimento de blocos fora de ordem;
- Tratamento gracioso de blocos duplicados;
- Validação estrita de integridade com SHA-1 (hash correto);
- Rejeição, descarte de dados e reset em caso de hash incorreto (dados corrompidos);
- Sincronização e requisições concorrentes entre múltiplos peers (Multi-threading / Thread-Safety);
- Reconstrução ordenada dos dados completos do arquivo e gravação em disco.
"""

import hashlib
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest

from src.hash_utils import compute_sha1
from src.peer import Bitfield
from src.piece_manager import (
    Block,
    BlockState,
    Piece,
    PieceManager,
    PieceState,
)
from src.torrent import TorrentMetadata


class TestPiece(unittest.TestCase):
    """Testes unitários para a classe Piece e seus blocos individuais."""

    def setUp(self):
        # Peça de 32 KB (32768 bytes) dividida em 2 blocos de 16 KB (16384 bytes)
        self.piece_data = b"A" * 16384 + b"B" * 16384
        self.expected_hash = compute_sha1(self.piece_data)
        self.piece = Piece(
            index=0,
            length=32768,
            expected_hash=self.expected_hash,
            block_size=16384,
        )

    def test_piece_initial_state(self):
        self.assertEqual(self.piece.index, 0)
        self.assertEqual(self.piece.length, 32768)
        self.assertEqual(self.piece.state, PieceState.MISSING)
        self.assertEqual(self.piece.num_blocks, 2)
        self.assertFalse(self.piece.is_completed())
        self.assertIsNone(self.piece.get_data())

        # Blocos
        self.assertEqual(self.piece.blocks[0].begin, 0)
        self.assertEqual(self.piece.blocks[0].length, 16384)
        self.assertEqual(self.piece.blocks[0].state, BlockState.MISSING)

        self.assertEqual(self.piece.blocks[1].begin, 16384)
        self.assertEqual(self.piece.blocks[1].length, 16384)
        self.assertEqual(self.piece.blocks[1].state, BlockState.MISSING)

    def test_piece_blocks_in_order(self):
        # 1. Adiciona primeiro bloco
        added1, completed1 = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added1)
        self.assertFalse(completed1)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)
        self.assertTrue(self.piece.blocks[0].is_received)
        self.assertFalse(self.piece.blocks[1].is_received)

        # 2. Adiciona segundo bloco (completa a peça com hash correto)
        added2, completed2 = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added2)
        self.assertTrue(completed2)
        self.assertEqual(self.piece.state, PieceState.COMPLETED)
        self.assertTrue(self.piece.is_completed())
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_blocks_out_of_order(self):
        # Adiciona bloco 1 antes do bloco 0
        added1, completed1 = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added1)
        self.assertFalse(completed1)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)

        # Agora adiciona bloco 0
        added0, completed0 = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added0)
        self.assertTrue(completed0)
        self.assertEqual(self.piece.state, PieceState.COMPLETED)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_duplicate_blocks(self):
        # Adiciona bloco 0
        added1, _ = self.piece.add_block(0, b"A" * 16384)
        self.assertTrue(added1)

        # Reentrega bloco 0 (duplicado)
        added_dup, _ = self.piece.add_block(0, b"A" * 16384)
        self.assertFalse(added_dup)  # Não adiciona novamente

        # Completa com bloco 1
        added2, completed = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(added2)
        self.assertTrue(completed)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_corrupt_hash_rejection_and_reset(self):
        # Entrega dados corrompidos (bloco 1 corrompido com 'Z')
        corrupted_block1 = b"Z" * 16384
        self.piece.add_block(0, b"A" * 16384)
        added2, completed = self.piece.add_block(16384, corrupted_block1)

        self.assertTrue(added2)
        self.assertFalse(completed)  # Falhou no SHA-1!

        # Deve ter resetado o estado para MISSING e descartado os blocos para novo download
        self.assertEqual(self.piece.state, PieceState.MISSING)
        self.assertFalse(self.piece.is_completed())
        self.assertIsNone(self.piece.get_data())
        self.assertFalse(self.piece.blocks[0].is_received)
        self.assertFalse(self.piece.blocks[1].is_received)

        # Agora entrega dados corretos e deve completar normalmente
        self.piece.add_block(0, b"A" * 16384)
        _, completed_now = self.piece.add_block(16384, b"B" * 16384)
        self.assertTrue(completed_now)
        self.assertEqual(self.piece.get_data(), self.piece_data)

    def test_piece_invalid_offsets_and_sizes(self):
        # Offset inexistente
        with self.assertRaises(ValueError):
            self.piece.add_block(500, b"A" * 16384)

        # Tamanho de bloco incompatível (menor ou maior)
        with self.assertRaises(ValueError):
            self.piece.add_block(0, b"A" * 100)
        with self.assertRaises(ValueError):
            self.piece.add_block(0, b"A" * 20000)

    def test_piece_get_next_missing_block_and_reset(self):
        b0 = self.piece.get_next_missing_block(mark_requested=True)
        self.assertIsNotNone(b0)
        self.assertEqual(b0.begin, 0)
        self.assertEqual(b0.state, BlockState.REQUESTED)
        self.assertEqual(self.piece.state, PieceState.DOWNLOADING)

        b1 = self.piece.get_next_missing_block(mark_requested=True)
        self.assertIsNotNone(b1)
        self.assertEqual(b1.begin, 16384)
        self.assertEqual(b1.state, BlockState.REQUESTED)

        # Nenhum bloco pendente restante
        b_none = self.piece.get_next_missing_block()
        self.assertIsNone(b_none)

        # Reseta requisições pendentes (ex: peer desconectou)
        self.piece.reset_pending_blocks()
        self.assertEqual(self.piece.blocks[0].state, BlockState.MISSING)
        self.assertEqual(self.piece.blocks[1].state, BlockState.MISSING)
        self.assertEqual(self.piece.state, PieceState.MISSING)


class TestPieceManager(unittest.TestCase):
    """Testes unitários e de integração para o PieceManager."""

    def setUp(self):
        # Torrent com 3 peças (total de 50.000 bytes, piece_length=20.000 bytes, block_size=8.192 bytes)
        # Peça 0: 20.000 bytes (blocos: 8192, 8192, 3616)
        # Peça 1: 20.000 bytes (blocos: 8192, 8192, 3616)
        # Peça 2 (última peça): 10.000 bytes (50000 % 20000) (blocos: 8192, 1808)
        self.p0_data = b"0" * 20000
        self.p1_data = b"1" * 20000
        self.p2_data = b"2" * 10000
        self.full_torrent_data = self.p0_data + self.p1_data + self.p2_data  # 50.000 bytes

        self.p0_hash = compute_sha1(self.p0_data)
        self.p1_hash = compute_sha1(self.p1_data)
        self.p2_hash = compute_sha1(self.p2_data)
        self.piece_hashes = [self.p0_hash, self.p1_hash, self.p2_hash]

        self.pm = PieceManager(
            total_length=50000,
            piece_length=20000,
            piece_hashes=self.piece_hashes,
            block_size=8192,
        )

    def test_piece_manager_initialization_and_sizes(self):
        self.assertEqual(self.pm.total_length, 50000)
        self.assertEqual(self.pm.piece_length, 20000)
        self.assertEqual(self.pm.num_pieces, 3)
        self.assertEqual(self.pm.block_size, 8192)
        self.assertEqual(self.pm.completed_pieces_count(), 0)
        self.assertEqual(self.pm.missing_pieces_count(), 3)
        self.assertEqual(self.pm.bytes_downloaded(), 0)
        self.assertEqual(self.pm.bytes_left(), 50000)
        self.assertEqual(self.pm.progress, 0.0)
        self.assertFalse(self.pm.is_complete)

        # Verificação do tamanho exato das peças
        self.assertEqual(self.pm.get_piece_length(0), 20000)
        self.assertEqual(self.pm.get_piece_length(1), 20000)
        self.assertEqual(self.pm.get_piece_length(2), 10000)  # Última peça

        # Verificação dos blocos da última peça (10000 = 8192 + 1808)
        p2 = self.pm.get_piece(2)
        self.assertEqual(p2.num_blocks, 2)
        self.assertEqual(p2.blocks[0].begin, 0)
        self.assertEqual(p2.blocks[0].length, 8192)
        self.assertEqual(p2.blocks[1].begin, 8192)
        self.assertEqual(p2.blocks[1].length, 1808)

    def test_complete_piece_download_and_bitfield(self):
        # Baixa peça 0 por completo
        # Blocos: (0, 8192), (8192, 8192), (16384, 3616)
        self.pm.add_block(0, 0, self.p0_data[0:8192])
        self.pm.add_block(0, 8192, self.p0_data[8192:16384])
        added, completed = self.pm.add_block(0, 16384, self.p0_data[16384:20000])

        self.assertTrue(added)
        self.assertTrue(completed)
        self.assertTrue(self.pm.is_piece_complete(0))
        self.assertTrue(self.pm.bitfield.has_piece(0))
        self.assertFalse(self.pm.bitfield.has_piece(1))
        self.assertEqual(self.pm.completed_pieces_count(), 1)
        self.assertEqual(self.pm.bytes_downloaded(), 20000)
        self.assertEqual(self.pm.bytes_left(), 30000)
        self.assertEqual(self.pm.progress, 20000 / 50000)
        self.assertEqual(self.pm.get_piece_data(0), self.p0_data)

    def test_download_all_pieces_and_reconstruct(self):
        # 1. Baixa peça 2 (última peça) primeiro
        self.pm.add_block(2, 0, self.p2_data[0:8192])
        self.pm.add_block(2, 8192, self.p2_data[8192:10000])
        self.assertTrue(self.pm.is_piece_complete(2))

        # 2. Baixa peça 0
        self.pm.add_block(0, 0, self.p0_data[0:8192])
        self.pm.add_block(0, 8192, self.p0_data[8192:16384])
        self.pm.add_block(0, 16384, self.p0_data[16384:20000])
        self.assertTrue(self.pm.is_piece_complete(0))

        # Tentativa de reconstrução antes de terminar tudo -> ValueError
        with self.assertRaises(ValueError):
            self.pm.get_all_data()

        # 3. Baixa peça 1
        self.pm.add_block(1, 0, self.p1_data[0:8192])
        self.pm.add_block(1, 8192, self.p1_data[8192:16384])
        self.pm.add_block(1, 16384, self.p1_data[16384:20000])
        self.assertTrue(self.pm.is_piece_complete(1))

        # Agora 100% concluído
        self.assertTrue(self.pm.is_complete)
        self.assertEqual(self.pm.completed_pieces_count(), 3)
        self.assertEqual(self.pm.bytes_downloaded(), 50000)
        self.assertEqual(self.pm.bytes_left(), 0)
        self.assertEqual(self.pm.progress, 1.0)
        self.assertTrue(self.pm.bitfield.is_complete)

        # Reconstrução ordenada perfeita
        reconstructed = self.pm.get_all_data()
        self.assertEqual(reconstructed, self.full_torrent_data)

    def test_save_to_file(self):
        # Baixa tudo
        for p_idx, p_data in enumerate([self.p0_data, self.p1_data, self.p2_data]):
            piece = self.pm.get_piece(p_idx)
            for block in piece.blocks:
                b_data = p_data[block.begin : block.begin + block.length]
                self.pm.add_block(p_idx, block.begin, b_data)

        self.assertTrue(self.pm.is_complete)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "downloads" / "output.bin"
            self.pm.save_to_file(out_file)

            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.read_bytes(), self.full_torrent_data)

    def test_get_next_block_to_request_with_peer_bitfield(self):
        # Peer possui apenas as peças 1 e 2 (Bitfield: [0b01100000])
        peer_bf = Bitfield(num_pieces=3)
        peer_bf.set_piece(1, True)
        peer_bf.set_piece(2, True)

        # Primeira requisição: deve pegar bloco da peça 1 (a primeira que o peer tem)
        req1 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertIsNotNone(req1)
        self.assertEqual(req1, (1, 0, 8192))

        # Segunda requisição: próximo bloco da peça 1
        req2 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req2, (1, 8192, 8192))

        # Terceira requisição: último bloco da peça 1
        req3 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req3, (1, 16384, 3616))

        # Quarta requisição: passa para a peça 2
        req4 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req4, (2, 0, 8192))

        # Reseta requisições da peça 1 (a peça 2 continua DOWNLOADING)
        self.pm.reset_pending_requests(piece_index=1)
        # Próxima requisição prioriza completar a peça 2 que já está DOWNLOADING
        req5 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req5, (2, 8192, 1808))

        # Agora que a peça 2 foi totalmente solicitada, retorna para a peça 1 (MISSING)
        req6 = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req6, (1, 0, 8192))

        # Reseta todas as peças pendentes globalmente
        self.pm.reset_pending_requests()
        req_restart = self.pm.get_next_block_to_request(peer_bitfield=peer_bf)
        self.assertEqual(req_restart, (1, 0, 8192))

    def test_concurrent_multi_peer_block_downloads(self):
        """
        Simula múltiplos peers concorrentes (threads) baixando blocos simultaneamente.
        Garante ausência de race conditions e integridade final.
        """
        num_workers = 8
        errors = []

        def worker_task(worker_id: int):
            try:
                while True:
                    req = self.pm.get_next_block_to_request()
                    if req is None:
                        # Nenhum bloco pendente
                        break

                    piece_idx, begin, length = req
                    # Simula obtenção do dado correto daquele bloco
                    if piece_idx == 0:
                        block_data = self.p0_data[begin : begin + length]
                    elif piece_idx == 1:
                        block_data = self.p1_data[begin : begin + length]
                    else:
                        block_data = self.p2_data[begin : begin + length]

                    # Adiciona o bloco ao PieceManager
                    self.pm.add_block(piece_idx, begin, block_data)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_workers):
            t = threading.Thread(target=worker_task, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertTrue(self.pm.is_complete)
        self.assertEqual(self.pm.completed_pieces_count(), 3)
        self.assertEqual(self.pm.get_all_data(), self.full_torrent_data)

    def test_granular_reset_block_and_reset_blocks(self):
        """Testa reset atômico de blocos individuais e múltiplos blocos."""
        # 1. Solicita blocos da peça 0: (0, 0), (0, 8192), (0, 16384)
        r0 = self.pm.get_next_block_to_request()
        r1 = self.pm.get_next_block_to_request()
        r2 = self.pm.get_next_block_to_request()

        self.assertEqual(r0, (0, 0, 8192))
        self.assertEqual(r1, (0, 8192, 8192))
        self.assertEqual(r2, (0, 16384, 3616))

        # Peça 0 agora não tem mais blocos MISSING
        r_p1 = self.pm.get_next_block_to_request()
        self.assertEqual(r_p1, (1, 0, 8192))

        # 2. Reseta apenas o bloco (0, 8192)
        res = self.pm.reset_block(0, 8192)
        self.assertTrue(res)

        # O próximo bloco requisitado deve ser o bloco (0, 8192) re-disponibilizado!
        r_retried = self.pm.get_next_block_to_request()
        self.assertEqual(r_retried, (0, 8192, 8192))

        # 3. Reseta múltiplos blocos via reset_blocks
        self.pm.reset_blocks([(0, 0), (0, 16384)])
        # Deve re-oferecer (0, 0)
        r_re0 = self.pm.get_next_block_to_request()
        self.assertEqual(r_re0, (0, 0, 8192))

    def test_reset_block_invalid_index(self):
        """Testa reset_block com índices fora de alcance."""
        self.assertFalse(self.pm.reset_block(-1, 0))
        self.assertFalse(self.pm.reset_block(999, 0))
        self.assertFalse(self.pm.reset_block(0, 999999))


if __name__ == "__main__":
    unittest.main()
