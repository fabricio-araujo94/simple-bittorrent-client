"""
Testes unitários abrangentes para a camada de interpretação de arquivos .torrent.

Cobre:
- Carregamento de torrents a partir de bytes e arquivos em disco;
- Parsing de torrents single-file e multi-file;
- Extração de announce, announce-list (tiers BEP 0012) e lista agregada de trackers;
- Extração precisa da seção info e cálculo do info_hash SHA-1;
- Extração de name, piece length, pieces e divisão em hashes individuais de 20 bytes;
- Métodos auxiliares de peças (get_piece_length, get_piece_hash, verify_piece);
- Validação estrita de campos obrigatórios e tipos de dados;
- Validação de consistência matemática (peças vs tamanho total vs piece length);
- Rejeição de torrents malformados, inconsistentes ou incompletos.
"""

import hashlib
import math
import os
import tempfile
import unittest
from pathlib import Path

from src.bencode import encode_bencode
from src.torrent import (
    FileInfo,
    TorrentMetadata,
    TorrentParseError,
    TorrentValidationError,
    load_torrent_bytes,
    load_torrent_file,
)


class TestTorrentParser(unittest.TestCase):
    """Testes principais para parsing e validação de metadados .torrent."""

    def setUp(self):
        # Cria dados simulados de 2 peças (500 KB no total, piece_length de 256 KB)
        self.piece_data_0 = b"A" * 262144
        self.piece_data_1 = b"B" * (512000 - 262144)  # 249856 bytes
        self.piece0_hash = hashlib.sha1(self.piece_data_0).digest()
        self.piece1_hash = hashlib.sha1(self.piece_data_1).digest()
        self.pieces_bytes = self.piece0_hash + self.piece1_hash

        # Dicionário 'info' single-file
        self.single_info_dict = {
            b"length": 512000,
            b"name": b"debian-live.iso",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
        }
        self.single_info_bencoded = encode_bencode(self.single_info_dict)
        self.expected_single_info_hash = hashlib.sha1(self.single_info_bencoded).digest()

        # Dicionário torrent single-file completo com metadados opcionais
        self.single_torrent_dict = {
            b"announce": b"http://tracker.debian.org:6969/announce",
            b"announce-list": [
                [b"http://tracker.debian.org:6969/announce", b"http://backup.debian.org/announce"],
                [b"udp://tracker.openbittorrent.com:80/announce"],
            ],
            b"comment": b"Debian Live Image",
            b"created by": b"mktorrent 1.1",
            b"creation date": 1672531199,
            b"info": self.single_info_dict,
        }
        self.single_torrent_bytes = encode_bencode(self.single_torrent_dict)

    # --- Testes de Sucesso (Single-file e Multi-file) ---

    def test_load_single_file_torrent_success(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # Validação básica de metadados
        self.assertEqual(metadata.announce, "http://tracker.debian.org:6969/announce")
        self.assertEqual(metadata.name, "debian-live.iso")
        self.assertEqual(metadata.piece_length, 262144)
        self.assertEqual(metadata.total_length, 512000)
        self.assertFalse(metadata.is_multi_file)
        self.assertEqual(len(metadata.files), 1)
        self.assertEqual(metadata.files[0].length, 512000)
        self.assertEqual(metadata.files[0].full_path, "debian-live.iso")

        # Validação de trackers e tiers (BEP 0012)
        expected_announce_list = [
            ["http://tracker.debian.org:6969/announce", "http://backup.debian.org/announce"],
            ["udp://tracker.openbittorrent.com:80/announce"],
        ]
        self.assertEqual(metadata.announce_list, expected_announce_list)
        expected_trackers = [
            "http://tracker.debian.org:6969/announce",
            "http://backup.debian.org/announce",
            "udp://tracker.openbittorrent.com:80/announce",
        ]
        self.assertEqual(metadata.trackers, expected_trackers)

        # Validação de hashes e integridade da seção info
        self.assertEqual(metadata.info_hash, self.expected_single_info_hash)
        self.assertEqual(metadata.info_hash_hex, self.expected_single_info_hash.hex())
        self.assertEqual(metadata.raw_info_bytes, self.single_info_bencoded)

        # Validação de divisão de peças
        self.assertEqual(metadata.num_pieces, 2)
        self.assertEqual(metadata.piece_hashes, [self.piece0_hash, self.piece1_hash])
        self.assertEqual(metadata.pieces, self.pieces_bytes)

        # Validação de metadados opcionais
        self.assertEqual(metadata.comment, "Debian Live Image")
        self.assertEqual(metadata.created_by, "mktorrent 1.1")
        self.assertEqual(metadata.creation_date, 1672531199)
        self.assertFalse(metadata.private)

    def test_load_multi_file_torrent_success(self):
        # 3 arquivos somando 512000 bytes
        file1_len = 200000
        file2_len = 100000
        file3_len = 212000

        multi_info_dict = {
            b"files": [
                {b"length": file1_len, b"path": [b"docs", b"manual.pdf"]},
                {b"length": file2_len, b"path": [b"docs", b"changelog.txt"]},
                {b"length": file3_len, b"path": [b"bin", b"app.exe"]},
            ],
            b"name": b"my_bundle",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
            b"private": 1,
        }
        multi_torrent_dict = {
            b"announce": b"http://tracker.private.org/announce",
            b"info": multi_info_dict,
        }
        raw_multi = encode_bencode(multi_torrent_dict)
        metadata = load_torrent_bytes(raw_multi)

        self.assertTrue(metadata.is_multi_file)
        self.assertEqual(metadata.name, "my_bundle")
        self.assertEqual(metadata.total_length, 512000)
        self.assertEqual(len(metadata.files), 3)

        self.assertEqual(metadata.files[0], FileInfo(length=200000, path=["docs", "manual.pdf"], full_path="docs/manual.pdf"))
        self.assertEqual(metadata.files[1], FileInfo(length=100000, path=["docs", "changelog.txt"], full_path="docs/changelog.txt"))
        self.assertEqual(metadata.files[2], FileInfo(length=212000, path=["bin", "app.exe"], full_path="bin/app.exe"))
        self.assertTrue(metadata.private)

    def test_load_torrent_file_from_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.torrent"
            file_path.write_bytes(self.single_torrent_bytes)

            metadata = load_torrent_file(file_path)
            self.assertEqual(metadata.name, "debian-live.iso")
            self.assertEqual(metadata.info_hash, self.expected_single_info_hash)

            # Teste passando como string
            metadata_str = load_torrent_file(str(file_path))
            self.assertEqual(metadata_str.info_hash, self.expected_single_info_hash)

    # --- Testes de Métodos Auxiliares de Peças ---

    def test_piece_length_helpers(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # Primeira peça: tamanho total padrão (262144)
        self.assertEqual(metadata.get_piece_length(0), 262144)
        # Segunda (última) peça: resto da divisão (512000 - 262144 = 249856)
        self.assertEqual(metadata.get_piece_length(1), 249856)

        # Índice fora de faixa
        with self.assertRaises(IndexError):
            metadata.get_piece_length(-1)
        with self.assertRaises(IndexError):
            metadata.get_piece_length(2)

    def test_get_piece_hash(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)
        self.assertEqual(metadata.get_piece_hash(0), self.piece0_hash)
        self.assertEqual(metadata.get_piece_hash(1), self.piece1_hash)

        with self.assertRaises(IndexError):
            metadata.get_piece_hash(5)

    def test_verify_piece(self):
        metadata = load_torrent_bytes(self.single_torrent_bytes)

        # Peça 0 válida
        self.assertTrue(metadata.verify_piece(0, self.piece_data_0))
        # Peça 1 válida
        self.assertTrue(metadata.verify_piece(1, self.piece_data_1))

        # Dados com hash incorreto
        corrupted_data = b"Z" * 262144
        self.assertFalse(metadata.verify_piece(0, corrupted_data))

        # Dados com tamanho incorreto (menor ou maior)
        self.assertFalse(metadata.verify_piece(0, b"short_data"))

        # Tipo inválido
        with self.assertRaises(TypeError):
            metadata.verify_piece(0, "not_bytes")  # type: ignore

        # Índice inválido
        with self.assertRaises(IndexError):
            metadata.verify_piece(99, self.piece_data_0)

    # --- Testes de Validação e Tratamento de Erros ---

    def test_load_torrent_invalid_inputs(self):
        # Entrada que não é bytes
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes("string_data")  # type: ignore
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(12345)  # type: ignore
        # Buffer vazio
        with self.assertRaises(TorrentParseError):
            load_torrent_bytes(b"")

    def test_load_torrent_file_errors(self):
        # Arquivo inexistente
        with self.assertRaises(FileNotFoundError):
            load_torrent_file("non_existent_file.torrent")

        # Caminho é um diretório
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(TorrentParseError):
                load_torrent_file(tmpdir)

    def test_missing_or_invalid_root_structure(self):
        # Raiz não é dicionário
        not_a_dict = encode_bencode([1, 2, 3])
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(not_a_dict)

        # Ausência de seção info
        no_info = encode_bencode({b"announce": b"http://tracker.com"})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(no_info)

        # Seção info não é dicionário
        bad_info_type = encode_bencode({b"announce": b"http://tracker.com", b"info": b"not_a_dict"})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_info_type)

    def test_missing_or_invalid_trackers(self):
        # Nem announce nem announce-list
        no_trackers = encode_bencode({b"info": self.single_info_dict})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(no_trackers)

        # Announce com tipo inválido
        bad_announce = encode_bencode({b"announce": 12345, b"info": self.single_info_dict})
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_announce)

        # Announce-list com tipo inválido
        bad_announce_list = encode_bencode({
            b"announce-list": b"not_a_list",
            b"info": self.single_info_dict,
        })
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(bad_announce_list)

    def test_missing_or_invalid_name(self):
        # Sem campo name
        bad_info = dict(self.single_info_dict)
        del bad_info[b"name"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # Name com string vazia
        bad_info[b"name"] = b""
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_missing_or_invalid_piece_length(self):
        bad_info = dict(self.single_info_dict)
        # piece length ausente
        del bad_info[b"piece length"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # piece length zero ou negativo
        bad_info[b"piece length"] = 0
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        bad_info[b"piece length"] = -262144
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_missing_or_invalid_pieces(self):
        bad_info = dict(self.single_info_dict)
        # pieces ausente
        del bad_info[b"pieces"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # pieces não é múltiplo de 20 bytes
        bad_info[b"pieces"] = b"1234567890"  # 10 bytes
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

    def test_single_and_multi_file_conflicts(self):
        # Ambos 'length' e 'files' presentes simultaneamente
        conflicted_info = dict(self.single_info_dict)
        conflicted_info[b"files"] = [{b"length": 512000, b"path": [b"file.bin"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": conflicted_info}))

        # Nem 'length' nem 'files' presentes
        empty_files_info = dict(self.single_info_dict)
        del empty_files_info[b"length"]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": empty_files_info}))

    def test_multi_file_validation_errors(self):
        # files vazio
        bad_multi_info = {
            b"files": [],
            b"name": b"bundle",
            b"piece length": 262144,
            b"pieces": self.pieces_bytes,
        }
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # Arquivo sem campo 'length'
        bad_multi_info[b"files"] = [{b"path": [b"file.txt"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # Arquivo com length negativo
        bad_multi_info[b"files"] = [{b"length": -10, b"path": [b"file.txt"]}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # Arquivo sem campo 'path'
        bad_multi_info[b"files"] = [{b"length": 100}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

        # Arquivo com path vazio
        bad_multi_info[b"files"] = [{b"length": 100, b"path": []}]
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_multi_info}))

    def test_mathematical_piece_count_inconsistency(self):
        # total_length = 512000, piece_length = 262144 -> math.ceil(512000 / 262144) = 2 peças
        # Passar apenas 1 hash de 20 bytes causa erro de inconsistência
        bad_info = dict(self.single_info_dict)
        bad_info[b"pieces"] = self.piece0_hash  # 1 peça ao invés de 2
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))

        # Passar 3 hashes de 20 bytes causa erro de inconsistência
        bad_info[b"pieces"] = self.pieces_bytes + self.piece0_hash  # 3 peças
        with self.assertRaises(TorrentValidationError):
            load_torrent_bytes(encode_bencode({b"announce": b"http://tr.org", b"info": bad_info}))


if __name__ == "__main__":
    unittest.main()

