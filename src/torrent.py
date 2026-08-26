"""
Módulo para interpretação de arquivos .torrent e representação de metadados.

Realiza o parsing de metadados BitTorrent (BEP 0003, BEP 0012, BEP 0027),
valida a integridade e consistência matemática de peças e arquivos,
e calcula o info_hash SHA-1 sobre os bytes brutos da seção 'info'.
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

from .bencode import BencodeError, decode_bencode_with_offsets
from .hash_utils import compute_sha1, verify_sha1


class TorrentError(Exception):
    """Exceção base para erros na camada de torrent."""
    pass


class TorrentParseError(TorrentError):
    """Exceção lançada quando o arquivo .torrent está malformado, incompleto ou inconsistente."""
    pass


class TorrentValidationError(TorrentParseError):
    """Exceção lançada quando campos obrigatórios ou regras de validação falham."""
    pass


class TorrentSecurityError(TorrentValidationError):
    """Exceção lançada quando detectada tentativa de violação de segurança (ex: Path Traversal)."""
    pass


def validate_safe_path_segment(segment: str) -> str:
    """
    Valida e sanitiza um segmento de caminho para impedir vulnerabilidades de Path Traversal.

    Rejeita:
    - Segmentos vazios, '.', '..';
    - Segmentos contendo '/', '\\', '\x00' (null bytes) ou ':' (unidades Windows).
    """
    if not isinstance(segment, str):
        raise TorrentValidationError(f"Segmento de caminho deve ser string, obtido {type(segment).__name__}.")

    seg = segment.strip()
    if not seg:
        raise TorrentValidationError("Segmento de caminho não pode ser vazio ou conter apenas espaços.")

    if seg in (".", "..") or ".." in seg:
        raise TorrentSecurityError(f"Tentativa de Path Traversal detectada no segmento de caminho: {segment!r}")

    if "\x00" in seg:
        raise TorrentSecurityError(f"Null byte detectado no segmento de caminho: {segment!r}")

    if "/" in seg or "\\" in seg:
        raise TorrentSecurityError(f"Separadores de diretório não permitidos dentro de segmento individual: {segment!r}")

    if ":" in seg:
        raise TorrentSecurityError(f"Caractere ':' não permitido no segmento de caminho: {segment!r}")

    return seg


@dataclass(frozen=True)
class FileInfo:
    """
    Representação de um arquivo contido no torrent (single-file ou multi-file).
    """
    length: int
    path: List[str]
    full_path: str
    md5sum: Optional[str] = None


@dataclass(frozen=True)
class TorrentMetadata:
    """
    Representação imutável e estruturada dos metadados de um arquivo .torrent.
    """
    announce: Optional[str]
    announce_list: List[List[str]]  # Tiers de trackers (BEP 0012)
    trackers: List[str]             # Lista única e ordenada de todos os trackers disponíveis
    info_hash: bytes                # SHA-1 binário de 20 bytes da seção 'info'
    info_hash_hex: str              # String hexadecimal de 40 caracteres do info_hash
    name: str                       # Nome do arquivo (single-file) ou diretório raiz (multi-file)
    piece_length: int               # Tamanho padrão de cada peça em bytes
    total_length: int               # Tamanho total somado de todos os arquivos em bytes
    pieces: bytes                   # Bytes brutos concatenados com os hashes SHA-1 das peças
    piece_hashes: List[bytes]       # Lista de hashes SHA-1 individuais (20 bytes cada)
    raw_info_bytes: bytes           # Bytes brutos Bencoded originais da seção 'info'
    is_multi_file: bool             # True se for multi-file, False se for single-file
    files: List[FileInfo]           # Lista de arquivos do torrent
    comment: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[int] = None
    private: bool = False

    @property
    def num_pieces(self) -> int:
        """Retorna o número total de peças do torrent."""
        return len(self.piece_hashes)

    def get_piece_length(self, piece_index: int) -> int:
        """
        Retorna o tamanho exato da peça para o índice informado.
        A última peça pode ser menor que `piece_length`.
        """
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Índice de peça fora do intervalo: {piece_index} (total: {self.num_pieces})"
            )
        if piece_index == self.num_pieces - 1:
            remainder = self.total_length % self.piece_length
            return remainder if remainder != 0 else self.piece_length
        return self.piece_length

    def get_piece_hash(self, piece_index: int) -> bytes:
        """Retorna o hash SHA-1 de 20 bytes esperado para a peça no índice informado."""
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Índice de peça fora do intervalo: {piece_index} (total: {self.num_pieces})"
            )
        return self.piece_hashes[piece_index]

    def verify_piece(self, piece_index: int, piece_data: bytes) -> bool:
        """
        Valida se os dados de uma peça coincidem com o tamanho esperado
        e com o hash SHA-1 registrado nos metadados.
        """
        if not isinstance(piece_data, (bytes, bytearray)):
            raise TypeError(f"Dados da peça devem ser bytes, obtido {type(piece_data).__name__}.")
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Índice de peça fora do intervalo: {piece_index} (total: {self.num_pieces})"
            )
        expected_length = self.get_piece_length(piece_index)
        if len(piece_data) != expected_length:
            return False
        return verify_sha1(bytes(piece_data), self.piece_hashes[piece_index])


def load_torrent_bytes(raw_bytes: Union[bytes, bytearray, memoryview]) -> TorrentMetadata:
    """
    Decodifica o buffer de bytes de um arquivo .torrent, valida todos os campos
    obrigatórios, extrai announce / announce-list, divide pieces em hashes SHA-1,
    calcula o info_hash e constrói o TorrentMetadata com proteção de segurança.
    """
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        raise TorrentParseError(
            f"Entrada esperada como bytes, obtido {type(raw_bytes).__name__}."
        )

    bytes_data = bytes(raw_bytes)
    if not bytes_data:
        raise TorrentParseError("Buffer do arquivo .torrent está vazio.")

    try:
        root_dict, _, raw_slices = decode_bencode_with_offsets(bytes_data)
    except BencodeError as e:
        raise TorrentParseError(f"Erro ao decodificar estrutura Bencode do torrent: {e}") from e

    if not isinstance(root_dict, dict):
        raise TorrentValidationError("O arquivo .torrent deve conter um dicionário Bencode na raiz.")

    # 1. Validação da seção 'info' e extração da fatia bruta exata
    if b"info" not in root_dict or b"info" not in raw_slices:
        raise TorrentValidationError("Dicionário obrigatório 'info' não encontrado no arquivo .torrent.")

    info_start, info_end = raw_slices[b"info"]
    raw_info_bytes = bytes_data[info_start:info_end]

    info = root_dict[b"info"]
    if not isinstance(info, dict):
        raise TorrentValidationError("A seção 'info' do torrent deve ser um dicionário.")

    # 2. Cálculo do info_hash SHA-1 sobre os bytes brutos exatos
    info_hash = compute_sha1(raw_info_bytes)
    info_hash_hex = info_hash.hex()

    # 3. Extração e validação de announce e announce-list (BEP 0012)
    announce: Optional[str] = None
    if b"announce" in root_dict:
        announce_raw = root_dict[b"announce"]
        if not isinstance(announce_raw, bytes):
            raise TorrentValidationError("Campo 'announce' deve ser do tipo byte string.")
        announce_str = announce_raw.decode('utf-8', errors='replace').strip()
        if announce_str:
            announce = announce_str

    announce_list: List[List[str]] = []
    if b"announce-list" in root_dict:
        raw_announce_list = root_dict[b"announce-list"]
        if not isinstance(raw_announce_list, list):
            raise TorrentValidationError("Campo 'announce-list' deve ser uma lista de tiers.")
        for tier_idx, tier in enumerate(raw_announce_list):
            if not isinstance(tier, list):
                raise TorrentValidationError(
                    f"Tier {tier_idx} em 'announce-list' deve ser uma lista de URLs."
                )
            tier_urls = []
            for url_item in tier:
                if not isinstance(url_item, bytes):
                    raise TorrentValidationError(
                        f"URL no tier {tier_idx} de 'announce-list' deve ser byte string."
                    )
                url_str = url_item.decode('utf-8', errors='replace').strip()
                if url_str:
                    tier_urls.append(url_str)
            if tier_urls:
                announce_list.append(tier_urls)

    # Validação de presença de ao menos um tracker
    if announce is None and not announce_list:
        raise TorrentValidationError(
            "O arquivo .torrent deve conter ao menos um tracker válido ('announce' ou 'announce-list')."
        )

    # Constrói lista única e desduplicada de todos os trackers disponíveis
    trackers_set = set()
    all_trackers: List[str] = []
    if announce:
        trackers_set.add(announce)
        all_trackers.append(announce)
    for tier in announce_list:
        for tr in tier:
            if tr not in trackers_set:
                trackers_set.add(tr)
                all_trackers.append(tr)

    # 4. Extração e validação do nome ('name') com proteção de Path Traversal
    if b"name" not in info:
        raise TorrentValidationError("Campo obrigatório 'name' não encontrado na seção 'info'.")
    name_raw = info[b"name"]
    if not isinstance(name_raw, bytes):
        raise TorrentValidationError("Campo 'name' na seção 'info' deve ser uma byte string.")
    name = validate_safe_path_segment(name_raw.decode('utf-8', errors='replace'))

    # 5. Extração e validação de 'piece length'
    if b"piece length" not in info:
        raise TorrentValidationError("Campo obrigatório 'piece length' não encontrado na seção 'info'.")
    piece_length = info[b"piece length"]
    if not isinstance(piece_length, int) or isinstance(piece_length, bool) or piece_length <= 0:
        raise TorrentValidationError(
            f"Campo 'piece length' deve ser um inteiro estritamente positivo (> 0), obtido: {piece_length!r}."
        )

    # 6. Extração e validação de arquivos (Single-file vs Multi-file)
    has_length = b"length" in info
    has_files = b"files" in info

    if has_length and has_files:
        raise TorrentValidationError(
            "Inconsistência na seção 'info': campos 'length' e 'files' não podem coabitar simultaneamente."
        )
    if not has_length and not has_files:
        raise TorrentValidationError(
            "A seção 'info' deve conter ou 'length' (single-file) ou 'files' (multi-file)."
        )

    files_list: List[FileInfo] = []
    is_multi_file = False
    total_length = 0

    if has_length:
        length_val = info[b"length"]
        if not isinstance(length_val, int) or isinstance(length_val, bool) or length_val < 0:
            raise TorrentValidationError(
                f"Campo 'length' em single-file deve ser um inteiro não-negativo (>= 0), obtido: {length_val!r}."
            )
        total_length = length_val
        is_multi_file = False
        md5_val = None
        if b"md5sum" in info and isinstance(info[b"md5sum"], bytes):
            md5_val = info[b"md5sum"].decode('ascii', errors='replace')
        files_list.append(FileInfo(length=total_length, path=[name], full_path=name, md5sum=md5_val))
    else:
        raw_files = info[b"files"]
        if not isinstance(raw_files, list) or len(raw_files) == 0:
            raise TorrentValidationError(
                "Campo 'files' em multi-file deve ser uma lista não-vazia de arquivos."
            )
        is_multi_file = True
        for f_idx, file_dict in enumerate(raw_files):
            if not isinstance(file_dict, dict):
                raise TorrentValidationError(f"Item {f_idx} em 'files' deve ser um dicionário.")
            if b"length" not in file_dict:
                raise TorrentValidationError(f"Campo 'length' ausente no arquivo {f_idx} em 'files'.")
            f_len = file_dict[b"length"]
            if not isinstance(f_len, int) or isinstance(f_len, bool) or f_len < 0:
                raise TorrentValidationError(
                    f"Campo 'length' no arquivo {f_idx} deve ser um inteiro não-negativo (>= 0), obtido: {f_len!r}."
                )
            if b"path" not in file_dict:
                raise TorrentValidationError(f"Campo 'path' ausente no arquivo {f_idx} em 'files'.")
            f_path_list = file_dict[b"path"]
            if not isinstance(f_path_list, list) or len(f_path_list) == 0:
                raise TorrentValidationError(
                    f"Campo 'path' no arquivo {f_idx} deve ser uma lista não-vazia de segmentos de caminho."
                )
            path_segments = []
            for seg_idx, seg in enumerate(f_path_list):
                if not isinstance(seg, bytes):
                    raise TorrentValidationError(
                        f"Segmento de caminho {seg_idx} no arquivo {f_idx} deve ser byte string."
                    )
                seg_str = validate_safe_path_segment(seg.decode('utf-8', errors='replace'))
                path_segments.append(seg_str)

            f_md5 = None
            if b"md5sum" in file_dict and isinstance(file_dict[b"md5sum"], bytes):
                f_md5 = file_dict[b"md5sum"].decode('ascii', errors='replace')

            full_path = "/".join(path_segments)
            files_list.append(FileInfo(length=f_len, path=path_segments, full_path=full_path, md5sum=f_md5))
            total_length += f_len

    # 7. Extração e validação do campo 'pieces' e divisão em hashes SHA-1
    if b"pieces" not in info:
        raise TorrentValidationError("Campo obrigatório 'pieces' não encontrado na seção 'info'.")
    pieces_raw = info[b"pieces"]
    if not isinstance(pieces_raw, bytes):
        raise TorrentValidationError("Campo 'pieces' na seção 'info' deve ser bytes.")

    if len(pieces_raw) % 20 != 0:
        raise TorrentValidationError(
            f"Tamanho do campo 'pieces' ({len(pieces_raw)} bytes) não é múltiplo de 20 bytes."
        )

    piece_hashes = [pieces_raw[i : i + 20] for i in range(0, len(pieces_raw), 20)]

    # 8. Validação de consistência matemática: total_length vs piece_length vs num_pieces
    expected_pieces = math.ceil(total_length / piece_length) if total_length > 0 else 0

    if total_length > 0 and len(piece_hashes) == 0:
        raise TorrentValidationError(
            f"Torrent com tamanho total de {total_length} bytes não possui nenhum hash em 'pieces'."
        )
    if total_length == 0 and len(piece_hashes) > 0:
        raise TorrentValidationError(
            f"Torrent com tamanho 0 bytes possui {len(piece_hashes)} peças em 'pieces'."
        )
    if len(piece_hashes) != expected_pieces:
        raise TorrentValidationError(
            f"Inconsistência no número de peças: esperado {expected_pieces} peças para o tamanho total "
            f"de {total_length} bytes (piece_length={piece_length}), mas 'pieces' contém {len(piece_hashes)} hashes."
        )

    # 9. Extração de metadados opcionais
    comment = None
    if b"comment" in root_dict and isinstance(root_dict[b"comment"], bytes):
        comment = root_dict[b"comment"].decode('utf-8', errors='replace')

    created_by = None
    if b"created by" in root_dict and isinstance(root_dict[b"created by"], bytes):
        created_by = root_dict[b"created by"].decode('utf-8', errors='replace')

    creation_date = None
    if b"creation date" in root_dict and isinstance(root_dict[b"creation date"], int) and not isinstance(root_dict[b"creation date"], bool):
        creation_date = root_dict[b"creation date"]

    private = False
    if b"private" in info and isinstance(info[b"private"], int) and not isinstance(info[b"private"], bool):
        private = (info[b"private"] == 1)

    return TorrentMetadata(
        announce=announce,
        announce_list=announce_list,
        trackers=all_trackers,
        info_hash=info_hash,
        info_hash_hex=info_hash_hex,
        name=name,
        piece_length=piece_length,
        total_length=total_length,
        pieces=pieces_raw,
        piece_hashes=piece_hashes,
        raw_info_bytes=raw_info_bytes,
        is_multi_file=is_multi_file,
        files=files_list,
        comment=comment,
        created_by=created_by,
        creation_date=creation_date,
        private=private,
    )


def load_torrent_file(filepath: Union[str, Path]) -> TorrentMetadata:
    """
    Carrega um arquivo .torrent do sistema de arquivos e constrói o TorrentMetadata.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo torrent não encontrado: {path}")
    if path.is_dir():
        raise TorrentParseError(f"Caminho especificado é um diretório, não um arquivo: {path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as e:
        raise TorrentParseError(f"Falha ao ler o arquivo torrent do disco: {e}") from e

    return load_torrent_bytes(raw_bytes)

