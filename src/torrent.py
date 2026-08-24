"""
Módulo para parsing de arquivos .torrent e representação de metadados.

Extrai metadados essenciais e garante a captura byte-precisa da seção 'info'
para o cálculo correto do info_hash SHA-1.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Union

from .bencode import decode_bencode_with_offsets, BencodeError
from .hash_utils import compute_sha1


class TorrentError(Exception):
    """Exceção base para erros na camada de torrent."""
    pass


class TorrentParseError(TorrentError):
    """Exceção lançada quando o arquivo .torrent está malformado ou incompleto."""
    pass


@dataclass(frozen=True)
class TorrentMetadata:
    """
    Representação imutável dos metadados de um arquivo .torrent.
    """
    announce: str
    info_hash: bytes           # SHA-1 binário de 20 bytes da seção 'info'
    info_hash_hex: str       # String hexadecimal de 40 caracteres
    name: str
    piece_length: int          # Tamanho de cada peça em bytes
    total_length: int          # Tamanho total do arquivo em bytes
    piece_hashes: List[bytes]  # Lista de hashes SHA-1 de 20 bytes por peça
    raw_info_bytes: bytes      # Bytes brutos Bencoded originais da seção 'info'

    @property
    def num_pieces(self) -> int:
        """Retorna o número total de peças do torrent."""
        return len(self.piece_hashes)


def load_torrent_bytes(raw_bytes: bytes) -> TorrentMetadata:
    """
    Decodifica o buffer de bytes de um arquivo .torrent, extrai a fatia
    bruta exata do dicionário 'info' e constrói o TorrentMetadata.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise TorrentParseError(f"Entrada esperada como bytes, obtido {type(raw_bytes).__name__}.")

    raw_bytes = bytes(raw_bytes)

    try:
        root_dict, _, raw_slices = decode_bencode_with_offsets(raw_bytes)
    except BencodeError as e:
        raise TorrentParseError(f"Erro ao decodificar estrutura Bencode do torrent: {e}") from e

    if not isinstance(root_dict, dict):
        raise TorrentParseError("O arquivo .torrent deve conter um dicionário Bencode na raiz.")

    # 1. Valida existência da chave 'info' e extrai os bytes brutos exatos (byte-slice)
    if b"info" not in root_dict or b"info" not in raw_slices:
        raise TorrentParseError("Dicionário obrigatório 'info' não encontrado no arquivo .torrent.")

    info_start, info_end = raw_slices[b"info"]
    raw_info_bytes = raw_bytes[info_start:info_end]

    # 2. Calcula o info_hash SHA-1 estritamente sobre a fatia bruta original
    info_hash = compute_sha1(raw_info_bytes)
    info_hash_hex = info_hash.hex()

    # 3. Processa os dados da seção 'info'
    info = root_dict[b"info"]
    if not isinstance(info, dict):
        raise TorrentParseError("A seção 'info' do torrent deve ser um dicionário.")

    # Extrai announce
    announce_raw = root_dict.get(b"announce", b"")
    if isinstance(announce_raw, bytes):
        announce = announce_raw.decode('utf-8', errors='replace')
    else:
        announce = str(announce_raw)

    # Extrai name
    name_raw = info.get(b"name", b"unnamed_torrent")
    if isinstance(name_raw, bytes):
        name = name_raw.decode('utf-8', errors='replace')
    else:
        name = str(name_raw)

    # Extrai piece length
    piece_length = info.get(b"piece length")
    if not isinstance(piece_length, int) or piece_length <= 0:
        raise TorrentParseError("Campo 'piece length' ausente ou inválido na seção 'info'.")

    # Extrai total length (Suporte single-file e multi-file)
    if b"length" in info:
        length_val = info[b"length"]
        if not isinstance(length_val, int) or length_val < 0:
            raise TorrentParseError("Campo 'length' inválido na seção 'info'.")
        total_length = length_val
    elif b"files" in info and isinstance(info[b"files"], list):
        total = 0
        for f in info[b"files"]:
            if isinstance(f, dict) and b"length" in f and isinstance(f[b"length"], int):
                total += f[b"length"]
        total_length = total
    else:
        raise TorrentParseError("Tamanho do arquivo ('length' ou 'files') não encontrado na seção 'info'.")

    # Extrai pieces (String binária com hashes concatenados de 20 bytes cada)
    pieces_raw = info.get(b"pieces")
    if not isinstance(pieces_raw, bytes):
        raise TorrentParseError("Campo 'pieces' ausente ou deve ser bytes na seção 'info'.")

    if len(pieces_raw) % 20 != 0:
        raise TorrentParseError(
            f"Tamanho do campo 'pieces' ({len(pieces_raw)} bytes) não é múltiplo de 20 bytes."
        )

    piece_hashes = [pieces_raw[i : i + 20] for i in range(0, len(pieces_raw), 20)]

    return TorrentMetadata(
        announce=announce,
        info_hash=info_hash,
        info_hash_hex=info_hash_hex,
        name=name,
        piece_length=piece_length,
        total_length=total_length,
        piece_hashes=piece_hashes,
        raw_info_bytes=raw_info_bytes,
    )


def load_torrent_file(filepath: Union[str, Path]) -> TorrentMetadata:
    """
    Carrega um arquivo .torrent do sistema de arquivos e constrói o TorrentMetadata.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo torrent não encontrado: {path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as e:
        raise TorrentParseError(f"Falha ao ler o arquivo torrent do disco: {e}") from e

    return load_torrent_bytes(raw_bytes)
