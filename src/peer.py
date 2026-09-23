"""
Módulo para a camada de protocolo de comunicação entre peers BitTorrent (Peer Wire Protocol).

Implementa a especificação BEP 0003:
- Conexão TCP robusta com peers;
- Montagem, envio e validação do Handshake de 68 bytes;
- Enquadramento (framing) e buffering de mensagens por prefixo de tamanho de 4 bytes (big-endian);
- Codificação e decodificação de todos os tipos de mensagens padrão:
  - Keep-Alive (len=0)
  - Choke (id=0)
  - Unchoke (id=1)
  - Interested (id=2)
  - Not Interested (id=3)
  - Have (id=4)
  - Bitfield (id=5)
  - Request (id=6)
  - Piece (id=7)
  - Cancel (id=8)
  - Port (id=9, BEP 0005)
- Suporte a leitura exata de N bytes com proteção contra fragmentação de rede;
- Tratamento de múltiplas mensagens em uma única leitura (packet coalescing);
- Proteção contra mensagens com tamanhos excessivos (Memory Exhaustion / DoS);
- Gerenciador de conexão de alto nível `PeerConnection` com controle de estados (choking/interested).
"""

import math
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, List, Optional, Tuple, Union


# ==============================================================================
# Constantes do Protocolo
# ==============================================================================

HANDSHAKE_PSTR = b"BitTorrent protocol"
HANDSHAKE_PSTRLEN = 19
HANDSHAKE_LENGTH = 68  # 1 byte pstrlen + 19 bytes pstr + 8 bytes reserved + 20 bytes info_hash + 20 bytes peer_id

# Tamanho padrão do bloco requisitado (16 KB)
DEFAULT_BLOCK_SIZE = 16384

# Limite máximo seguro para tamanho de bloco individual (128 KB)
MAX_BLOCK_SIZE = 128 * 1024

# Limite de segurança para tamanho de mensagens individuais (2 MB) para evitar estouro de memória
MAX_MESSAGE_LENGTH = 2 * 1024 * 1024

# Limite máximo para o buffer de recepção interno de um peer (4 MB) contra ataques de exaustão de memória
MAX_PEER_BUFFER_SIZE = 4 * 1024 * 1024


class MessageID(IntEnum):
    """Identificadores numéricos padrão de mensagens BitTorrent (BEP 0003)."""
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOT_INTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8
    PORT = 9


# ==============================================================================
# Exceções
# ==============================================================================

class PeerError(Exception):
    """Exceção base para erros na camada de protocolo de peers."""
    pass


class PeerConnectionError(PeerError):
    """Falha de conexão com o peer remoto (recusa, erro de rede, etc.)."""
    pass


class PeerConnectionClosedError(PeerConnectionError):
    """Conexão foi encerrada prematuramente pelo peer remoto (EOF recebido)."""
    pass


class PeerTimeoutError(PeerConnectionError):
    """Tempo limite (timeout) excedido durante operação de conexão, envio ou leitura."""
    pass


class PeerProtocolError(PeerError):
    """Violação das regras do protocolo BitTorrent (dados corrompidos, campos inválidos)."""
    pass


class HandshakeError(PeerProtocolError):
    """Falha na validação ou negociação do Handshake com o peer."""
    pass


class MessageSizeError(PeerProtocolError):
    """Mensagem excede o limite máximo permitido ou possui tamanho incompatível com seu tipo."""
    pass


# ==============================================================================
# Estrutura do Handshake
# ==============================================================================

@dataclass(frozen=True)
class Handshake:
    """
    Representação do handshake BitTorrent (68 bytes).
    """
    info_hash: bytes
    peer_id: bytes
    pstr: bytes = HANDSHAKE_PSTR
    reserved: bytes = b"\x00" * 8

    def __post_init__(self):
        if not isinstance(self.info_hash, (bytes, bytearray)) or len(self.info_hash) != 20:
            raise ValueError(f"info_hash deve ter exatamente 20 bytes, obtido {len(self.info_hash) if isinstance(self.info_hash, (bytes, bytearray)) else type(self.info_hash).__name__}.")
        if not isinstance(self.peer_id, (bytes, bytearray)) or len(self.peer_id) != 20:
            raise ValueError(f"peer_id deve ter exatamente 20 bytes, obtido {len(self.peer_id) if isinstance(self.peer_id, (bytes, bytearray)) else type(self.peer_id).__name__}.")
        if not isinstance(self.reserved, (bytes, bytearray)) or len(self.reserved) != 8:
            raise ValueError(f"reserved deve ter exatamente 8 bytes, obtido {len(self.reserved) if isinstance(self.reserved, (bytes, bytearray)) else type(self.reserved).__name__}.")
        if self.pstr != HANDSHAKE_PSTR:
            raise ValueError(f"pstr deve ser {HANDSHAKE_PSTR!r}, obtido {self.pstr!r}.")

    def encode(self) -> bytes:
        """Serializa o Handshake em seus 68 bytes binários."""
        return encode_handshake(
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            reserved=self.reserved,
            pstr=self.pstr,
        )


def encode_handshake(
    info_hash: Union[bytes, bytearray],
    peer_id: Union[bytes, bytearray],
    reserved: Union[bytes, bytearray] = b"\x00" * 8,
    pstr: bytes = HANDSHAKE_PSTR,
) -> bytes:
    """
    Monta os 68 bytes binários do Handshake BitTorrent.
    Formato: <1 byte pstrlen><pstr><8 bytes reserved><20 bytes info_hash><20 bytes peer_id>
    """
    if len(pstr) != HANDSHAKE_PSTRLEN:
        raise ValueError(f"pstr deve ter {HANDSHAKE_PSTRLEN} bytes, obtido {len(pstr)}.")
    info_bytes = bytes(info_hash)
    if len(info_bytes) != 20:
        raise ValueError(f"info_hash deve ter exatamente 20 bytes, obtido {len(info_bytes)} bytes.")
    peer_id_bytes = bytes(peer_id)
    if len(peer_id_bytes) != 20:
        raise ValueError(f"peer_id deve ter exatamente 20 bytes, obtido {len(peer_id_bytes)} bytes.")
    reserved_bytes = bytes(reserved)
    if len(reserved_bytes) != 8:
        raise ValueError(f"reserved deve ter exatamente 8 bytes, obtido {len(reserved_bytes)} bytes.")

    return struct.pack("!B", len(pstr)) + pstr + reserved_bytes + info_bytes + peer_id_bytes


def parse_handshake(
    data: Union[bytes, bytearray, memoryview],
    expected_info_hash: Optional[Union[bytes, bytearray]] = None,
    expected_peer_id: Optional[Union[bytes, bytearray]] = None,
) -> Handshake:
    """
    Decodifica e valida os 68 bytes recebidos de um Handshake.

    Raises:
        HandshakeError: Se o tamanho, protocolo, info_hash ou peer_id forem inválidos.
    """
    raw = bytes(data)
    if len(raw) != HANDSHAKE_LENGTH:
        raise HandshakeError(
            f"Tamanho do handshake inválido: esperado {HANDSHAKE_LENGTH} bytes, obtido {len(raw)} bytes."
        )

    pstrlen = raw[0]
    if pstrlen != HANDSHAKE_PSTRLEN:
        raise HandshakeError(
            f"pstrlen inválido no handshake: esperado {HANDSHAKE_PSTRLEN}, obtido {pstrlen}."
        )

    pstr = raw[1 : 1 + pstrlen]
    if pstr != HANDSHAKE_PSTR:
        raise HandshakeError(
            f"Identificador de protocolo inválido no handshake: esperado {HANDSHAKE_PSTR!r}, obtido {pstr!r}."
        )

    reserved = raw[1 + pstrlen : 1 + pstrlen + 8]
    info_hash = raw[1 + pstrlen + 8 : 1 + pstrlen + 8 + 20]
    peer_id = raw[1 + pstrlen + 8 + 20 : 1 + pstrlen + 8 + 20 + 20]

    if expected_info_hash is not None:
        expected_hash_bytes = bytes(expected_info_hash)
        if info_hash != expected_hash_bytes:
            raise HandshakeError(
                f"info_hash divergente no handshake do peer: "
                f"esperado {expected_hash_bytes.hex()}, obtido {info_hash.hex()}."
            )

    if expected_peer_id is not None:
        expected_pid_bytes = bytes(expected_peer_id)
        if peer_id != expected_pid_bytes:
            raise HandshakeError(
                f"peer_id divergente no handshake do peer: "
                f"esperado {expected_pid_bytes.hex()}, obtido {peer_id.hex()}."
            )

    return Handshake(
        info_hash=info_hash,
        peer_id=peer_id,
        pstr=pstr,
        reserved=reserved,
    )


# ==============================================================================
# Estrutura Auxiliar Bitfield
# ==============================================================================

class Bitfield:
    """
    Representação eficiente e manipulável do bitfield de peças BitTorrent (BEP 0003).

    Cada bit representa a posse de uma peça pelo peer (1 = presente, 0 = ausente).
    O bit de ordem mais alta (0x80) no primeiro byte representa a peça de índice 0.
    """

    def __init__(self, num_pieces: int, initial_bytes: Optional[Union[bytes, bytearray]] = None):
        if num_pieces < 0:
            raise ValueError(f"num_pieces não pode ser negativo: {num_pieces}")
        self.num_pieces = num_pieces
        expected_len = (num_pieces + 7) // 8

        if initial_bytes is not None:
            raw = bytes(initial_bytes)
            if len(raw) != expected_len:
                raise ValueError(
                    f"Tamanho do bitfield ({len(raw)} bytes) incompatível com "
                    f"num_pieces={num_pieces} (esperado {expected_len} bytes)."
                )
            # Validação estrita de bits sobressalentes (BEP 0003)
            spare_bits = (expected_len * 8) - num_pieces
            if spare_bits > 0 and len(raw) > 0:
                mask = (1 << spare_bits) - 1
                if raw[-1] & mask != 0:
                    raise PeerProtocolError(
                        f"Bitfield inválido: bits sobressalentes não-nulos detectados no final do bitfield (spare_bits={spare_bits})."
                    )
            self._data = bytearray(raw)
        else:
            self._data = bytearray(expected_len)

    def has_piece(self, index: int) -> bool:
        """Verifica se a peça no índice especificado está presente (True) ou ausente (False)."""
        if not (0 <= index < self.num_pieces):
            raise IndexError(f"Índice de peça fora do intervalo: {index} (total: {self.num_pieces})")
        byte_idx = index // 8
        bit_idx = 7 - (index % 8)
        return bool(self._data[byte_idx] & (1 << bit_idx))

    def set_piece(self, index: int, value: bool = True) -> None:
        """Define o estado de posse da peça no índice informado."""
        if not (0 <= index < self.num_pieces):
            raise IndexError(f"Índice de peça fora do intervalo: {index} (total: {self.num_pieces})")
        byte_idx = index // 8
        bit_idx = 7 - (index % 8)
        if value:
            self._data[byte_idx] |= (1 << bit_idx)
        else:
            self._data[byte_idx] &= ~(1 << bit_idx)

    def count(self) -> int:
        """Retorna a contagem total de peças presentes."""
        return sum(1 for i in range(self.num_pieces) if self.has_piece(i))

    @property
    def is_complete(self) -> bool:
        """Indica se todas as peças do torrent estão presentes (seeder)."""
        return self.count() == self.num_pieces

    def to_bytes(self) -> bytes:
        """Retorna a representação em bytes do bitfield."""
        return bytes(self._data)

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray], num_pieces: Optional[int] = None) -> "Bitfield":
        """Constrói uma instância a partir de bytes brutos."""
        raw = bytes(data)
        pieces_count = num_pieces if num_pieces is not None else len(raw) * 8
        return cls(num_pieces=pieces_count, initial_bytes=raw)

    def __repr__(self) -> str:
        return f"<Bitfield: {self.count()}/{self.num_pieces} peças>"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Bitfield):
            return False
        return self.num_pieces == other.num_pieces and self.to_bytes() == other.to_bytes()


# ==============================================================================
# Mensagens do Peer Wire Protocol
# ==============================================================================

class PeerMessage:
    """Classe base para todas as mensagens do Peer Protocol."""

    def encode(self) -> bytes:
        """Serializa a mensagem completa com o prefixo de 4 bytes de tamanho."""
        raise NotImplementedError


@dataclass(frozen=True)
class KeepAliveMessage(PeerMessage):
    """Mensagem Keep-Alive: tamanho=0, sem ID e sem payload (4 bytes: 00 00 00 00)."""
    msg_id: Optional[int] = None

    def encode(self) -> bytes:
        return struct.pack("!I", 0)


@dataclass(frozen=True)
class ChokeMessage(PeerMessage):
    """Mensagem Choke: ID=0, notifica que o remetente não atenderá requisições."""
    msg_id: Optional[int] = MessageID.CHOKE

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.CHOKE)


@dataclass(frozen=True)
class UnchokeMessage(PeerMessage):
    """Mensagem Unchoke: ID=1, notifica que o remetente está pronto para atender requisições."""
    msg_id: Optional[int] = MessageID.UNCHOKE

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.UNCHOKE)


@dataclass(frozen=True)
class InterestedMessage(PeerMessage):
    """Mensagem Interested: ID=2, notifica interesse em baixar peças do peer."""
    msg_id: Optional[int] = MessageID.INTERESTED

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.INTERESTED)


@dataclass(frozen=True)
class NotInterestedMessage(PeerMessage):
    """Mensagem Not Interested: ID=3, notifica falta de interesse nas peças do peer."""
    msg_id: Optional[int] = MessageID.NOT_INTERESTED

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.NOT_INTERESTED)


@dataclass(frozen=True)
class HaveMessage(PeerMessage):
    """Mensagem Have: ID=4, notifica que o peer baixou e validou com sucesso uma peça específica."""
    piece_index: int
    msg_id: Optional[int] = MessageID.HAVE

    def __post_init__(self):
        if not isinstance(self.piece_index, int) or isinstance(self.piece_index, bool) or self.piece_index < 0:
            raise ValueError(f"piece_index deve ser inteiro não-negativo, obtido {self.piece_index!r}.")

    def encode(self) -> bytes:
        return struct.pack("!IBI", 5, MessageID.HAVE, self.piece_index)


@dataclass(frozen=True)
class BitfieldMessage(PeerMessage):
    """Mensagem Bitfield: ID=5, envia o mapa de peças possuídas pelo peer."""
    bitfield: bytes
    msg_id: Optional[int] = MessageID.BITFIELD

    def __post_init__(self):
        if not isinstance(self.bitfield, (bytes, bytearray)):
            raise TypeError(f"bitfield deve ser bytes, obtido {type(self.bitfield).__name__}.")

    def encode(self) -> bytes:
        raw = bytes(self.bitfield)
        return struct.pack("!IB", 1 + len(raw), MessageID.BITFIELD) + raw

    def to_bitfield(self, num_pieces: Optional[int] = None) -> Bitfield:
        """Converte os bytes desta mensagem em uma instância manipulável de Bitfield."""
        return Bitfield.from_bytes(self.bitfield, num_pieces=num_pieces)


@dataclass(frozen=True)
class RequestMessage(PeerMessage):
    """
    Mensagem Request: ID=6, requisita um bloco de dados de uma peça ao peer.
    - index: índice da peça (uint32)
    - begin: deslocamento em bytes dentro da peça (uint32)
    - length: tamanho do bloco requisitado em bytes (uint32, tipicamente 16384)
    """
    index: int
    begin: int
    length: int
    msg_id: Optional[int] = MessageID.REQUEST

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin), ("length", self.length)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} deve ser um inteiro não-negativo, obtido {val!r}.")
        if self.length == 0:
            raise ValueError("length do bloco requisitado não pode ser zero.")

    def encode(self) -> bytes:
        return struct.pack("!IBIII", 13, MessageID.REQUEST, self.index, self.begin, self.length)


@dataclass(frozen=True)
class PieceMessage(PeerMessage):
    """
    Mensagem Piece: ID=7, entrega um bloco de dados de uma peça requisitada.
    - index: índice da peça (uint32)
    - begin: deslocamento em bytes dentro da peça (uint32)
    - block: conteúdo binário do bloco
    """
    index: int
    begin: int
    block: bytes
    msg_id: Optional[int] = MessageID.PIECE

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} deve ser um inteiro não-negativo, obtido {val!r}.")
        if not isinstance(self.block, (bytes, bytearray)):
            raise TypeError(f"block deve ser bytes, obtido {type(self.block).__name__}.")

    def encode(self) -> bytes:
        raw_block = bytes(self.block)
        return struct.pack("!IBII", 9 + len(raw_block), MessageID.PIECE, self.index, self.begin) + raw_block


@dataclass(frozen=True)
class CancelMessage(PeerMessage):
    """
    Mensagem Cancel: ID=8, cancela uma requisição de bloco previamente enviada.
    """
    index: int
    begin: int
    length: int
    msg_id: Optional[int] = MessageID.CANCEL

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin), ("length", self.length)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} deve ser um inteiro não-negativo, obtido {val!r}.")
        if self.length == 0:
            raise ValueError("length do cancel não pode ser zero.")

    def encode(self) -> bytes:
        return struct.pack("!IBIII", 13, MessageID.CANCEL, self.index, self.begin, self.length)


@dataclass(frozen=True)
class PortMessage(PeerMessage):
    """
    Mensagem Port (BEP 0005): ID=9, indica a porta de escuta da DHT UDP do peer.
    """
    listen_port: int
    msg_id: Optional[int] = MessageID.PORT

    def __post_init__(self):
        if not isinstance(self.listen_port, int) or isinstance(self.listen_port, bool) or not (0 < self.listen_port <= 65535):
            raise ValueError(f"listen_port deve ser entre 1 e 65535, obtido {self.listen_port!r}.")

    def encode(self) -> bytes:
        return struct.pack("!IBH", 3, MessageID.PORT, self.listen_port)


@dataclass(frozen=True)
class UnknownMessage(PeerMessage):
    """Representação de mensagem com ID desconhecido para extensão futura."""
    msg_id: Optional[int]
    payload: bytes

    def encode(self) -> bytes:
        raw = bytes(self.payload)
        id_val = self.msg_id if self.msg_id is not None else 0
        return struct.pack("!IB", 1 + len(raw), id_val) + raw


# ==============================================================================
# Construtores Rápidos e Encoders
# ==============================================================================

def encode_keep_alive() -> bytes:
    """Retorna os bytes da mensagem Keep-Alive (4 bytes zerados)."""
    return KeepAliveMessage().encode()


def encode_choke() -> bytes:
    """Retorna os bytes da mensagem Choke."""
    return ChokeMessage().encode()


def encode_unchoke() -> bytes:
    """Retorna os bytes da mensagem Unchoke."""
    return UnchokeMessage().encode()


def encode_interested() -> bytes:
    """Retorna os bytes da mensagem Interested."""
    return InterestedMessage().encode()


def encode_not_interested() -> bytes:
    """Retorna os bytes da mensagem Not Interested."""
    return NotInterestedMessage().encode()


def encode_have(piece_index: int) -> bytes:
    """Retorna os bytes da mensagem Have para o índice informado."""
    return HaveMessage(piece_index=piece_index).encode()


def encode_bitfield(bitfield: Union[bytes, bytearray, Bitfield]) -> bytes:
    """Retorna os bytes da mensagem Bitfield."""
    raw = bitfield.to_bytes() if isinstance(bitfield, Bitfield) else bytes(bitfield)
    return BitfieldMessage(bitfield=raw).encode()


def encode_request(index: int, begin: int, length: int) -> bytes:
    """Retorna os bytes da mensagem Request."""
    return RequestMessage(index=index, begin=begin, length=length).encode()


def encode_piece(index: int, begin: int, block: Union[bytes, bytearray]) -> bytes:
    """Retorna os bytes da mensagem Piece."""
    return PieceMessage(index=index, begin=begin, block=bytes(block)).encode()


def encode_cancel(index: int, begin: int, length: int) -> bytes:
    """Retorna os bytes da mensagem Cancel."""
    return CancelMessage(index=index, begin=begin, length=length).encode()


def encode_port(listen_port: int) -> bytes:
    """Retorna os bytes da mensagem Port."""
    return PortMessage(listen_port=listen_port).encode()


def encode_message(msg: PeerMessage) -> bytes:
    """Serializa qualquer objeto PeerMessage em seu formato binário."""
    if not isinstance(msg, PeerMessage):
        raise TypeError(f"Esperado PeerMessage, obtido {type(msg).__name__}.")
    return msg.encode()


# ==============================================================================
# Parsers de Mensagens
# ==============================================================================

def parse_message_payload(length: int, payload: bytes) -> PeerMessage:
    """
    Decodifica o conteúdo de uma mensagem a partir do seu prefixo de tamanho e payload.

    Args:
        length: Valor inteiro do prefixo de 4 bytes (tamanho de ID + dados).
        payload: Bytes exatamente correspondentes a `length` (contendo ID + dados).

    Raises:
        PeerProtocolError / MessageSizeError: Se a mensagem estiver truncada ou malformada.
    """
    if len(payload) != length:
        raise PeerProtocolError(
            f"Tamanho do payload ({len(payload)} bytes) diverge do length prefix ({length} bytes)."
        )

    if length == 0:
        return KeepAliveMessage()

    msg_id = payload[0]
    data = payload[1:]

    if msg_id == MessageID.CHOKE:
        if length != 1:
            raise MessageSizeError(f"Mensagem Choke deve ter length=1, obtido {length}.")
        return ChokeMessage()

    elif msg_id == MessageID.UNCHOKE:
        if length != 1:
            raise MessageSizeError(f"Mensagem Unchoke deve ter length=1, obtido {length}.")
        return UnchokeMessage()

    elif msg_id == MessageID.INTERESTED:
        if length != 1:
            raise MessageSizeError(f"Mensagem Interested deve ter length=1, obtido {length}.")
        return InterestedMessage()

    elif msg_id == MessageID.NOT_INTERESTED:
        if length != 1:
            raise MessageSizeError(f"Mensagem Not Interested deve ter length=1, obtido {length}.")
        return NotInterestedMessage()

    elif msg_id == MessageID.HAVE:
        if length != 5 or len(data) != 4:
            raise MessageSizeError(f"Mensagem Have deve ter length=5 (4 bytes de índice), obtido {length}.")
        piece_index = struct.unpack("!I", data)[0]
        return HaveMessage(piece_index=piece_index)

    elif msg_id == MessageID.BITFIELD:
        if length < 1:
            raise MessageSizeError(f"Mensagem Bitfield com tamanho inválido: {length}.")
        return BitfieldMessage(bitfield=data)

    elif msg_id == MessageID.REQUEST:
        if length != 13 or len(data) != 12:
            raise MessageSizeError(f"Mensagem Request deve ter length=13 (12 bytes de payload), obtido {length}.")
        index, begin, block_length = struct.unpack("!III", data)
        if block_length > MAX_BLOCK_SIZE:
            raise MessageSizeError(
                f"Tamanho do bloco solicitado ({block_length} bytes) excede o limite máximo ({MAX_BLOCK_SIZE} bytes)."
            )
        return RequestMessage(index=index, begin=begin, length=block_length)

    elif msg_id == MessageID.PIECE:
        if length < 9 or len(data) < 8:
            raise MessageSizeError(f"Mensagem Piece deve ter length >= 9, obtido {length}.")
        index, begin = struct.unpack("!II", data[:8])
        block = data[8:]
        if len(block) > MAX_BLOCK_SIZE:
            raise MessageSizeError(
                f"Tamanho do bloco recebido ({len(block)} bytes) excede o limite máximo ({MAX_BLOCK_SIZE} bytes)."
            )
        return PieceMessage(index=index, begin=begin, block=block)

    elif msg_id == MessageID.CANCEL:
        if length != 13 or len(data) != 12:
            raise MessageSizeError(f"Mensagem Cancel deve ter length=13 (12 bytes de payload), obtido {length}.")
        index, begin, block_length = struct.unpack("!III", data)
        if block_length > MAX_BLOCK_SIZE:
            raise MessageSizeError(
                f"Tamanho do bloco no Cancel ({block_length} bytes) excede o limite máximo ({MAX_BLOCK_SIZE} bytes)."
            )
        return CancelMessage(index=index, begin=begin, length=block_length)

    elif msg_id == MessageID.PORT:
        if length != 3 or len(data) != 2:
            raise MessageSizeError(f"Mensagem Port deve ter length=3 (2 bytes de payload), obtido {length}.")
        port = struct.unpack("!H", data)[0]
        return PortMessage(listen_port=port)

    else:
        return UnknownMessage(msg_id=msg_id, payload=data)


def parse_message(raw_msg_bytes: Union[bytes, bytearray, memoryview]) -> PeerMessage:
    """
    Decodifica uma mensagem serializada completa a partir do seu buffer bruto
    (incluindo o prefixo de 4 bytes de tamanho).
    """
    raw = bytes(raw_msg_bytes)
    if len(raw) < 4:
        raise PeerProtocolError(f"Buffer insuficiente ({len(raw)} bytes) para conter o length prefix de 4 bytes.")

    length = struct.unpack("!I", raw[:4])[0]
    payload = raw[4:]

    if len(payload) != length:
        raise PeerProtocolError(
            f"Tamanho do payload recebido ({len(payload)} bytes) diverge do prefixo de tamanho ({length} bytes)."
        )

    return parse_message_payload(length, payload)


def parse_messages_from_buffer(
    buffer: bytearray,
    max_message_length: int = MAX_MESSAGE_LENGTH,
) -> List[PeerMessage]:
    """
    Consome e decodifica todas as mensagens completas contidas no buffer mutável fornecido.
    Mensagens parciais ou incompletas são preservadas no buffer para leitura posterior.
    """
    messages: List[PeerMessage] = []

    while len(buffer) >= 4:
        length = struct.unpack("!I", buffer[:4])[0]

        if length > max_message_length:
            raise MessageSizeError(
                f"Tamanho de mensagem {length} bytes excede o limite permitido ({max_message_length} bytes)."
            )

        total_needed = 4 + length
        if len(buffer) < total_needed:
            # Mensagem incompleta, aguarda mais dados
            break

        msg_chunk = bytes(buffer[:total_needed])
        del buffer[:total_needed]
        messages.append(parse_message(msg_chunk))

    return messages


# ==============================================================================
# Gerenciador de Conexão TCP (PeerConnection)
# ==============================================================================

class PeerConnection:
    """
    Gerenciador robusto de conexão TCP de baixo e médio nível com um peer BitTorrent.

    Recursos:
    - Leitura precisa de exatamente N bytes (`recv_exact`) com buffer interno;
    - Proteção contra fragmentação TCP e absorção de múltiplas mensagens por leitura;
    - Handshake completo com envio e validação estrita;
    - Leitura estruturada de mensagens com verificação de limites máximos;
    - Envio seguro de mensagens (`send_exact`, `send_message`);
    - Rastreamento dos estados do protocolo (choking e interested de ambos os lados);
    - Suporte a context manager (`with PeerConnection(...)`).
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        sock: Optional[socket.socket] = None,
        default_timeout: float = 10.0,
        num_pieces: Optional[int] = None,
    ):
        self.peer_host = host
        self.peer_port = port
        self.default_timeout = default_timeout
        self.num_pieces = num_pieces
        self._sock: Optional[socket.socket] = sock
        self._buffer = bytearray()
        self.peer_handshake: Optional[Handshake] = None

        # Estados de controle do protocolo (BEP 0003)
        self.am_choking: bool = True
        self.am_interested: bool = False
        self.peer_choking: bool = True
        self.peer_interested: bool = False
        self.peer_bitfield: Optional[Bitfield] = None

        if self._sock is not None:
            self._sock.settimeout(self.default_timeout)

    @property
    def is_connected(self) -> bool:
        """Verifica se o socket está instanciado."""
        return self._sock is not None

    def connect(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        """
        Estabelece a conexão TCP com o peer remoto.
        """
        if host is not None:
            self.peer_host = host
        if port is not None:
            self.peer_port = port

        if not self.peer_host or not self.peer_port:
            raise ValueError("Host e porta do peer são obrigatórios para estabelecer a conexão.")

        connect_timeout = timeout if timeout is not None else self.default_timeout
        try:
            self._sock = socket.create_connection(
                (self.peer_host, self.peer_port),
                timeout=connect_timeout,
            )
            # Desativa o algoritmo de Nagle para envio imediato de mensagens curtas
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock.settimeout(self.default_timeout)
        except (socket.timeout, TimeoutError) as e:
            raise PeerTimeoutError(
                f"Timeout ao conectar ao peer {self.peer_host}:{self.peer_port} após {connect_timeout}s."
            ) from e
        except socket.error as e:
            raise PeerConnectionError(
                f"Falha ao conectar ao peer {self.peer_host}:{self.peer_port}: {e}"
            ) from e

    def close(self) -> None:
        """Fecha o socket e limpa o buffer interno."""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._buffer.clear()

    def __enter__(self) -> "PeerConnection":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def recv_exact(self, n: int, timeout: Optional[float] = None) -> bytes:
        """
        Lê exatamente N bytes da conexão ou do buffer interno.

        Bloqueia de maneira robusta até que todos os N bytes tenham sido acumulados.

        Raises:
            PeerConnectionError: Se o socket não estiver conectado.
            PeerConnectionClosedError: Se a conexão for fechada antes de receber N bytes.
            PeerTimeoutError: Se o tempo limite de leitura for atingido.
        """
        if n < 0:
            raise ValueError(f"Quantidade de bytes não pode ser negativa: {n}")
        if n == 0:
            return b""

        # Se já temos os bytes no buffer interno, extrai imediatamente
        if len(self._buffer) >= n:
            chunk = bytes(self._buffer[:n])
            del self._buffer[:n]
            return chunk

        if self._sock is None:
            raise PeerConnectionError("Socket não conectado.")

        effective_timeout = timeout if timeout is not None else self.default_timeout
        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(effective_timeout)

        try:
            while len(self._buffer) < n:
                needed = n - len(self._buffer)
                read_size = max(4096, needed)
                try:
                    data = self._sock.recv(read_size)
                except (socket.timeout, TimeoutError) as e:
                    raise PeerTimeoutError(
                        f"Timeout aguardando {needed} bytes do peer ({self.peer_host}:{self.peer_port})."
                    ) from e
                except socket.error as e:
                    raise PeerConnectionError(
                        f"Erro de socket ao receber dados do peer: {e}"
                    ) from e

                if not data:
                    raise PeerConnectionClosedError(
                        f"Conexão fechada pelo peer ({self.peer_host}:{self.peer_port}) antes de receber {n} bytes "
                        f"(obtido {len(self._buffer)} bytes, faltavam {needed} bytes)."
                    )

                self._buffer.extend(data)
                if len(self._buffer) > MAX_PEER_BUFFER_SIZE:
                    raise MessageSizeError(
                        f"Buffer de recepção do peer ({self.peer_host}:{self.peer_port}) excedeu o limite máximo seguro ({MAX_PEER_BUFFER_SIZE} bytes)."
                    )

            chunk = bytes(self._buffer[:n])
            del self._buffer[:n]
            return chunk

        finally:
            if self._sock is not None:
                try:
                    self._sock.settimeout(old_timeout)
                except Exception:
                    pass

    def send_exact(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """
        Envia exatamente todos os bytes fornecidos através do socket.

        Raises:
            PeerConnectionError: Se o socket não estiver conectado ou ocorrer erro de rede.
            PeerTimeoutError: Se o timeout de escrita for atingido.
        """
        if self._sock is None:
            raise PeerConnectionError("Socket não conectado.")

        data_bytes = bytes(data)
        if not data_bytes:
            return

        try:
            self._sock.sendall(data_bytes)
        except (socket.timeout, TimeoutError) as e:
            raise PeerTimeoutError(
                f"Timeout ao enviar {len(data_bytes)} bytes para o peer ({self.peer_host}:{self.peer_port})."
            ) from e
        except socket.error as e:
            raise PeerConnectionError(
                f"Erro ao enviar dados para o peer ({self.peer_host}:{self.peer_port}): {e}"
            ) from e

    def perform_handshake(
        self,
        info_hash: Union[bytes, bytearray],
        peer_id: Union[bytes, bytearray],
        expected_peer_id: Optional[Union[bytes, bytearray]] = None,
        reserved: Union[bytes, bytearray] = b"\x00" * 8,
        timeout: Optional[float] = None,
    ) -> Handshake:
        """
        Executa a negociação de Handshake completa:
        1. Envia o handshake de 68 bytes deste cliente;
        2. Lê exatamente os 68 bytes do handshake de resposta do peer;
        3. Valida pstrlen, pstr e info_hash (e opcionalmente peer_id).
        """
        outbound = encode_handshake(
            info_hash=info_hash,
            peer_id=peer_id,
            reserved=reserved,
        )
        self.send_exact(outbound)

        inbound_bytes = self.recv_exact(HANDSHAKE_LENGTH, timeout=timeout)
        handshake = parse_handshake(
            inbound_bytes,
            expected_info_hash=info_hash,
            expected_peer_id=expected_peer_id,
        )
        self.peer_handshake = handshake
        return handshake

    def read_message(
        self,
        max_message_length: int = MAX_MESSAGE_LENGTH,
        timeout: Optional[float] = None,
    ) -> PeerMessage:
        """
        Lê e decodifica a próxima mensagem BitTorrent do stream.

        1. Lê o prefixo de 4 bytes do tamanho;
        2. Valida o limite de segurança contra mensagens excessivas;
        3. Lê exatamente o payload de tamanho `length`;
        4. Decodifica a mensagem e atualiza o estado interno da conexão.
        """
        len_bytes = self.recv_exact(4, timeout=timeout)
        length = struct.unpack("!I", len_bytes)[0]

        if length > max_message_length:
            raise MessageSizeError(
                f"Tamanho de mensagem {length} bytes excede o limite permitido ({max_message_length} bytes)."
            )

        if length == 0:
            return KeepAliveMessage()

        payload = self.recv_exact(length, timeout=timeout)
        msg = parse_message_payload(length, payload)

        # Atualiza os estados locais automaticamente com base na mensagem recebida
        self._update_state_from_received_message(msg)

        return msg

    def _update_state_from_received_message(self, msg: PeerMessage) -> None:
        """Atualiza flags de controle a partir de uma mensagem recebida do peer."""
        if isinstance(msg, ChokeMessage):
            self.peer_choking = True
        elif isinstance(msg, UnchokeMessage):
            self.peer_choking = False
        elif isinstance(msg, InterestedMessage):
            self.peer_interested = True
        elif isinstance(msg, NotInterestedMessage):
            self.peer_interested = False
        elif isinstance(msg, BitfieldMessage):
            self.peer_bitfield = msg.to_bitfield(num_pieces=self.num_pieces)
        elif isinstance(msg, HaveMessage):
            if self.peer_bitfield is not None and msg.piece_index < self.peer_bitfield.num_pieces:
                self.peer_bitfield.set_piece(msg.piece_index, True)

    def send_message(self, msg: PeerMessage) -> None:
        """
        Serializa e envia uma mensagem BitTorrent ao peer, atualizando estados locais.
        """
        self.send_exact(msg.encode())

        # Atualiza os estados locais com base na mensagem enviada
        if isinstance(msg, ChokeMessage):
            self.am_choking = True
        elif isinstance(msg, UnchokeMessage):
            self.am_choking = False
        elif isinstance(msg, InterestedMessage):
            self.am_interested = True
        elif isinstance(msg, NotInterestedMessage):
            self.am_interested = False

    # --------------------------------------------------------------------------
    # Métodos de Conveniência para Envio de Mensagens
    # --------------------------------------------------------------------------

    def send_choke(self) -> None:
        """Envia mensagem Choke."""
        self.send_message(ChokeMessage())

    def send_unchoke(self) -> None:
        """Envia mensagem Unchoke."""
        self.send_message(UnchokeMessage())

    def send_interested(self) -> None:
        """Envia mensagem Interested."""
        self.send_message(InterestedMessage())

    def send_not_interested(self) -> None:
        """Envia mensagem Not Interested."""
        self.send_message(NotInterestedMessage())

    def send_have(self, piece_index: int) -> None:
        """Envia mensagem Have com o índice da peça."""
        self.send_message(HaveMessage(piece_index=piece_index))

    def send_bitfield(self, bitfield: Union[bytes, bytearray, Bitfield]) -> None:
        """Envia mensagem Bitfield."""
        raw = bitfield.to_bytes() if isinstance(bitfield, Bitfield) else bytes(bitfield)
        self.send_message(BitfieldMessage(bitfield=raw))

    def send_request(self, index: int, begin: int, length: int = DEFAULT_BLOCK_SIZE) -> None:
        """Envia mensagem Request de um bloco."""
        self.send_message(RequestMessage(index=index, begin=begin, length=length))

    def send_piece(self, index: int, begin: int, block: Union[bytes, bytearray]) -> None:
        """Envia mensagem Piece com um bloco de dados."""
        self.send_message(PieceMessage(index=index, begin=begin, block=bytes(block)))

    def send_cancel(self, index: int, begin: int, length: int = DEFAULT_BLOCK_SIZE) -> None:
        """Envia mensagem Cancel de uma requisição de bloco."""
        self.send_message(CancelMessage(index=index, begin=begin, length=length))

    def send_keep_alive(self) -> None:
        """Envia mensagem Keep-Alive."""
        self.send_message(KeepAliveMessage())
