"""
Module for the BitTorrent Peer Wire Protocol communication layer.

Implements the BEP 0003 specification:
- Robust TCP connection with peers;
- Assembly, transmission, and validation of the 68-byte Handshake;
- Framing and message buffering using 4-byte big-endian length prefix;
- Encoding and decoding of all standard message types:
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
- Support for reading exactly N bytes with protection against network fragmentation;
- Handling multiple messages in a single read (packet coalescing);
- Protection against oversized messages (Memory Exhaustion / DoS);
- High-level `PeerConnection` connection manager with state tracking (choking/interested).
"""

import math
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ==============================================================================
# Protocol Constants
# ==============================================================================

HANDSHAKE_PSTR = b"BitTorrent protocol"
HANDSHAKE_PSTRLEN = 19
HANDSHAKE_LENGTH = 68  # 1 byte pstrlen + 19 bytes pstr + 8 bytes reserved + 20 bytes info_hash + 20 bytes peer_id

# Standard requested block size (16 KB)
DEFAULT_BLOCK_SIZE = 16384

# Safe maximum limit for individual block size (128 KB)
MAX_BLOCK_SIZE = 128 * 1024

# Security limit for individual message size (2 MB) to prevent memory exhaustion
MAX_MESSAGE_LENGTH = 2 * 1024 * 1024

# Maximum limit for internal peer receive buffer (4 MB) against memory exhaustion attacks
MAX_PEER_BUFFER_SIZE = 4 * 1024 * 1024


class MessageID(IntEnum):
    """Standard numerical identifiers for BitTorrent messages (BEP 0003)."""
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
# Exceptions
# ==============================================================================

class PeerError(Exception):
    """Base exception for errors in the peer protocol layer."""
    pass


class PeerConnectionError(PeerError):
    """Connection failure with remote peer (refused, network error, etc.)."""
    pass


class PeerConnectionClosedError(PeerConnectionError):
    """Connection was prematurely closed by remote peer (EOF received)."""
    pass


class PeerTimeoutError(PeerConnectionError):
    """Timeout exceeded during connection, send, or receive operation."""
    pass


class PeerProtocolError(PeerError):
    """Violation of BitTorrent protocol rules (corrupted data, invalid fields)."""
    pass


class HandshakeError(PeerProtocolError):
    """Handshake validation or negotiation failure with peer."""
    pass


class MessageSizeError(PeerProtocolError):
    """Message exceeds maximum allowed limit or has size incompatible with its type."""
    pass


# ==============================================================================
# Handshake Structure
# ==============================================================================

@dataclass(frozen=True)
class Handshake:
    """
    Representation of the BitTorrent handshake (68 bytes).
    """
    info_hash: bytes
    peer_id: bytes
    pstr: bytes = HANDSHAKE_PSTR
    reserved: bytes = b"\x00" * 8

    def __post_init__(self):
        if not isinstance(self.info_hash, (bytes, bytearray)) or len(self.info_hash) != 20:
            raise ValueError(f"info_hash must be exactly 20 bytes, got {len(self.info_hash) if isinstance(self.info_hash, (bytes, bytearray)) else type(self.info_hash).__name__}.")
        if not isinstance(self.peer_id, (bytes, bytearray)) or len(self.peer_id) != 20:
            raise ValueError(f"peer_id must be exactly 20 bytes, got {len(self.peer_id) if isinstance(self.peer_id, (bytes, bytearray)) else type(self.peer_id).__name__}.")
        if not isinstance(self.reserved, (bytes, bytearray)) or len(self.reserved) != 8:
            raise ValueError(f"reserved must be exactly 8 bytes, got {len(self.reserved) if isinstance(self.reserved, (bytes, bytearray)) else type(self.reserved).__name__}.")
        if self.pstr != HANDSHAKE_PSTR:
            raise ValueError(f"pstr must be {HANDSHAKE_PSTR!r}, got {self.pstr!r}.")

    def encode(self) -> bytes:
        """Serialize Handshake into its 68 binary bytes."""
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
    Assemble the 68 binary bytes of the BitTorrent Handshake.
    Format: <1 byte pstrlen><pstr><8 bytes reserved><20 bytes info_hash><20 bytes peer_id>
    """
    if len(pstr) != HANDSHAKE_PSTRLEN:
        raise ValueError(f"pstr must be {HANDSHAKE_PSTRLEN} bytes, got {len(pstr)}.")
    info_bytes = bytes(info_hash)
    if len(info_bytes) != 20:
        raise ValueError(f"info_hash must be exactly 20 bytes, got {len(info_bytes)} bytes.")
    peer_id_bytes = bytes(peer_id)
    if len(peer_id_bytes) != 20:
        raise ValueError(f"peer_id must be exactly 20 bytes, got {len(peer_id_bytes)} bytes.")
    reserved_bytes = bytes(reserved)
    if len(reserved_bytes) != 8:
        raise ValueError(f"reserved must be exactly 8 bytes, got {len(reserved_bytes)} bytes.")

    return struct.pack("!B", len(pstr)) + pstr + reserved_bytes + info_bytes + peer_id_bytes


def parse_handshake(
    data: Union[bytes, bytearray, memoryview],
    expected_info_hash: Optional[Union[bytes, bytearray]] = None,
    expected_peer_id: Optional[Union[bytes, bytearray]] = None,
) -> Handshake:
    """
    Decode and validate the 68 bytes received from a Handshake.

    Raises:
        HandshakeError: If length, protocol, info_hash, or peer_id are invalid.
    """
    raw = bytes(data)
    if len(raw) != HANDSHAKE_LENGTH:
        raise HandshakeError(
            f"Invalid handshake length: expected {HANDSHAKE_LENGTH} bytes, got {len(raw)} bytes."
        )

    pstrlen = raw[0]
    if pstrlen != HANDSHAKE_PSTRLEN:
        raise HandshakeError(
            f"Invalid pstrlen in handshake: expected {HANDSHAKE_PSTRLEN}, got {pstrlen}."
        )

    pstr = raw[1 : 1 + pstrlen]
    if pstr != HANDSHAKE_PSTR:
        raise HandshakeError(
            f"Invalid protocol identifier in handshake: expected {HANDSHAKE_PSTR!r}, got {pstr!r}."
        )

    reserved = raw[1 + pstrlen : 1 + pstrlen + 8]
    info_hash = raw[1 + pstrlen + 8 : 1 + pstrlen + 8 + 20]
    peer_id = raw[1 + pstrlen + 8 + 20 : 1 + pstrlen + 8 + 20 + 20]

    if expected_info_hash is not None:
        expected_hash_bytes = bytes(expected_info_hash)
        if info_hash != expected_hash_bytes:
            raise HandshakeError(
                f"info_hash mismatch in peer handshake: "
                f"expected {expected_hash_bytes.hex()}, got {info_hash.hex()}."
            )

    if expected_peer_id is not None:
        expected_pid_bytes = bytes(expected_peer_id)
        if peer_id != expected_pid_bytes:
            raise HandshakeError(
                f"peer_id mismatch in peer handshake: "
                f"expected {expected_pid_bytes.hex()}, got {peer_id.hex()}."
            )

    return Handshake(
        info_hash=info_hash,
        peer_id=peer_id,
        pstr=pstr,
        reserved=reserved,
    )


# ==============================================================================
# Bitfield Helper Structure
# ==============================================================================

class Bitfield:
    """
    Efficient and manipulable representation of BitTorrent piece bitfield (BEP 0003).

    Each bit represents piece possession by the peer (1 = present, 0 = absent).
    The highest-order bit (0x80) in the first byte represents piece index 0.
    """

    def __init__(self, num_pieces: int, initial_bytes: Optional[Union[bytes, bytearray]] = None):
        if num_pieces < 0:
            raise ValueError(f"num_pieces cannot be negative: {num_pieces}")
        self.num_pieces = num_pieces
        expected_len = (num_pieces + 7) // 8

        if initial_bytes is not None:
            raw = bytes(initial_bytes)
            if len(raw) != expected_len:
                raise ValueError(
                    f"Bitfield size ({len(raw)} bytes) incompatible with "
                    f"num_pieces={num_pieces} (expected {expected_len} bytes)."
                )
            # Strict validation of spare bits (BEP 0003)
            spare_bits = (expected_len * 8) - num_pieces
            if spare_bits > 0 and len(raw) > 0:
                mask = (1 << spare_bits) - 1
                if raw[-1] & mask != 0:
                    raise PeerProtocolError(
                        f"Invalid bitfield: non-zero spare bits detected at end of bitfield (spare_bits={spare_bits})."
                    )
            self._data = bytearray(raw)
        else:
            self._data = bytearray(expected_len)

    def has_piece(self, index: int) -> bool:
        """Check whether piece at specified index is present (True) or absent (False)."""
        if not (0 <= index < self.num_pieces):
            raise IndexError(f"Piece index out of range: {index} (total: {self.num_pieces})")
        byte_idx = index // 8
        bit_idx = 7 - (index % 8)
        return bool(self._data[byte_idx] & (1 << bit_idx))

    def set_piece(self, index: int, value: bool = True) -> None:
        """Set possession status of piece at given index."""
        if not (0 <= index < self.num_pieces):
            raise IndexError(f"Piece index out of range: {index} (total: {self.num_pieces})")
        byte_idx = index // 8
        bit_idx = 7 - (index % 8)
        if value:
            self._data[byte_idx] |= (1 << bit_idx)
        else:
            self._data[byte_idx] &= ~(1 << bit_idx)

    def count(self) -> int:
        """Return total count of present pieces."""
        return sum(1 for i in range(self.num_pieces) if self.has_piece(i))

    @property
    def is_complete(self) -> bool:
        """Indicate whether all pieces in the torrent are present (seeder)."""
        return self.count() == self.num_pieces

    def to_bytes(self) -> bytes:
        """Return byte representation of the bitfield."""
        return bytes(self._data)

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray], num_pieces: Optional[int] = None) -> "Bitfield":
        """Construct instance from raw bytes."""
        raw = bytes(data)
        pieces_count = num_pieces if num_pieces is not None else len(raw) * 8
        return cls(num_pieces=pieces_count, initial_bytes=raw)

    def __repr__(self) -> str:
        return f"<Bitfield: {self.count()}/{self.num_pieces} pieces>"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Bitfield):
            return False
        return self.num_pieces == other.num_pieces and self.to_bytes() == other.to_bytes()


# ==============================================================================
# Peer Wire Protocol Messages
# ==============================================================================

class PeerMessage:
    """Base class for all Peer Protocol messages."""

    def encode(self) -> bytes:
        """Serialize complete message with 4-byte length prefix."""
        raise NotImplementedError


@dataclass(frozen=True)
class KeepAliveMessage(PeerMessage):
    """Keep-Alive message: length=0, no ID, no payload (4 bytes: 00 00 00 00)."""
    msg_id: Optional[int] = None

    def encode(self) -> bytes:
        return struct.pack("!I", 0)


@dataclass(frozen=True)
class ChokeMessage(PeerMessage):
    """Choke message: ID=0, notifies that sender will not fulfill requests."""
    msg_id: Optional[int] = MessageID.CHOKE

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.CHOKE)


@dataclass(frozen=True)
class UnchokeMessage(PeerMessage):
    """Unchoke message: ID=1, notifies that sender is ready to fulfill requests."""
    msg_id: Optional[int] = MessageID.UNCHOKE

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.UNCHOKE)


@dataclass(frozen=True)
class InterestedMessage(PeerMessage):
    """Interested message: ID=2, notifies interest in downloading pieces from peer."""
    msg_id: Optional[int] = MessageID.INTERESTED

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.INTERESTED)


@dataclass(frozen=True)
class NotInterestedMessage(PeerMessage):
    """Not Interested message: ID=3, notifies lack of interest in peer pieces."""
    msg_id: Optional[int] = MessageID.NOT_INTERESTED

    def encode(self) -> bytes:
        return struct.pack("!IB", 1, MessageID.NOT_INTERESTED)


@dataclass(frozen=True)
class HaveMessage(PeerMessage):
    """Have message: ID=4, notifies that peer successfully downloaded and verified a specific piece."""
    piece_index: int
    msg_id: Optional[int] = MessageID.HAVE

    def __post_init__(self):
        if not isinstance(self.piece_index, int) or isinstance(self.piece_index, bool) or self.piece_index < 0:
            raise ValueError(f"piece_index must be a non-negative integer, got {self.piece_index!r}.")

    def encode(self) -> bytes:
        return struct.pack("!IBI", 5, MessageID.HAVE, self.piece_index)


@dataclass(frozen=True)
class BitfieldMessage(PeerMessage):
    """Bitfield message: ID=5, sends the map of pieces possessed by peer."""
    bitfield: bytes
    msg_id: Optional[int] = MessageID.BITFIELD

    def __post_init__(self):
        if not isinstance(self.bitfield, (bytes, bytearray)):
            raise TypeError(f"bitfield must be bytes, got {type(self.bitfield).__name__}.")

    def encode(self) -> bytes:
        raw = bytes(self.bitfield)
        return struct.pack("!IB", 1 + len(raw), MessageID.BITFIELD) + raw

    def to_bitfield(self, num_pieces: Optional[int] = None) -> Bitfield:
        """Convert bytes of this message into a manipulable Bitfield instance."""
        return Bitfield.from_bytes(self.bitfield, num_pieces=num_pieces)


@dataclass(frozen=True)
class RequestMessage(PeerMessage):
    """
    Request message: ID=6, requests a data block of a piece from peer.
    - index: piece index (uint32)
    - begin: byte offset within piece (uint32)
    - length: requested block size in bytes (uint32, typically 16384)
    """
    index: int
    begin: int
    length: int
    msg_id: Optional[int] = MessageID.REQUEST

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin), ("length", self.length)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {val!r}.")
        if self.length == 0:
            raise ValueError("Requested block length cannot be zero.")

    def encode(self) -> bytes:
        return struct.pack("!IBIII", 13, MessageID.REQUEST, self.index, self.begin, self.length)


@dataclass(frozen=True)
class PieceMessage(PeerMessage):
    """
    Piece message: ID=7, delivers a data block of a requested piece.
    - index: piece index (uint32)
    - begin: byte offset within piece (uint32)
    - block: binary content of block
    """
    index: int
    begin: int
    block: bytes
    msg_id: Optional[int] = MessageID.PIECE

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {val!r}.")
        if not isinstance(self.block, (bytes, bytearray)):
            raise TypeError(f"block must be bytes, got {type(self.block).__name__}.")

    def encode(self) -> bytes:
        raw_block = bytes(self.block)
        return struct.pack("!IBII", 9 + len(raw_block), MessageID.PIECE, self.index, self.begin) + raw_block


@dataclass(frozen=True)
class CancelMessage(PeerMessage):
    """
    Cancel message: ID=8, cancels a previously sent block request.
    """
    index: int
    begin: int
    length: int
    msg_id: Optional[int] = MessageID.CANCEL

    def __post_init__(self):
        for name, val in [("index", self.index), ("begin", self.begin), ("length", self.length)]:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {val!r}.")
        if self.length == 0:
            raise ValueError("Cancel length cannot be zero.")

    def encode(self) -> bytes:
        return struct.pack("!IBIII", 13, MessageID.CANCEL, self.index, self.begin, self.length)


@dataclass(frozen=True)
class PortMessage(PeerMessage):
    """
    Port message (BEP 0005): ID=9, specifies listening port of peer's UDP DHT.
    """
    listen_port: int
    msg_id: Optional[int] = MessageID.PORT

    def __post_init__(self):
        if not isinstance(self.listen_port, int) or isinstance(self.listen_port, bool) or not (0 < self.listen_port <= 65535):
            raise ValueError(f"listen_port must be between 1 and 65535, got {self.listen_port!r}.")

    def encode(self) -> bytes:
        return struct.pack("!IBH", 3, MessageID.PORT, self.listen_port)


@dataclass(frozen=True)
class UnknownMessage(PeerMessage):
    """Representation of message with unknown ID for future extensions."""
    msg_id: Optional[int]
    payload: bytes

    def encode(self) -> bytes:
        raw = bytes(self.payload)
        id_val = self.msg_id if self.msg_id is not None else 0
        return struct.pack("!IB", 1 + len(raw), id_val) + raw


# ==============================================================================
# Fast Constructors and Encoders
# ==============================================================================

def encode_keep_alive() -> bytes:
    """Return bytes of Keep-Alive message (4 zero bytes)."""
    return KeepAliveMessage().encode()


def encode_choke() -> bytes:
    """Return bytes of Choke message."""
    return ChokeMessage().encode()


def encode_unchoke() -> bytes:
    """Return bytes of Unchoke message."""
    return UnchokeMessage().encode()


def encode_interested() -> bytes:
    """Return bytes of Interested message."""
    return InterestedMessage().encode()


def encode_not_interested() -> bytes:
    """Return bytes of Not Interested message."""
    return NotInterestedMessage().encode()


def encode_have(piece_index: int) -> bytes:
    """Return bytes of Have message for given index."""
    return HaveMessage(piece_index=piece_index).encode()


def encode_bitfield(bitfield: Union[bytes, bytearray, Bitfield]) -> bytes:
    """Return bytes of Bitfield message."""
    raw = bitfield.to_bytes() if isinstance(bitfield, Bitfield) else bytes(bitfield)
    return BitfieldMessage(bitfield=raw).encode()


def encode_request(index: int, begin: int, length: int) -> bytes:
    """Return bytes of Request message."""
    return RequestMessage(index=index, begin=begin, length=length).encode()


def encode_piece(index: int, begin: int, block: Union[bytes, bytearray]) -> bytes:
    """Return bytes of Piece message."""
    return PieceMessage(index=index, begin=begin, block=bytes(block)).encode()


def encode_cancel(index: int, begin: int, length: int) -> bytes:
    """Return bytes of Cancel message."""
    return CancelMessage(index=index, begin=begin, length=length).encode()


def encode_port(listen_port: int) -> bytes:
    """Return bytes of Port message."""
    return PortMessage(listen_port=listen_port).encode()


def encode_message(msg: PeerMessage) -> bytes:
    """Serialize any PeerMessage object into its binary format."""
    if not isinstance(msg, PeerMessage):
        raise TypeError(f"Expected PeerMessage, got {type(msg).__name__}.")
    return msg.encode()


# ==============================================================================
# ==============================================================================
# Message Parsers
# ==============================================================================

def _parse_choke(length: int, data: bytes) -> ChokeMessage:
    if length != 1:
        raise MessageSizeError(f"Choke message must have length=1, got {length}.")
    return ChokeMessage()


def _parse_unchoke(length: int, data: bytes) -> UnchokeMessage:
    if length != 1:
        raise MessageSizeError(f"Unchoke message must have length=1, got {length}.")
    return UnchokeMessage()


def _parse_interested(length: int, data: bytes) -> InterestedMessage:
    if length != 1:
        raise MessageSizeError(f"Interested message must have length=1, got {length}.")
    return InterestedMessage()


def _parse_not_interested(length: int, data: bytes) -> NotInterestedMessage:
    if length != 1:
        raise MessageSizeError(f"Not Interested message must have length=1, got {length}.")
    return NotInterestedMessage()


def _parse_have(length: int, data: bytes) -> HaveMessage:
    if length != 5 or len(data) != 4:
        raise MessageSizeError(f"Have message must have length=5 (4 index bytes), got {length}.")
    piece_index = struct.unpack("!I", data)[0]
    return HaveMessage(piece_index=piece_index)


def _parse_bitfield(length: int, data: bytes) -> BitfieldMessage:
    if length < 1:
        raise MessageSizeError(f"Bitfield message with invalid length: {length}.")
    return BitfieldMessage(bitfield=data)


def _parse_request(length: int, data: bytes) -> RequestMessage:
    if length != 13 or len(data) != 12:
        raise MessageSizeError(f"Request message must have length=13 (12-byte payload), got {length}.")
    index, begin, block_length = struct.unpack("!III", data)
    if block_length > MAX_BLOCK_SIZE:
        raise MessageSizeError(
            f"Requested block length ({block_length} bytes) exceeds maximum limit ({MAX_BLOCK_SIZE} bytes)."
        )
    return RequestMessage(index=index, begin=begin, length=block_length)


def _parse_piece(length: int, data: bytes) -> PieceMessage:
    if length < 9 or len(data) < 8:
        raise MessageSizeError(f"Piece message must have length >= 9, got {length}.")
    index, begin = struct.unpack("!II", data[:8])
    block = data[8:]
    if len(block) > MAX_BLOCK_SIZE:
        raise MessageSizeError(
            f"Received block length ({len(block)} bytes) exceeds maximum limit ({MAX_BLOCK_SIZE} bytes)."
        )
    return PieceMessage(index=index, begin=begin, block=block)


def _parse_cancel(length: int, data: bytes) -> CancelMessage:
    if length != 13 or len(data) != 12:
        raise MessageSizeError(f"Cancel message must have length=13 (12-byte payload), got {length}.")
    index, begin, block_length = struct.unpack("!III", data)
    if block_length > MAX_BLOCK_SIZE:
        raise MessageSizeError(
            f"Block length in Cancel ({block_length} bytes) exceeds maximum limit ({MAX_BLOCK_SIZE} bytes)."
        )
    return CancelMessage(index=index, begin=begin, length=block_length)


def _parse_port(length: int, data: bytes) -> PortMessage:
    if length != 3 or len(data) != 2:
        raise MessageSizeError(f"Port message must have length=3 (2-byte payload), got {length}.")
    port = struct.unpack("!H", data)[0]
    return PortMessage(listen_port=port)


MESSAGE_PARSERS: Dict[int, Callable[[int, bytes], PeerMessage]] = {
    MessageID.CHOKE: _parse_choke,
    MessageID.UNCHOKE: _parse_unchoke,
    MessageID.INTERESTED: _parse_interested,
    MessageID.NOT_INTERESTED: _parse_not_interested,
    MessageID.HAVE: _parse_have,
    MessageID.BITFIELD: _parse_bitfield,
    MessageID.REQUEST: _parse_request,
    MessageID.PIECE: _parse_piece,
    MessageID.CANCEL: _parse_cancel,
    MessageID.PORT: _parse_port,
}


def parse_message_payload(length: int, payload: bytes) -> PeerMessage:
    """
    Decode message content from its length prefix and payload.

    Args:
        length: Integer value of 4-byte prefix (length of ID + data).
        payload: Bytes exactly corresponding to `length` (containing ID + data).

    Raises:
        PeerProtocolError / MessageSizeError: If message is truncated or malformed.
    """
    if len(payload) != length:
        raise PeerProtocolError(
            f"Payload length ({len(payload)} bytes) differs from length prefix ({length} bytes)."
        )

    if length == 0:
        return KeepAliveMessage()

    msg_id = payload[0]
    data = payload[1:]

    parser = MESSAGE_PARSERS.get(msg_id)
    if parser is not None:
        return parser(length, data)

    return UnknownMessage(msg_id=msg_id, payload=data)


def parse_message(raw_msg_bytes: Union[bytes, bytearray, memoryview]) -> PeerMessage:
    """
    Decode a complete serialized message from its raw buffer
    (including the 4-byte length prefix).
    """
    raw = bytes(raw_msg_bytes)
    if len(raw) < 4:
        raise PeerProtocolError(f"Insufficient buffer ({len(raw)} bytes) to contain 4-byte length prefix.")

    length = struct.unpack("!I", raw[:4])[0]
    payload = raw[4:]

    if len(payload) != length:
        raise PeerProtocolError(
            f"Received payload length ({len(payload)} bytes) differs from length prefix ({length} bytes)."
        )

    return parse_message_payload(length, payload)


def parse_messages_from_buffer(
    buffer: bytearray,
    max_message_length: int = MAX_MESSAGE_LENGTH,
) -> List[PeerMessage]:
    """
    Consume and decode all complete messages contained in the provided mutable buffer.
    Partial or incomplete messages are preserved in the buffer for subsequent reads.
    """
    messages: List[PeerMessage] = []

    while len(buffer) >= 4:
        length = struct.unpack("!I", buffer[:4])[0]

        if length > max_message_length:
            raise MessageSizeError(
                f"Message length {length} bytes exceeds allowed limit ({max_message_length} bytes)."
            )

        total_needed = 4 + length
        if len(buffer) < total_needed:
            # Incomplete message, wait for more data
            break

        msg_chunk = bytes(buffer[:total_needed])
        del buffer[:total_needed]
        messages.append(parse_message(msg_chunk))

    return messages


# ==============================================================================
# TCP Connection Manager (PeerConnection)
# ==============================================================================

class PeerConnection:
    """
    Robust low- and mid-level TCP connection manager for a BitTorrent peer.

    Features:
    - Precise reading of exactly N bytes (`recv_exact`) with internal buffering;
    - TCP fragmentation protection and absorption of multiple messages per read;
    - Complete handshake negotiation with sending and strict validation;
    - Structured reading of messages with maximum limit checks;
    - Safe message sending (`send_exact`, `send_message`);
    - Protocol state tracking (choking and interested flags on both ends);
    - Context manager support (`with PeerConnection(...)`).
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

        # Protocol control states (BEP 0003)
        self.am_choking: bool = True
        self.am_interested: bool = False
        self.peer_choking: bool = True
        self.peer_interested: bool = False
        self.peer_bitfield: Optional[Bitfield] = None

        if self._sock is not None:
            self._sock.settimeout(self.default_timeout)

    @property
    def is_connected(self) -> bool:
        """Check whether socket is instantiated."""
        return self._sock is not None

    def connect(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        """
        Establish TCP connection with remote peer.
        """
        if host is not None:
            self.peer_host = host
        if port is not None:
            self.peer_port = port

        if not self.peer_host or not self.peer_port:
            raise ValueError("Peer host and port are required to establish connection.")

        connect_timeout = timeout if timeout is not None else self.default_timeout
        try:
            self._sock = socket.create_connection(
                (self.peer_host, self.peer_port),
                timeout=connect_timeout,
            )
            # Disable Nagle algorithm for immediate sending of short messages
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock.settimeout(self.default_timeout)
        except (socket.timeout, TimeoutError) as e:
            raise PeerTimeoutError(
                f"Timeout connecting to peer {self.peer_host}:{self.peer_port} after {connect_timeout}s."
            ) from e
        except socket.error as e:
            raise PeerConnectionError(
                f"Failed to connect to peer {self.peer_host}:{self.peer_port}: {e}"
            ) from e

    def close(self) -> None:
        """Close socket and clear internal buffer."""
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
        Read exactly N bytes from connection or internal buffer.

        Robustly blocks until all N bytes have accumulated.

        Raises:
            PeerConnectionError: If socket is not connected.
            PeerConnectionClosedError: If connection is closed before receiving N bytes.
            PeerTimeoutError: If read timeout is reached.
        """
        if n < 0:
            raise ValueError(f"Byte count cannot be negative: {n}")
        if n == 0:
            return b""

        # If bytes are already in internal buffer, extract immediately
        if len(self._buffer) >= n:
            chunk = bytes(self._buffer[:n])
            del self._buffer[:n]
            return chunk

        if self._sock is None:
            raise PeerConnectionError("Socket not connected.")

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
                        f"Timeout waiting for {needed} bytes from peer ({self.peer_host}:{self.peer_port})."
                    ) from e
                except socket.error as e:
                    raise PeerConnectionError(
                        f"Socket error receiving data from peer: {e}"
                    ) from e

                if not data:
                    raise PeerConnectionClosedError(
                        f"Connection closed by peer ({self.peer_host}:{self.peer_port}) before receiving {n} bytes "
                        f"(got {len(self._buffer)} bytes, missing {needed} bytes)."
                    )

                self._buffer.extend(data)
                if len(self._buffer) > MAX_PEER_BUFFER_SIZE:
                    raise MessageSizeError(
                        f"Peer receive buffer ({self.peer_host}:{self.peer_port}) exceeded maximum safe limit ({MAX_PEER_BUFFER_SIZE} bytes)."
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
        Send exactly all provided bytes through the socket.

        Raises:
            PeerConnectionError: If socket is not connected or network error occurs.
            PeerTimeoutError: If write timeout is reached.
        """
        if self._sock is None:
            raise PeerConnectionError("Socket not connected.")

        data_bytes = bytes(data)
        if not data_bytes:
            return

        try:
            self._sock.sendall(data_bytes)
        except (socket.timeout, TimeoutError) as e:
            raise PeerTimeoutError(
                f"Timeout sending {len(data_bytes)} bytes to peer ({self.peer_host}:{self.peer_port})."
            ) from e
        except socket.error as e:
            raise PeerConnectionError(
                f"Error sending data to peer ({self.peer_host}:{self.peer_port}): {e}"
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
        Perform complete Handshake negotiation:
        1. Sends 68-byte handshake from this client;
        2. Reads exactly 68 bytes from peer response handshake;
        3. Validates pstrlen, pstr, and info_hash (and optionally peer_id).
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
        Read and decode next BitTorrent message from stream.

        1. Reads 4-byte length prefix;
        2. Validates safety limit against oversized messages;
        3. Reads exactly `length` payload bytes;
        4. Decodes message and updates internal connection state.
        """
        len_bytes = self.recv_exact(4, timeout=timeout)
        length = struct.unpack("!I", len_bytes)[0]

        if length > max_message_length:
            raise MessageSizeError(
                f"Message length {length} bytes exceeds allowed limit ({max_message_length} bytes)."
            )

        if length == 0:
            return KeepAliveMessage()

        payload = self.recv_exact(length, timeout=timeout)
        msg = parse_message_payload(length, payload)

        # Automatically update local states based on received message
        self._update_state_from_received_message(msg)

        return msg

    def _update_state_from_received_message(self, msg: PeerMessage) -> None:
        """Update control flags from a message received from peer."""
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
        Serialize and send a BitTorrent message to peer, updating local states.
        """
        self.send_exact(msg.encode())

        # Update local states based on sent message
        if isinstance(msg, ChokeMessage):
            self.am_choking = True
        elif isinstance(msg, UnchokeMessage):
            self.am_choking = False
        elif isinstance(msg, InterestedMessage):
            self.am_interested = True
        elif isinstance(msg, NotInterestedMessage):
            self.am_interested = False

    # --------------------------------------------------------------------------
    # Convenience Methods for Sending Messages
    # --------------------------------------------------------------------------

    def send_choke(self) -> None:
        """Send Choke message."""
        self.send_message(ChokeMessage())

    def send_unchoke(self) -> None:
        """Send Unchoke message."""
        self.send_message(UnchokeMessage())

    def send_interested(self) -> None:
        """Send Interested message."""
        self.send_message(InterestedMessage())

    def send_not_interested(self) -> None:
        """Send Not Interested message."""
        self.send_message(NotInterestedMessage())

    def send_have(self, piece_index: int) -> None:
        """Send Have message with piece index."""
        self.send_message(HaveMessage(piece_index=piece_index))

    def send_bitfield(self, bitfield: Union[bytes, bytearray, Bitfield]) -> None:
        """Send Bitfield message."""
        raw = bitfield.to_bytes() if isinstance(bitfield, Bitfield) else bytes(bitfield)
        self.send_message(BitfieldMessage(bitfield=raw))

    def send_request(self, index: int, begin: int, length: int = DEFAULT_BLOCK_SIZE) -> None:
        """Send Request message for a block."""
        self.send_message(RequestMessage(index=index, begin=begin, length=length))

    def send_piece(self, index: int, begin: int, block: Union[bytes, bytearray]) -> None:
        """Send Piece message with a data block."""
        self.send_message(PieceMessage(index=index, begin=begin, block=bytes(block)))

    def send_cancel(self, index: int, begin: int, length: int = DEFAULT_BLOCK_SIZE) -> None:
        """Send Cancel message for a block request."""
        self.send_message(CancelMessage(index=index, begin=begin, length=length))

    def send_keep_alive(self) -> None:
        """Send Keep-Alive message."""
        self.send_message(KeepAliveMessage())

