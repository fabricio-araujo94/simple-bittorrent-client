"""
Bencode Parser and Serializer in pure Python.

Supports the BitTorrent Bencode specification (BEP 0003):
- Integers: i<number>e
- Byte Strings: <length>:<data>
- Lists: l<item1><item2>...e
- Dictionaries: d<key1><val1>...e (Keys must be lexicographically sorted byte strings)

Ensures byte-accurate tracking of offsets in the original buffer to
preserve the integrity of the 'info' section when calculating info_hash.
"""

from functools import singledispatch
from typing import Any, Dict, List, Optional, Tuple, Union


class BencodeError(Exception):
    """Base exception for errors in the Bencode layer."""
    pass


class BencodeDecodeError(BencodeError):
    """Exception raised when a syntax or type error occurs while decoding Bencode."""
    pass


class BencodeTruncatedError(BencodeDecodeError):
    """Exception raised when Bencode data ends prematurely (truncated data)."""
    pass


class BencodeEncodeError(BencodeError):
    """Exception raised when an error occurs while encoding an object to Bencode."""
    pass


MAX_BENCODE_DEPTH = 100
MAX_INT_DIGITS = 64
MAX_BENCODE_STRING_LENGTH = 100 * 1024 * 1024  # 100 MB


class BencodeDecoder:
    """
    Bencode decoder with strict BEP 0003 compliance validation,
    depth/memory DoS protection, and raw offset tracking.
    """

    def __init__(self, data: bytes, max_depth: int = MAX_BENCODE_DEPTH):
        self._data = data
        self._len = len(data)
        self.max_depth = max_depth
        # Maps root dictionary keys to their raw offsets (start, end)
        self.raw_slices: Dict[bytes, Tuple[int, int]] = {}
        # Maps key paths (tuples) to raw offsets (start, end)
        self.raw_slices_by_path: Dict[Tuple[bytes, ...], Tuple[int, int]] = {}

    def decode(self) -> Tuple[Any, int]:
        """
        Decode the first Bencode value starting from the beginning of the buffer.
        Returns (decoded_object, next_index).
        """
        if self._len == 0:
            raise BencodeTruncatedError("Empty buffer. No Bencode data to decode.")
        val, end_idx = self._parse_at(0, depth=0)
        return val, end_idx

    def _parse_at(
        self, idx: int, depth: int = 0, current_path: Tuple[bytes, ...] = ()
    ) -> Tuple[Any, int]:
        if depth > self.max_depth:
            raise BencodeDecodeError(
                f"Maximum nesting depth ({self.max_depth}) exceeded in Bencode (potential DoS attack)."
            )

        if idx >= self._len:
            raise BencodeTruncatedError(f"Unexpected end of buffer at offset {idx}.")

        byte = self._data[idx : idx + 1]

        if byte == b'i':
            return self._parse_int(idx)
        elif byte.isdigit():
            return self._parse_string(idx)
        elif byte == b'l':
            return self._parse_list(idx, depth=depth)
        elif byte == b'd':
            return self._parse_dict(idx, depth=depth, current_path=current_path)
        elif byte == b'e':
            raise BencodeDecodeError(f"Unexpected terminator 'e' out of context at offset {idx}.")
        else:
            raise BencodeDecodeError(f"Invalid Bencode character {byte!r} at offset {idx}.")

    def _parse_int(self, idx: int) -> Tuple[int, int]:
        end_idx = self._data.find(b'e', idx + 1)
        if end_idx == -1:
            raise BencodeTruncatedError(
                f"Truncated Bencode integer: terminator 'e' not found starting from offset {idx}."
            )

        int_bytes = self._data[idx + 1 : end_idx]
        if not int_bytes:
            raise BencodeDecodeError(f"Empty Bencode integer at offset {idx}.")

        if len(int_bytes) > MAX_INT_DIGITS:
            raise BencodeDecodeError(
                f"Bencode integer length ({len(int_bytes)} digits) exceeds safe limit of {MAX_INT_DIGITS} digits."
            )

        # Strict BEP 0003 compliance validations:
        # 1. Cannot have '+' sign
        # 2. If starts with '-', cannot be '-0' or have leading zeros
        # 3. If positive, cannot have leading zeros (except '0')
        # 4. Only ASCII digits allowed
        if int_bytes.startswith(b'+'):
            raise BencodeDecodeError(f"'+' sign not allowed in Bencode integer at offset {idx}.")

        if int_bytes.startswith(b'-'):
            digits = int_bytes[1:]
            if not digits:
                raise BencodeDecodeError(f"Incomplete negative integer 'i-e' at offset {idx}.")
            if digits == b'0' or digits.startswith(b'0'):
                raise BencodeDecodeError(
                    f"Leading zero or invalid '-0' in negative integer at offset {idx}."
                )
            if not digits.isdigit():
                raise BencodeDecodeError(
                    f"Non-numeric characters in Bencode integer {int_bytes!r} at offset {idx}."
                )
        else:
            if len(int_bytes) > 1 and int_bytes.startswith(b'0'):
                raise BencodeDecodeError(
                    f"Leading zero not allowed in Bencode integer at offset {idx}."
                )
            if not int_bytes.isdigit():
                raise BencodeDecodeError(
                    f"Non-numeric characters in Bencode integer {int_bytes!r} at offset {idx}."
                )

        try:
            val = int(int_bytes.decode('ascii'))
            return val, end_idx + 1
        except ValueError:
            raise BencodeDecodeError(f"Invalid numerical value {int_bytes!r} at offset {idx}.")

    def _parse_string(self, idx: int) -> Tuple[bytes, int]:
        colon_idx = self._data.find(b':', idx)
        if colon_idx == -1:
            # If contains only digits until end of buffer, ':' delimiter was truncated
            length_part = self._data[idx:]
            if length_part.isdigit():
                raise BencodeTruncatedError(
                    f"Truncated Bencode string: delimiter ':' not found starting from offset {idx}."
                )
            raise BencodeDecodeError(
                f"Delimiter ':' not found for string starting from offset {idx}."
            )

        length_bytes = self._data[idx:colon_idx]
        if not length_bytes:
            raise BencodeDecodeError(f"Missing string length before ':' at offset {idx}.")

        if length_bytes.startswith(b'+') or length_bytes.startswith(b'-'):
            raise BencodeDecodeError(
                f"Sign not allowed in Bencode string length at offset {idx}."
            )

        if not length_bytes.isdigit():
            raise BencodeDecodeError(
                f"String length must contain only ASCII digits, got {length_bytes!r} at offset {idx}."
            )

        if len(length_bytes) > 1 and length_bytes.startswith(b'0'):
            raise BencodeDecodeError(
                f"Leading zero not allowed in string length at offset {idx}."
            )

        try:
            length = int(length_bytes.decode('ascii'))
        except ValueError:
            raise BencodeDecodeError(f"Invalid string length {length_bytes!r} at offset {idx}.")

        if length > MAX_BENCODE_STRING_LENGTH:
            raise BencodeDecodeError(
                f"Bencode string length ({length} bytes) exceeds maximum allowed limit ({MAX_BENCODE_STRING_LENGTH} bytes)."
            )

        start_str = colon_idx + 1
        end_str = start_str + length

        if end_str > self._len:
            missing = end_str - self._len
            raise BencodeTruncatedError(
                f"Truncated Bencode string at offset {idx}: expected {length} bytes, "
                f"but only {self._len - start_str} bytes remain in buffer (missing {missing} bytes)."
            )

        return self._data[start_str:end_str], end_str

    def _parse_list(self, idx: int, depth: int = 0) -> Tuple[list, int]:
        curr = idx + 1
        result = []
        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1
            item, curr = self._parse_at(curr, depth=depth + 1)
            result.append(item)

        raise BencodeTruncatedError(
            f"Truncated Bencode list: terminator 'e' not found starting from offset {idx}."
        )

    def _parse_dict(
        self, idx: int, depth: int = 0, current_path: Tuple[bytes, ...] = ()
    ) -> Tuple[dict, int]:
        curr = idx + 1
        result = {}
        last_key: Optional[bytes] = None

        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1

            # Bencode dictionary keys MUST be byte strings
            first_byte = self._data[curr : curr + 1]
            if not first_byte.isdigit():
                raise BencodeDecodeError(
                    f"Bencode dictionary key must be a string at offset {curr} (found {first_byte!r})."
                )

            key, curr = self._parse_string(curr)

            # Strict validation of lexicographical key order (BEP 0003)
            if last_key is not None:
                if key == last_key:
                    raise BencodeDecodeError(
                        f"Duplicate key in Bencode dictionary: {key!r} at offset {curr}."
                    )
                if key < last_key:
                    raise BencodeDecodeError(
                        f"Dictionary keys out of lexicographical order: "
                        f"{last_key!r} appeared before {key!r} at offset {curr}."
                    )

            last_key = key

            # If buffer ends immediately after key, value is missing
            if curr >= self._len:
                raise BencodeTruncatedError(
                    f"Truncated Bencode dictionary: missing value for key {key!r} at offset {curr}."
                )

            val_start = curr
            val_path = current_path + (key,)
            val, curr = self._parse_at(curr, depth=depth + 1, current_path=val_path)
            val_end = curr

            result[key] = val

            # Record raw slices
            # If root dictionary (depth == 0), save in raw_slices
            if depth == 0:
                self.raw_slices[key] = (val_start, val_end)

            # Always save in full path map
            self.raw_slices_by_path[val_path] = (val_start, val_end)

        raise BencodeTruncatedError(
            f"Truncated Bencode dictionary: terminator 'e' not found starting from offset {idx}."
        )


def decode_bencode(data: Union[bytes, bytearray, memoryview], strict: bool = True) -> Any:
    """
    Decode a byte buffer into Python structures (int, bytes, list, dict).

    Args:
        data: Buffer containing Bencoded data.
        strict: If True, ensures that all buffer bytes are consumed.

    Returns:
        The decoded Python object.

    Raises:
        BencodeTruncatedError: If data ends prematurely.
        BencodeDecodeError: If data is malformed or invalid.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BencodeDecodeError(f"Expected input as bytes, got {type(data).__name__}.")

    bytes_data = bytes(data)
    if not bytes_data:
        raise BencodeTruncatedError("Empty buffer. No Bencode data to decode.")

    decoder = BencodeDecoder(bytes_data)
    val, end_idx = decoder.decode()

    if strict and end_idx < len(bytes_data):
        trailing_len = len(bytes_data) - end_idx
        raise BencodeDecodeError(
            f"Extra data ({trailing_len} bytes) found after end of Bencode object at offset {end_idx}."
        )

    return val


def decode_bencode_with_offsets(
    data: Union[bytes, bytearray, memoryview]
) -> Tuple[Any, int, Dict[bytes, Tuple[int, int]]]:
    """
    Decode Bencode buffer and return:
    (decoded_object, bytes_consumed, root_keys_offset_map)
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BencodeDecodeError(f"Expected input as bytes, got {type(data).__name__}.")

    bytes_data = bytes(data)
    if not bytes_data:
        raise BencodeTruncatedError("Empty buffer. No Bencode data to decode.")

    decoder = BencodeDecoder(bytes_data)
    val, end_idx = decoder.decode()
    return val, end_idx, decoder.raw_slices


def extract_info_bytes(data: Union[bytes, bytearray, memoryview]) -> bytes:
    """
    Extract exact raw bytes of 'info' section from a bencoded torrent
    for direct SHA-1 info_hash calculation.
    """
    bytes_data = bytes(data)
    val, _, slices = decode_bencode_with_offsets(bytes_data)
    if not isinstance(val, dict):
        raise BencodeDecodeError("Bencode root must be a dictionary to extract 'info'.")
    if b"info" not in slices:
        raise BencodeDecodeError("Key 'info' not found in root dictionary.")
    start, end = slices[b"info"]
    return bytes_data[start:end]


@singledispatch
def encode_bencode(val: Any) -> bytes:
    """
    Encode Python objects into bytes in Bencode format.

    Supported types:
    - int (not bool) -> i<val>e
    - bytes, bytearray, memoryview -> <len>:<bytes>
    - str -> <len_utf8>:<utf8_bytes>
    - list, tuple -> l<item1><item2>...e
    - dict -> d<key1><val1><key2><val2>...e (lexicographically sorted keys)

    Raises:
        BencodeEncodeError: If type is unsupported or duplicate/invalid keys exist.
    """
    raise BencodeEncodeError(f"Unsupported type for Bencode: {type(val).__name__}.")


@encode_bencode.register(bool)
def _encode_bool(val: bool) -> bytes:
    raise BencodeEncodeError("Boolean type ('bool') is not supported by Bencode format.")


@encode_bencode.register(int)
def _encode_int(val: int) -> bytes:
    return f"i{val}e".encode("ascii")


@encode_bencode.register(bytes)
def _encode_bytes(val: bytes) -> bytes:
    return f"{len(val)}:".encode("ascii") + val


@encode_bencode.register(bytearray)
def _encode_bytearray(val: bytearray) -> bytes:
    raw = bytes(val)
    return f"{len(raw)}:".encode("ascii") + raw


@encode_bencode.register(memoryview)
def _encode_memoryview(val: memoryview) -> bytes:
    raw = bytes(val)
    return f"{len(raw)}:".encode("ascii") + raw


@encode_bencode.register(str)
def _encode_str(val: str) -> bytes:
    encoded = val.encode("utf-8")
    return f"{len(encoded)}:".encode("ascii") + encoded


@encode_bencode.register(list)
def _encode_list(val: list) -> bytes:
    items = b"".join(encode_bencode(item) for item in val)
    return b"l" + items + b"e"


@encode_bencode.register(tuple)
def _encode_tuple(val: tuple) -> bytes:
    items = b"".join(encode_bencode(item) for item in val)
    return b"l" + items + b"e"


@encode_bencode.register(dict)
def _encode_dict(val: dict) -> bytes:
    encoded_pairs = []
    seen_keys = set()
    for k, v in val.items():
        if isinstance(k, bool):
            raise BencodeEncodeError("Boolean key is not supported in Bencode.")
        elif isinstance(k, (bytes, bytearray, memoryview)):
            k_bytes = bytes(k)
        elif isinstance(k, str):
            k_bytes = k.encode("utf-8")
        else:
            raise BencodeEncodeError(
                f"Dictionary key must be string or bytes, got {type(k).__name__}."
            )
        if k_bytes in seen_keys:
            raise BencodeEncodeError(
                f"Duplicate key detected when encoding dictionary: {k_bytes!r}."
            )
        seen_keys.add(k_bytes)
        encoded_pairs.append((k_bytes, v))

    # Strict byte lexicographical ordering
    encoded_pairs.sort(key=lambda pair: pair[0])

    result = bytearray(b"d")
    for k_bytes, v in encoded_pairs:
        result.extend(f"{len(k_bytes)}:".encode("ascii") + k_bytes)
        result.extend(encode_bencode(v))
    result.extend(b"e")
    return bytes(result)

