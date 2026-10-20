"""
Module for interpreting .torrent files and representing metadata.

Parses BitTorrent metadata (BEP 0003, BEP 0012, BEP 0027),
validates mathematical consistency and integrity of pieces and files,
and calculates the SHA-1 info_hash over the raw bytes of the 'info' section.
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .bencode import BencodeError, decode_bencode_with_offsets
from .hash_utils import compute_sha1, verify_sha1


class TorrentError(Exception):
    """Base exception for errors in the torrent layer."""
    pass


class TorrentParseError(TorrentError):
    """Exception raised when a .torrent file is malformed, incomplete, or inconsistent."""
    pass


class TorrentValidationError(TorrentParseError):
    """Exception raised when required fields or validation rules fail."""
    pass


class TorrentSecurityError(TorrentValidationError):
    """Exception raised when a security violation attempt is detected (e.g., Path Traversal)."""
    pass


def validate_safe_path_segment(segment: str) -> str:
    """
    Validate and sanitize a path segment to prevent Path Traversal vulnerabilities.

    Rejects:
    - Empty segments, '.', '..';
    - Segments containing '/', '\\', '\x00' (null bytes) or ':' (Windows drive letters).
    """
    if not isinstance(segment, str):
        raise TorrentValidationError(f"Path segment must be a string, got {type(segment).__name__}.")

    seg = segment.strip()
    if not seg:
        raise TorrentValidationError("Path segment cannot be empty or contain only whitespace.")

    if seg in (".", "..") or ".." in seg:
        raise TorrentSecurityError(f"Path Traversal attempt detected in path segment: {segment!r}")

    if "\x00" in seg:
        raise TorrentSecurityError(f"Null byte detected in path segment: {segment!r}")

    if "/" in seg or "\\" in seg:
        raise TorrentSecurityError(f"Directory separators not allowed within individual segment: {segment!r}")

    if ":" in seg:
        raise TorrentSecurityError(f"Character ':' not allowed in path segment: {segment!r}")

    return seg


@dataclass(frozen=True)
class FileInfo:
    """
    Representation of a file contained in the torrent (single-file or multi-file).
    """
    length: int
    path: List[str]
    full_path: str
    md5sum: Optional[str] = None


@dataclass(frozen=True)
class TorrentMetadata:
    """
    Immutable structured representation of metadata from a .torrent file.
    """
    announce: Optional[str]
    announce_list: List[List[str]]  # Tracker tiers (BEP 0012)
    trackers: List[str]             # Unique ordered list of all available trackers
    info_hash: bytes                # 20-byte binary SHA-1 of the 'info' section
    info_hash_hex: str              # 40-character hexadecimal string of the info_hash
    name: str                       # File name (single-file) or root directory name (multi-file)
    piece_length: int               # Standard length of each piece in bytes
    total_length: int               # Sum of total length of all files in bytes
    pieces: bytes                   # Raw concatenated SHA-1 piece hashes
    piece_hashes: List[bytes]       # List of individual SHA-1 piece hashes (20 bytes each)
    raw_info_bytes: bytes           # Original raw Bencoded bytes of the 'info' section
    is_multi_file: bool             # True if multi-file, False if single-file
    files: List[FileInfo]           # List of files in the torrent
    comment: Optional[str] = None
    created_by: Optional[str] = None
    creation_date: Optional[int] = None
    private: bool = False

    @property
    def num_pieces(self) -> int:
        """Return the total number of pieces in the torrent."""
        return len(self.piece_hashes)

    def get_piece_length(self, piece_index: int) -> int:
        """
        Return the exact piece length for the given index.
        The last piece may be smaller than `piece_length`.
        """
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
            )
        if piece_index == self.num_pieces - 1:
            remainder = self.total_length % self.piece_length
            return remainder if remainder != 0 else self.piece_length
        return self.piece_length

    def get_piece_hash(self, piece_index: int) -> bytes:
        """Return the expected 20-byte SHA-1 hash for the piece at the given index."""
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
            )
        return self.piece_hashes[piece_index]

    def verify_piece(self, piece_index: int, piece_data: bytes) -> bool:
        """
        Validate whether piece data matches the expected length
        and the SHA-1 hash recorded in the metadata.
        """
        if not isinstance(piece_data, (bytes, bytearray)):
            raise TypeError(f"Piece data must be bytes, got {type(piece_data).__name__}.")
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
            )
        expected_length = self.get_piece_length(piece_index)
        if len(piece_data) != expected_length:
            return False
        return verify_sha1(bytes(piece_data), self.piece_hashes[piece_index])


def load_torrent_bytes(raw_bytes: Union[bytes, bytearray, memoryview]) -> TorrentMetadata:
    """
    Decode byte buffer of a .torrent file, validate all required fields,
    extract announce / announce-list, split pieces into SHA-1 hashes,
    calculate info_hash, and construct TorrentMetadata with security checks.
    """
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        raise TorrentParseError(
            f"Expected input as bytes, got {type(raw_bytes).__name__}."
        )

    bytes_data = bytes(raw_bytes)
    if not bytes_data:
        raise TorrentParseError(".torrent file buffer is empty.")

    try:
        root_dict, _, raw_slices = decode_bencode_with_offsets(bytes_data)
    except BencodeError as e:
        raise TorrentParseError(f"Error decoding torrent Bencode structure: {e}") from e

    if not isinstance(root_dict, dict):
        raise TorrentValidationError(".torrent file must contain a Bencode dictionary at root.")

    # 1. Validate 'info' section and extract exact raw slice
    if b"info" not in root_dict or b"info" not in raw_slices:
        raise TorrentValidationError("Required 'info' dictionary not found in .torrent file.")

    info_start, info_end = raw_slices[b"info"]
    raw_info_bytes = bytes_data[info_start:info_end]

    info = root_dict[b"info"]
    if not isinstance(info, dict):
        raise TorrentValidationError("Torrent 'info' section must be a dictionary.")

    # 2. Compute SHA-1 info_hash over exact raw bytes
    info_hash = compute_sha1(raw_info_bytes)
    info_hash_hex = info_hash.hex()

def _parse_trackers(root_dict: Dict[bytes, Any]) -> Tuple[Optional[str], List[List[str]], List[str]]:
    announce: Optional[str] = None
    if b"announce" in root_dict:
        announce_raw = root_dict[b"announce"]
        if not isinstance(announce_raw, bytes):
            raise TorrentValidationError("'announce' field must be a byte string.")
        announce_str = announce_raw.decode('utf-8', errors='replace').strip()
        if announce_str:
            announce = announce_str

    announce_list: List[List[str]] = []
    if b"announce-list" in root_dict:
        raw_announce_list = root_dict[b"announce-list"]
        if not isinstance(raw_announce_list, list):
            raise TorrentValidationError("'announce-list' field must be a list of tiers.")
        for tier_idx, tier in enumerate(raw_announce_list):
            if not isinstance(tier, list):
                raise TorrentValidationError(
                    f"Tier {tier_idx} in 'announce-list' must be a list of URLs."
                )
            tier_urls = []
            for url_item in tier:
                if not isinstance(url_item, bytes):
                    raise TorrentValidationError(
                        f"URL in tier {tier_idx} of 'announce-list' must be a byte string."
                    )
                url_str = url_item.decode('utf-8', errors='replace').strip()
                if url_str:
                    tier_urls.append(url_str)
            if tier_urls:
                announce_list.append(tier_urls)

    if announce is None and not announce_list:
        raise TorrentValidationError(
            ".torrent file must contain at least one valid tracker ('announce' or 'announce-list')."
        )

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

    return announce, announce_list, all_trackers


def _parse_files_info(info: Dict[bytes, Any], name: str) -> Tuple[List[FileInfo], bool, int]:
    has_length = b"length" in info
    has_files = b"files" in info

    if has_length and has_files:
        raise TorrentValidationError(
            "Inconsistency in 'info' section: 'length' and 'files' cannot both exist simultaneously."
        )
    if not has_length and not has_files:
        raise TorrentValidationError(
            "'info' section must contain either 'length' (single-file) or 'files' (multi-file)."
        )

    files_list: List[FileInfo] = []
    if has_length:
        length_val = info[b"length"]
        if not isinstance(length_val, int) or isinstance(length_val, bool) or length_val < 0:
            raise TorrentValidationError(
                f"'length' field in single-file must be a non-negative integer (>= 0), got: {length_val!r}."
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
                "'files' field in multi-file must be a non-empty list of files."
            )
        is_multi_file = True
        total_length = 0
        for f_idx, file_dict in enumerate(raw_files):
            if not isinstance(file_dict, dict):
                raise TorrentValidationError(f"Item {f_idx} in 'files' must be a dictionary.")
            if b"length" not in file_dict:
                raise TorrentValidationError(f"Missing 'length' field in file {f_idx} in 'files'.")
            f_len = file_dict[b"length"]
            if not isinstance(f_len, int) or isinstance(f_len, bool) or f_len < 0:
                raise TorrentValidationError(
                    f"'length' field in file {f_idx} must be a non-negative integer (>= 0), got: {f_len!r}."
                )
            if b"path" not in file_dict:
                raise TorrentValidationError(f"Missing 'path' field in file {f_idx} in 'files'.")
            f_path_list = file_dict[b"path"]
            if not isinstance(f_path_list, list) or len(f_path_list) == 0:
                raise TorrentValidationError(
                    f"'path' field in file {f_idx} must be a non-empty list of path segments."
                )
            path_segments = []
            for seg_idx, seg in enumerate(f_path_list):
                if not isinstance(seg, bytes):
                    raise TorrentValidationError(
                        f"Path segment {seg_idx} in file {f_idx} must be a byte string."
                    )
                seg_str = validate_safe_path_segment(seg.decode('utf-8', errors='replace'))
                path_segments.append(seg_str)

            f_md5 = None
            if b"md5sum" in file_dict and isinstance(file_dict[b"md5sum"], bytes):
                f_md5 = file_dict[b"md5sum"].decode('ascii', errors='replace')

            full_path = "/".join(path_segments)
            files_list.append(FileInfo(length=f_len, path=path_segments, full_path=full_path, md5sum=f_md5))
            total_length += f_len

    return files_list, is_multi_file, total_length


def _parse_and_validate_pieces(
    info: Dict[bytes, Any], total_length: int, piece_length: int
) -> Tuple[bytes, List[bytes]]:
    if b"pieces" not in info:
        raise TorrentValidationError("Required 'pieces' field not found in 'info' section.")
    pieces_raw = info[b"pieces"]
    if not isinstance(pieces_raw, bytes):
        raise TorrentValidationError("'pieces' field in 'info' section must be bytes.")

    if len(pieces_raw) % 20 != 0:
        raise TorrentValidationError(
            f"Size of 'pieces' field ({len(pieces_raw)} bytes) is not a multiple of 20 bytes."
        )

    piece_hashes = [pieces_raw[i : i + 20] for i in range(0, len(pieces_raw), 20)]

    expected_pieces = math.ceil(total_length / piece_length) if total_length > 0 else 0
    if total_length > 0 and len(piece_hashes) == 0:
        raise TorrentValidationError(
            f"Torrent with total size of {total_length} bytes has no hashes in 'pieces'."
        )
    if total_length == 0 and len(piece_hashes) > 0:
        raise TorrentValidationError(
            f"Torrent with size 0 bytes has {len(piece_hashes)} pieces in 'pieces'."
        )
    if len(piece_hashes) != expected_pieces:
        raise TorrentValidationError(
            f"Inconsistency in number of pieces: expected {expected_pieces} pieces for total size "
            f"of {total_length} bytes (piece_length={piece_length}), but 'pieces' contains {len(piece_hashes)} hashes."
        )

    return pieces_raw, piece_hashes


def _parse_optional_metadata(
    root_dict: Dict[bytes, Any], info: Dict[bytes, Any]
) -> Tuple[Optional[str], Optional[str], Optional[int], bool]:
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

    return comment, created_by, creation_date, private


def load_torrent_bytes(raw_bytes: Union[bytes, bytearray, memoryview]) -> TorrentMetadata:
    """
    Decode byte buffer of a .torrent file, validate all required fields,
    extract announce / announce-list, split pieces into SHA-1 hashes,
    calculate info_hash, and construct TorrentMetadata with security checks.
    """
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        raise TorrentParseError(
            f"Expected input as bytes, got {type(raw_bytes).__name__}."
        )

    bytes_data = bytes(raw_bytes)
    if not bytes_data:
        raise TorrentParseError(".torrent file buffer is empty.")

    try:
        root_dict, _, raw_slices = decode_bencode_with_offsets(bytes_data)
    except BencodeError as e:
        raise TorrentParseError(f"Error decoding torrent Bencode structure: {e}") from e

    if not isinstance(root_dict, dict):
        raise TorrentValidationError(".torrent file must contain a Bencode dictionary at root.")

    # 1. Validate 'info' section and extract exact raw slice
    if b"info" not in root_dict or b"info" not in raw_slices:
        raise TorrentValidationError("Required 'info' dictionary not found in .torrent file.")

    info_start, info_end = raw_slices[b"info"]
    raw_info_bytes = bytes_data[info_start:info_end]

    info = root_dict[b"info"]
    if not isinstance(info, dict):
        raise TorrentValidationError("Torrent 'info' section must be a dictionary.")

    # 2. Compute SHA-1 info_hash over exact raw bytes
    info_hash = compute_sha1(raw_info_bytes)
    info_hash_hex = info_hash.hex()

    # 3. Extract and validate announce and announce-list (BEP 0012)
    announce, announce_list, all_trackers = _parse_trackers(root_dict)

    # 4. Extract and validate 'name' with Path Traversal protection
    if b"name" not in info:
        raise TorrentValidationError("Required 'name' field not found in 'info' section.")
    name_raw = info[b"name"]
    if not isinstance(name_raw, bytes):
        raise TorrentValidationError("'name' field in 'info' section must be a byte string.")
    name = validate_safe_path_segment(name_raw.decode('utf-8', errors='replace'))

    # 5. Extract and validate 'piece length'
    if b"piece length" not in info:
        raise TorrentValidationError("Required 'piece length' field not found in 'info' section.")
    piece_length = info[b"piece length"]
    if not isinstance(piece_length, int) or isinstance(piece_length, bool) or piece_length <= 0:
        raise TorrentValidationError(
            f"'piece length' field must be a strictly positive integer (> 0), got: {piece_length!r}."
        )

    # 6. Extract and validate files (Single-file vs Multi-file)
    files_list, is_multi_file, total_length = _parse_files_info(info, name)

    # 7. Extract and validate 'pieces' field and split into SHA-1 hashes
    pieces_raw, piece_hashes = _parse_and_validate_pieces(info, total_length, piece_length)

    # 8. Extract optional metadata
    comment, created_by, creation_date, private = _parse_optional_metadata(root_dict, info)

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
    Load a .torrent file from the filesystem and construct TorrentMetadata.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Torrent file not found: {path}")
    if path.is_dir():
        raise TorrentParseError(f"Specified path is a directory, not a file: {path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as e:
        raise TorrentParseError(f"Failed to read torrent file from disk: {e}") from e

    return load_torrent_bytes(raw_bytes)


def ensure_torrent_metadata(
    torrent: Union[TorrentMetadata, bytes, bytearray, memoryview, str, Path],
) -> TorrentMetadata:
    """
    Ensure the input is converted to a TorrentMetadata instance.

    Accepts:
    - TorrentMetadata directly
    - Path or str (reads file and decodes)
    - bytes, bytearray, memoryview (decodes raw Bencode bytes)
    """
    if isinstance(torrent, TorrentMetadata):
        return torrent
    elif isinstance(torrent, (str, Path)):
        return load_torrent_file(torrent)
    elif isinstance(torrent, (bytes, bytearray, memoryview)):
        return load_torrent_bytes(torrent)
    else:
        raise TypeError(f"Invalid type for torrent argument: {type(torrent).__name__}.")



