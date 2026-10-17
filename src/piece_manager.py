"""
Module for piece and block management (Piece Manager).

Responsibilities:
- Structured representation of Blocks (`Block`), Pieces (`Piece`), and their states (`BlockState`, `PieceState`);
- Accurate division of pieces into standard-sized blocks (16 KB) with automatic handling of the last piece and last block;
- In-memory storage of out-of-order received blocks and deduplication of repeated blocks;
- Strict SHA-1 integrity validation of assembled pieces;
- Automatic block discarding and resetting upon hash verification failure (corrupted piece);
- Thread-safe synchronization for concurrent access across multiple peers (Lock/RLock);
- Download progress tracking and local Bitfield generation;
- Ordered reconstruction of file/torrent data.
"""

import random
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union

from .hash_utils import verify_sha1
from .peer import DEFAULT_BLOCK_SIZE, Bitfield
from .torrent import (
    TorrentMetadata,
    TorrentSecurityError,
    ensure_torrent_metadata,
    load_torrent_bytes,
    load_torrent_file,
)


# ==============================================================================
# Block and Piece States
# ==============================================================================

class BlockState(Enum):
    """State of an individual block within a piece."""
    MISSING = "missing"        # Not yet requested or received
    REQUESTED = "requested"    # Requested from a peer, awaiting response
    RECEIVED = "received"      # Data received and stored in memory


class PieceState(Enum):
    """State of a torrent piece."""
    MISSING = "missing"          # No blocks completed/verified
    DOWNLOADING = "downloading"  # At least one block requested or received
    COMPLETED = "completed"      # All blocks received and SHA-1 hash validated


# ==============================================================================
# Block Representation
# ==============================================================================

@dataclass
class Block:
    """
    Representation of an individual data block within a piece.
    """
    piece_index: int
    begin: int
    length: int
    state: BlockState = BlockState.MISSING
    data: Optional[bytes] = None

    @property
    def is_received(self) -> bool:
        """Check whether the block has already been received."""
        return self.state == BlockState.RECEIVED and self.data is not None

    def reset(self) -> None:
        """Reset the block to initial MISSING state and discard data."""
        self.state = BlockState.MISSING
        self.data = None


# ==============================================================================
# Piece Representation
# ==============================================================================

class Piece:
    """
    Representation of a torrent piece composed of data blocks.

    Manages the lifecycle of its blocks, in-memory storage,
    sequential assembly, and SHA-1 hash integrity validation.
    """

    def __init__(
        self,
        index: int,
        length: int,
        expected_hash: Union[bytes, bytearray],
        block_size: int = DEFAULT_BLOCK_SIZE,
    ):
        if index < 0:
            raise ValueError(f"Piece index cannot be negative: {index}")
        if length <= 0:
            raise ValueError(f"Piece length must be strictly positive: {length}")
        if len(expected_hash) != 20:
            raise ValueError(
                f"Expected hash must be exactly 20 bytes, got {len(expected_hash)} bytes."
            )
        if block_size <= 0:
            raise ValueError(f"Block size must be strictly positive: {block_size}")

        self.index = index
        self.length = length
        self.expected_hash = bytes(expected_hash)
        self.block_size = block_size
        self.state = PieceState.MISSING

        self._lock = threading.RLock()
        self._data: Optional[bytes] = None
        self.blocks: List[Block] = self._init_blocks()

    def _init_blocks(self) -> List[Block]:
        """Divide the piece into contiguous blocks of block_size."""
        blocks: List[Block] = []
        offset = 0
        while offset < self.length:
            b_len = min(self.block_size, self.length - offset)
            blocks.append(
                Block(
                    piece_index=self.index,
                    begin=offset,
                    length=b_len,
                    state=BlockState.MISSING,
                )
            )
            offset += b_len
        return blocks

    @property
    def num_blocks(self) -> int:
        """Total number of blocks in this piece."""
        return len(self.blocks)

    def is_all_blocks_received(self) -> bool:
        """Check whether all blocks have been received."""
        return all(b.is_received for b in self.blocks)

    def is_completed(self) -> bool:
        """Check whether the piece has been completely assembled and validated."""
        return self.state == PieceState.COMPLETED and self._data is not None

    def add_block(self, begin: int, data: Union[bytes, bytearray, memoryview]) -> Tuple[bool, bool]:
        """
        Add data for a received block.

        Handles out-of-order receipt and discards duplicate blocks.
        If all blocks have been received, automatically runs SHA-1 hash validation.

        Returns:
            Tuple[bool, bool]: (block_added_successfully, piece_completed_and_valid)
        """
        raw_data = bytes(data)

        with self._lock:
            if self.state == PieceState.COMPLETED:
                # Piece already completed and validated previously
                return False, True

            # Locate block corresponding to 'begin' offset
            target_block: Optional[Block] = None
            for b in self.blocks:
                if b.begin == begin:
                    target_block = b
                    break

            if target_block is None:
                raise ValueError(
                    f"Offset {begin} does not correspond to any valid block in piece {self.index} (length: {self.length})."
                )

            if len(raw_data) != target_block.length:
                raise ValueError(
                    f"Received block size ({len(raw_data)} bytes) differs from expected "
                    f"({target_block.length} bytes) at offset {begin} of piece {self.index}."
                )

            # If block was already received previously (duplicate)
            if target_block.is_received:
                return False, self.state == PieceState.COMPLETED

            # Store block data
            target_block.data = raw_data
            target_block.state = BlockState.RECEIVED

            # Check if all blocks are completed
            if self.is_all_blocks_received():
                # Assemble complete piece data in order
                assembled = self._assemble_blocks()
                if verify_sha1(assembled, self.expected_hash):
                    self._data = assembled
                    self.state = PieceState.COMPLETED
                    return True, True
                else:
                    # Hash validation failure (corrupted data)
                    self.reset()
                    return True, False
            else:
                self.state = PieceState.DOWNLOADING
                return True, False

    def _assemble_blocks(self) -> bytes:
        """Concatenate all received blocks in offset order."""
        sorted_blocks = sorted(self.blocks, key=lambda b: b.begin)
        return b"".join(b.data for b in sorted_blocks if b.data is not None)

    def validate(self) -> bool:
        """
        Validate integrity of the complete piece against expected SHA-1 hash.
        If hash is valid, marks as COMPLETED. If invalid, resets all blocks.
        """
        with self._lock:
            if self.state == PieceState.COMPLETED:
                return True

            if not self.is_all_blocks_received():
                return False

            assembled = self._assemble_blocks()
            if verify_sha1(assembled, self.expected_hash):
                self._data = assembled
                self.state = PieceState.COMPLETED
                return True
            else:
                self.reset()
                return False

    def get_data(self) -> Optional[bytes]:
        """Return validated bytes of the piece, or None if incomplete."""
        with self._lock:
            return self._data

    def get_next_missing_block(self, mark_requested: bool = True) -> Optional[Block]:
        """
        Return the next pending block (MISSING).
        Optionally mark the block as REQUESTED.
        """
        with self._lock:
            if self.state == PieceState.COMPLETED:
                return None

            for b in self.blocks:
                if b.state == BlockState.MISSING:
                    if mark_requested:
                        b.state = BlockState.REQUESTED
                        self.state = PieceState.DOWNLOADING
                    return b
            return None

    def reset_block(self, begin: int) -> bool:
        """
        Reset a specific block from REQUESTED back to MISSING.
        Returns True if block was reset, False otherwise.
        """
        with self._lock:
            if self.state == PieceState.COMPLETED:
                return False

            for b in self.blocks:
                if b.begin == begin:
                    if b.state == BlockState.REQUESTED:
                        b.state = BlockState.MISSING
                        has_received = any(blk.state == BlockState.RECEIVED for blk in self.blocks)
                        has_requested = any(blk.state == BlockState.REQUESTED for blk in self.blocks)
                        if has_received or has_requested:
                            self.state = PieceState.DOWNLOADING
                        else:
                            self.state = PieceState.MISSING
                        return True
                    return False
            return False

    def reset_pending_blocks(self) -> None:
        """Reset blocks marked as REQUESTED back to MISSING."""
        with self._lock:
            if self.state == PieceState.COMPLETED:
                return
            for b in self.blocks:
                if b.state == BlockState.REQUESTED:
                    b.state = BlockState.MISSING

            has_received = any(b.state == BlockState.RECEIVED for b in self.blocks)
            self.state = PieceState.DOWNLOADING if has_received else PieceState.MISSING

    def reset(self) -> None:
        """Completely reset the piece and all its blocks back to MISSING."""
        with self._lock:
            for b in self.blocks:
                b.reset()
            self._data = None
            self.state = PieceState.MISSING


# ==============================================================================
# Piece Manager
# ==============================================================================

class PieceManager:
    """
    Central manager for torrent pieces and blocks state.

    Responsible for:
    - Initializing all pieces from `TorrentMetadata` (or equivalent parameters);
    - Calculating exact piece and block sizes, including the last piece;
    - Tracking pending, downloading, and completed pieces;
    - Offering safe block selection for downloading across multiple concurrent peers;
    - Receiving blocks from peers, handling duplicates and out-of-order blocks;
    - Validating SHA-1 hashes upon completion of each piece;
    - Maintaining thread-safe synchronization for multi-thread concurrency;
    - Reconstructing complete ordered data for the file/torrent.
    """

    def __init__(
        self,
        torrent: Optional[Union[TorrentMetadata, bytes, bytearray, memoryview, str, Path]] = None,
        *,
        total_length: Optional[int] = None,
        piece_length: Optional[int] = None,
        piece_hashes: Optional[Sequence[Union[bytes, bytearray]]] = None,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ):
        self._lock = threading.RLock()
        self.block_size = block_size

        resolved_meta: Optional[TorrentMetadata] = None
        if torrent is not None:
            resolved_meta = ensure_torrent_metadata(torrent)

        self.metadata: Optional[TorrentMetadata] = resolved_meta
        if resolved_meta is not None:
            self.total_length = resolved_meta.total_length
            self.piece_length = resolved_meta.piece_length
            hashes_list = resolved_meta.piece_hashes
        else:
            if total_length is None or piece_length is None or piece_hashes is None:
                raise ValueError(
                    "Must provide 'torrent' or parameters 'total_length', 'piece_length' and 'piece_hashes'."
                )
            self.total_length = total_length
            self.piece_length = piece_length
            hashes_list = [bytes(h) for h in piece_hashes]

        if self.total_length < 0:
            raise ValueError(f"total_length cannot be negative: {self.total_length}")
        if self.piece_length <= 0:
            raise ValueError(f"piece_length must be positive: {self.piece_length}")

        self.num_pieces = len(hashes_list)
        self.bitfield = Bitfield(num_pieces=self.num_pieces)
        self.pieces: List[Piece] = self._init_pieces(hashes_list)
        self._availability: List[int] = [0] * self.num_pieces

    def _init_pieces(self, piece_hashes: Sequence[Union[bytes, bytearray]]) -> List[Piece]:
        """Initialize all Piece instances calculating the exact length of each."""
        pieces: List[Piece] = []
        for i, expected_hash in enumerate(piece_hashes):
            p_len = self.get_piece_length(i)
            pieces.append(
                Piece(
                    index=i,
                    length=p_len,
                    expected_hash=bytes(expected_hash),
                    block_size=self.block_size,
                )
            )
        return pieces

    def get_piece_length(self, piece_index: int) -> int:
        """
        Return size in bytes of piece at the given index.
        Handles the last piece size properly.
        """
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
            )

        if piece_index == self.num_pieces - 1:
            remainder = self.total_length % self.piece_length
            return remainder if remainder != 0 else self.piece_length
        return self.piece_length

    def get_piece(self, piece_index: int) -> Piece:
        """Return the Piece instance for the given index."""
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
            )
        return self.pieces[piece_index]

    def is_piece_complete(self, piece_index: int) -> bool:
        """Check whether a specific piece is complete and validated."""
        with self._lock:
            return self.get_piece(piece_index).is_completed()

    @property
    def is_complete(self) -> bool:
        """Indicate whether all pieces of the torrent have been downloaded and validated."""
        with self._lock:
            return self.completed_pieces_count() == self.num_pieces

    def completed_pieces_count(self) -> int:
        """Return the number of completed and validated pieces."""
        with self._lock:
            return sum(1 for p in self.pieces if p.is_completed())

    def downloading_pieces_count(self) -> int:
        """Return the number of pieces currently being downloaded."""
        with self._lock:
            return sum(1 for p in self.pieces if p.state == PieceState.DOWNLOADING)

    def missing_pieces_count(self) -> int:
        """Return the number of pieces not yet started (MISSING)."""
        with self._lock:
            return sum(1 for p in self.pieces if p.state == PieceState.MISSING)

    def bytes_downloaded(self) -> int:
        """Return the total bytes downloaded and successfully validated."""
        with self._lock:
            return sum(p.length for p in self.pieces if p.is_completed())

    def bytes_left(self) -> int:
        """Return total remaining bytes to complete the torrent."""
        with self._lock:
            return max(0, self.total_length - self.bytes_downloaded())

    @property
    def progress(self) -> float:
        """Return download progress fraction (between 0.0 and 1.0)."""
        with self._lock:
            if self.total_length == 0:
                return 1.0
            return self.bytes_downloaded() / self.total_length

    def add_block(
        self,
        piece_index: int,
        begin: int,
        data: Union[bytes, bytearray, memoryview],
    ) -> Tuple[bool, bool]:
        """
        Receive and process a data block for the specified piece.

        Synchronizes the local bitfield if the piece is completed successfully.

        Returns:
            Tuple[bool, bool]: (block_added, piece_completed_and_valid)
        """
        with self._lock:
            piece = self.get_piece(piece_index)
            added, completed = piece.add_block(begin, data)

            if completed:
                self.bitfield.set_piece(piece_index, True)

            return added, completed

    # ==============================================================================
    # Availability Tracking (Rarest First / BEP 0003)
    # ==============================================================================

    def add_peer_bitfield(self, bitfield: Optional[Bitfield]) -> None:
        """
        Increment availability of each piece present in the new peer's bitfield.
        """
        if bitfield is None:
            return
        with self._lock:
            for i in range(min(self.num_pieces, bitfield.num_pieces)):
                if bitfield.has_piece(i):
                    self._availability[i] += 1

    def remove_peer_bitfield(self, bitfield: Optional[Bitfield]) -> None:
        """
        Decrement availability of each piece when a peer disconnects.
        """
        if bitfield is None:
            return
        with self._lock:
            for i in range(min(self.num_pieces, bitfield.num_pieces)):
                if bitfield.has_piece(i):
                    self._availability[i] = max(0, self._availability[i] - 1)

    def update_peer_have(self, piece_index: int) -> None:
        """
        Increment availability of a piece upon receiving a Have message from a peer.
        """
        with self._lock:
            if 0 <= piece_index < self.num_pieces:
                self._availability[piece_index] += 1

    def decrement_piece_availability(self, piece_index: int) -> None:
        """
        Decrement availability of a specific piece.
        """
        with self._lock:
            if 0 <= piece_index < self.num_pieces:
                self._availability[piece_index] = max(0, self._availability[piece_index] - 1)

    def get_piece_availability(self, piece_index: int) -> int:
        """
        Return current availability count (how many peers possess it) for the given piece.
        """
        with self._lock:
            if not (0 <= piece_index < self.num_pieces):
                raise IndexError(
                    f"Piece index out of range: {piece_index} (total: {self.num_pieces})"
                )
            return self._availability[piece_index]

    def get_all_availabilities(self) -> List[int]:
        """
        Return a copy of the availability list for all pieces.
        """
        with self._lock:
            return list(self._availability)

    def get_next_block_to_request(
        self,
        peer_bitfield: Optional[Bitfield] = None,
        tie_breaker: str = "index",
    ) -> Optional[Tuple[int, int, int]]:
        """
        Thread-safely select next block to request from a peer following
        the Rarest First strategy (BEP 0003).

        Prioritization and Tie-breaking Strategy:
        1. Filters non-completed pieces (MISSING or DOWNLOADING) that peer possesses
           in their bitfield (`peer_bitfield.has_piece(piece.index)`);
        2. Prioritizes pieces already in progress (`DOWNLOADING`) to finish pending blocks;
        3. Prioritizes pieces with lower swarm availability (Rarest First);
        4. Deterministic tie-breaker: among pieces with same priority/rarity,
           uses lowest piece index (`piece.index`) as default criterion.

        Returns:
            Optional[Tuple[int, int, int]]: (piece_index, begin, length) or None if no blocks available.
        """
        with self._lock:
            # 1. Collect eligible pieces (incomplete and possessed by peer)
            eligible_pieces: List[Piece] = []
            for piece in self.pieces:
                if piece.is_completed() or piece.state == PieceState.COMPLETED:
                    continue
                if peer_bitfield is not None and not peer_bitfield.has_piece(piece.index):
                    continue
                eligible_pieces.append(piece)

            if not eligible_pieces:
                return None

            # 2. Sort based on strategy:
            #    - DOWNLOADING first (0 for DOWNLOADING, 1 for MISSING)
            #    - Lowest availability (Rarest First)
            #    - Tie-breaker: lowest piece index (or random if tie_breaker="random")
            if tie_breaker == "random":
                eligible_pieces.sort(
                    key=lambda p: (
                        1 if p.state == PieceState.MISSING else 0,
                        self._availability[p.index],
                        random.random(),
                    )
                )
            else:
                eligible_pieces.sort(
                    key=lambda p: (
                        1 if p.state == PieceState.MISSING else 0,
                        self._availability[p.index],
                        p.index,
                    )
                )

            # 3. Extract next pending block from first piece that has blocks
            for piece in eligible_pieces:
                block = piece.get_next_missing_block(mark_requested=True)
                if block is not None:
                    return piece.index, block.begin, block.length

            return None

    def reset_block(self, piece_index: int, begin: int) -> bool:
        """
        Reset a specific block of a piece from REQUESTED back to MISSING.
        """
        with self._lock:
            if 0 <= piece_index < self.num_pieces:
                return self.get_piece(piece_index).reset_block(begin)
            return False

    def reset_blocks(self, blocks: Sequence[Tuple[int, int]]) -> None:
        """
        Reset multiple blocks (piece_index, begin) back to MISSING.
        """
        with self._lock:
            for piece_idx, begin in blocks:
                if 0 <= piece_idx < self.num_pieces:
                    self.get_piece(piece_idx).reset_block(begin)

    def reset_pending_requests(self, piece_index: Optional[int] = None) -> None:
        """
        Reset blocks marked as REQUESTED back to MISSING.
        Useful when a peer disconnects before delivering requested blocks.
        """
        with self._lock:
            if piece_index is not None:
                self.get_piece(piece_index).reset_pending_blocks()
            else:
                for piece in self.pieces:
                    piece.reset_pending_blocks()

    def get_piece_data(self, piece_index: int) -> Optional[bytes]:
        """Return validated data of an individual piece."""
        with self._lock:
            return self.get_piece(piece_index).get_data()

    def get_all_data(self) -> bytes:
        """
        Reconstruct and return all ordered torrent data in bytes.

        Raises:
            ValueError: If download is not yet 100% complete.
        """
        with self._lock:
            if not self.is_complete:
                raise ValueError(
                    f"Cannot reconstruct data: incomplete download "
                    f"({self.completed_pieces_count()}/{self.num_pieces} pieces downloaded)."
                )

            return b"".join(p.get_data() for p in self.pieces)  # type: ignore

    def verify_piece(self, piece_index: int, data: Union[bytes, bytearray, memoryview]) -> bool:
        """
        Verify whether raw piece data matches its expected SHA-1 hash.
        If valid, marks piece as COMPLETED, sets blocks as RECEIVED, and updates bitfield.
        Returns True if valid, False if invalid or corrupted.
        """
        with self._lock:
            if not (0 <= piece_index < self.num_pieces):
                return False
            piece = self.get_piece(piece_index)
            raw_bytes = bytes(data)
            if len(raw_bytes) != piece.length:
                return False
            if verify_sha1(raw_bytes, piece.expected_hash):
                piece._data = raw_bytes
                piece.state = PieceState.COMPLETED
                for b in piece.blocks:
                    b.state = BlockState.RECEIVED
                    b.data = raw_bytes[b.begin : b.begin + b.length]
                self.bitfield.set_piece(piece_index, True)
                return True
            else:
                piece.reset()
                return False

    def check_existing_data(self, data: Union[bytes, bytearray, memoryview]) -> int:
        """
        Check existing data (e.g. from partial file) and validate each piece by SHA-1.
        Returns number of valid pieces found and completed.
        """
        raw = bytes(data)
        valid_count = 0
        with self._lock:
            offset = 0
            for i, piece in enumerate(self.pieces):
                if offset + piece.length <= len(raw):
                    piece_data = raw[offset : offset + piece.length]
                    if self.verify_piece(i, piece_data):
                        valid_count += 1
                offset += piece.length
        return valid_count

    def check_existing_file(self, target_path: Union[str, Path]) -> int:
        """
        Read existing file from disk and validate each of its pieces with SHA-1.
        Reads pieces on-demand piece by piece without loading whole file into memory.
        Valid pieces are marked completed and will not be re-downloaded.
        """
        path = Path(target_path)
        if not path.is_file():
            return 0
        valid_count = 0
        try:
            with open(path, "rb") as f:
                with self._lock:
                    for i, piece in enumerate(self.pieces):
                        piece_data = f.read(piece.length)
                        if len(piece_data) == piece.length:
                            if self.verify_piece(i, piece_data):
                                valid_count += 1
                        else:
                            break
            return valid_count
        except OSError:
            return 0

    def save_to_file(self, target_path: Union[str, Path]) -> None:
        """
        Save reconstructed torrent data to disk.

        Supports:
        - Single-file torrents (or instances without metadata): saves to a single file at target path.
        - Multi-file torrents: saves all files preserving directory hierarchy specified
          by metadata under provided base directory.
        """
        data = self.get_all_data()
        dest = Path(target_path).resolve()

        if self.metadata is not None and self.metadata.is_multi_file:
            base_dir = (dest / self.metadata.name).resolve() if dest.name != self.metadata.name else dest
            offset = 0
            for file_info in self.metadata.files:
                file_path = base_dir.joinpath(*file_info.path).resolve()
                try:
                    file_path.relative_to(base_dir)
                except ValueError:
                    raise TorrentSecurityError(f"Path Traversal attempt when saving file: {file_path}")

                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_data = data[offset : offset + file_info.length]
                file_path.write_bytes(file_data)
                offset += file_info.length
        else:
            if self.metadata is not None and not self.metadata.is_multi_file and dest.is_dir():
                target_file = (dest / self.metadata.name).resolve()
                try:
                    target_file.relative_to(dest)
                except ValueError:
                    raise TorrentSecurityError(f"Path Traversal attempt when saving file: {target_file}")
            else:
                target_file = dest

            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(data)

