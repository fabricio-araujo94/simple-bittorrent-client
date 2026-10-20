"""
Main orchestration and BitTorrent download module (Client / Downloader).

Integrates the following layers:
1. Torrent Parser (`TorrentMetadata`, `load_torrent_file`, `load_torrent_bytes`);
2. HTTP Tracker (`HTTPTrackerClient`, `query_http_tracker`);
3. Peer Wire Protocol (`PeerConnection`, `Handshake`, `Bitfield`, messages);
4. Piece Manager (`PieceManager`, `Piece`, `Block`).

Implemented Download Flow:
1. Load and validate torrent metadata (.torrent / bytes);
2. Extract 20-byte SHA-1 `info_hash` and generate `peer_id`;
3. Query and send initial announce to HTTP Tracker to discover peers;
4. Establish TCP connection and negotiate 68-byte Handshake with strict validation;
5. Receive and update piece maps (`Bitfield` and `Have`);
6. Send `Interested` message to peers possessing needed pieces;
7. Await `Unchoke` message from peer;
8. Select available pieces and blocks (16 KB) sequentially and thread-safely;
9. Send `Request` messages and receive `Piece` messages;
10. Store blocks, assemble piece, and validate integrity via SHA-1 hash;
11. Notify piece completion and repeat cycle until 100% of torrent is downloaded;
12. Orderly reconstruction and saving of file.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .hash_utils import compute_sha1
from .peer import (
    DEFAULT_BLOCK_SIZE,
    Bitfield,
    BitfieldMessage,
    ChokeMessage,
    HandshakeError,
    HaveMessage,
    InterestedMessage,
    KeepAliveMessage,
    MessageSizeError,
    NotInterestedMessage,
    PeerConnection,
    PeerConnectionClosedError,
    PeerConnectionError,
    PeerError,
    PeerMessage,
    PeerProtocolError,
    PeerTimeoutError,
    PieceMessage,
    UnchokeMessage,
)
from .piece_manager import PieceManager, PieceState
from .torrent import (
    FileInfo,
    TorrentMetadata,
    ensure_torrent_metadata,
    load_torrent_bytes,
    load_torrent_file,
)
from .tracker import (
    HTTPTrackerClient,
    HTTPOpenerType,
    PeerInfo,
    TrackerError,
    TrackerResponse,
)

logger = logging.getLogger("simple_bittorrent.client")


class DownloadError(Exception):
    """Base exception for errors during the download process."""
    pass


class DownloadIncompleteError(DownloadError):
    """Exception raised when download finishes without all pieces being obtained."""
    pass


class NoPeersAvailableError(DownloadError):
    """Exception raised when the swarm has no available peers or none responds."""
    pass


class TrackerUnavailableError(DownloadError):
    """Exception raised when none of the provided trackers is reachable."""
    pass


@dataclass
class DownloadProgress:
    """Structure containing real-time download progress statistics."""
    total_length: int
    bytes_downloaded: int
    bytes_left: int
    completed_pieces: int
    total_pieces: int
    progress_percentage: float
    is_complete: bool


class TorrentClient:
    """
    Unified BitTorrent client for concurrent torrent downloading from multiple peers.
    """

    def __init__(
        self,
        torrent: Union[TorrentMetadata, bytes, bytearray, memoryview, str, Path],
        *,
        output_path: Optional[Union[str, Path]] = None,
        peer_id: Optional[Union[bytes, str]] = None,
        port: int = 6881,
        block_size: int = DEFAULT_BLOCK_SIZE,
        max_in_flight: int = 4,
        peer_timeout: float = 10.0,
        tracker_timeout: float = 15.0,
        http_opener: Optional[HTTPOpenerType] = None,
        auto_resume: bool = False,
    ):
        # 1. Load and validate torrent metadata
        self.torrent_meta = ensure_torrent_metadata(torrent)

        self.info_hash = self.torrent_meta.info_hash
        self.output_path = Path(output_path) if output_path else None
        self.port = port
        self.block_size = block_size
        self.max_in_flight = max(1, max_in_flight)
        self.peer_timeout = peer_timeout
        self.tracker_timeout = tracker_timeout
        self.http_opener = http_opener

        # 2. Initialize PieceManager
        self.piece_manager = PieceManager(
            torrent=self.torrent_meta,
            block_size=self.block_size,
        )

        # 3. Initialize Tracker Client
        self.tracker_client = HTTPTrackerClient(
            torrent=self.torrent_meta,
            peer_id=peer_id,
            port=self.port,
            opener=self.http_opener,
        )
        self.peer_id = self.tracker_client.peer_id

        # Concurrency control, active connections, and shutdown
        self._stop_requested = False
        self._lock = threading.RLock()
        self._active_connections: List[PeerConnection] = []
        self._active_connections_lock = threading.Lock()

        # Automatic verification of existing files for download resuming
        if auto_resume and self.output_path is not None:
            self.check_existing_files(self.output_path)

    @property
    def is_complete(self) -> bool:
        """Check whether all torrent pieces have been downloaded and verified."""
        return self.piece_manager.is_complete

    def _register_connection(self, conn: PeerConnection) -> None:
        """Register an active peer connection."""
        with self._active_connections_lock:
            self._active_connections.append(conn)

    def _unregister_connection(self, conn: PeerConnection) -> None:
        """Unregister a peer connection."""
        with self._active_connections_lock:
            if conn in self._active_connections:
                self._active_connections.remove(conn)

    def _broadcast_have(self, piece_index: int) -> None:
        """Send Have message to all active peer connections."""
        with self._active_connections_lock:
            active = list(self._active_connections)
        dead_connections: List[PeerConnection] = []
        for conn in active:
            try:
                conn.send_have(piece_index)
            except (PeerConnectionError, OSError) as e:
                logger.debug(f"Failed to send Have to peer {conn.peer_host}:{conn.peer_port}: {e}")
                dead_connections.append(conn)

        if dead_connections:
            with self._active_connections_lock:
                for dead_conn in dead_connections:
                    if dead_conn in self._active_connections:
                        self._active_connections.remove(dead_conn)

    def check_existing_files(self, target_destination: Optional[Union[str, Path]] = None) -> int:
        """
        Check if partial files already exist on disk and validate each piece with SHA-1.
        Valid pieces are marked completed and reused for the download.
        Reads pieces on-demand directly from files on disk,
        maintaining O(piece_length) memory consumption to avoid MemoryError on large torrents.
        """
        dest = Path(target_destination) if target_destination is not None else self.output_path
        if dest is None:
            return 0

        if not self.torrent_meta.is_multi_file:
            target_file = dest if not dest.is_dir() else dest / self.torrent_meta.name
            return self.piece_manager.check_existing_file(target_file)
        else:
            base_dir = dest / self.torrent_meta.name if not dest.name == self.torrent_meta.name else dest
            if not base_dir.is_dir():
                return 0
            return self._verify_multi_file_existing_pieces(base_dir)

    def _verify_multi_file_existing_pieces(self, base_dir: Path) -> int:
        """
        Validate pieces spanning multiple files on disk for auto-resume.
        Streams piece data with O(piece_length) memory consumption.
        """
        # Map each file to its global offsets [start_offset, end_offset)
        file_spans = []
        cur_offset = 0
        for file_info in self.torrent_meta.files:
            file_path = base_dir.joinpath(*file_info.path)
            file_spans.append((cur_offset, cur_offset + file_info.length, file_path, file_info.length))
            cur_offset += file_info.length

        valid_count = 0
        opened_files = {}
        try:
            piece_offset = 0
            for piece_index in range(self.torrent_meta.num_pieces):
                piece_len = self.torrent_meta.get_piece_length(piece_index)
                piece_end = piece_offset + piece_len
                piece_buf = bytearray(piece_len)

                for f_start, f_end, f_path, f_len in file_spans:
                    if f_end <= piece_offset or f_start >= piece_end:
                        continue

                    # Overlap interval within torrent global offsets
                    overlap_start = max(piece_offset, f_start)
                    overlap_end = min(piece_end, f_end)
                    read_len = overlap_end - overlap_start

                    file_seek_pos = overlap_start - f_start
                    piece_buf_pos = overlap_start - piece_offset

                    if f_path.is_file():
                        if f_path not in opened_files:
                            opened_files[f_path] = open(f_path, "rb")
                        f = opened_files[f_path]
                        f.seek(file_seek_pos)
                        chunk = f.read(read_len)
                        piece_buf[piece_buf_pos : piece_buf_pos + len(chunk)] = chunk
                    else:
                        # File does not exist on disk, remains 0x00
                        pass

                if self.piece_manager.verify_piece(piece_index, bytes(piece_buf)):
                    valid_count += 1

                piece_offset += piece_len
        except OSError:
            pass
        finally:
            for f in opened_files.values():
                try:
                    f.close()
                except OSError:
                    pass

        return valid_count

    def get_progress(self) -> DownloadProgress:
        """Return current download progress."""
        downloaded = self.piece_manager.bytes_downloaded()
        total = self.torrent_meta.total_length
        pct = (downloaded / total * 100.0) if total > 0 else 100.0
        return DownloadProgress(
            total_length=total,
            bytes_downloaded=downloaded,
            bytes_left=self.piece_manager.bytes_left(),
            completed_pieces=self.piece_manager.completed_pieces_count(),
            total_pieces=self.torrent_meta.num_pieces,
            progress_percentage=pct,
            is_complete=self.piece_manager.is_complete,
        )

    def discover_peers(self) -> List[PeerInfo]:
        """
        Query HTTP tracker (with fallback across multiple trackers if available)
        to obtain list of available peers in the swarm.
        """
        trackers_to_try: List[str] = []
        if self.torrent_meta.announce:
            trackers_to_try.append(self.torrent_meta.announce)
        if self.torrent_meta.trackers:
            for tr in self.torrent_meta.trackers:
                if tr not in trackers_to_try:
                    trackers_to_try.append(tr)

        if not trackers_to_try:
            raise TrackerUnavailableError("No tracker URLs configured in torrent.")

        last_error = None
        for tracker_url in trackers_to_try:
            try:
                resp: TrackerResponse = self.tracker_client.announce(
                    uploaded=0,
                    downloaded=self.piece_manager.bytes_downloaded(),
                    left=self.piece_manager.bytes_left(),
                    event="started",
                    timeout=self.tracker_timeout,
                    tracker_url=tracker_url,
                )
                return resp.peers
            except TrackerError as e:
                logger.warning(f"Failed to query tracker {tracker_url}: {e}")
                last_error = e

        if last_error is not None:
            raise TrackerUnavailableError(f"All trackers are unreachable: {last_error}") from last_error
        return []

    def _send_in_flight_requests(
        self,
        conn: PeerConnection,
        in_flight: Dict[Tuple[int, int], int],
        max_in_flight: int,
    ) -> None:
        """Send pending block requests up to max_in_flight limit if unchoked."""
        if conn.peer_choking:
            return

        while len(in_flight) < max_in_flight and not self.piece_manager.is_complete and not self._stop_requested:
            req = self.piece_manager.get_next_block_to_request(peer_bitfield=conn.peer_bitfield)
            if req is None:
                break
            piece_idx, begin, length = req
            try:
                conn.send_request(index=piece_idx, begin=begin, length=length)
                in_flight[(piece_idx, begin)] = length
            except Exception:
                self.piece_manager.reset_block(piece_idx, begin)
                raise

    def _handle_incoming_peer_message(
        self,
        conn: PeerConnection,
        msg: PeerMessage,
        in_flight: Dict[Tuple[int, int], int],
        registered_bitfield: Optional[Bitfield],
        on_progress: Optional[Callable[[DownloadProgress], None]],
    ) -> Optional[Bitfield]:
        """Process incoming peer protocol message and update state/in-flight maps."""
        if isinstance(msg, PieceMessage):
            in_flight.pop((msg.index, msg.begin), None)
            _, completed = self.piece_manager.add_block(
                piece_index=msg.index,
                begin=msg.begin,
                data=msg.block,
            )
            if completed:
                self._broadcast_have(msg.index)
            if on_progress is not None:
                on_progress(self.get_progress())

        elif isinstance(msg, ChokeMessage):
            conn.peer_choking = True
            for (p_idx, b_begin) in list(in_flight.keys()):
                self.piece_manager.reset_block(p_idx, b_begin)
            in_flight.clear()

        elif isinstance(msg, UnchokeMessage):
            conn.peer_choking = False

        elif isinstance(msg, HaveMessage):
            if conn.peer_bitfield is None:
                conn.peer_bitfield = Bitfield(num_pieces=self.torrent_meta.num_pieces)
                registered_bitfield = conn.peer_bitfield
            if msg.piece_index < conn.peer_bitfield.num_pieces:
                if not conn.peer_bitfield.has_piece(msg.piece_index):
                    conn.peer_bitfield.set_piece(msg.piece_index, True)
                    self.piece_manager.update_peer_have(msg.piece_index)

        elif isinstance(msg, BitfieldMessage):
            if registered_bitfield is not None:
                self.piece_manager.remove_peer_bitfield(registered_bitfield)
            conn.peer_bitfield = msg.to_bitfield(self.torrent_meta.num_pieces)
            registered_bitfield = conn.peer_bitfield
            self.piece_manager.add_peer_bitfield(registered_bitfield)

        return registered_bitfield

    def download_from_peer_connection(
        self,
        conn: PeerConnection,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
        max_blocks_per_iteration: int = 1000,
        max_in_flight: Optional[int] = None,
    ) -> bool:
        """
        Execute download loop with an established peer connection that completed handshake.

        Specific error handling:
        - Disconnect/EOF: `PeerConnectionClosedError`
        - Timeout: `PeerTimeoutError`
        - Protocol violations: `HandshakeError`, `MessageSizeError`, `PeerProtocolError`
        - Network failure: `PeerConnectionError`, `OSError`
        - Malformed data or unexpected indices: `ValueError`, `IndexError`

        Returns:
            bool: True if torrent download completed or progressed, False if disconnected/failed.
        """
        effective_max_in_flight = max_in_flight if max_in_flight is not None else self.max_in_flight
        self._register_connection(conn)
        in_flight: Dict[Tuple[int, int], int] = {}  # (piece_idx, begin) -> length
        registered_bitfield: Optional[Bitfield] = None

        try:
            # 1. Send 'Interested'
            conn.send_interested()

            if conn.peer_bitfield is not None:
                registered_bitfield = conn.peer_bitfield
                self.piece_manager.add_peer_bitfield(registered_bitfield)

            consecutive_no_requests = 0
            iteration = 0

            while not self.piece_manager.is_complete and not self._stop_requested:
                iteration += 1
                if 0 < max_blocks_per_iteration < iteration:
                    break

                # 1. Pipeline requests up to in_flight limit
                self._send_in_flight_requests(conn, in_flight, effective_max_in_flight)

                # 2. Decide how to read from socket based on in-flight requests
                if len(in_flight) == 0:
                    if conn.peer_choking:
                        # Choked by peer and no pending requests: wait for message (unchoke/have/bitfield)
                        try:
                            msg = conn.read_message(timeout=self.peer_timeout)
                        except PeerTimeoutError:
                            logger.debug(f"Peer {conn.peer_host}:{conn.peer_port} remained choked after timeout.")
                            break
                    else:
                        consecutive_no_requests += 1
                        if consecutive_no_requests >= 50:
                            break
                        try:
                            msg = conn.read_message(timeout=min(self.peer_timeout, 0.5))
                        except PeerTimeoutError:
                            time.sleep(0.02)
                            continue
                else:
                    consecutive_no_requests = 0
                    msg = conn.read_message(timeout=self.peer_timeout)

                # 3. Process received message
                registered_bitfield = self._handle_incoming_peer_message(
                    conn, msg, in_flight, registered_bitfield, on_progress
                )

                if not isinstance(msg, KeepAliveMessage):
                    consecutive_no_requests = 0

            return self.piece_manager.is_complete

        except PeerConnectionClosedError as e:
            logger.debug(f"Peer {conn.peer_host}:{conn.peer_port} disconnected (EOF): {e}")
            return False
        except PeerTimeoutError as e:
            logger.debug(f"Communication timeout with peer {conn.peer_host}:{conn.peer_port}: {e}")
            return False
        except (HandshakeError, MessageSizeError, PeerProtocolError) as e:
            logger.warning(f"Protocol violation by peer {conn.peer_host}:{conn.peer_port}: {e}")
            return False
        except (PeerConnectionError, OSError) as e:
            logger.debug(f"Connection error with peer {conn.peer_host}:{conn.peer_port}: {e}")
            return False
        except (ValueError, IndexError) as e:
            logger.warning(f"Unexpected data received from peer {conn.peer_host}:{conn.peer_port}: {e}")
            return False
        finally:
            # Release any in-flight blocks assigned to this peer
            for (p_idx, b_begin) in list(in_flight.keys()):
                self.piece_manager.reset_block(p_idx, b_begin)
            in_flight.clear()
            if registered_bitfield is not None:
                self.piece_manager.remove_peer_bitfield(registered_bitfield)
            self._unregister_connection(conn)

    def download_from_peer(
        self,
        peer: PeerInfo,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
        max_in_flight: Optional[int] = None,
    ) -> bool:
        """
        Connect to a peer, perform handshake, and start block downloading.
        Specifically handles handshake, network, and timeout errors.
        """
        if self.piece_manager.is_complete:
            return True

        conn = PeerConnection(
            host=peer.ip,
            port=peer.port,
            default_timeout=self.peer_timeout,
            num_pieces=self.torrent_meta.num_pieces,
        )

        try:
            conn.connect()
            # Perform BitTorrent handshake (BEP 0003)
            conn.perform_handshake(
                info_hash=self.info_hash,
                peer_id=self.peer_id,
            )

            # Run request and download cycle
            return self.download_from_peer_connection(
                conn,
                on_progress=on_progress,
                max_in_flight=max_in_flight,
            )

        except HandshakeError as e:
            logger.warning(f"Handshake rejected by peer {peer.ip}:{peer.port}: {e}")
            return False
        except (PeerConnectionError, PeerTimeoutError, OSError) as e:
            logger.debug(f"Connection failure with peer {peer.ip}:{peer.port}: {e}")
            return False
        finally:
            conn.close()

    def download(
        self,
        peers: Optional[Sequence[PeerInfo]] = None,
        max_workers: int = 4,
        max_in_flight: Optional[int] = None,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
    ) -> bytes:
        """
        Execute full concurrent torrent download flow across multiple peers.

        Concurrency Strategy: Threading (Worker Threads per Peer)
        - Maintains multiple simultaneous peer connections;
        - Each connection operates in its own thread with a dedicated TCP socket;
        - Coordinated atomic block distribution via PieceManager (thread-safe);
        - Request pipelining per peer for high performance without overloading;
        - Strict failure isolation: peer disconnection re-queues only its own
          in-flight blocks and the thread attempts the next available peer.

        Returns:
            bytes: Complete ordered data of the reconstructed torrent.
        """
        self._stop_requested = False

        # If already 100% complete (e.g. from existing resume file), return immediately
        if self.piece_manager.is_complete:
            return self._finalize_download()

        # Retrieve peers if not explicitly passed
        available_peers: List[PeerInfo] = list(peers) if peers is not None else self.discover_peers()
        if not available_peers:
            raise NoPeersAvailableError("No available peers in swarm to perform download.")

        peer_queue: queue.Queue[PeerInfo] = queue.Queue()
        for peer in available_peers:
            peer_queue.put(peer)

        def worker_loop():
            while not self.piece_manager.is_complete and not self._stop_requested:
                try:
                    peer = peer_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self.download_from_peer(
                        peer,
                        on_progress=on_progress,
                        max_in_flight=max_in_flight,
                    )
                except (PeerError, OSError) as e:
                    logger.debug(f"Peer error with {peer.ip}:{peer.port}: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error in peer worker ({peer.ip}:{peer.port}): {e}", exc_info=True)

        num_workers = min(max(1, max_workers), len(available_peers))
        threads: List[threading.Thread] = []
        for i in range(num_workers):
            t = threading.Thread(target=worker_loop, name=f"PeerWorker-{i}", daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if not self.piece_manager.is_complete:
            raise DownloadIncompleteError(
                f"Incomplete download: "
                f"{self.piece_manager.completed_pieces_count()}/{self.torrent_meta.num_pieces} pieces obtained "
                f"({self.piece_manager.bytes_downloaded()}/{self.torrent_meta.total_length} bytes)."
            )

        return self._finalize_download()

    def _finalize_download(self) -> bytes:
        """
        Reconstruct final file, write to disk if requested, and notify tracker.
        """
        all_data = self.piece_manager.get_all_data()

        # Write to disk
        if self.output_path is not None:
            self.save_files(self.output_path)

        # Notify tracker of completion
        try:
            self.tracker_client.complete(
                uploaded=0,
                downloaded=self.torrent_meta.total_length,
                timeout=self.tracker_timeout,
            )
        except Exception as e:
            logger.debug(f"Could not send completed event to tracker: {e}")

        return all_data

    def save_files(self, target_destination: Union[str, Path]) -> None:
        """
        Save downloaded files respecting single-file or multi-file structure.
        Ensures strict isolation against Path Traversal and arbitrary disk writes.
        """
        all_data = self.piece_manager.get_all_data()
        dest = Path(target_destination).resolve()

        if not self.torrent_meta.is_multi_file:
            # Single-file
            if dest.is_dir():
                target_file = (dest / self.torrent_meta.name).resolve()
                try:
                    target_file.relative_to(dest)
                except ValueError:
                    raise DownloadError(f"Path Traversal attempt when saving file: {target_file}")
            else:
                target_file = dest

            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(all_data)
        else:
            # Multi-file
            base_dir = (dest / self.torrent_meta.name).resolve() if not dest.name == self.torrent_meta.name else dest
            offset = 0
            for file_info in self.torrent_meta.files:
                file_path = base_dir.joinpath(*file_info.path).resolve()
                try:
                    file_path.relative_to(base_dir)
                except ValueError:
                    raise DownloadError(f"Path Traversal attempt when saving file: {file_path}")

                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_data = all_data[offset : offset + file_info.length]
                file_path.write_bytes(file_data)
                offset += file_info.length

    def stop(self) -> None:
        """
        Signal stop to all active download threads and immediately close
        peer connections to prevent blocking.
        """
        self._stop_requested = True
        with self._active_connections_lock:
            active_conns = list(self._active_connections)
        for conn in active_conns:
            try:
                conn.close()
            except Exception:
                pass

        try:
            self.tracker_client.stop(
                uploaded=0,
                downloaded=self.piece_manager.bytes_downloaded(),
                left=self.piece_manager.bytes_left(),
                timeout=min(self.tracker_timeout, 3.0),
            )
        except Exception:
            pass
