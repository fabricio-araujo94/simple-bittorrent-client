"""
Module for communicating with BitTorrent trackers via HTTP/HTTPS.

Implements the BitTorrent HTTP announce specification (BEP 0003, BEP 0023):
- Constructing GET announce requests with mandatory and optional parameters;
- Strict URL encoding (RFC 3986 / percent-encoding) for binary data such as info_hash and peer_id;
- Generating unique peer_id in Azureus-style format;
- Parsing and validating Bencode tracker responses;
- Handling 'failure reason' and 'warning message';
- Extracting peers both in IPv4 compact format (BEP 0023: 6 bytes per peer) and dictionary/list format (BEP 0003);
- Structured handling of HTTP errors, connection failures, and timeouts;
- Support for injecting custom HTTP transports/openers for deterministic testing without external network access.
"""

import gzip
import random
import socket
import string
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Union

from .bencode import BencodeError, decode_bencode
from .torrent import TorrentMetadata, load_torrent_bytes, load_torrent_file


# ==============================================================================
# Exceptions
# ==============================================================================

class TrackerError(Exception):
    """Base exception for all BitTorrent tracker-related errors."""
    pass


class TrackerConnectionError(TrackerError):
    """Exception raised when a network connection failure occurs with the tracker."""
    pass


class TrackerTimeoutError(TrackerConnectionError):
    """Exception raised when communication with the tracker exceeds the timeout limit."""
    pass


class TrackerHTTPError(TrackerError):
    """Exception raised when the HTTP server returns an error status code (4xx, 5xx)."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TrackerResponseError(TrackerError):
    """Exception raised when the tracker response is invalid, malformed, or unexpected."""
    pass


class TrackerFailureError(TrackerResponseError):
    """Exception raised when the tracker explicitly responds with 'failure reason'."""

    def __init__(self, failure_reason: str):
        super().__init__(f"Tracker rejected request: {failure_reason}")
        self.failure_reason = failure_reason


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass(frozen=True)
class PeerInfo:
    """
    Structured and immutable representation of a BitTorrent peer.
    """
    ip: str
    port: int
    peer_id: Optional[bytes] = None

    @property
    def peer_id_hex(self) -> Optional[str]:
        """Return the peer_id as a hexadecimal string, if present."""
        return self.peer_id.hex() if self.peer_id else None

    def __str__(self) -> str:
        if self.peer_id:
            return f"{self.ip}:{self.port} (peer_id: {self.peer_id!r})"
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class TrackerResponse:
    """
    Structured representation of the Bencode response returned by an HTTP tracker.
    """
    interval: int
    peers: List[PeerInfo]
    min_interval: Optional[int] = None
    tracker_id: Optional[str] = None
    complete: Optional[int] = None        # Seeders
    incomplete: Optional[int] = None      # Leechers
    warning_message: Optional[str] = None
    raw_dict: Optional[dict] = None

    @property
    def num_peers(self) -> int:
        """Number of peers returned in this response."""
        return len(self.peers)


# ==============================================================================
# Peer ID Utilities and Encoding
# ==============================================================================

def generate_peer_id(prefix: str = "-ST0001-") -> bytes:
    """
    Generate a unique 20-byte identifier for this client (BEP 0020).
    Azureus-style default: 8-character prefix + 12 random alphanumeric characters.

    Example: b'-ST0001-a1b2c3d4e5f6'
    """
    prefix_bytes = prefix.encode("ascii")
    if len(prefix_bytes) > 20:
        raise ValueError(
            f"peer_id prefix cannot be longer than 20 bytes (has {len(prefix_bytes)} bytes)."
        )
    remaining_len = 20 - len(prefix_bytes)
    random_chars = "".join(random.choices(string.ascii_letters + string.digits, k=remaining_len))
    return prefix_bytes + random_chars.encode("ascii")


def urlencode_binary(data: Union[bytes, bytearray, memoryview]) -> str:
    """
    Perform strict percent-encoding of raw bytes according to RFC 3986.
    Ensures non-alphanumeric bytes (including spaces, null bytes, and control characters)
    are escaped as uppercase %XX.
    """
    return urllib.parse.quote_from_bytes(bytes(data), safe=b"")


# ==============================================================================
# Announce URL Construction
# ==============================================================================

def build_announce_url(
    base_url: str,
    info_hash: Union[bytes, bytearray, memoryview],
    peer_id: Union[bytes, str],
    port: int = 6881,
    uploaded: int = 0,
    downloaded: int = 0,
    left: int = 0,
    compact: bool = True,
    no_peer_id: Optional[bool] = None,
    event: Optional[str] = None,
    numwant: Optional[int] = None,
    ip: Optional[str] = None,
    key: Optional[str] = None,
    trackerid: Optional[str] = None,
) -> str:
    """
    Build the full URL for an HTTP GET announce request to the tracker.

    Strictly complies with BEP 0003 and BEP 0023 specifications:
    - `info_hash`: 20 raw bytes converted via percent-encoding (do not use hex!);
    - `peer_id`: 20 bytes or string converted via percent-encoding;
    - `port`: TCP listening port (1-65535);
    - `uploaded`: total bytes uploaded so far (integer >= 0);
    - `downloaded`: total bytes downloaded so far (integer >= 0);
    - `left`: remaining bytes to download (integer >= 0);
    - `compact`: if True, sends `compact=1` indicating support for compact peer lists;
    - `event`: client event ('started', 'completed', 'stopped', or None for regular);
    - Additional optional parameters: no_peer_id, numwant, ip, key, trackerid.

    Raises:
        ValueError / TypeError: If any parameter is invalid or has an incorrect type.
    """
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Tracker base URL cannot be empty.")

    # 1. info_hash: must be exactly 20 bytes
    if not isinstance(info_hash, (bytes, bytearray, memoryview)):
        raise TypeError(f"info_hash must be bytes, got {type(info_hash).__name__}.")
    info_hash_bytes = bytes(info_hash)
    if len(info_hash_bytes) != 20:
        raise ValueError(f"info_hash must be exactly 20 bytes, got {len(info_hash_bytes)} bytes.")

    # 2. peer_id: must be exactly 20 bytes
    if isinstance(peer_id, str):
        peer_id_bytes = peer_id.encode("utf-8")
    elif isinstance(peer_id, (bytes, bytearray, memoryview)):
        peer_id_bytes = bytes(peer_id)
    else:
        raise TypeError(f"peer_id must be str or bytes, got {type(peer_id).__name__}.")
    if len(peer_id_bytes) != 20:
        raise ValueError(f"peer_id must be exactly 20 bytes, got {len(peer_id_bytes)} bytes.")

    # 3. port: 1-65535
    if not isinstance(port, int) or isinstance(port, bool) or not (0 < port <= 65535):
        raise ValueError(f"port must be an integer between 1 and 65535, got {port!r}.")

    # 4. uploaded, downloaded, left: integers >= 0
    for name, val in [("uploaded", uploaded), ("downloaded", downloaded), ("left", left)]:
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValueError(f"{name} must be a non-negative integer (>= 0), got {val!r}.")

    # Parameter assembly
    query_params: List[str] = [
        f"info_hash={urlencode_binary(info_hash_bytes)}",
        f"peer_id={urlencode_binary(peer_id_bytes)}",
        f"port={port}",
        f"uploaded={uploaded}",
        f"downloaded={downloaded}",
        f"left={left}",
        f"compact={1 if compact else 0}",
    ]

    if no_peer_id is not None:
        query_params.append(f"no_peer_id={1 if no_peer_id else 0}")

    if event:
        event_str = event.strip()
        if event_str:
            query_params.append(f"event={urllib.parse.quote(event_str, safe='')}")

    if numwant is not None:
        if not isinstance(numwant, int) or isinstance(numwant, bool) or numwant < 0:
            raise ValueError(f"numwant must be a non-negative integer (>= 0), got {numwant!r}.")
        query_params.append(f"numwant={numwant}")

    if ip is not None:
        ip_str = ip.strip()
        if ip_str:
            query_params.append(f"ip={urllib.parse.quote(ip_str, safe='')}")

    if key is not None:
        key_str = key.strip()
        if key_str:
            query_params.append(f"key={urllib.parse.quote(key_str, safe='')}")

    if trackerid is not None:
        trackerid_str = trackerid.strip()
        if trackerid_str:
            query_params.append(f"trackerid={urllib.parse.quote(trackerid_str, safe='')}")

    clean_base = base_url.strip()
    parsed_base = urllib.parse.urlparse(clean_base)
    if parsed_base.scheme.lower() not in ("http", "https"):
        raise TrackerError(
            f"Unsupported or insecure tracker URL scheme: {parsed_base.scheme!r} (only http and https are allowed)."
        )
    if not parsed_base.netloc:
        raise TrackerError(f"Invalid tracker URL (missing hostname): {clean_base!r}.")

    query_string = "&".join(query_params)

    if "?" in clean_base:
        if clean_base.endswith("?") or clean_base.endswith("&"):
            return f"{clean_base}{query_string}"
        return f"{clean_base}&{query_string}"
    return f"{clean_base}?{query_string}"


# ==============================================================================
# Response Parsing and Peer Extraction
# ==============================================================================

def parse_compact_peers_ipv4(peers_bytes: Union[bytes, bytearray, memoryview]) -> List[PeerInfo]:
    """
    Decode peer list in compact IPv4 format (BEP 0023).

    Each peer is encoded in 6 contiguous bytes in network byte order (big-endian):
    - Bytes 0..3: IPv4 address (e.g., \x7f\x00\x00\x01 -> "127.0.0.1")
    - Bytes 4..5: TCP port (e.g., \x1a\xe1 -> 6881)

    Raises:
        TrackerResponseError: If length is not an exact multiple of 6 bytes.
    """
    raw = bytes(peers_bytes)
    if len(raw) % 6 != 0:
        raise TrackerResponseError(
            f"Length of compact peers ({len(raw)} bytes) is not a multiple of 6 bytes."
        )

    peers: List[PeerInfo] = []
    for i in range(0, len(raw), 6):
        chunk = raw[i : i + 6]
        ip_bytes = chunk[:4]
        port_bytes = chunk[4:6]
        ip_str = socket.inet_ntoa(ip_bytes)
        port_int = struct.unpack("!H", port_bytes)[0]
        peers.append(PeerInfo(ip=ip_str, port=port_int, peer_id=None))

    return peers


def parse_dictionary_peers(peers_list: list) -> List[PeerInfo]:
    """
    Decode peer list in traditional dictionary format (BEP 0003).

    Each item in the list is a dictionary containing:
    - 'ip': string or byte string with peer IP/hostname;
    - 'port': integer with TCP port;
    - 'peer id' (optional): 20-byte string with peer identity.

    Raises:
        TrackerResponseError: If data structure or types are invalid.
    """
    if not isinstance(peers_list, list):
        raise TrackerResponseError(
            f"Invalid peers format: expected list, got {type(peers_list).__name__}."
        )

    peers: List[PeerInfo] = []
    for idx, item in enumerate(peers_list):
        if not isinstance(item, dict):
            raise TrackerResponseError(f"Item {idx} in peer list must be a dictionary.")

        # ip
        if b"ip" not in item:
            raise TrackerResponseError(f"Missing 'ip' field in peer {idx}.")
        raw_ip = item[b"ip"]
        if isinstance(raw_ip, (bytes, bytearray)):
            ip_str = bytes(raw_ip).decode("utf-8", errors="replace").strip()
        elif isinstance(raw_ip, str):
            ip_str = raw_ip.strip()
        else:
            raise TrackerResponseError(f"'ip' field in peer {idx} must be bytes or str.")

        if not ip_str:
            raise TrackerResponseError(f"'ip' field in peer {idx} cannot be empty.")

        # port
        if b"port" not in item:
            raise TrackerResponseError(f"Missing 'port' field in peer {idx}.")
        port_val = item[b"port"]
        if not isinstance(port_val, int) or isinstance(port_val, bool) or not (0 < port_val <= 65535):
            raise TrackerResponseError(
                f"Invalid port for peer {idx}: must be integer between 1 and 65535, got {port_val!r}."
            )

        # peer id (optional)
        peer_id_bytes: Optional[bytes] = None
        if b"peer id" in item:
            raw_pid = item[b"peer id"]
            if isinstance(raw_pid, (bytes, bytearray)):
                peer_id_bytes = bytes(raw_pid)
            elif isinstance(raw_pid, str):
                peer_id_bytes = raw_pid.encode("utf-8")
            else:
                raise TrackerResponseError(f"'peer id' field in peer {idx} must be bytes or str.")

        peers.append(PeerInfo(ip=ip_str, port=port_val, peer_id=peer_id_bytes))

    return peers


def parse_tracker_response(raw_response: Union[bytes, bytearray, memoryview]) -> TrackerResponse:
    """
    Decode and validate Bencoded response received from an HTTP tracker (BEP 0003, BEP 0023).

    Raises:
        TrackerFailureError: If tracker responded with 'failure reason'.
        TrackerResponseError: If Bencode is invalid or required fields are missing (such as 'interval').
    """
    if not isinstance(raw_response, (bytes, bytearray, memoryview)):
        raise TrackerResponseError(
            f"Tracker response expected as bytes, got {type(raw_response).__name__}."
        )

    raw_bytes = bytes(raw_response)
    if not raw_bytes:
        raise TrackerResponseError("Empty response received from tracker.")

    try:
        data = decode_bencode(raw_bytes, strict=False)
    except BencodeError as e:
        raise TrackerResponseError(f"Error decoding Bencode from tracker response: {e}") from e

    if not isinstance(data, dict):
        raise TrackerResponseError("Tracker Bencode response root must be a dictionary.")

    # 1. Check explicit failure reported by tracker ('failure reason')
    if b"failure reason" in data:
        reason_raw = data[b"failure reason"]
        if isinstance(reason_raw, (bytes, bytearray)):
            reason_str = bytes(reason_raw).decode("utf-8", errors="replace")
        else:
            reason_str = str(reason_raw)
        raise TrackerFailureError(reason_str)

    # 2. Validate and extract mandatory interval
    if b"interval" not in data:
        raise TrackerResponseError("Required 'interval' field not found in tracker response.")

    interval_val = data[b"interval"]
    if not isinstance(interval_val, int) or isinstance(interval_val, bool) or interval_val <= 0:
        raise TrackerResponseError(
            f"'interval' field must be a strictly positive integer (> 0), got {interval_val!r}."
        )

    # 3. Extract peers (compact or list of dictionaries)
    peers: List[PeerInfo] = []
    if b"peers" in data:
        raw_peers = data[b"peers"]
        if isinstance(raw_peers, (bytes, bytearray)):
            peers = parse_compact_peers_ipv4(raw_peers)
        elif isinstance(raw_peers, list):
            peers = parse_dictionary_peers(raw_peers)
        else:
            raise TrackerResponseError(
                f"Invalid format for 'peers' field: expected bytes or list, got {type(raw_peers).__name__}."
            )

    # 4. Extract optional specification fields
    min_interval = None
    if b"min interval" in data and isinstance(data[b"min interval"], int) and not isinstance(data[b"min interval"], bool):
        min_interval = data[b"min interval"]

    tracker_id = None
    if b"tracker id" in data and isinstance(data[b"tracker id"], (bytes, bytearray, str)):
        raw_tid = data[b"tracker id"]
        tracker_id = bytes(raw_tid).decode("utf-8", errors="replace") if isinstance(raw_tid, (bytes, bytearray)) else raw_tid

    complete = None
    if b"complete" in data and isinstance(data[b"complete"], int) and not isinstance(data[b"complete"], bool):
        complete = data[b"complete"]

    incomplete = None
    if b"incomplete" in data and isinstance(data[b"incomplete"], int) and not isinstance(data[b"incomplete"], bool):
        incomplete = data[b"incomplete"]

    warning_message = None
    if b"warning message" in data and isinstance(data[b"warning message"], (bytes, bytearray)):
        warning_message = bytes(data[b"warning message"]).decode("utf-8", errors="replace")

    return TrackerResponse(
        interval=interval_val,
        peers=peers,
        min_interval=min_interval,
        tracker_id=tracker_id,
        complete=complete,
        incomplete=incomplete,
        warning_message=warning_message,
        raw_dict=data,
    )


# ==============================================================================
# HTTP Request Execution with urllib
# ==============================================================================

def execute_http_get(
    url: str,
    timeout: float = 15.0,
    user_agent: str = "SimpleBitTorrent/1.0",
    opener: Optional[Any] = None,
) -> bytes:
    """
    Execute an HTTP GET request using urllib and return response body as bytes.

    Supports automatic gzip decompression and maps network/HTTP exceptions to the
    TrackerError exception hierarchy.

    Allows injection of custom `opener` (function or urllib OpenerDirector) for
    unit testing without actual Internet connection.
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme.lower() not in ("http", "https"):
        raise TrackerError(
            f"Unsupported or insecure URL scheme: {parsed_url.scheme!r} (only http and https are allowed)."
        )

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        },
    )

    resp = None
    try:
        if opener is not None:
            if hasattr(opener, "open"):
                resp = opener.open(req, timeout=timeout)
            elif callable(opener):
                resp = opener(req, timeout=timeout)
            else:
                raise TypeError(f"Provided opener is not callable and has no 'open' method: {opener!r}.")
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)

        raw_bytes = resp.read()

        # Automatic gzip decompression if returned
        is_gzip = False
        if hasattr(resp, "headers") and resp.headers:
            content_encoding = resp.headers.get("Content-Encoding", "").lower()
            if "gzip" in content_encoding:
                is_gzip = True

        if not is_gzip and len(raw_bytes) >= 2 and raw_bytes[:2] == b"\x1f\x8b":
            is_gzip = True

        if is_gzip:
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass

        return raw_bytes

    except urllib.error.HTTPError as e:
        resp = e
        # If HTTP server returns body with Bencoded 'failure reason' (e.g. 400 or 403)
        body = b""
        try:
            body = e.read()
        except Exception:
            pass

        if body:
            try:
                parsed = decode_bencode(body, strict=False)
                if isinstance(parsed, dict) and b"failure reason" in parsed:
                    reason_bytes = parsed[b"failure reason"]
                    reason = bytes(reason_bytes).decode("utf-8", errors="replace") if isinstance(reason_bytes, (bytes, bytearray)) else str(reason_bytes)
                    raise TrackerFailureError(reason) from e
            except TrackerFailureError:
                raise
            except Exception:
                pass

        raise TrackerHTTPError(
            f"Tracker returned HTTP error {e.code}: {e.reason}",
            status_code=e.code,
        ) from e

    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)) or "timed out" in str(e.reason).lower():
            raise TrackerTimeoutError(f"Timeout connecting to tracker: {e.reason}") from e
        raise TrackerConnectionError(f"Connection failure with tracker: {e.reason}") from e

    except (socket.timeout, TimeoutError) as e:
        raise TrackerTimeoutError(f"Timeout connecting to tracker: {e}") from e

    except TrackerError:
        raise

    except Exception as e:
        raise TrackerConnectionError(f"Unexpected error communicating with tracker: {e}") from e

    finally:
        if resp is not None:
            close = getattr(resp, "close", None)
            if callable(close):
                close()


def query_http_tracker(
    announce_url: str,
    info_hash: Union[bytes, bytearray, memoryview],
    peer_id: Union[bytes, str],
    port: int = 6881,
    uploaded: int = 0,
    downloaded: int = 0,
    left: int = 0,
    compact: bool = True,
    no_peer_id: Optional[bool] = None,
    event: Optional[str] = None,
    numwant: Optional[int] = None,
    ip: Optional[str] = None,
    key: Optional[str] = None,
    trackerid: Optional[str] = None,
    timeout: float = 15.0,
    user_agent: str = "SimpleBitTorrent/1.0",
    opener: Optional[Any] = None,
) -> TrackerResponse:
    """
    Direct utility function to query an HTTP tracker, execute announce,
    and return decoded TrackerResponse.
    """
    url = build_announce_url(
        base_url=announce_url,
        info_hash=info_hash,
        peer_id=peer_id,
        port=port,
        uploaded=uploaded,
        downloaded=downloaded,
        left=left,
        compact=compact,
        no_peer_id=no_peer_id,
        event=event,
        numwant=numwant,
        ip=ip,
        key=key,
        trackerid=trackerid,
    )
    raw_data = execute_http_get(url=url, timeout=timeout, user_agent=user_agent, opener=opener)
    return parse_tracker_response(raw_data)


# ==============================================================================
# HTTP Tracker Client
# ==============================================================================

class HTTPTrackerClient:
    """
    High-level client for managing and communicating with BitTorrent HTTP trackers.

    Can be instantiated directly from:
    - A `TorrentMetadata` object;
    - Raw bytes content of a .torrent file;
    - Filesystem path to a .torrent file;
    - Or explicit parameters (`info_hash`, `announce_url`, `total_length`).
    """

    def __init__(
        self,
        torrent: Optional[Union[TorrentMetadata, bytes, bytearray, memoryview, str, Path]] = None,
        *,
        info_hash: Optional[Union[bytes, bytearray, memoryview]] = None,
        announce_url: Optional[str] = None,
        total_length: Optional[int] = None,
        peer_id: Optional[Union[bytes, str]] = None,
        port: int = 6881,
        user_agent: str = "SimpleBitTorrent/1.0",
        opener: Optional[Any] = None,
    ):
        self.torrent_meta: Optional[TorrentMetadata] = None

        if torrent is not None:
            if isinstance(torrent, TorrentMetadata):
                self.torrent_meta = torrent
            elif isinstance(torrent, (str, Path)):
                self.torrent_meta = load_torrent_file(torrent)
            elif isinstance(torrent, (bytes, bytearray, memoryview)):
                self.torrent_meta = load_torrent_bytes(torrent)
            else:
                raise TypeError(
                    f"Invalid type for torrent argument: {type(torrent).__name__}."
                )

        # Resolve info_hash
        resolved_info_hash = info_hash
        if resolved_info_hash is None and self.torrent_meta is not None:
            resolved_info_hash = self.torrent_meta.info_hash
        if resolved_info_hash is None:
            raise ValueError("info_hash not provided and not found in torrent.")
        self.info_hash = bytes(resolved_info_hash)

        # Resolve announce_url
        resolved_announce = announce_url
        if resolved_announce is None and self.torrent_meta is not None:
            resolved_announce = self.torrent_meta.announce or (
                self.torrent_meta.trackers[0] if self.torrent_meta.trackers else None
            )
        self.announce_url = resolved_announce

        # Resolve total_length
        resolved_length = total_length
        if resolved_length is None and self.torrent_meta is not None:
            resolved_length = self.torrent_meta.total_length
        self.total_length = resolved_length if resolved_length is not None else 0

        # Resolve peer_id
        if peer_id is None:
            self.peer_id = generate_peer_id()
        elif isinstance(peer_id, str):
            self.peer_id = peer_id.encode("utf-8")
        elif isinstance(peer_id, (bytes, bytearray, memoryview)):
            self.peer_id = bytes(peer_id)
        else:
            raise TypeError(f"peer_id must be bytes or str, got {type(peer_id).__name__}.")

        self.port = port
        self.user_agent = user_agent
        self.opener = opener

        # Tracker session state
        self.last_tracker_id: Optional[str] = None
        self.last_response: Optional[TrackerResponse] = None

    def announce(
        self,
        uploaded: int = 0,
        downloaded: int = 0,
        left: Optional[int] = None,
        event: Optional[str] = None,
        compact: bool = True,
        no_peer_id: Optional[bool] = None,
        numwant: Optional[int] = None,
        ip: Optional[str] = None,
        key: Optional[str] = None,
        trackerid: Optional[str] = None,
        timeout: float = 15.0,
        tracker_url: Optional[str] = None,
    ) -> TrackerResponse:
        """
        Execute an HTTP announce and return decoded TrackerResponse.
        """
        target_url = tracker_url or self.announce_url
        if not target_url:
            raise ValueError("No announce URL provided or configured in client.")

        calc_left = left if left is not None else max(0, self.total_length - downloaded)
        effective_trackerid = trackerid if trackerid is not None else self.last_tracker_id

        response = query_http_tracker(
            announce_url=target_url,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            port=self.port,
            uploaded=uploaded,
            downloaded=downloaded,
            left=calc_left,
            compact=compact,
            no_peer_id=no_peer_id,
            event=event,
            numwant=numwant,
            ip=ip,
            key=key,
            trackerid=effective_trackerid,
            timeout=timeout,
            user_agent=self.user_agent,
            opener=self.opener,
        )

        if response.tracker_id:
            self.last_tracker_id = response.tracker_id
        self.last_response = response

        return response

    def start(
        self,
        uploaded: int = 0,
        downloaded: int = 0,
        left: Optional[int] = None,
        compact: bool = True,
        **kwargs: Any,
    ) -> TrackerResponse:
        """Send initial announce with event='started'."""
        return self.announce(
            uploaded=uploaded,
            downloaded=downloaded,
            left=left,
            event="started",
            compact=compact,
            **kwargs,
        )

    def complete(
        self,
        uploaded: int = 0,
        downloaded: Optional[int] = None,
        compact: bool = True,
        **kwargs: Any,
    ) -> TrackerResponse:
        """Send completion announce with event='completed' and left=0."""
        down = downloaded if downloaded is not None else self.total_length
        return self.announce(
            uploaded=uploaded,
            downloaded=down,
            left=0,
            event="completed",
            compact=compact,
            **kwargs,
        )

    def stop(
        self,
        uploaded: int = 0,
        downloaded: int = 0,
        left: Optional[int] = None,
        compact: bool = True,
        **kwargs: Any,
    ) -> TrackerResponse:
        """Send termination announce with event='stopped'."""
        return self.announce(
            uploaded=uploaded,
            downloaded=downloaded,
            left=left,
            event="stopped",
            compact=compact,
            **kwargs,
        )

