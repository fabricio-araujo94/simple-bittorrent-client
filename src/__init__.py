"""
Pacote principal do cliente BitTorrent educacional em Python.
"""

from .bencode import (
    BencodeDecodeError,
    BencodeDecoder,
    BencodeEncodeError,
    BencodeError,
    BencodeTruncatedError,
    decode_bencode,
    decode_bencode_with_offsets,
    encode_bencode,
    extract_info_bytes,
)
from .hash_utils import compute_sha1, verify_sha1
from .torrent import (
    FileInfo,
    TorrentError,
    TorrentMetadata,
    TorrentParseError,
    TorrentValidationError,
    load_torrent_bytes,
    load_torrent_file,
)
from .tracker import (
    HTTPTrackerClient,
    PeerInfo,
    TrackerConnectionError,
    TrackerError,
    TrackerFailureError,
    TrackerHTTPError,
    TrackerResponse,
    TrackerResponseError,
    TrackerTimeoutError,
    build_announce_url,
    execute_http_get,
    generate_peer_id,
    parse_compact_peers_ipv4,
    parse_dictionary_peers,
    parse_tracker_response,
    query_http_tracker,
    urlencode_binary,
)

__all__ = [
    # Bencode
    "BencodeError",
    "BencodeDecodeError",
    "BencodeTruncatedError",
    "BencodeEncodeError",
    "BencodeDecoder",
    "decode_bencode",
    "decode_bencode_with_offsets",
    "extract_info_bytes",
    "encode_bencode",
    # Hash utils
    "compute_sha1",
    "verify_sha1",
    # Torrent
    "FileInfo",
    "TorrentError",
    "TorrentParseError",
    "TorrentValidationError",
    "TorrentMetadata",
    "load_torrent_bytes",
    "load_torrent_file",
    # Tracker
    "TrackerError",
    "TrackerConnectionError",
    "TrackerTimeoutError",
    "TrackerHTTPError",
    "TrackerResponseError",
    "TrackerFailureError",
    "PeerInfo",
    "TrackerResponse",
    "generate_peer_id",
    "urlencode_binary",
    "build_announce_url",
    "parse_compact_peers_ipv4",
    "parse_dictionary_peers",
    "parse_tracker_response",
    "execute_http_get",
    "query_http_tracker",
    "HTTPTrackerClient",
]
