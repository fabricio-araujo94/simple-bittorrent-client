"""
Comprehensive unit tests for HTTP tracker communication module.

Covers:
- Correct announce URL construction with mandatory and optional parameters;
- Strict URL encoding of binary hashes and peer IDs (RFC 3986 percent-encoding);
- Parsing valid Bencoded responses with interval and additional metadata;
- Compact IPv4 peer extraction (BEP 0023);
- Dictionary/list traditional peer format extraction (BEP 0003);
- Handling of 'failure reason' and 'warning message';
- Rejection of invalid, malformed, or incomplete responses;
- Simulation of network errors, timeouts, and HTTP errors without relying on real Internet;
- Tests of high-level HTTPTrackerClient.
"""

import gzip
import io
import socket
import struct
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Optional

from src.bencode import encode_bencode
from src.torrent import TorrentMetadata, load_torrent_bytes
from src.tracker import (
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


class MockHTTPResponse:
    """Objeto auxiliar para simular respostas urllib HTTP."""

    def __init__(self, data: bytes, code: int = 200, headers: Optional[dict] = None):
        self.data = data
        self.code = code
        self.headers = headers or {}
        self.closed = False

    def read(self) -> bytes:
        return self.data

    def close(self) -> None:
        self.closed = True


class TestAnnounceUrlBuilder(unittest.TestCase):
    """Tests for announce URL construction and encoding."""

    def setUp(self):
        self.info_hash = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78"
        self.peer_id = b"-ST0001-1234567890ab"
        self.base_url = "http://tracker.example.com:6969/announce"

    def test_build_announce_url_required_parameters(self):
        url = build_announce_url(
            base_url=self.base_url,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            port=6881,
            uploaded=0,
            downloaded=1024,
            left=2048,
            compact=True,
        )

        self.assertTrue(url.startswith(self.base_url + "?"))
        # Verify presence and formatting of each parameter in query string
        self.assertIn("info_hash=%124Vx%9A%BC%DE%F0%124Vx%9A%BC%DE%F0%124Vx", url)
        self.assertIn("peer_id=-ST0001-1234567890ab", url)
        self.assertIn("port=6881", url)
        self.assertIn("uploaded=0", url)
        self.assertIn("downloaded=1024", url)
        self.assertIn("left=2048", url)
        self.assertIn("compact=1", url)

    def test_urlencode_binary_special_bytes(self):
        # Ensure special characters, spaces (%20), plus (%2B), null bytes (%00) and 0xFF
        # are strictly percent-encoded without losing integrity
        special_bytes = b"\x00\x20\x2b\x3f\x26\x3d\xff" + b"abc-._~"
        encoded = urlencode_binary(special_bytes)
        self.assertEqual(encoded, "%00%20%2B%3F%26%3D%FFabc-._~")

    def test_build_announce_url_with_existing_query_params(self):
        base_with_passkey = "http://tracker.example.com/announce?passkey=secret123"
        url = build_announce_url(
            base_url=base_with_passkey,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            port=6881,
        )
        self.assertTrue(url.startswith("http://tracker.example.com/announce?passkey=secret123&"))
        self.assertIn("info_hash=", url)

        # Base ending with '?'
        base_with_question = "http://tracker.example.com/announce?"
        url_q = build_announce_url(
            base_url=base_with_question,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            port=6881,
        )
        self.assertFalse("?&" in url_q)
        self.assertTrue(url_q.startswith("http://tracker.example.com/announce?info_hash="))

    def test_build_announce_url_events_and_optional_params(self):
        url = build_announce_url(
            base_url=self.base_url,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            port=6881,
            event="started",
            compact=False,
            no_peer_id=True,
            numwant=50,
            ip="192.168.1.10",
            key="clientkey99",
            trackerid="trk_session_42",
        )
        self.assertIn("event=started", url)
        self.assertIn("compact=0", url)
        self.assertIn("no_peer_id=1", url)
        self.assertIn("numwant=50", url)
        self.assertIn("ip=192.168.1.10", url)
        self.assertIn("key=clientkey99", url)
        self.assertIn("trackerid=trk_session_42", url)

    def test_peer_id_from_string(self):
        peer_id_str = "-ST0001-abcdefghijkl"
        url = build_announce_url(
            base_url=self.base_url,
            info_hash=self.info_hash,
            peer_id=peer_id_str,
            port=6881,
        )
        self.assertIn(f"peer_id={peer_id_str}", url)

    def test_invalid_parameters_raise_errors(self):
        # Empty base url
        with self.assertRaises(ValueError):
            build_announce_url("", self.info_hash, self.peer_id)

        # info_hash with incorrect size
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, b"short_hash", self.peer_id)

        # info_hash non-bytes
        with self.assertRaises(TypeError):
            build_announce_url(self.base_url, "not_bytes", self.peer_id)  # type: ignore

        # peer_id with incorrect size
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, b"short_peer_id")

        # Invalid port
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, port=0)
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, port=70000)

        # Negative values
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, uploaded=-1)
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, downloaded=-5)
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, left=-10)
        with self.assertRaises(ValueError):
            build_announce_url(self.base_url, self.info_hash, self.peer_id, numwant=-1)


class TestPeerExtraction(unittest.TestCase):
    """Tests for compact (IPv4) and dictionary peer extraction."""

    def test_parse_compact_peers_single(self):
        # 127.0.0.1:6881 -> \x7f\x00\x00\x01 \x1a\xe1
        peer_bytes = socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)
        peers = parse_compact_peers_ipv4(peer_bytes)

        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].ip, "127.0.0.1")
        self.assertEqual(peers[0].port, 6881)
        self.assertIsNone(peers[0].peer_id)
        self.assertEqual(str(peers[0]), "127.0.0.1:6881")

    def test_parse_compact_peers_multiple(self):
        # 3 peers: 192.168.1.100:8080, 10.0.0.1:51413, 203.0.113.42:65535
        p1 = socket.inet_aton("192.168.1.100") + struct.pack("!H", 8080)
        p2 = socket.inet_aton("10.0.0.1") + struct.pack("!H", 51413)
        p3 = socket.inet_aton("203.0.113.42") + struct.pack("!H", 65535)
        raw = p1 + p2 + p3

        peers = parse_compact_peers_ipv4(raw)
        self.assertEqual(len(peers), 3)
        self.assertEqual(peers[0], PeerInfo("192.168.1.100", 8080))
        self.assertEqual(peers[1], PeerInfo("10.0.0.1", 51413))
        self.assertEqual(peers[2], PeerInfo("203.0.113.42", 65535))

    def test_parse_compact_peers_empty(self):
        peers = parse_compact_peers_ipv4(b"")
        self.assertEqual(peers, [])

    def test_parse_compact_peers_invalid_length(self):
        # 5 bytes (not divisible by 6)
        with self.assertRaises(TrackerResponseError) as ctx:
            parse_compact_peers_ipv4(b"\x01\x02\x03\x04\x05")
        self.assertIn("is not a multiple of 6", str(ctx.exception))

        # 7 bytes
        with self.assertRaises(TrackerResponseError):
            parse_compact_peers_ipv4(b"\x01\x02\x03\x04\x05\x06\x07")

    def test_parse_dictionary_peers_valid(self):
        raw_list = [
            {
                b"ip": b"192.168.1.50",
                b"port": 6881,
                b"peer id": b"-UT2210-123456789012",
            },
            {
                b"ip": b"tracker.peer.com",
                b"port": 8080,
            },
        ]
        peers = parse_dictionary_peers(raw_list)
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0].ip, "192.168.1.50")
        self.assertEqual(peers[0].port, 6881)
        self.assertEqual(peers[0].peer_id, b"-UT2210-123456789012")
        self.assertEqual(peers[0].peer_id_hex, b"-UT2210-123456789012".hex())
        self.assertIn("peer_id:", str(peers[0]))

        self.assertEqual(peers[1].ip, "tracker.peer.com")
        self.assertEqual(peers[1].port, 8080)
        self.assertIsNone(peers[1].peer_id)

    def test_parse_dictionary_peers_invalid(self):
        # Element is not dict
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers(["not_a_dict"])  # type: ignore

        # Missing ip
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers([{b"port": 6881}])

        # Missing port
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers([{b"ip": b"1.1.1.1"}])

        # Invalid port
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers([{b"ip": b"1.1.1.1", b"port": 0}])
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers([{b"ip": b"1.1.1.1", b"port": 70000}])

        # Empty IP
        with self.assertRaises(TrackerResponseError):
            parse_dictionary_peers([{b"ip": b"", b"port": 6881}])


class TestTrackerResponseParser(unittest.TestCase):
    """Tests for parsing and validation of full tracker responses."""

    def test_parse_valid_compact_response(self):
        peer1_bytes = socket.inet_aton("192.168.0.1") + struct.pack("!H", 6881)
        peer2_bytes = socket.inet_aton("10.0.0.2") + struct.pack("!H", 6889)

        resp_dict = {
            b"interval": 1800,
            b"min interval": 900,
            b"tracker id": b"tracker_alpha",
            b"complete": 42,
            b"incomplete": 5,
            b"warning message": b"Tracker rebalancing soon",
            b"peers": peer1_bytes + peer2_bytes,
        }
        raw_bencode = encode_bencode(resp_dict)

        resp = parse_tracker_response(raw_bencode)
        self.assertEqual(resp.interval, 1800)
        self.assertEqual(resp.min_interval, 900)
        self.assertEqual(resp.tracker_id, "tracker_alpha")
        self.assertEqual(resp.complete, 42)
        self.assertEqual(resp.incomplete, 5)
        self.assertEqual(resp.warning_message, "Tracker rebalancing soon")
        self.assertEqual(resp.num_peers, 2)
        self.assertEqual(resp.peers[0].ip, "192.168.0.1")
        self.assertEqual(resp.peers[0].port, 6881)
        self.assertEqual(resp.peers[1].ip, "10.0.0.2")
        self.assertEqual(resp.peers[1].port, 6889)

    def test_parse_valid_dictionary_response(self):
        resp_dict = {
            b"interval": 1200,
            b"peers": [
                {b"ip": b"172.16.0.5", b"port": 5000, b"peer id": b"12345678901234567890"}
            ],
        }
        raw_bencode = encode_bencode(resp_dict)
        resp = parse_tracker_response(raw_bencode)

        self.assertEqual(resp.interval, 1200)
        self.assertEqual(len(resp.peers), 1)
        self.assertEqual(resp.peers[0].ip, "172.16.0.5")
        self.assertEqual(resp.peers[0].port, 5000)
        self.assertEqual(resp.peers[0].peer_id, b"12345678901234567890")

    def test_parse_failure_reason(self):
        resp_dict = {
            b"failure reason": b"Torrent not registered with this private tracker",
        }
        raw_bencode = encode_bencode(resp_dict)

        with self.assertRaises(TrackerFailureError) as ctx:
            parse_tracker_response(raw_bencode)

        self.assertIn("Torrent not registered with this private tracker", str(ctx.exception))
        self.assertEqual(ctx.exception.failure_reason, "Torrent not registered with this private tracker")

    def test_parse_invalid_responses(self):
        # Empty buffer
        with self.assertRaises(TrackerResponseError):
            parse_tracker_response(b"")

        # Not valid Bencode (e.g. error HTML)
        with self.assertRaises(TrackerResponseError) as ctx:
            parse_tracker_response(b"<html><body>502 Bad Gateway</body></html>")
        self.assertIn("Error decoding Bencode", str(ctx.exception))

        # Root is not a dictionary
        with self.assertRaises(TrackerResponseError):
            parse_tracker_response(encode_bencode([b"item1", b"item2"]))

        # Missing interval field
        no_interval = encode_bencode({b"peers": b""})
        with self.assertRaises(TrackerResponseError) as ctx:
            parse_tracker_response(no_interval)
        self.assertIn("Required 'interval' field", str(ctx.exception))

        # Invalid interval (<= 0 or incorrect type)
        bad_interval = encode_bencode({b"interval": 0, b"peers": b""})
        with self.assertRaises(TrackerResponseError):
            parse_tracker_response(bad_interval)

        bad_interval_type = encode_bencode({b"interval": b"1800", b"peers": b""})
        with self.assertRaises(TrackerResponseError):
            parse_tracker_response(bad_interval_type)

        # Peers with invalid type
        bad_peers_type = encode_bencode({b"interval": 1800, b"peers": 12345})
        with self.assertRaises(TrackerResponseError):
            parse_tracker_response(bad_peers_type)


class TestNetworkExecutionAndMocks(unittest.TestCase):
    """Tests for simulated HTTP requests with mock opener and test abstractions."""

    def setUp(self):
        self.info_hash = b"01234567890123456789"
        self.peer_id = b"-ST0001-abcdefghijkl"
        self.announce_url = "http://tracker.test/announce"

    def test_query_http_tracker_success(self):
        peer_bytes = socket.inet_aton("192.168.1.1") + struct.pack("!H", 6881)
        resp_data = encode_bencode({b"interval": 900, b"peers": peer_bytes})

        def mock_opener(req, timeout=15.0):
            # Validate headers and request URL
            self.assertIn("SimpleBitTorrent", req.headers.get("User-agent"))
            self.assertIn("info_hash=", req.full_url)
            return MockHTTPResponse(resp_data)

        response = query_http_tracker(
            announce_url=self.announce_url,
            info_hash=self.info_hash,
            peer_id=self.peer_id,
            opener=mock_opener,
        )

        self.assertEqual(response.interval, 900)
        self.assertEqual(len(response.peers), 1)
        self.assertEqual(response.peers[0].ip, "192.168.1.1")

    def test_execute_http_get_gzip_support(self):
        raw_bencode = encode_bencode({b"interval": 600, b"peers": b""})
        compressed = gzip.compress(raw_bencode)
        response = MockHTTPResponse(compressed, headers={"Content-Encoding": "gzip"})

        def mock_opener(req, timeout=15.0):
            return response

        data = execute_http_get("http://tracker.test/announce", opener=mock_opener)
        self.assertEqual(data, raw_bencode)
        self.assertTrue(response.closed)

    def test_http_error_handling(self):
        def mock_opener_404(req, timeout=15.0):
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=404,
                msg="Not Found",
                hdrs={},  # type: ignore
                fp=io.BytesIO(b"Tracker not found"),
            )

        with self.assertRaises(TrackerHTTPError) as ctx:
            execute_http_get("http://tracker.test/announce", opener=mock_opener_404)

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("404", str(ctx.exception))

    def test_http_error_with_bencoded_failure_reason(self):
        # Server returns 400 Bad Request but with Bencoded 'failure reason' body
        fail_body = encode_bencode({b"failure reason": b"invalid passkey provided"})

        def mock_opener_400_bencode(req, timeout=15.0):
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=400,
                msg="Bad Request",
                hdrs={},  # type: ignore
                fp=io.BytesIO(fail_body),
            )

        with self.assertRaises(TrackerFailureError) as ctx:
            execute_http_get("http://tracker.test/announce", opener=mock_opener_400_bencode)

        self.assertEqual(ctx.exception.failure_reason, "invalid passkey provided")

    def test_timeout_handling(self):
        # socket.timeout
        def mock_opener_socket_timeout(req, timeout=15.0):
            raise socket.timeout("timed out")

        with self.assertRaises(TrackerTimeoutError) as ctx:
            execute_http_get("http://tracker.test/announce", opener=mock_opener_socket_timeout)
        self.assertIn("Timeout", str(ctx.exception))

        # urllib.error.URLError encapsulando timeout
        def mock_opener_urlerror_timeout(req, timeout=15.0):
            raise urllib.error.URLError(reason=socket.timeout("The read operation timed out"))

        with self.assertRaises(TrackerTimeoutError):
            execute_http_get("http://tracker.test/announce", opener=mock_opener_urlerror_timeout)

    def test_connection_error_handling(self):
        def mock_opener_conn_refused(req, timeout=15.0):
            raise urllib.error.URLError(reason="Connection refused")

        with self.assertRaises(TrackerConnectionError) as ctx:
            execute_http_get("http://tracker.test/announce", opener=mock_opener_conn_refused)
        self.assertIn("Connection refused", str(ctx.exception))


class TestHTTPTrackerClient(unittest.TestCase):
    """Tests for high-level HTTPTrackerClient."""

    def setUp(self):
        self.info_dict = {
            b"length": 1048576,  # 1 MB
            b"name": b"sample.iso",
            b"piece length": 262144,
            b"pieces": b"A" * 80,  # 4 pieces
        }
        self.torrent_dict = {
            b"announce": b"http://tracker.sample.org/announce",
            b"info": self.info_dict,
        }
        self.torrent_bytes = encode_bencode(self.torrent_dict)
        self.metadata = load_torrent_bytes(self.torrent_bytes)

    def test_client_init_from_metadata(self):
        client = HTTPTrackerClient(self.metadata)
        self.assertEqual(client.info_hash, self.metadata.info_hash)
        self.assertEqual(client.announce_url, "http://tracker.sample.org/announce")
        self.assertEqual(client.total_length, 1048576)
        self.assertEqual(len(client.peer_id), 20)

    def test_client_init_from_bytes_and_file(self):
        # From raw bytes
        client_bytes = HTTPTrackerClient(self.torrent_bytes)
        self.assertEqual(client_bytes.info_hash, self.metadata.info_hash)

        # From disk file
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.torrent"
            file_path.write_bytes(self.torrent_bytes)

            client_file = HTTPTrackerClient(file_path)
            self.assertEqual(client_file.info_hash, self.metadata.info_hash)

    def test_client_init_from_explicit_params(self):
        raw_hash = b"X" * 20
        client = HTTPTrackerClient(
            info_hash=raw_hash,
            announce_url="http://custom.tracker/announce",
            total_length=500,
        )
        self.assertEqual(client.info_hash, raw_hash)
        self.assertEqual(client.announce_url, "http://custom.tracker/announce")
        self.assertEqual(client.total_length, 500)

    def test_client_announce_lifecycle_and_tracker_id(self):
        peer_data = socket.inet_aton("10.0.0.1") + struct.pack("!H", 6881)
        captured_requests = []

        def mock_opener(req, timeout=15.0):
            captured_requests.append(req.full_url)
            return MockHTTPResponse(
                encode_bencode({
                    b"interval": 1800,
                    b"tracker id": b"session_123",
                    b"peers": peer_data,
                })
            )

        client = HTTPTrackerClient(self.metadata, opener=mock_opener)

        # 1. 'started' event
        resp_start = client.start(uploaded=0, downloaded=0)
        self.assertEqual(resp_start.interval, 1800)
        self.assertEqual(client.last_tracker_id, "session_123")
        self.assertIn("event=started", captured_requests[-1])
        self.assertIn("left=1048576", captured_requests[-1])

        # 2. Regular announce (must resend trackerid='session_123' and recalculated left)
        resp_reg = client.announce(uploaded=50000, downloaded=100000)
        self.assertIn("trackerid=session_123", captured_requests[-1])
        self.assertIn("uploaded=50000", captured_requests[-1])
        self.assertIn("downloaded=100000", captured_requests[-1])
        self.assertIn("left=948576", captured_requests[-1])  # 1048576 - 100000

        # 3. 'completed' event
        resp_comp = client.complete(uploaded=100000, downloaded=1048576)
        self.assertIn("event=completed", captured_requests[-1])
        self.assertIn("left=0", captured_requests[-1])

        # 4. 'stopped' event
        resp_stop = client.stop(uploaded=100000, downloaded=1048576)
        self.assertIn("event=stopped", captured_requests[-1])

    def test_client_missing_announce_url_raises_error(self):
        client = HTTPTrackerClient(info_hash=b"Z" * 20)
        with self.assertRaises(ValueError) as ctx:
            client.announce()
        self.assertIn("No announce URL provided", str(ctx.exception))

    def test_generate_peer_id(self):
        pid = generate_peer_id("-AZ4000-")
        self.assertEqual(len(pid), 20)
        self.assertTrue(pid.startswith(b"-AZ4000-"))


if __name__ == "__main__":
    unittest.main()
