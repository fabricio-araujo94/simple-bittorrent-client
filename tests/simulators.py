"""
Módulo de componentes simulados e fixtures para testes de integração do Simple BitTorrent Client.

Fornece:
1. `TorrentFixtureBuilder`: Criação programática de torrents (.torrent) single e multi-file com hashes válidos;
2. `SimulatedTrackerServer`: Servidor HTTP de Tracker local (127.0.0.1) com suporte a registro de eventos, falhas e compact peers;
3. `SimulatedPeerServer`: Servidor TCP de Peer local (127.0.0.1) altamente configurável (handshake, bitfield, unchoke, corrupção, quedas);
4. `SimulatedSwarm`: Gerenciador de enxame de múltiplos peers simulados em portas locais dinâmicas.
"""

import http.server
import io
import os
import queue
import random
import socket
import socketserver
import struct
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from src.bencode import encode_bencode
from src.hash_utils import compute_sha1
from src.peer import (
    DEFAULT_BLOCK_SIZE,
    Bitfield,
    BitfieldMessage,
    ChokeMessage,
    Handshake,
    HaveMessage,
    InterestedMessage,
    KeepAliveMessage,
    NotInterestedMessage,
    PieceMessage,
    RequestMessage,
    UnchokeMessage,
    encode_handshake,
    parse_handshake,
    parse_message,
)
from src.torrent import FileInfo, TorrentMetadata, load_torrent_bytes
from src.tracker import PeerInfo


# ==============================================================================
# 1. Construtor de Fixtures de Torrent (.torrent)
# ==============================================================================

@dataclass
class GeneratedTorrentFixture:
    """Dados completos gerados para uma fixture de teste de torrent."""
    torrent_bytes: bytes
    torrent_meta: TorrentMetadata
    info_hash: bytes
    total_data: bytes
    file_map: Dict[str, bytes]
    piece_length: int
    piece_hashes: List[bytes]
    temp_dir: tempfile.TemporaryDirectory
    torrent_file_path: Path


class TorrentFixtureBuilder:
    """
    Construtor determinístico e reproduzível de arquivos e metadados .torrent.
    Gera arquivos simples (single-file) e estruturas com diretórios aninhados (multi-file).
    """

    @staticmethod
    def create_single_file_torrent(
        filename: str = "test_sample.dat",
        file_size: int = 64 * 1024,  # 64 KB
        piece_length: int = 16 * 1024,  # 16 KB (4 peças)
        announce_url: str = "http://127.0.0.1:8000/announce",
        announce_list: Optional[List[List[str]]] = None,
        custom_content: Optional[bytes] = None,
    ) -> GeneratedTorrentFixture:
        """Cria um torrent de arquivo único com conteúdo aleatório reproduzível ou customizado."""
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(temp_dir.name)

        if custom_content is not None:
            content = custom_content
            file_size = len(content)
        else:
            # Conteúdo pseudoaleatório determinístico baseado no tamanho
            rng = random.Random(file_size ^ 0xABCD1234)
            content = rng.randbytes(file_size)

        # Calcula os hashes SHA-1 das peças
        piece_hashes: List[bytes] = []
        for i in range(0, len(content), piece_length):
            piece_chunk = content[i : i + piece_length]
            piece_hashes.append(compute_sha1(piece_chunk))

        pieces_concatenated = b"".join(piece_hashes)

        info_dict = {
            "name": filename,
            "piece length": piece_length,
            "pieces": pieces_concatenated,
            "length": file_size,
        }

        torrent_dict = {
            "announce": announce_url,
            "info": info_dict,
        }
        if announce_list is not None:
            torrent_dict["announce-list"] = announce_list

        raw_bencode = encode_bencode(torrent_dict)
        meta = load_torrent_bytes(raw_bencode)

        torrent_file = temp_path / f"{filename}.torrent"
        torrent_file.write_bytes(raw_bencode)

        return GeneratedTorrentFixture(
            torrent_bytes=raw_bencode,
            torrent_meta=meta,
            info_hash=meta.info_hash,
            total_data=content,
            file_map={filename: content},
            piece_length=piece_length,
            piece_hashes=piece_hashes,
            temp_dir=temp_dir,
            torrent_file_path=torrent_file,
        )

    @staticmethod
    def create_multi_file_torrent(
        root_dir_name: str = "sample_project",
        files_spec: Optional[List[Tuple[List[str], int]]] = None,
        piece_length: int = 16 * 1024,
        announce_url: str = "http://127.0.0.1:8000/announce",
        announce_list: Optional[List[List[str]]] = None,
    ) -> GeneratedTorrentFixture:
        """
        Cria um torrent multi-file com múltiplos arquivos e diretórios aninhados.
        
        Args:
            root_dir_name: Nome do diretório raiz.
            files_spec: Lista de tuplas (segmentos_de_caminho, tamanho_em_bytes).
        """
        if files_spec is None:
            files_spec = [
                (["docs", "readme.txt"], 2048),
                (["src", "main.py"], 10240),
                (["data", "nested", "blob.bin"], 35000),
            ]

        temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(temp_dir.name)

        total_data = bytearray()
        files_dict_list = []
        file_map: Dict[str, bytes] = {}

        for idx, (path_segments, size) in enumerate(files_spec):
            rng = random.Random((idx + 1) * 99991)
            file_bytes = rng.randbytes(size)
            total_data.extend(file_bytes)

            rel_path = "/".join(path_segments)
            file_map[rel_path] = file_bytes

            files_dict_list.append({
                "length": size,
                "path": path_segments,
            })

        total_bytes = bytes(total_data)
        piece_hashes: List[bytes] = []
        for i in range(0, len(total_bytes), piece_length):
            chunk = total_bytes[i : i + piece_length]
            piece_hashes.append(compute_sha1(chunk))

        pieces_blob = b"".join(piece_hashes)

        info_dict = {
            "name": root_dir_name,
            "piece length": piece_length,
            "pieces": pieces_blob,
            "files": files_dict_list,
        }

        torrent_dict = {
            "announce": announce_url,
            "info": info_dict,
        }
        if announce_list is not None:
            torrent_dict["announce-list"] = announce_list

        raw_bencode = encode_bencode(torrent_dict)
        meta = load_torrent_bytes(raw_bencode)

        torrent_file = temp_path / f"{root_dir_name}.torrent"
        torrent_file.write_bytes(raw_bencode)

        return GeneratedTorrentFixture(
            torrent_bytes=raw_bencode,
            torrent_meta=meta,
            info_hash=meta.info_hash,
            total_data=total_bytes,
            file_map=file_map,
            piece_length=piece_length,
            piece_hashes=piece_hashes,
            temp_dir=temp_dir,
            torrent_file_path=torrent_file,
        )


# ==============================================================================
# 2. Servidor de Tracker HTTP Simulado (Localhost)
# ==============================================================================

@dataclass
class TrackerAnnounceRecord:
    """Registro de uma requisição de announce recebida pelo tracker."""
    info_hash: bytes
    peer_id: bytes
    port: int
    uploaded: int
    downloaded: int
    left: int
    event: Optional[str]
    ip: str
    timestamp: float = field(default_factory=time.time)


class SimulatedTrackerServer:
    """
    Servidor HTTP de Tracker BitTorrent local, rápido e thread-safe.
    Executa em loopback (127.0.0.1) com porta efêmera aleatória.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.port: int = 0
        self.httpd: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.is_running = False

        # Estado do tracker
        self.lock = threading.Lock()
        self.registered_peers: List[PeerInfo] = []
        self.announces: List[TrackerAnnounceRecord] = []
        self.custom_failure_reason: Optional[str] = None
        self.force_http_status: Optional[int] = None
        self.interval: int = 1800
        self.min_interval: int = 300

    @property
    def announce_url(self) -> str:
        return f"http://{self.host}:{self.port}/announce"

    def set_peers(self, peers: Sequence[PeerInfo]) -> None:
        """Define os peers que serão retornados nas consultas."""
        with self.lock:
            self.registered_peers = list(peers)

    def add_peer(self, peer: PeerInfo) -> None:
        """Adiciona um peer à lista."""
        with self.lock:
            self.registered_peers.append(peer)

    def set_failure(self, reason: Optional[str]) -> None:
        """Define uma razão de falha Bencode para retornar aos clientes."""
        with self.lock:
            self.custom_failure_reason = reason

    def set_http_error(self, status_code: Optional[int]) -> None:
        """Força o servidor a responder com um status HTTP específico (ex: 500, 404)."""
        with self.lock:
            self.force_http_status = status_code

    def get_announces(self) -> List[TrackerAnnounceRecord]:
        """Retorna cópia das requisições registradas."""
        with self.lock:
            return list(self.announces)

    def start(self) -> str:
        """Inicia o servidor HTTP em background thread."""
        parent = self

        class TrackerHTTPHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                # Silencia logs padrão do HTTP server para não poluir os testes
                pass

            def do_GET(self):
                with parent.lock:
                    if parent.force_http_status is not None:
                        self.send_response(parent.force_http_status)
                        self.end_headers()
                        self.wfile.write(b"Server Error")
                        return

                parsed = urllib.parse.urlparse(self.path)
                if not parsed.path.endswith("/announce"):
                    self.send_response(404)
                    self.end_headers()
                    return

                # Parse de query string sem decodificar info_hash e peer_id como UTF-8
                raw_info_hash = b""
                raw_peer_id = b""
                port_val = 6881
                uploaded = 0
                downloaded = 0
                left = 0
                event = None

                for param in parsed.query.split("&"):
                    if not param:
                        continue
                    if "=" in param:
                        k, v = param.split("=", 1)
                    else:
                        k, v = param, ""
                    if k == "info_hash":
                        raw_info_hash = urllib.parse.unquote_to_bytes(v)
                    elif k == "peer_id":
                        raw_peer_id = urllib.parse.unquote_to_bytes(v)
                    elif k == "port":
                        port_val = int(v) if v.isdigit() else 6881
                    elif k == "uploaded":
                        uploaded = int(v) if v.isdigit() else 0
                    elif k == "downloaded":
                        downloaded = int(v) if v.isdigit() else 0
                    elif k == "left":
                        left = int(v) if v.isdigit() else 0
                    elif k == "event":
                        event = urllib.parse.unquote(v)

                record = TrackerAnnounceRecord(
                    info_hash=raw_info_hash,
                    peer_id=raw_peer_id,
                    port=port_val,
                    uploaded=uploaded,
                    downloaded=downloaded,
                    left=left,
                    event=event,
                    ip=self.client_address[0],
                )

                with parent.lock:
                    parent.announces.append(record)
                    failure_reason = parent.custom_failure_reason
                    peers_to_send = list(parent.registered_peers)

                if failure_reason is not None:
                    resp_dict = {"failure reason": failure_reason}
                else:
                    # Gera resposta de peers em formato compacto IPv4 (6 bytes por peer)
                    compact_bytes = bytearray()
                    for p in peers_to_send:
                        ip_parts = [int(x) for x in p.ip.split(".")]
                        compact_bytes.extend(bytes(ip_parts))
                        compact_bytes.extend(struct.pack("!H", p.port))

                    resp_dict = {
                        "interval": parent.interval,
                        "min interval": parent.min_interval,
                        "complete": 1,
                        "incomplete": len(peers_to_send),
                        "peers": bytes(compact_bytes),
                    }

                body = encode_bencode(resp_dict)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.HTTPServer((self.host, self.requested_port), TrackerHTTPHandler)
        self.port = self.httpd.server_port
        self.is_running = True

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="SimulatedTracker")
        self.thread.start()
        return self.announce_url

    def stop(self) -> None:
        """Encerra o servidor HTTP."""
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread is not None:
            self.thread.join(timeout=2.0)
            self.thread = None
        self.is_running = False


# ==============================================================================
# 3. Servidor de Peer TCP Simulado (Localhost)
# ==============================================================================

@dataclass
class PeerBehavior:
    """Configuração granular de comportamento para um peer simulado."""
    peer_id: bytes = b"-ST0001-mockpeer0001"
    # Conjunto de índices de peças que o peer possui
    pieces_possessed: Optional[Set[int]] = None
    # Se True, envia Bitfield no início; se False, envia Have para cada peça
    send_bitfield: bool = True
    # Se True, inicia choked e depois desboqueia
    choke_first: bool = False
    choke_delay: float = 0.05
    never_unchoke: bool = False
    # Índices de peças a corromper intencionalmente (envia dados com hash divergente)
    corrupt_pieces: Set[int] = field(default_factory=set)
    # Quantidade máxima de blocos/requests a atender antes de desconectar subitamente (-1 = ilimitado)
    disconnect_after_blocks: int = -1
    # Se True, simula handshake inválido com info_hash adulterado
    send_bad_handshake_hash: bool = False
    # Se True, rejeita/fecha conexão no handshake
    close_on_handshake: bool = False

    def __post_init__(self):
        if len(self.peer_id) != 20:
            if len(self.peer_id) < 20:
                self.peer_id = self.peer_id.ljust(20, b"-")
            else:
                self.peer_id = self.peer_id[:20]


class SimulatedPeerServer:
    """
    Servidor TCP de Peer BitTorrent local rodando em loopback (127.0.0.1).
    Capaz de atender múltiplos downloads concorrentes e simular anomalias de protocolo.
    """

    def __init__(
        self,
        torrent_fixture: GeneratedTorrentFixture,
        behavior: Optional[PeerBehavior] = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self.fixture = torrent_fixture
        self.behavior = behavior or PeerBehavior()
        self.host = host
        self.port = port
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.is_running = False

        # Métricas gravadas
        self.lock = threading.Lock()
        self.connected_clients: int = 0
        self.blocks_served: int = 0
        self.received_messages: List[str] = []
        self.client_peer_ids: List[bytes] = []

    @property
    def peer_info(self) -> PeerInfo:
        return PeerInfo(ip=self.host, port=self.port, peer_id=self.behavior.peer_id)

    def start(self) -> PeerInfo:
        """Inicia o socket TCP do peer na porta indicada/efêmera."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.port = self.server_sock.getsockname()[1]
        self.server_sock.listen(10)
        self.is_running = True

        self.thread = threading.Thread(target=self._listen_loop, daemon=True, name=f"SimPeer-{self.port}")
        self.thread.start()
        return self.peer_info

    def _listen_loop(self) -> None:
        while self.is_running and self.server_sock:
            try:
                sock, addr = self.server_sock.accept()
            except (OSError, socket.error):
                break
            
            with self.lock:
                self.connected_clients += 1

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(sock,),
                daemon=True,
                name=f"SimPeerClient-{self.port}",
            )
            client_thread.start()

    def _handle_client(self, sock: socket.socket) -> None:
        sock.settimeout(5.0)
        try:
            # 1. Handshake do cliente (68 bytes)
            hs_data = self._recv_exact(sock, 68)
            if not hs_data:
                return
            client_hs = parse_handshake(hs_data)
            with self.lock:
                self.client_peer_ids.append(client_hs.peer_id)

            if self.behavior.close_on_handshake:
                return

            # 2. Responde o Handshake
            resp_hash = (
                b"\x00" * 20
                if self.behavior.send_bad_handshake_hash
                else self.fixture.info_hash
            )
            sock.sendall(encode_handshake(resp_hash, self.behavior.peer_id))

            if self.behavior.send_bad_handshake_hash:
                return

            total_len = len(self.fixture.total_data)
            p_len = self.fixture.piece_length
            num_pieces = (total_len + p_len - 1) // p_len

            possessed = (
                self.behavior.pieces_possessed
                if self.behavior.pieces_possessed is not None
                else set(range(num_pieces))
            )

            # 3. Envia Bitfield ou Haves
            if self.behavior.send_bitfield and possessed:
                bf = Bitfield(num_pieces=num_pieces)
                for p_idx in possessed:
                    if 0 <= p_idx < num_pieces:
                        bf.set_piece(p_idx, True)
                sock.sendall(BitfieldMessage(bitfield=bf.to_bytes()).encode())
            elif possessed:
                for p_idx in sorted(possessed):
                    sock.sendall(HaveMessage(piece_index=p_idx).encode())

            # 4. Controle de Choke / Unchoke
            if self.behavior.never_unchoke:
                sock.sendall(ChokeMessage().encode())
            elif self.behavior.choke_first:
                sock.sendall(ChokeMessage().encode())
                time.sleep(self.behavior.choke_delay)
                sock.sendall(UnchokeMessage().encode())
            else:
                sock.sendall(UnchokeMessage().encode())

            # 5. Loop de Mensagens do Cliente
            buffer = bytearray()
            blocks_sent_this_session = 0

            while self.is_running:
                data = sock.recv(16384)
                if not data:
                    break
                buffer.extend(data)

                while len(buffer) >= 4:
                    msg_len = struct.unpack("!I", buffer[:4])[0]
                    if len(buffer) < 4 + msg_len:
                        break
                    raw_msg = bytes(buffer[: 4 + msg_len])
                    del buffer[: 4 + msg_len]

                    if msg_len == 0:
                        with self.lock:
                            self.received_messages.append("keepalive")
                        continue

                    msg = parse_message(raw_msg)
                    with self.lock:
                        self.received_messages.append(type(msg).__name__)

                    if isinstance(msg, InterestedMessage):
                        if not self.behavior.never_unchoke:
                            sock.sendall(UnchokeMessage().encode())

                    elif isinstance(msg, RequestMessage):
                        if (
                            self.behavior.disconnect_after_blocks >= 0
                            and blocks_sent_this_session >= self.behavior.disconnect_after_blocks
                        ):
                            # Simula desconexão abrupta
                            return

                        # Calcula fatia de dados
                        piece_start = msg.index * p_len
                        block_start = piece_start + msg.begin
                        block_end = block_start + msg.length

                        if msg.index in self.behavior.corrupt_pieces:
                            # Injeta dados corrompidos
                            block_data = b"\xFF" * msg.length
                        else:
                            block_data = self.fixture.total_data[block_start:block_end]

                        resp_piece = PieceMessage(
                            index=msg.index,
                            begin=msg.begin,
                            block=block_data,
                        )
                        sock.sendall(resp_piece.encode())

                        blocks_sent_this_session += 1
                        with self.lock:
                            self.blocks_served += 1

        except (socket.timeout, OSError, ConnectionResetError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _recv_exact(self, sock: socket.socket, length: int) -> bytes:
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def stop(self) -> None:
        """Encerra o socket do peer."""
        self.is_running = False
        if self.server_sock is not None:
            try:
                self.server_sock.close()
            except OSError:
                pass
            self.server_sock = None
        if self.thread is not None:
            self.thread.join(timeout=2.0)
            self.thread = None


# ==============================================================================
# 4. Gerenciador de Enxame Simulado (SimulatedSwarm)
# ==============================================================================

class SimulatedSwarm:
    """
    Context Manager e orquestrador de enxame local contendo Tracker e múltiplos Peers.
    Garante limpeza e encerramento determinístico de todos os sockets ao final dos testes.
    """

    def __init__(self, torrent_fixture: Optional[GeneratedTorrentFixture] = None):
        self.tracker = SimulatedTrackerServer()
        self.tracker_url = self.tracker.start()
        self.fixture = torrent_fixture
        self.peers: List[SimulatedPeerServer] = []

    def set_fixture(self, fixture: GeneratedTorrentFixture) -> None:
        self.fixture = fixture

    def spawn_peer(self, behavior: Optional[PeerBehavior] = None) -> SimulatedPeerServer:
        """Cria e inicia um peer no enxame."""
        if self.fixture is None:
            raise ValueError("Fixture não configurada no SimulatedSwarm.")
        peer = SimulatedPeerServer(self.fixture, behavior=behavior)
        peer.start()
        self.peers.append(peer)
        self.tracker.add_peer(peer.peer_info)
        return peer

    def start(self) -> str:
        """Retorna a announce_url do tracker."""
        return self.tracker_url

    def stop(self) -> None:
        """Para todos os peers e o tracker."""
        for peer in self.peers:
            peer.stop()
        self.peers.clear()
        self.tracker.stop()

    def __enter__(self) -> "SimulatedSwarm":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
        if self.fixture is not None:
            self.fixture.temp_dir.cleanup()

