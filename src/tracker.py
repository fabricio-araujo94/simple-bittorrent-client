"""
Módulo para comunicação com trackers BitTorrent via HTTP/HTTPS.

Implementa a especificação de announce HTTP do BitTorrent (BEP 0003, BEP 0023):
- Construção de requisições GET de announce com parâmetros obrigatórios e opcionais;
- URL encoding rigoroso (RFC 3986 / percent-encoding) para dados binários como info_hash e peer_id;
- Geração de peer_id único no padrão Azureus-style;
- Parsing e validação da resposta Bencode do tracker;
- Tratamento de 'failure reason' e mensagens de aviso ('warning message');
- Extração de peers tanto no formato compactado IPv4 (BEP 0023: 6 bytes por peer) quanto em dicionários/listas (BEP 0003);
- Tratamento estruturado de erros HTTP, falhas de conexão e timeouts;
- Suporte a injeção de transportes/openers HTTP para testes determinísticos sem acesso à rede externa.
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
# Exceções
# ==============================================================================

class TrackerError(Exception):
    """Exceção base para todos os erros relacionados a trackers BitTorrent."""
    pass


class TrackerConnectionError(TrackerError):
    """Exceção lançada quando ocorre falha de conexão de rede com o tracker."""
    pass


class TrackerTimeoutError(TrackerConnectionError):
    """Exceção lançada quando a comunicação com o tracker excede o timeout limite."""
    pass


class TrackerHTTPError(TrackerError):
    """Exceção lançada quando o servidor HTTP retorna um status de erro (4xx, 5xx)."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TrackerResponseError(TrackerError):
    """Exceção lançada quando a resposta do tracker é inválida, malformada ou inesperada."""
    pass


class TrackerFailureError(TrackerResponseError):
    """Exceção lançada quando o tracker responde explicitamente com 'failure reason'."""

    def __init__(self, failure_reason: str):
        super().__init__(f"Tracker rejeitou a requisição: {failure_reason}")
        self.failure_reason = failure_reason


# ==============================================================================
# Estruturas de Dados
# ==============================================================================

@dataclass(frozen=True)
class PeerInfo:
    """
    Representação estruturada e imutável de um peer BitTorrent.
    """
    ip: str
    port: int
    peer_id: Optional[bytes] = None

    @property
    def peer_id_hex(self) -> Optional[str]:
        """Retorna o peer_id em string hexadecimal, se presente."""
        return self.peer_id.hex() if self.peer_id else None

    def __str__(self) -> str:
        if self.peer_id:
            return f"{self.ip}:{self.port} (peer_id: {self.peer_id!r})"
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class TrackerResponse:
    """
    Representação estruturada da resposta Bencode retornada por um tracker HTTP.
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
        """Número de peers retornados nesta resposta."""
        return len(self.peers)


# ==============================================================================
# Utilitários de Peer ID e Codificação
# ==============================================================================

def generate_peer_id(prefix: str = "-ST0001-") -> bytes:
    """
    Gera um identificador único de 20 bytes para este cliente (BEP 0020).
    Padrão Azureus-style: prefixo de 8 caracteres + 12 caracteres alfanuméricos aleatórios.
    
    Exemplo: b'-ST0001-a1b2c3d4e5f6'
    """
    prefix_bytes = prefix.encode("ascii")
    if len(prefix_bytes) > 20:
        raise ValueError(
            f"Prefixo do peer_id não pode ter mais de 20 bytes (possui {len(prefix_bytes)} bytes)."
        )
    remaining_len = 20 - len(prefix_bytes)
    random_chars = "".join(random.choices(string.ascii_letters + string.digits, k=remaining_len))
    return prefix_bytes + random_chars.encode("ascii")


def urlencode_binary(data: Union[bytes, bytearray, memoryview]) -> str:
    """
    Realiza o percent-encoding estrito de bytes brutos conforme RFC 3986.
    Garante que bytes não-alfanuméricos (incluindo espaços, bytes nulos e caracteres de controle)
    sejam escapados no formato %XX em maiúsculas.
    """
    return urllib.parse.quote_from_bytes(bytes(data), safe=b"")


# ==============================================================================
# Construção de URLs de Announce
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
    Constrói a URL completa para uma requisição GET de announce ao tracker HTTP.

    Respeita com rigor as especificações BEP 0003 e BEP 0023:
    - `info_hash`: 20 bytes brutos convertidos via percent-encoding (não usar hex!);
    - `peer_id`: 20 bytes ou string convertida via percent-encoding;
    - `port`: porta TCP em escuta (1-65535);
    - `uploaded`: total de bytes enviados até o momento (inteiro >= 0);
    - `downloaded`: total de bytes baixados até o momento (inteiro >= 0);
    - `left`: total de bytes restantes para download (inteiro >= 0);
    - `compact`: se True, envia `compact=1` indicando suporte a lista compacta de peers;
    - `event`: evento do cliente ('started', 'completed', 'stopped' ou None para regular);
    - Parâmetros opcionais adicionais: no_peer_id, numwant, ip, key, trackerid.

    Raises:
        ValueError / TypeError: Se algum parâmetro for inválido ou de tipo incorreto.
    """
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("URL base do tracker não pode ser vazia.")

    # 1. info_hash: deve ser exatamente 20 bytes
    if not isinstance(info_hash, (bytes, bytearray, memoryview)):
        raise TypeError(f"info_hash deve ser bytes, obtido {type(info_hash).__name__}.")
    info_hash_bytes = bytes(info_hash)
    if len(info_hash_bytes) != 20:
        raise ValueError(f"info_hash deve ter exatamente 20 bytes, obtido {len(info_hash_bytes)} bytes.")

    # 2. peer_id: deve ter exatamente 20 bytes
    if isinstance(peer_id, str):
        peer_id_bytes = peer_id.encode("utf-8")
    elif isinstance(peer_id, (bytes, bytearray, memoryview)):
        peer_id_bytes = bytes(peer_id)
    else:
        raise TypeError(f"peer_id deve ser str ou bytes, obtido {type(peer_id).__name__}.")
    if len(peer_id_bytes) != 20:
        raise ValueError(f"peer_id deve ter exatamente 20 bytes, obtido {len(peer_id_bytes)} bytes.")

    # 3. port: 1-65535
    if not isinstance(port, int) or isinstance(port, bool) or not (0 < port <= 65535):
        raise ValueError(f"port deve ser um inteiro entre 1 e 65535, obtido {port!r}.")

    # 4. uploaded, downloaded, left: inteiros >= 0
    for name, val in [("uploaded", uploaded), ("downloaded", downloaded), ("left", left)]:
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValueError(f"{name} deve ser um inteiro não-negativo (>= 0), obtido {val!r}.")

    # Montagem dos parâmetros
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
            raise ValueError(f"numwant deve ser um inteiro não-negativo (>= 0), obtido {numwant!r}.")
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
            f"Esquema de URL do tracker não suportado ou inseguro: {parsed_base.scheme!r} (apenas http e https são permitidos)."
        )
    if not parsed_base.netloc:
        raise TrackerError(f"URL de tracker inválida (hostname ausente): {clean_base!r}.")

    query_string = "&".join(query_params)

    if "?" in clean_base:
        if clean_base.endswith("?") or clean_base.endswith("&"):
            return f"{clean_base}{query_string}"
        return f"{clean_base}&{query_string}"
    return f"{clean_base}?{query_string}"


# ==============================================================================
# Parsing de Respostas e Extração de Peers
# ==============================================================================

def parse_compact_peers_ipv4(peers_bytes: Union[bytes, bytearray, memoryview]) -> List[PeerInfo]:
    """
    Decodifica a lista de peers no formato compacto IPv4 (BEP 0023).

    Cada peer é codificado em 6 bytes contíguos em ordem de rede (big-endian):
    - Bytes 0..3: Endereço IPv4 (ex: \x7f\x00\x00\x01 -> "127.0.0.1")
    - Bytes 4..5: Porta TCP (ex: \x1a\xe1 -> 6881)

    Raises:
        TrackerResponseError: Se o tamanho não for múltiplo exato de 6 bytes.
    """
    raw = bytes(peers_bytes)
    if len(raw) % 6 != 0:
        raise TrackerResponseError(
            f"Tamanho dos peers compactados ({len(raw)} bytes) não é múltiplo de 6 bytes."
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
    Decodifica a lista de peers no formato tradicional de dicionários (BEP 0003).

    Cada item da lista é um dicionário contendo:
    - 'ip': string ou byte string com o IP/hostname do peer;
    - 'port': inteiro com a porta TCP;
    - 'peer id' (opcional): byte string de 20 bytes com a identidade do peer.

    Raises:
        TrackerResponseError: Se a estrutura ou tipos dos dados forem inválidos.
    """
    if not isinstance(peers_list, list):
        raise TrackerResponseError(
            f"Formato de peers inválido: esperado list, obtido {type(peers_list).__name__}."
        )

    peers: List[PeerInfo] = []
    for idx, item in enumerate(peers_list):
        if not isinstance(item, dict):
            raise TrackerResponseError(f"Item {idx} na lista de peers deve ser um dicionário.")

        # ip
        if b"ip" not in item:
            raise TrackerResponseError(f"Campo 'ip' ausente no peer {idx}.")
        raw_ip = item[b"ip"]
        if isinstance(raw_ip, (bytes, bytearray)):
            ip_str = bytes(raw_ip).decode("utf-8", errors="replace").strip()
        elif isinstance(raw_ip, str):
            ip_str = raw_ip.strip()
        else:
            raise TrackerResponseError(f"Campo 'ip' no peer {idx} deve ser bytes ou str.")

        if not ip_str:
            raise TrackerResponseError(f"Campo 'ip' no peer {idx} não pode ser vazio.")

        # port
        if b"port" not in item:
            raise TrackerResponseError(f"Campo 'port' ausente no peer {idx}.")
        port_val = item[b"port"]
        if not isinstance(port_val, int) or isinstance(port_val, bool) or not (0 < port_val <= 65535):
            raise TrackerResponseError(
                f"Porta inválida para o peer {idx}: deve ser inteiro entre 1 e 65535, obtido {port_val!r}."
            )

        # peer id (opcional)
        peer_id_bytes: Optional[bytes] = None
        if b"peer id" in item:
            raw_pid = item[b"peer id"]
            if isinstance(raw_pid, (bytes, bytearray)):
                peer_id_bytes = bytes(raw_pid)
            elif isinstance(raw_pid, str):
                peer_id_bytes = raw_pid.encode("utf-8")
            else:
                raise TrackerResponseError(f"Campo 'peer id' no peer {idx} deve ser bytes ou str.")

        peers.append(PeerInfo(ip=ip_str, port=port_val, peer_id=peer_id_bytes))

    return peers


def parse_tracker_response(raw_response: Union[bytes, bytearray, memoryview]) -> TrackerResponse:
    """
    Decodifica e valida a resposta Bencoded recebida de um tracker HTTP (BEP 0003, BEP 0023).

    Raises:
        TrackerFailureError: Se o tracker respondeu com 'failure reason'.
        TrackerResponseError: Se o Bencode for inválido ou faltar campos obrigatórios (como 'interval').
    """
    if not isinstance(raw_response, (bytes, bytearray, memoryview)):
        raise TrackerResponseError(
            f"Resposta do tracker esperada como bytes, obtido {type(raw_response).__name__}."
        )

    raw_bytes = bytes(raw_response)
    if not raw_bytes:
        raise TrackerResponseError("Resposta vazia recebida do tracker.")

    try:
        data = decode_bencode(raw_bytes, strict=False)
    except BencodeError as e:
        raise TrackerResponseError(f"Erro ao decodificar Bencode da resposta do tracker: {e}") from e

    if not isinstance(data, dict):
        raise TrackerResponseError("A raiz da resposta Bencode do tracker deve ser um dicionário.")

    # 1. Verifica falha explícita reportada pelo tracker ('failure reason')
    if b"failure reason" in data:
        reason_raw = data[b"failure reason"]
        if isinstance(reason_raw, (bytes, bytearray)):
            reason_str = bytes(reason_raw).decode("utf-8", errors="replace")
        else:
            reason_str = str(reason_raw)
        raise TrackerFailureError(reason_str)

    # 2. Valida e extrai intervalo obrigatório
    if b"interval" not in data:
        raise TrackerResponseError("Campo obrigatório 'interval' não encontrado na resposta do tracker.")

    interval_val = data[b"interval"]
    if not isinstance(interval_val, int) or isinstance(interval_val, bool) or interval_val <= 0:
        raise TrackerResponseError(
            f"Campo 'interval' deve ser um inteiro estritamente positivo (> 0), obtido {interval_val!r}."
        )

    # 3. Extrai peers (compactados ou lista de dicionários)
    peers: List[PeerInfo] = []
    if b"peers" in data:
        raw_peers = data[b"peers"]
        if isinstance(raw_peers, (bytes, bytearray)):
            peers = parse_compact_peers_ipv4(raw_peers)
        elif isinstance(raw_peers, list):
            peers = parse_dictionary_peers(raw_peers)
        else:
            raise TrackerResponseError(
                f"Formato inválido para o campo 'peers': esperado bytes ou list, obtido {type(raw_peers).__name__}."
            )

    # 4. Extrai campos opcionais da especificação
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
# Execução de Requisições HTTP com urllib
# ==============================================================================

def execute_http_get(
    url: str,
    timeout: float = 15.0,
    user_agent: str = "SimpleBitTorrent/1.0",
    opener: Optional[Any] = None,
) -> bytes:
    """
    Executa uma requisição HTTP GET utilizando urllib e retorna o corpo da resposta em bytes.

    Suporta descompressão automática de gzip e mapeia exceções de rede/HTTP para a hierarquia
    de exceções TrackerError.

    Permite injeção de `opener` customizado (função ou urllib OpenerDirector) para testes
    unitários sem necessidade de conexão com a Internet real.
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme.lower() not in ("http", "https"):
        raise TrackerError(
            f"Esquema de URL inseguro ou não suportado: {parsed_url.scheme!r} (apenas http e https são permitidos)."
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
                raise TypeError(f"Opener fornecido não é chamável nem possui método 'open': {opener!r}.")
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)

        raw_bytes = resp.read()

        # Descompressão automática de gzip caso retornado
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
        # Se o servidor HTTP retornar corpo com 'failure reason' Bencoded (ex: 400 ou 403)
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
            f"Tracker retornou erro HTTP {e.code}: {e.reason}",
            status_code=e.code,
        ) from e

    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)) or "timed out" in str(e.reason).lower():
            raise TrackerTimeoutError(f"Timeout ao conectar ao tracker: {e.reason}") from e
        raise TrackerConnectionError(f"Falha de conexão com o tracker: {e.reason}") from e

    except (socket.timeout, TimeoutError) as e:
        raise TrackerTimeoutError(f"Timeout ao conectar ao tracker: {e}") from e

    except TrackerError:
        raise

    except Exception as e:
        raise TrackerConnectionError(f"Erro inesperado ao comunicar com o tracker: {e}") from e

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
    Função utilitária direta para consultar um tracker HTTP, executar o announce
    e retornar o TrackerResponse decodificado.
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
# Cliente HTTP de Tracker
# ==============================================================================

class HTTPTrackerClient:
    """
    Cliente de alto nível para gerenciamento e comunicação com trackers BitTorrent HTTP.

    Pode ser instanciado diretamente a partir de:
    - Um objeto `TorrentMetadata`;
    - O conteúdo de bytes de um arquivo .torrent;
    - O caminho em disco para um arquivo .torrent;
    - Ou parâmetros explícitos (`info_hash`, `announce_url`, `total_length`).
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
                    f"Tipo inválido para o argumento torrent: {type(torrent).__name__}."
                )

        # Resolução de info_hash
        resolved_info_hash = info_hash
        if resolved_info_hash is None and self.torrent_meta is not None:
            resolved_info_hash = self.torrent_meta.info_hash
        if resolved_info_hash is None:
            raise ValueError("info_hash não fornecido e não encontrado no torrent.")
        self.info_hash = bytes(resolved_info_hash)

        # Resolução de announce_url
        resolved_announce = announce_url
        if resolved_announce is None and self.torrent_meta is not None:
            resolved_announce = self.torrent_meta.announce or (
                self.torrent_meta.trackers[0] if self.torrent_meta.trackers else None
            )
        self.announce_url = resolved_announce

        # Resolução de total_length
        resolved_length = total_length
        if resolved_length is None and self.torrent_meta is not None:
            resolved_length = self.torrent_meta.total_length
        self.total_length = resolved_length if resolved_length is not None else 0

        # Resolução de peer_id
        if peer_id is None:
            self.peer_id = generate_peer_id()
        elif isinstance(peer_id, str):
            self.peer_id = peer_id.encode("utf-8")
        elif isinstance(peer_id, (bytes, bytearray, memoryview)):
            self.peer_id = bytes(peer_id)
        else:
            raise TypeError(f"peer_id deve ser bytes ou str, obtido {type(peer_id).__name__}.")

        self.port = port
        self.user_agent = user_agent
        self.opener = opener

        # Estado da sessão com o tracker
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
        Executa um announce HTTP e retorna o TrackerResponse decodificado.
        """
        target_url = tracker_url or self.announce_url
        if not target_url:
            raise ValueError("Nenhuma URL de announce informada ou configurada no cliente.")

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
        """Envia o announce inicial com event='started'."""
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
        """Envia o announce de conclusão com event='completed' e left=0."""
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
        """Envia o announce de encerramento com event='stopped'."""
        return self.announce(
            uploaded=uploaded,
            downloaded=downloaded,
            left=left,
            event="stopped",
            compact=compact,
            **kwargs,
        )
