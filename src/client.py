"""
Módulo principal de orquestração e download BitTorrent (Client / Downloader).

Integra as camadas:
1. Torrent Parser (`TorrentMetadata`, `load_torrent_file`, `load_torrent_bytes`);
2. Tracker HTTP (`HTTPTrackerClient`, `query_http_tracker`);
3. Peer Wire Protocol (`PeerConnection`, `Handshake`, `Bitfield`, mensagens);
4. Piece Manager (`PieceManager`, `Piece`, `Block`).

Fluxo de Download implementado:
1. Carregamento e validação de metadados do torrent (.torrent / bytes);
2. Extração do `info_hash` SHA-1 de 20 bytes e geração de `peer_id`;
3. Consulta e anúncio inicial ao Tracker HTTP para descoberta de peers;
4. Conexão TCP e negociação de Handshake de 68 bytes com validação estrita;
5. Recepção e atualização de mapas de peças (`Bitfield` e `Have`);
6. Envio de mensagem `Interested` aos peers que possuem peças pendentes;
7. Aguardo de desbloqueio (`Unchoke`) pelo peer;
8. Seleção sequencial e thread-safe de peças e blocos (16 KB) disponíveis;
9. Envio de mensagens `Request` e recepção de mensagens `Piece`;
10. Armazenamento de blocos, montagem da peça e validação de integridade por hash SHA-1;
11. Notificação de conclusão de peça e repetição do ciclo até 100% do torrent ser obtido;
12. Reconstrução ordenada e gravação do arquivo.
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
    HaveMessage,
    InterestedMessage,
    KeepAliveMessage,
    NotInterestedMessage,
    PeerConnection,
    PeerConnectionClosedError,
    PeerConnectionError,
    PeerError,
    PeerProtocolError,
    PeerTimeoutError,
    PieceMessage,
    UnchokeMessage,
)
from .piece_manager import PieceManager, PieceState
from .torrent import FileInfo, TorrentMetadata, load_torrent_bytes, load_torrent_file
from .tracker import HTTPTrackerClient, PeerInfo, TrackerError, TrackerResponse

logger = logging.getLogger("simple_bittorrent.client")


class DownloadError(Exception):
    """Exceção base para erros durante o processo de download."""
    pass


class DownloadIncompleteError(DownloadError):
    """Exceção lançada quando o download termina sem que todas as peças tenham sido obtidas."""
    pass


@dataclass
class DownloadProgress:
    """Estrutura com estatísticas de progresso do download em tempo real."""
    total_length: int
    bytes_downloaded: int
    bytes_left: int
    completed_pieces: int
    total_pieces: int
    progress_percentage: float
    is_complete: bool


class TorrentClient:
    """
    Cliente BitTorrent unificado para download concorrente de torrents a partir de múltiplos peers.
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
        http_opener: Optional[Any] = None,
    ):
        # 1. Carrega e valida metadados do torrent
        if isinstance(torrent, TorrentMetadata):
            self.torrent_meta = torrent
        elif isinstance(torrent, (str, Path)):
            self.torrent_meta = load_torrent_file(torrent)
        elif isinstance(torrent, (bytes, bytearray, memoryview)):
            self.torrent_meta = load_torrent_bytes(torrent)
        else:
            raise TypeError(f"Tipo inválido para o argumento torrent: {type(torrent).__name__}.")

        self.info_hash = self.torrent_meta.info_hash
        self.output_path = Path(output_path) if output_path else None
        self.port = port
        self.block_size = block_size
        self.max_in_flight = max(1, max_in_flight)
        self.peer_timeout = peer_timeout
        self.tracker_timeout = tracker_timeout
        self.http_opener = http_opener

        # 2. Inicializa o PieceManager
        self.piece_manager = PieceManager(
            torrent=self.torrent_meta,
            block_size=self.block_size,
        )

        # 3. Inicializa o Tracker Client
        self.tracker_client = HTTPTrackerClient(
            torrent=self.torrent_meta,
            peer_id=peer_id,
            port=self.port,
            opener=self.http_opener,
        )
        self.peer_id = self.tracker_client.peer_id

        # Controle de concorrência, conexões ativas e parada
        self._stop_requested = False
        self._lock = threading.RLock()
        self._active_connections: List[PeerConnection] = []
        self._active_connections_lock = threading.Lock()

    @property
    def is_complete(self) -> bool:
        """Verifica se todas as peças do torrent foram baixadas e validadas."""
        return self.piece_manager.is_complete

    def _register_connection(self, conn: PeerConnection) -> None:
        """Registra uma conexão de peer ativa."""
        with self._active_connections_lock:
            self._active_connections.append(conn)

    def _unregister_connection(self, conn: PeerConnection) -> None:
        """Desregistra uma conexão de peer."""
        with self._active_connections_lock:
            if conn in self._active_connections:
                self._active_connections.remove(conn)

    def _broadcast_have(self, piece_index: int) -> None:
        """Envia mensagem Have para todas as conexões de peers ativas."""
        with self._active_connections_lock:
            active = list(self._active_connections)
        for conn in active:
            try:
                conn.send_have(piece_index)
            except Exception:
                pass

    def get_progress(self) -> DownloadProgress:
        """Retorna o progresso atual do download."""
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
        Consulta o tracker HTTP para obter a lista de peers disponíveis.
        """
        try:
            resp: TrackerResponse = self.tracker_client.start(
                uploaded=0,
                downloaded=self.piece_manager.bytes_downloaded(),
                left=self.piece_manager.bytes_left(),
                timeout=self.tracker_timeout,
            )
            return resp.peers
        except TrackerError as e:
            logger.warning(f"Falha ao consultar tracker: {e}")
            raise DownloadError(f"Erro ao obter peers do tracker: {e}") from e

    def download_from_peer_connection(
        self,
        conn: PeerConnection,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
        max_blocks_per_iteration: int = 1000,
        max_in_flight: Optional[int] = None,
    ) -> bool:
        """
        Executa o ciclo de download com uma conexão de peer já estabelecida e com handshake realizado.

        Recursos:
        1. Pipelining de requisições (respeita max_in_flight);
        2. Rastreamento e isolamento de requisições em voo exclusivas desta conexão;
        3. Recepção assíncrona de blocos e controle de fluxo (Choke/Unchoke/Have/Bitfield);
        4. Devolução atômica de blocos ao PieceManager em caso de choke ou desconexão;
        5. Notificação de conclusão de peças (Have) aos outros peers.

        Returns:
            bool: True se o download do torrent foi concluído ou progrediu, False se desconectou/falhou.
        """
        effective_max_in_flight = max_in_flight if max_in_flight is not None else self.max_in_flight
        self._register_connection(conn)
        in_flight: Dict[Tuple[int, int], int] = {}  # (piece_idx, begin) -> length
        registered_bitfield: Optional[Bitfield] = None

        try:
            # 1. Envia 'Interested'
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

                # 1. Se o peer estiver unchoked, envia requisições até atingir o limite em voo (Pipelining)
                if not conn.peer_choking:
                    while len(in_flight) < effective_max_in_flight and not self.piece_manager.is_complete and not self._stop_requested:
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

                # 2. Decide como ler do socket com base nas requisições em voo
                if len(in_flight) == 0:
                    if conn.peer_choking:
                        # Bloqueado pelo peer e sem requests pendentes: aguarda mensagem (unchoke/have/bitfield)
                        try:
                            msg = conn.read_message(timeout=self.peer_timeout)
                        except PeerTimeoutError:
                            # Timeout aguardando unchoke
                            break
                    else:
                        # Unchoked, mas nenhum bloco pôde ser solicitado no momento (ex: peças já em voo em outros peers)
                        consecutive_no_requests += 1
                        if consecutive_no_requests >= 50:
                            break
                        try:
                            msg = conn.read_message(timeout=min(self.peer_timeout, 0.5))
                        except PeerTimeoutError:
                            time.sleep(0.02)
                            continue
                else:
                    # Há requisições em voo: aguarda a resposta do peer
                    consecutive_no_requests = 0
                    msg = conn.read_message(timeout=self.peer_timeout)

                # 3. Processa a mensagem recebida
                if isinstance(msg, PieceMessage):
                    in_flight.pop((msg.index, msg.begin), None)

                    added, completed = self.piece_manager.add_block(
                        piece_index=msg.index,
                        begin=msg.begin,
                        data=msg.block,
                    )

                    if completed:
                        # Peça validada com sucesso via SHA-1: notifica outros peers
                        self._broadcast_have(msg.index)

                    if on_progress is not None:
                        on_progress(self.get_progress())

                    if self.piece_manager.is_complete:
                        break

                elif isinstance(msg, ChokeMessage):
                    conn.peer_choking = True
                    # Peer nos bloqueou: libera blocos em voo para outros peers
                    for (p_idx, b_begin) in list(in_flight.keys()):
                        self.piece_manager.reset_block(p_idx, b_begin)
                    in_flight.clear()

                elif isinstance(msg, UnchokeMessage):
                    conn.peer_choking = False
                    consecutive_no_requests = 0

                elif isinstance(msg, HaveMessage):
                    if conn.peer_bitfield is None:
                        conn.peer_bitfield = Bitfield(num_pieces=self.torrent_meta.num_pieces)
                        registered_bitfield = conn.peer_bitfield
                    if msg.piece_index < conn.peer_bitfield.num_pieces:
                        if not conn.peer_bitfield.has_piece(msg.piece_index):
                            conn.peer_bitfield.set_piece(msg.piece_index, True)
                            self.piece_manager.update_peer_have(msg.piece_index)
                    consecutive_no_requests = 0

                elif isinstance(msg, BitfieldMessage):
                    if registered_bitfield is not None:
                        self.piece_manager.remove_peer_bitfield(registered_bitfield)
                    conn.peer_bitfield = msg.to_bitfield(self.torrent_meta.num_pieces)
                    registered_bitfield = conn.peer_bitfield
                    self.piece_manager.add_peer_bitfield(registered_bitfield)
                    consecutive_no_requests = 0

                elif isinstance(msg, KeepAliveMessage):
                    pass

            return self.piece_manager.is_complete

        except (PeerError, TimeoutError, OSError) as e:
            logger.debug(f"Falha de comunicação com peer durante download: {e}")
            return False
        finally:
            # Libera qualquer bloco em voo atribuído a este peer
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
        Conecta a um peer, realiza o handshake e inicia o download de blocos.
        """
        if self.piece_manager.is_complete:
            return True

        conn = PeerConnection(
            host=peer.ip,
            port=peer.port,
            default_timeout=self.peer_timeout,
        )

        try:
            conn.connect()
            # Realiza handshake BitTorrent (BEP 0003)
            conn.perform_handshake(
                info_hash=self.info_hash,
                peer_id=self.peer_id,
            )

            # Executa o ciclo de requisição e download
            return self.download_from_peer_connection(
                conn,
                on_progress=on_progress,
                max_in_flight=max_in_flight,
            )

        except (PeerError, TimeoutError, OSError) as e:
            logger.debug(f"Não foi possível baixar do peer {peer.ip}:{peer.port}: {e}")
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
        Executa o fluxo completo de download concorrente do torrent a partir de múltiplos peers.

        Estratégia de Concorrência: Threading (Worker Threads por Peer)
        - Mantém múltiplas conexões simultâneas com peers;
        - Cada conexão opera em sua própria thread com socket TCP dedicado;
        - Distribuição coordenada e atômica de blocos via PieceManager (thread-safe);
        - Pipelining de requisições por peer para alta performance sem sobrecarga;
        - Isolamento estrito de falhas: desconexão de um peer re-enfileira apenas seus próprios
          blocos em voo e a thread tenta o próximo peer disponível.

        Returns:
            bytes: Dados completos e ordenados do torrent reconstruído.
        """
        self._stop_requested = False

        # Se já estiver 100% completo, retorna diretamente
        if self.piece_manager.is_complete:
            return self._finalize_download()

        # Obtém peers caso não tenham sido passados
        available_peers: List[PeerInfo] = list(peers) if peers is not None else self.discover_peers()
        if not available_peers:
            raise DownloadError("Nenhum peer disponível para realizar o download.")

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
                except Exception as e:
                    logger.debug(f"Erro em worker de peer ({peer.ip}:{peer.port}): {e}")

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
                f"Download incompleto: "
                f"{self.piece_manager.completed_pieces_count()}/{self.torrent_meta.num_pieces} peças obtidas "
                f"({self.piece_manager.bytes_downloaded()}/{self.torrent_meta.total_length} bytes)."
            )

        return self._finalize_download()

    def _finalize_download(self) -> bytes:
        """
        Reconstrói o arquivo final, grava em disco se necessário e notifica o tracker.
        """
        all_data = self.piece_manager.get_all_data()

        # Gravação em disco
        if self.output_path is not None:
            self.save_files(self.output_path)

        # Notifica tracker de conclusão
        try:
            self.tracker_client.complete(
                uploaded=0,
                downloaded=self.torrent_meta.total_length,
                timeout=self.tracker_timeout,
            )
        except Exception as e:
            logger.debug(f"Não foi possível enviar evento completed ao tracker: {e}")

        return all_data

    def save_files(self, target_destination: Union[str, Path]) -> None:
        """
        Grava os arquivos baixados respeitando a estrutura single-file ou multi-file.
        """
        all_data = self.piece_manager.get_all_data()
        dest = Path(target_destination)

        if not self.torrent_meta.is_multi_file:
            # Single-file
            target_file = dest if not dest.is_dir() else dest / self.torrent_meta.name
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(all_data)
        else:
            # Multi-file
            base_dir = dest / self.torrent_meta.name if not dest.name == self.torrent_meta.name else dest
            offset = 0
            for file_info in self.torrent_meta.files:
                file_path = base_dir.joinpath(*file_info.path)
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_data = all_data[offset : offset + file_info.length]
                file_path.write_bytes(file_data)
                offset += file_info.length

    def stop(self) -> None:
        """Sinaliza parada para todas as threads de download ativas."""
        self._stop_requested = True
        try:
            self.tracker_client.stop(
                uploaded=0,
                downloaded=self.piece_manager.bytes_downloaded(),
                left=self.piece_manager.bytes_left(),
                timeout=self.tracker_timeout,
            )
        except Exception:
            pass
