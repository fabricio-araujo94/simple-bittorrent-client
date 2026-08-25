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
12. Reconstrução ordenada e gravação do arquivo final (single-file ou multi-file).
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Union

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
    Cliente BitTorrent unificado para download de torrents.
    """

    def __init__(
        self,
        torrent: Union[TorrentMetadata, bytes, bytearray, memoryview, str, Path],
        *,
        output_path: Optional[Union[str, Path]] = None,
        peer_id: Optional[Union[bytes, str]] = None,
        port: int = 6881,
        block_size: int = DEFAULT_BLOCK_SIZE,
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

        # Controle de concorrência e parada
        self._stop_requested = False
        self._lock = threading.RLock()

    @property
    def is_complete(self) -> bool:
        """Verifica se todas as peças do torrent foram baixadas e validadas."""
        return self.piece_manager.is_complete

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
    ) -> bool:
        """
        Executa o ciclo de download com uma conexão de peer já estabelecida e com handshake realizado.

        Etapas:
        1. Processa mensagens iniciais do peer (Bitfield/Have);
        2. Envia 'Interested' se o peer tiver peças necessárias;
        3. Aguarda 'Unchoke';
        4. Requisita blocos sequencialmente e armazena respostas 'Piece';
        5. Valida hashes SHA-1 e atualiza o PieceManager.

        Returns:
            bool: True se o download do torrent foi concluído ou progrediu, False se desconectou/falhou.
        """
        try:
            # 1. Envia 'Interested'
            conn.send_interested()

            consecutive_no_requests = 0
            iteration = 0

            while not self.piece_manager.is_complete and not self._stop_requested:
                iteration += 1
                if iteration > max_blocks_per_iteration and max_blocks_per_iteration > 0:
                    break

                # Se estiver bloqueado (choked), aguarda desbloqueio
                if conn.peer_choking:
                    try:
                        msg = conn.read_message(timeout=self.peer_timeout)
                        if isinstance(msg, UnchokeMessage):
                            conn.peer_choking = False
                        elif isinstance(msg, HaveMessage):
                            if conn.peer_bitfield is not None and msg.piece_index < conn.peer_bitfield.num_pieces:
                                conn.peer_bitfield.set_piece(msg.piece_index, True)
                        elif isinstance(msg, BitfieldMessage):
                            conn.peer_bitfield = msg.to_bitfield(self.torrent_meta.num_pieces)
                        continue
                    except PeerTimeoutError:
                        # Timeout aguardando unchoke
                        break

                # 2. Seleciona o próximo bloco a solicitar
                req = self.piece_manager.get_next_block_to_request(peer_bitfield=conn.peer_bitfield)
                if req is None:
                    # Nenhum bloco pendente que este peer possua no momento
                    consecutive_no_requests += 1
                    if consecutive_no_requests >= 3:
                        break
                    time.sleep(0.01)
                    continue

                consecutive_no_requests = 0
                piece_idx, begin, length = req

                # 3. Envia mensagem Request
                conn.send_request(index=piece_idx, begin=begin, length=length)

                # 4. Lê mensagens do peer até receber a resposta da Piece
                block_received = False
                while not block_received:
                    msg = conn.read_message(timeout=self.peer_timeout)

                    if isinstance(msg, PieceMessage):
                        if msg.index == piece_idx and msg.begin == begin:
                            # 5. Adiciona o bloco e valida integridade no PieceManager
                            added, completed = self.piece_manager.add_block(
                                piece_index=msg.index,
                                begin=msg.begin,
                                data=msg.block,
                            )
                            block_received = True

                            if completed:
                                # Peça validada com sucesso via SHA-1!
                                try:
                                    conn.send_have(msg.index)
                                except Exception:
                                    pass

                            if on_progress is not None:
                                on_progress(self.get_progress())

                        else:
                            # Bloco recebido para outro offset ou peça
                            self.piece_manager.add_block(msg.index, msg.begin, msg.block)

                    elif isinstance(msg, ChokeMessage):
                        # Peer nos bloqueou novamente
                        conn.peer_choking = True
                        self.piece_manager.reset_pending_requests(piece_index=piece_idx)
                        break

                    elif isinstance(msg, HaveMessage):
                        if conn.peer_bitfield is not None and msg.piece_index < conn.peer_bitfield.num_pieces:
                            conn.peer_bitfield.set_piece(msg.piece_index, True)

                    elif isinstance(msg, BitfieldMessage):
                        conn.peer_bitfield = msg.to_bitfield(self.torrent_meta.num_pieces)

                    elif isinstance(msg, KeepAliveMessage):
                        pass

            return self.piece_manager.is_complete

        except (PeerError, TimeoutError, OSError) as e:
            logger.debug(f"Falha de comunicação com peer durante download: {e}")
            self.piece_manager.reset_pending_requests()
            return False

    def download_from_peer(
        self,
        peer: PeerInfo,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
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
            return self.download_from_peer_connection(conn, on_progress=on_progress)

        except (PeerError, TimeoutError, OSError) as e:
            logger.debug(f"Não foi possível baixar do peer {peer.ip}:{peer.port}: {e}")
            return False
        finally:
            conn.close()

    def download(
        self,
        peers: Optional[Sequence[PeerInfo]] = None,
        max_workers: int = 4,
        on_progress: Optional[Callable[[DownloadProgress], None]] = None,
    ) -> bytes:
        """
        Executa o fluxo completo de download do torrent.

        1. Obtém a lista de peers (do tracker ou fornecida);
        2. Conecta e baixa blocos dos peers até atingir 100%;
        3. Valida a integridade total do arquivo;
        4. Grava em disco se `output_path` tiver sido configurado;
        5. Notifica o tracker sobre a conclusão (`completed`).

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

        # Tenta baixar utilizando os peers disponíveis
        if max_workers <= 1 or len(available_peers) == 1:
            for peer in available_peers:
                if self.piece_manager.is_complete or self._stop_requested:
                    break
                self.download_from_peer(peer, on_progress=on_progress)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(available_peers))) as executor:
                futures = [
                    executor.submit(self.download_from_peer, peer, on_progress)
                    for peer in available_peers
                ]
                for fut in futures:
                    try:
                        fut.result()
                    except Exception as e:
                        logger.debug(f"Erro em thread de peer: {e}")

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
