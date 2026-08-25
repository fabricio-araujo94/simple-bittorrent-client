"""
Módulo para gerenciamento de peças e blocos (Piece Manager).

Responsabilidades:
- Representação estruturada de Blocos (`Block`), Peças (`Piece`) e seus estados (`BlockState`, `PieceState`);
- Divisão precisa de peças em blocos de tamanho padrão (16 KB) com ajuste automático na última peça e no último bloco;
- Armazenamento em memória de blocos recebidos fora de ordem e tratamento de blocos duplicados;
- Validação estrita de integridade de peças montadas via hash SHA-1;
- Descarte e reset automático de blocos em caso de falha de verificação de hash (peça corrompida);
- Sincronização segura para acesso concorrente por múltiplos peers (Thread-Safe com Lock/RLock);
- Rastreamento de progresso de download e geração de Bitfield local;
- Reconstrução ordenada dos dados do arquivo/torrent.
"""

import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union

from .hash_utils import verify_sha1
from .peer import DEFAULT_BLOCK_SIZE, Bitfield
from .torrent import TorrentMetadata, load_torrent_bytes, load_torrent_file


# ==============================================================================
# Estados de Blocos e Peças
# ==============================================================================

class BlockState(Enum):
    """Estado de um bloco dentro de uma peça."""
    MISSING = "missing"        # Ainda não solicitado nem recebido
    REQUESTED = "requested"    # Solicitado a um peer, aguardando resposta
    RECEIVED = "received"      # Dados recebidos e armazenados em memória


class PieceState(Enum):
    """Estado de uma peça do torrent."""
    MISSING = "missing"          # Nenhum bloco completo/verificado
    DOWNLOADING = "downloading"  # Ao menos um bloco solicitado ou recebido
    COMPLETED = "completed"      # Todos os blocos recebidos e hash SHA-1 validado


# ==============================================================================
# Representação de Bloco
# ==============================================================================

@dataclass
class Block:
    """
    Representação de um bloco individual de dados dentro de uma peça.
    """
    piece_index: int
    begin: int
    length: int
    state: BlockState = BlockState.MISSING
    data: Optional[bytes] = None

    @property
    def is_received(self) -> bool:
        """Verifica se o bloco já foi recebido."""
        return self.state == BlockState.RECEIVED and self.data is not None

    def reset(self) -> None:
        """Reseta o bloco para o estado inicial MISSING e descarta os dados."""
        self.state = BlockState.MISSING
        self.data = None


# ==============================================================================
# Representação de Peça
# ==============================================================================

class Piece:
    """
    Representação de uma peça do torrent composta por blocos de dados.

    Gerencia o ciclo de vida dos seus blocos, armazenamento em memória,
    montagem sequencial e validação de integridade por hash SHA-1.
    """

    def __init__(
        self,
        index: int,
        length: int,
        expected_hash: Union[bytes, bytearray],
        block_size: int = DEFAULT_BLOCK_SIZE,
    ):
        if index < 0:
            raise ValueError(f"Índice de peça não pode ser negativo: {index}")
        if length <= 0:
            raise ValueError(f"Tamanho da peça deve ser estritamente positivo: {length}")
        if len(expected_hash) != 20:
            raise ValueError(
                f"Hash esperado deve ter exatamente 20 bytes, obtido {len(expected_hash)} bytes."
            )
        if block_size <= 0:
            raise ValueError(f"Tamanho do bloco deve ser estritamente positivo: {block_size}")

        self.index = index
        self.length = length
        self.expected_hash = bytes(expected_hash)
        self.block_size = block_size
        self.state = PieceState.MISSING

        self._lock = threading.RLock()
        self._data: Optional[bytes] = None
        self.blocks: List[Block] = self._init_blocks()

    def _init_blocks(self) -> List[Block]:
        """Divide a peça em blocos contíguos de tamanho block_size."""
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
        """Número total de blocos nesta peça."""
        return len(self.blocks)

    def is_all_blocks_received(self) -> bool:
        """Verifica se todos os blocos foram recebidos."""
        return all(b.is_received for b in self.blocks)

    def is_completed(self) -> bool:
        """Verifica se a peça foi completamente montada e validada."""
        return self.state == PieceState.COMPLETED and self._data is not None

    def add_block(self, begin: int, data: Union[bytes, bytearray, memoryview]) -> Tuple[bool, bool]:
        """
        Adiciona os dados de um bloco recebido.

        Trata recebimento fora de ordem e descarta blocos duplicados.
        Se todos os blocos tiverem sido recebidos, executa automaticamente a validação de hash SHA-1.

        Returns:
            Tuple[bool, bool]: (bloco_adicionado_com_sucesso, peca_concluida_e_valida)
        """
        raw_data = bytes(data)

        with self._lock:
            if self.state == PieceState.COMPLETED:
                # Peça já concluída e validada anteriormente
                return False, True

            # Localiza o bloco correspondente ao offset 'begin'
            target_block: Optional[Block] = None
            for b in self.blocks:
                if b.begin == begin:
                    target_block = b
                    break

            if target_block is None:
                raise ValueError(
                    f"Offset {begin} não corresponde a nenhum bloco válido na peça {self.index} (tamanho: {self.length})."
                )

            if len(raw_data) != target_block.length:
                raise ValueError(
                    f"Tamanho do bloco recebido ({len(raw_data)} bytes) diverge do esperado "
                    f"({target_block.length} bytes) no offset {begin} da peça {self.index}."
                )

            # Se o bloco já foi recebido anteriormente (duplicado)
            if target_block.is_received:
                return False, self.state == PieceState.COMPLETED

            # Armazena os dados do bloco
            target_block.data = raw_data
            target_block.state = BlockState.RECEIVED

            # Verifica se todos os blocos foram completados
            if self.is_all_blocks_received():
                # Monta os dados completos da peça em ordem
                assembled = self._assemble_blocks()
                if verify_sha1(assembled, self.expected_hash):
                    self._data = assembled
                    self.state = PieceState.COMPLETED
                    return True, True
                else:
                    # Falha na validação do hash (dados corrompidos)
                    self.reset()
                    return True, False
            else:
                self.state = PieceState.DOWNLOADING
                return True, False

    def _assemble_blocks(self) -> bytes:
        """Concatena todos os blocos recebidos na ordem de seus offsets."""
        sorted_blocks = sorted(self.blocks, key=lambda b: b.begin)
        return b"".join(b.data for b in sorted_blocks if b.data is not None)

    def validate(self) -> bool:
        """
        Valida a integridade da peça completa contra o hash SHA-1 esperado.
        Se o hash for válido, marca como COMPLETED. Se inválido, reseta todos os blocos.
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
        """Retorna os bytes validados da peça, ou None se incompleta."""
        with self._lock:
            return self._data

    def get_next_missing_block(self, mark_requested: bool = True) -> Optional[Block]:
        """
        Retorna o próximo bloco pendente (MISSING).
        Opcionalmente marca o bloco como REQUESTED.
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

    def reset_pending_blocks(self) -> None:
        """Reseta blocos marcados como REQUESTED de volta para MISSING."""
        with self._lock:
            if self.state == PieceState.COMPLETED:
                return
            has_received = False
            for b in self.blocks:
                if b.state == BlockState.REQUESTED:
                    b.state = BlockState.MISSING
                elif b.state == BlockState.RECEIVED:
                    has_received = True

            self.state = PieceState.DOWNLOADING if has_received else PieceState.MISSING

    def reset(self) -> None:
        """Reseta completamente a peça e todos os seus blocos para MISSING."""
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
    Gerenciador central do estado das peças e blocos de um torrent.

    Responsável por:
    - Inicializar todas as peças a partir de `TorrentMetadata` (ou parâmetros equivalentes);
    - Calcular tamanhos exatos de peças e blocos, incluindo a última peça;
    - Acompanhar peças pendentes, em download e completadas;
    - Oferecer seleção segura de blocos para download com múltiplos peers concorrentes;
    - Receber blocos de peers, tratar duplicatas e fora de ordem;
    - Validar hashes SHA-1 ao completar cada peça;
    - Manter sincronização segura para concorrência multi-thread (Thread-Safe);
    - Reconstruir ordenadamente os dados completos do arquivo/torrent.
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
            if isinstance(torrent, TorrentMetadata):
                resolved_meta = torrent
            elif isinstance(torrent, (str, Path)):
                resolved_meta = load_torrent_file(torrent)
            elif isinstance(torrent, (bytes, bytearray, memoryview)):
                resolved_meta = load_torrent_bytes(torrent)
            else:
                raise TypeError(f"Tipo inválido para torrent: {type(torrent).__name__}.")

        if resolved_meta is not None:
            self.total_length = resolved_meta.total_length
            self.piece_length = resolved_meta.piece_length
            hashes_list = resolved_meta.piece_hashes
        else:
            if total_length is None or piece_length is None or piece_hashes is None:
                raise ValueError(
                    "É necessário fornecer 'torrent' ou os parâmetros 'total_length', 'piece_length' e 'piece_hashes'."
                )
            self.total_length = total_length
            self.piece_length = piece_length
            hashes_list = [bytes(h) for h in piece_hashes]

        if self.total_length < 0:
            raise ValueError(f"total_length não pode ser negativo: {self.total_length}")
        if self.piece_length <= 0:
            raise ValueError(f"piece_length deve ser positivo: {self.piece_length}")

        self.num_pieces = len(hashes_list)
        self.bitfield = Bitfield(num_pieces=self.num_pieces)
        self.pieces: List[Piece] = self._init_pieces(hashes_list)

    def _init_pieces(self, piece_hashes: Sequence[Union[bytes, bytearray]]) -> List[Piece]:
        """Inicializa todas as instâncias de Piece calculando o tamanho exato de cada uma."""
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
        Retorna o tamanho em bytes da peça no índice informado.
        Trata o tamanho da última peça adequadamente.
        """
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Índice de peça fora do intervalo: {piece_index} (total: {self.num_pieces})"
            )

        if piece_index == self.num_pieces - 1:
            remainder = self.total_length % self.piece_length
            return remainder if remainder != 0 else self.piece_length
        return self.piece_length

    def get_piece(self, piece_index: int) -> Piece:
        """Retorna a instância de Piece para o índice informado."""
        if not (0 <= piece_index < self.num_pieces):
            raise IndexError(
                f"Índice de peça fora do intervalo: {piece_index} (total: {self.num_pieces})"
            )
        return self.pieces[piece_index]

    def is_piece_complete(self, piece_index: int) -> bool:
        """Verifica se uma peça específica está completa e validada."""
        with self._lock:
            return self.get_piece(piece_index).is_completed()

    @property
    def is_complete(self) -> bool:
        """Indica se todas as peças do torrent foram baixadas e validadas."""
        with self._lock:
            return self.completed_pieces_count() == self.num_pieces

    def completed_pieces_count(self) -> int:
        """Retorna o número de peças concluídas e validadas."""
        with self._lock:
            return sum(1 for p in self.pieces if p.is_completed())

    def downloading_pieces_count(self) -> int:
        """Retorna o número de peças atualmente em download."""
        with self._lock:
            return sum(1 for p in self.pieces if p.state == PieceState.DOWNLOADING)

    def missing_pieces_count(self) -> int:
        """Retorna o número de peças ainda não iniciadas (MISSING)."""
        with self._lock:
            return sum(1 for p in self.pieces if p.state == PieceState.MISSING)

    def bytes_downloaded(self) -> int:
        """Retorna o total de bytes baixados e validados com sucesso."""
        with self._lock:
            return sum(p.length for p in self.pieces if p.is_completed())

    def bytes_left(self) -> int:
        """Retorna o total de bytes restantes para concluir o torrent."""
        with self._lock:
            return max(0, self.total_length - self.bytes_downloaded())

    @property
    def progress(self) -> float:
        """Retorna a fração de progresso do download (entre 0.0 e 1.0)."""
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
        Recebe e processa um bloco de dados para a peça especificada.

        Sincroniza o bitfield local caso a peça seja concluída com sucesso.

        Returns:
            Tuple[bool, bool]: (bloco_adicionado, peca_concluida_e_valida)
        """
        with self._lock:
            piece = self.get_piece(piece_index)
            added, completed = piece.add_block(begin, data)

            if completed:
                self.bitfield.set_piece(piece_index, True)

            return added, completed

    def get_next_block_to_request(
        self,
        peer_bitfield: Optional[Bitfield] = None,
    ) -> Optional[Tuple[int, int, int]]:
        """
        Seleciona thread-safe o próximo bloco a ser requisitado a um peer.

        Estratégia:
        1. Prioriza peças que já estão em andamento (`DOWNLOADING`) para completá-las o mais rápido possível;
        2. Em seguida, seleciona peças pendentes (`MISSING`) que o peer possua em seu bitfield.

        Returns:
            Optional[Tuple[int, int, int]]: (piece_index, begin, length) ou None se não houver blocos disponíveis.
        """
        with self._lock:
            # 1. Tenta encontrar blocos faltantes em peças já em progresso
            for piece in self.pieces:
                if piece.state == PieceState.DOWNLOADING:
                    if peer_bitfield is not None and not peer_bitfield.has_piece(piece.index):
                        continue
                    block = piece.get_next_missing_block(mark_requested=True)
                    if block is not None:
                        return piece.index, block.begin, block.length

            # 2. Tenta encontrar blocos em peças ainda não iniciadas (MISSING)
            for piece in self.pieces:
                if piece.state == PieceState.MISSING:
                    if peer_bitfield is not None and not peer_bitfield.has_piece(piece.index):
                        continue
                    block = piece.get_next_missing_block(mark_requested=True)
                    if block is not None:
                        return piece.index, block.begin, block.length

            return None

    def reset_pending_requests(self, piece_index: Optional[int] = None) -> None:
        """
        Reseta blocos marcados como REQUESTED de volta para MISSING.
        Útil quando um peer desconecta antes de entregar os blocos solicitados.
        """
        with self._lock:
            if piece_index is not None:
                self.get_piece(piece_index).reset_pending_blocks()
            else:
                for piece in self.pieces:
                    piece.reset_pending_blocks()

    def get_piece_data(self, piece_index: int) -> Optional[bytes]:
        """Retorna os dados validados de uma peça individual."""
        with self._lock:
            return self.get_piece(piece_index).get_data()

    def get_all_data(self) -> bytes:
        """
        Reconstrói e retorna todos os dados ordenados do torrent em bytes.

        Raises:
            ValueError: Se o download ainda não estiver 100% concluído.
        """
        with self._lock:
            if not self.is_complete:
                raise ValueError(
                    f"Não é possível reconstruir os dados: download incompleto "
                    f"({self.completed_pieces_count()}/{self.num_pieces} peças baixadas)."
                )

            return b"".join(p.get_data() for p in self.pieces)  # type: ignore

    def save_to_file(self, target_path: Union[str, Path]) -> None:
        """
        Grava os dados reconstruídos do torrent em um arquivo no disco.
        """
        data = self.get_all_data()
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
