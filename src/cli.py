"""
Interface de Linha de Comando (CLI) para o Cliente BitTorrent Educacional em Python.

Permite inspecionar metadados de arquivos .torrent e realizar o download
completo via linha de comando com barra de progresso e estatísticas em tempo real.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from .client import DownloadError, DownloadProgress, TorrentClient
from .torrent import TorrentError, load_torrent_file


def format_bytes(size: int) -> str:
    """Formata bytes em unidades legíveis (B, KB, MB, GB)."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def print_torrent_info(torrent_path: Path) -> None:
    """Exibe informações detalhadas dos metadados de um arquivo .torrent."""
    try:
        meta = load_torrent_file(torrent_path)
    except Exception as e:
        print(f"\n[ERRO] Falha ao ler metadados do arquivo .torrent: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 60)
    print(" METADADOS DO TORRENT")
    print("=" * 60)
    print(f" Nome:               {meta.name}")
    print(f" Info Hash (Hex):    {meta.info_hash_hex}")
    print(f" Tamanho Total:      {format_bytes(meta.total_length)} ({meta.total_length:,} bytes)")
    print(f" Tamanho da Peça:    {format_bytes(meta.piece_length)} ({meta.piece_length:,} bytes)")
    print(f" Total de Peças:     {meta.num_pieces}")
    print(f" Tipo:               {'Multi-file' if meta.is_multi_file else 'Single-file'}")
    print(f" Tracker Principal:  {meta.announce or 'Nenhum'}")

    if meta.trackers:
        print(f" Lista de Trackers:  ({len(meta.trackers)} encontrados)")
        for tr in meta.trackers:
            print(f"   - {tr}")

    if meta.is_multi_file:
        print(f" Arquivos Contidos:  ({len(meta.files)} arquivos)")
        for f in meta.files[:10]:
            print(f"   - {f.full_path} ({format_bytes(f.length)})")
        if len(meta.files) > 10:
            print(f"   ... e mais {len(meta.files) - 10} arquivos.")
    print("=" * 60 + "\n")


def build_progress_bar(progress: DownloadProgress, start_time: float) -> str:
    """Gera uma barra de progresso visual para o terminal."""
    bar_width = 30
    filled = int(bar_width * (progress.progress_percentage / 100.0))
    bar = "█" * filled + "░" * (bar_width - filled)

    elapsed = max(0.001, time.time() - start_time)
    speed = progress.bytes_downloaded / elapsed
    speed_str = f"{format_bytes(int(speed))}/s"

    return (
        f"\r[{bar}] {progress.progress_percentage:5.1f}% | "
        f"{format_bytes(progress.bytes_downloaded)} / {format_bytes(progress.total_length)} | "
        f"Peças: {progress.completed_pieces}/{progress.total_pieces} | "
        f"Velocidade: {speed_str}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cliente BitTorrent Educacional em Python Puro (BEP 0003, BEP 0023)."
    )
    parser.add_argument(
        "torrent",
        type=Path,
        help="Caminho para o arquivo .torrent",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Diretório ou caminho de destino para salvar o arquivo baixado (padrão: diretório atual)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Número de threads simultâneas para download de peers (padrão: 4)",
    )
    parser.add_argument(
        "-f",
        "--max-in-flight",
        type=int,
        default=4,
        help="Número máximo de requisições de blocos (16 KB) em voo por peer (padrão: 4)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout de socket em segundos para comunicação com peers (padrão: 10.0s)",
    )
    parser.add_argument(
        "--tracker-timeout",
        type=float,
        default=15.0,
        help="Timeout em segundos para consulta ao HTTP Tracker (padrão: 15.0s)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=6881,
        help="Porta TCP anunciada ao tracker (padrão: 6881)",
    )
    parser.add_argument(
        "--auto-resume",
        action="store_true",
        help="Verifica arquivos parciais já existentes no destino para retomar o download",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Apenas exibe os metadados do torrent sem iniciar o download",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Habilita logs detalhados de depuração",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
        )

    if not args.torrent.exists():
        print(f"[ERRO] Arquivo torrent não encontrado: {args.torrent}", file=sys.stderr)
        sys.exit(1)

    if args.info:
        print_torrent_info(args.torrent)
        sys.exit(0)

    print_torrent_info(args.torrent)

    output_dir = args.output if args.output is not None else Path.cwd()

    print(f"[*] Destino de gravação: {output_dir.resolve()}")
    print(f"[*] Conexões concorrentes (workers): {args.workers}")
    print(f"[*] Pipelining por peer (in-flight): {args.max_in_flight} blocos de 16 KB")
    print("[*] Conectando ao tracker e descobrindo peers...")

    client = TorrentClient(
        torrent=args.torrent,
        output_path=output_dir,
        port=args.port,
        max_in_flight=args.max_in_flight,
        peer_timeout=args.timeout,
        tracker_timeout=args.tracker_timeout,
        auto_resume=args.auto_resume,
    )

    start_time = time.time()

    def on_progress(p: DownloadProgress) -> None:
        sys.stdout.write(build_progress_bar(p, start_time))
        sys.stdout.flush()

    try:
        data = client.download(
            max_workers=args.workers,
            max_in_flight=args.max_in_flight,
            on_progress=on_progress,
        )
        print("\n\n" + "=" * 60)
        print(" [✓] DOWNLOAD CONCLUÍDO COM SUCESSO!")
        print(f"     Tempo Total: {time.time() - start_time:.2f} segundos")
        print(f"     Total Baixado: {format_bytes(len(data))}")
        print(f"     Arquivo salvo em: {output_dir.resolve()}")
        print("=" * 60)
    except KeyboardInterrupt:
        print("\n\n[!] Download interrompido pelo usuário. Finalizando...")
        client.stop()
        sys.exit(130)
    except DownloadError as e:
        print(f"\n\n[ERRO] Falha durante o download: {e}", file=sys.stderr)
        client.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
