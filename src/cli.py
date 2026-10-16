"""
Command Line Interface (CLI) for the Educational BitTorrent Client in Python.

Allows inspecting .torrent file metadata and performing full downloads
via command line with a progress bar and real-time statistics.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from .client import DownloadError, DownloadProgress, TorrentClient
from .torrent import TorrentError, load_torrent_file


def format_bytes(size: int) -> str:
    """Format bytes into human-readable units (B, KB, MB, GB)."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def print_torrent_info(torrent_path: Path) -> None:
    """Display detailed metadata information for a .torrent file."""
    try:
        meta = load_torrent_file(torrent_path)
    except Exception as e:
        print(f"\n[ERROR] Failed to read .torrent file metadata: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 60)
    print(" TORRENT METADATA")
    print("=" * 60)
    print(f" Name:               {meta.name}")
    print(f" Info Hash (Hex):    {meta.info_hash_hex}")
    print(f" Total Size:         {format_bytes(meta.total_length)} ({meta.total_length:,} bytes)")
    print(f" Piece Size:         {format_bytes(meta.piece_length)} ({meta.piece_length:,} bytes)")
    print(f" Total Pieces:       {meta.num_pieces}")
    print(f" Type:               {'Multi-file' if meta.is_multi_file else 'Single-file'}")
    print(f" Main Tracker:       {meta.announce or 'None'}")

    if meta.trackers:
        print(f" Tracker List:       ({len(meta.trackers)} found)")
        for tr in meta.trackers:
            print(f"   - {tr}")

    if meta.is_multi_file:
        print(f" Contained Files:    ({len(meta.files)} files)")
        for f in meta.files[:10]:
            print(f"   - {f.full_path} ({format_bytes(f.length)})")
        if len(meta.files) > 10:
            print(f"   ... and {len(meta.files) - 10} more files.")
    print("=" * 60 + "\n")


def build_progress_bar(progress: DownloadProgress, start_time: float) -> str:
    """Generate a visual progress bar for the terminal."""
    bar_width = 30
    filled = int(bar_width * (progress.progress_percentage / 100.0))
    bar = "█" * filled + "░" * (bar_width - filled)

    elapsed = max(0.001, time.time() - start_time)
    speed = progress.bytes_downloaded / elapsed
    speed_str = f"{format_bytes(int(speed))}/s"

    return (
        f"\r[{bar}] {progress.progress_percentage:5.1f}% | "
        f"{format_bytes(progress.bytes_downloaded)} / {format_bytes(progress.total_length)} | "
        f"Pieces: {progress.completed_pieces}/{progress.total_pieces} | "
        f"Speed: {speed_str}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Educational BitTorrent Client in Pure Python (BEP 0003, BEP 0023)."
    )
    parser.add_argument(
        "torrent",
        type=Path,
        help="Path to .torrent file",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Target directory or path to save downloaded file (default: current directory)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent threads for peer downloads (default: 4)",
    )
    parser.add_argument(
        "-f",
        "--max-in-flight",
        type=int,
        default=4,
        help="Maximum number of in-flight block requests (16 KB) per peer (default: 4)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds for peer communication (default: 10.0s)",
    )
    parser.add_argument(
        "--tracker-timeout",
        type=float,
        default=15.0,
        help="Timeout in seconds for HTTP Tracker queries (default: 15.0s)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=6881,
        help="TCP port announced to tracker (default: 6881)",
    )
    parser.add_argument(
        "--auto-resume",
        action="store_true",
        help="Check existing partial files in destination to resume download",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Only display torrent metadata without starting download",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logs",
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
        print(f"[ERROR] Torrent file not found: {args.torrent}", file=sys.stderr)
        sys.exit(1)

    if args.info:
        print_torrent_info(args.torrent)
        sys.exit(0)

    print_torrent_info(args.torrent)

    output_dir = args.output if args.output is not None else Path.cwd()

    print(f"[*] Download destination: {output_dir.resolve()}")
    print(f"[*] Concurrent connections (workers): {args.workers}")
    print(f"[*] Pipelining per peer (in-flight): {args.max_in_flight} blocks of 16 KB")
    print("[*] Connecting to tracker and discovering peers...")

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
        print(" [✓] DOWNLOAD COMPLETED SUCCESSFULLY!")
        print(f"     Total Time: {time.time() - start_time:.2f} seconds")
        print(f"     Total Downloaded: {format_bytes(len(data))}")
        print(f"     File saved to: {output_dir.resolve()}")
        print("=" * 60)
    except KeyboardInterrupt:
        print("\n\n[!] Download interrupted by user. Shutting down...")
        client.stop()
        sys.exit(130)
    except DownloadError as e:
        print(f"\n\n[ERROR] Download failed: {e}", file=sys.stderr)
        client.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
