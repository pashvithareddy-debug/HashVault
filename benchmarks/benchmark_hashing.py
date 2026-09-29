"""Benchmark hashing throughput and peak Python memory per algorithm.

Usage: python benchmarks/benchmark_hashing.py [--size-mb 100] [--chunk-size 1MB] [--repeat 3]
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hashvault.algorithms import available_algorithms  # noqa: E402
from hashvault.core.hasher import hash_file, parse_size  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size-mb", type=int, default=100)
    ap.add_argument("--chunk-size", default="1MB")
    ap.add_argument("--repeat", type=int, default=3, help="runs per algorithm; best time is reported")
    args = ap.parse_args()
    chunk = parse_size(args.chunk_size)

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "bench.bin"
        block = os.urandom(1024 * 1024)
        with open(path, "wb") as f:
            for _ in range(args.size_mb):
                f.write(block)

        print(f"File: {args.size_mb} MB random data | chunk: {args.chunk_size} | best of {args.repeat}")
        print(f"{'Algorithm':<12}{'Time (s)':>10}{'MB/s':>10}{'Peak mem (KiB)':>17}")
        for alg in available_algorithms():
            best = min(_time(path, alg.name, chunk) for _ in range(args.repeat))
            tracemalloc.start()
            hash_file(path, alg.name, chunk)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            print(f"{alg.name:<12}{best:>10.3f}{args.size_mb / best:>10.0f}{peak / 1024:>17.0f}")


def _time(path: Path, algorithm: str, chunk: int) -> float:
    start = time.perf_counter()
    hash_file(path, algorithm, chunk)
    return time.perf_counter() - start


if __name__ == "__main__":
    main()
