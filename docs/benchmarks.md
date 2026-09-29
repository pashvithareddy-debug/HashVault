# Benchmarks

Measured with `python benchmarks/benchmark_hashing.py --size-mb 200 --repeat 3` (best of 3, 1 MiB chunks,
200 MB of random data, warm page cache, so this measures hashing throughput rather than disk speed).

**Environment:** Linux x86_64 VM, 1 vCPU Intel Xeon @ 2.10 GHz, CPython 3.12.3.
Absolute numbers depend on your CPU and OpenSSL build; the *relative* ordering is the useful part.
Run the script on your own machine to get your numbers.

| Algorithm | Time (s) | Throughput (MB/s) | Peak Python memory |
|---|---:|---:|---:|
| sha256 | 0.184 | 1089 | ~1 MiB |
| sha512 | 0.386 | 519 | ~1 MiB |
| sha3-256 | 0.541 | 370 | ~1 MiB |
| sha3-512 | 1.018 | 196 | ~1 MiB |
| blake2b | 0.370 | 540 | ~1 MiB |
| blake2s | 0.575 | 348 | ~1 MiB |
| sha1 (legacy) | 0.163 | 1226 | ~1 MiB |
| md5 (legacy) | 0.384 | 521 | ~1 MiB |

Takeaways
- Memory is flat (~1 chunk) no matter the file size: a test hashes a 64 MiB file with under 4 MiB peak
  and another crosses the 2 GiB boundary.
- SHA-256 is fastest among the recommended algorithms here, likely thanks to hardware SHA extensions
  in this CPU/OpenSSL build. SHA-512 and BLAKE2b are close to each other; SHA3 is slowest in software.
- Peak memory is measured with `tracemalloc`, so it covers Python allocations, not the interpreter baseline.
