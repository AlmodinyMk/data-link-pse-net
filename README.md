# PSE-Net Plain

[![CI](https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/ci.yml/badge.svg)](https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/ci.yml)
[![PSE-Net Plain CI](https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/python-app.yml/badge.svg)](https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/python-app.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23846190.svg)](https://doi.org/10.5281/zenodo.23846190)

A Reference Implementation and Network Transmission Protocol for the Weighted Pair-Symbol Encoding System.

Companion implementation to the paper: "PSE-Net Plain: A Reference Implementation and Network Transmission Protocol for the Weighted Pair-Symbol Encoding System" by Mohammed Khalid Almodiny.

## Overview

`pse_net_plain.py` carries the weighted pair-symbol encoding system from input bytes to output across TCP network connections.
It introduces the Within-State Ladder Rule, ensuring all encoded values remain under `0.100`.
This allows the transmission protocol to drop leading zeros and encode each 4-byte block into 12 BCD digits (48 bits).

The repository contains two wire-compatible implementations:

| Implementation | File | Dependencies |
|---|---|---|
| Python reference | `pse_net_plain.py` | Python 3.6+ standard library only |
| Rust (TCP / TLS, concurrent server, streaming) | `src/main.rs` | `rustls`, `rustls-pemfile` |

## Key Features

- **Zero external dependencies (Python)**: pure Python 3.6+ standard library (`socket`, `zlib`, `struct`, `argparse`).
- **Ladder rule**: keeps fractional parts below 100, reducing packet size by dropping 4 fixed zero digits per 4-byte block.
- **Dual operating modes**:
  - `bcd`: transmits encoded system digits (1.5x data ratio).
  - `raw`: transmits raw binary bytes while rebuilding system numbers locally at the receiver.
- **Network protocol and frame integrity**: big-endian framing with built-in CRC-32 integrity validation.

## Requirements

- Python 3.6 or later (Python implementation).
- Rust 1.75 or later (Rust implementation). On Windows, the MSVC build tools.

## Quick Start: Python

```bash
# 1. Run exhaustive selftest & loopback test
python3 pse_net_plain.py selftest

# 2. Encode binary file into system representation numbers
python3 pse_net_plain.py encode input.bin

# 3. Decode system representation back to original hex/bytes
python3 pse_net_plain.py decode 3468.025033036018

# 4. Start receiver node on port 5050
python3 pse_net_plain.py receive --port 5050 --out received.bin

# 5. Send file across TCP network (BCD mode)
python3 pse_net_plain.py send input.bin --host 127.0.0.1 --port 5050 --mode bcd
```

## Quick Start: Rust

```bash
cargo build --release
cargo test --release

# receiver (add --tls-cert server.pem --tls-key server.key for TLS)
./target/release/pse_net receive --port 5050 --out-dir received

# sender (add --tls-ca ca.pem --server-name HOST for TLS)
./target/release/pse_net send input.bin --host 127.0.0.1 --port 5050 --mode bcd
```

The Rust and Python implementations use the same frame format (`PSE2`) and can send to each other.

## Limitations

The encoding is a representation, not a compressor: `bcd` mode sends 1.5x the data, `raw` mode sends the data itself. Without TLS the transport is neither encrypted nor authenticated.
