# PSE-Net Plain

A Reference Implementation and Network Transmission Protocol for the Weighted Pair-Symbol Encoding System.

Companion implementation to the paper: "PSE-Net Plain: A Reference Implementation and Network Transmission Protocol for the Weighted Pair-Symbol Encoding System" by Mohammed Khalid Almodiny.

## Overview
`pse_net_plain.py` carries the weighted pair-symbol encoding system from input bytes to output across TCP network connections.
It introduces the Within-State Ladder Rule , ensuring all encoded values remain under `0.100`.
This allows the transmission protocol to drop leading zeros and encode each 4-byte block into 12 BCD digits (48 bits).

## Key Features
- Zero External Dependencies: Uses pure Python 3.6+ standard library (`socket`, `zlib`, `struct`, `argparse`).
- Ladder Rule Logic: Keeps fractional parts below 100[cite: 7], reducing packet size by dropping 4 fixed zero digits per 4-byte block.
- **Dual Operating Modes**:
  - `bcd`: Transmits encoded system digits (1.5x data ratio).
  - `raw`: Transmits raw binary bytes while rebuilding system numbers locally at the receiver.
- **Network Protocol & Frame Integrity**: Big-endian framing with built-in CRC-32 integrity validation.

## Requirements
- Python 3.6 or later.
- No 3rd-party dependencies required.

## Quick Start & Usage

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

[ [PSE-Net Plain CI]
(https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/python-app.yml/badge.svg)](https://github.com/AlmodinyMk/data-link-pse-net/actions/workflows/python-app.yml)
[ [DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23846190.svg)](https://doi.org/10.5281/zenodo.23846190)
