#!/usr/bin/env python3
"""
License : Creative Commons Attribution Non Commercial No Derivatives 4.0 International.
pse_net_plain.py — Weighted Pair-Symbol Encoding (no encryption): input -> encoding -> network -> decoding -> output

Pipeline
    bytes (8 bits)  ->  two 4-bit groups -> four 2-bit pairs (weights 00:2 01:3 10:5 11:13)
                    ->  value X.0YY  (X = relational state 0-9, YY = sum, ladder for repeats)
    4 bytes         ->  number  X4 X3 X2 X1 . 0YY1 0YY2 0YY3 0YY4
    transmission    ->  the fixed zeros are dropped: 12 BCD digits per 4 bytes (48 bits)
    frame           ->  header (magic, mode, length, checksum-16) + payload

Modes
    bcd  : sends the system's digits (12 bits per byte)       -- the paper's representation
    raw  : sends the original pairs (8 bits per byte)         -- smallest possible transmission;
           the receiver still rebuilds the X.0YY numbers locally for analysis/verification

Commands
    python3 pse_net_plain.py encode  <file>                     print the numbers for a file
    python3 pse_net_plain.py decode  <num> [<num> ...]          numbers -> bytes (hex)
    python3 pse_net_plain.py receive --port 5050 --out recv.bin [--once]
    python3 pse_net_plain.py send    --host 127.0.0.1 --port 5050 <file> [--mode bcd|raw]
    python3 pse_net_plain.py selftest                            table, codec and network loopback tests

Integrity: CRC-32 (zlib), which also detects swapped bytes.
No encryption: use pse_net_secure.py for AES-256-GCM.

Only the Python standard library is used.
"""
import argparse
import os
import socket
import struct
import sys
import threading
import zlib
from collections import defaultdict

# =================================================================== rules
WEIGHTS = {"00": 2, "01": 3, "10": 5, "11": 13}            # R2
GROUPS = [f"{i:04b}" for i in range(16)]
STATE_VALUE = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 0}


def gsum(g):                     # R4
    return WEIGHTS[g[:2]] + WEIGHTS[g[2:]]


def glarger(g):                  # R3: 1 = starts larger, 0 = starts smaller or equal
    return 1 if WEIGHTS[g[:2]] > WEIGHTS[g[2:]] else 0


def first_smaller(g1, g2):       # R5
    s1, s2 = gsum(g1), gsum(g2)
    return s1 < s2 if s1 != s2 else glarger(g1) < glarger(g2)


def state(g1, g2):               # R6: ten relational states
    f1, f2 = glarger(g1), glarger(g2)
    if g1 == g2:
        return 9 if f1 else 10
    base = {(0, 0): 1, (1, 0): 3, (0, 1): 5, (1, 1): 7}[(f1, f2)]
    return base if first_smaller(g1, g2) else base + 1


def build_table():
    """Return (enc, dec): byte (0-255) <-> value in units of 0.001.

    Repetitions are resolved with the ladder rule inside each state:
    the first cell of a repeated sum keeps it (smallest smaller-group sum first),
    the others move one step (0.001) at a time above the largest sum of that state.
    All values stay below X.100, so the first digit of every 3-digit section is 0.
    """
    by_state = defaultdict(lambda: defaultdict(list))
    for g1 in GROUPS:
        for g2 in GROUPS:
            x = STATE_VALUE[state(g1, g2)]
            s = gsum(g1) + gsum(g2)
            by_state[x][s].append((min(gsum(g1), gsum(g2)), g1 + g2))
    enc = {}
    for x, sums in by_state.items():
        used = set(sums)
        nxt = max(used)
        for s in sorted(sums):
            cells = sorted(sums[s])
            enc[int(cells[0][1], 2)] = x * 1000 + s
            for _, bits in cells[1:]:
                nxt += 1
                while nxt in used:
                    nxt += 1
                used.add(nxt)
                enc[int(bits, 2)] = x * 1000 + nxt
    dec = {v: b for b, v in enc.items()}
    assert len(enc) == 256 and len(dec) == 256, "table is not one-to-one"
    assert all(v % 1000 < 100 for v in enc.values()), "section would need its first digit"
    return enc, dec


ENC, DEC = build_table()

# ========================================================== codec (numbers)
def encode_block(b4):
    """4 bytes -> 'X4X3X2X1.0YY0YY0YY0YY'"""
    v = [ENC[b] for b in b4]
    return "".join(str(x // 1000) for x in reversed(v)) + "." + "".join(f"{x % 1000:03d}" for x in v)


def decode_block(num):
    ip, fp = num.strip().split(".")
    if len(ip) != 4 or len(fp) != 12 or not (ip + fp).isdigit():
        raise ValueError(f"bad number: {num!r}")
    out = []
    for i in range(4):
        v = int(ip[3 - i]) * 1000 + int(fp[3 * i:3 * i + 3])
        if v not in DEC:
            raise ValueError(f"{v / 1000:.3f} is not a value of this system")
        out.append(DEC[v])
    return bytes(out)


def to_numbers(data):
    pad = (-len(data)) % 4
    data = data + b"\x00" * pad
    return [encode_block(data[i:i + 4]) for i in range(0, len(data), 4)], pad


# ============================================= transmission (BCD, no zeros)
def numbers_to_digits(nums):
    """drop the fixed zeros: X4X3X2X1 + YY1..YY4 -> 12 digits per number"""
    out = []
    for n in nums:
        ip, fp = n.split(".")
        out.append(ip + "".join(fp[3 * i + 1:3 * i + 3] for i in range(4)))
    return "".join(out)


def digits_to_numbers(d):
    if len(d) % 12:
        raise ValueError("digit stream is not a multiple of 12")
    nums = []
    for k in range(0, len(d), 12):
        blk = d[k:k + 12]
        nums.append(blk[:4] + "." + "".join("0" + blk[4 + 2 * i:6 + 2 * i] for i in range(4)))
    return nums


def bcd_pack(d):
    if len(d) % 2:
        d += "F"                              # unused nibble as padding
    return bytes(int(d[i], 16) << 4 | int(d[i + 1], 16) for i in range(0, len(d), 2))


def bcd_unpack(b, ndigits):
    s = "".join(f"{x:02X}" for x in b)[:ndigits]
    if s and not s.isdigit():
        raise ValueError("invalid BCD digit in payload")
    return s


# ====================================================================== frame
MAGIC = b"PSE2"
MODE_BCD, MODE_RAW = 1, 2
FLAG_ENC = 0x01
HDR = struct.Struct(">4sBBIII")            # magic, mode, flags, original length, body length, crc32


def make_frame(data, mode="bcd"):
    if mode == "raw":
        payload, m = data, MODE_RAW
    else:
        nums, _ = to_numbers(data)
        payload, m = bcd_pack(numbers_to_digits(nums)), MODE_BCD
    crc = zlib.crc32(data) & 0xFFFFFFFF
    hdr = HDR.pack(MAGIC, m, 0, len(data), len(payload), crc)
    body = payload
    return hdr + body


def parse_frame(frame):
    if len(frame) < HDR.size:
        raise ValueError("frame too short")
    magic, mode, flags, n, blen, crc = HDR.unpack_from(frame)
    if magic != MAGIC:
        raise ValueError("not a PSE frame")
    hdr, body = frame[:HDR.size], frame[HDR.size:HDR.size + blen]
    if len(body) != blen:
        raise ValueError("truncated frame")
    if flags & FLAG_ENC:
        raise ValueError("frame is encrypted: use pse_net_secure.py")
    payload = body
    if mode == MODE_RAW:
        data = payload
        nums, _ = to_numbers(data)             # receiver rebuilds the system's numbers
    elif mode == MODE_BCD:
        blocks = (n + 3) // 4
        nums = digits_to_numbers(bcd_unpack(payload, blocks * 12))
        data = b"".join(decode_block(x) for x in nums)[:n]
    else:
        raise ValueError(f"unknown mode {mode}")
    if zlib.crc32(data) & 0xFFFFFFFF != crc:
        raise ValueError("CRC-32 mismatch: data corrupted in transit")
    return data, nums


# ==================================================================== network
def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed early")
        buf += chunk
    return bytes(buf)


def send_data(host, port, data, mode="bcd"):
    frame = make_frame(data, mode)
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(struct.pack(">I", len(frame)) + frame)
        ack = recv_exact(s, 2)
    return len(frame), ack == b"OK"


def handle(conn):
    size = struct.unpack(">I", recv_exact(conn, 4))[0]
    if size > 2 ** 31:
        conn.sendall(b"ER")
        return None, None, "frame too large"
    frame = recv_exact(conn, size)
    try:
        data, nums = parse_frame(frame)
        conn.sendall(b"OK")
        return data, nums, None
    except ValueError as e:
        conn.sendall(b"ER")
        return None, None, str(e)


def serve(port, out_path=None, once=False, ready=None, result=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen()
        srv.settimeout(1.0)                    # lets Ctrl+C work on Windows as well
        if ready:
            ready.set()
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            conn.settimeout(30)
            with conn:
                try:
                    data, nums, err = handle(conn)
                except (OSError, ConnectionError, struct.error) as e:
                    data, nums, err = None, None, f"connection error: {e}"   # server keeps running
            if err:
                print(f"[{addr[0]}] rejected: {err}")
            else:
                print(f"[{addr[0]}] {len(data)} bytes received and verified ({len(nums)} numbers)")
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(data)
                if result is not None:
                    result.append((data, nums))
            if once:
                return


# ===================================================================== tests
def selftest():
    import random
    vals = list(ENC.values())
    assert len(set(vals)) == 256
    print(f"table          : 256 distinct values, largest {max(vals) / 1000:.3f}, every section starts with 0")
    assert all(DEC[ENC[b]] == b for b in range(256))
    ex = bytes([0b11101000, 0b11111000, 0b11101011, 0b10011010])
    n = encode_block(ex)
    print(f"example        : {ex.hex()} -> {n} -> transmitted digits {numbers_to_digits([n])}")
    assert decode_block(n) == ex
    rnd = random.Random(7)
    for size in (0, 1, 3, 4, 5, 1000):
        d = bytes(rnd.randrange(256) for _ in range(size))
        for mode in ("bcd", "raw"):
            assert parse_frame(make_frame(d, mode))[0] == d
    bad = bytearray(make_frame(ex * 10, "bcd")); bad[-1] ^= 0x01
    try:
        parse_frame(bytes(bad)); raise AssertionError("corruption not detected")
    except ValueError:
        pass
    sw = bytearray(make_frame(bytes([1, 2, 3, 4]), "raw")); sw[-4], sw[-3] = sw[-3], sw[-4]
    try:
        parse_frame(bytes(sw)); raise AssertionError("swap not detected")
    except ValueError:
        pass
    print("frames         : bcd and raw round trips OK, corruption and byte swap detected (CRC-32)")
    d = os.urandom(100_000)
    sizes = {m: len(make_frame(d, m)) for m in ("bcd", "raw")}
    print(f"sizes (100 KB) : bcd {sizes['bcd']:,} bytes (x{sizes['bcd'] / len(d):.2f}), "
          f"raw {sizes['raw']:,} bytes (x{sizes['raw'] / len(d):.2f})")
    ready, result = threading.Event(), []
    t = threading.Thread(target=serve, kwargs=dict(port=50555, once=True, ready=ready, result=result), daemon=True)
    t.start(); ready.wait(5)
    sent, ok = send_data("127.0.0.1", 50555, d, "bcd")
    t.join(5)
    assert ok and result and result[0][0] == d
    print(f"network        : {len(d):,} bytes sent over TCP as {sent:,} bytes, received and verified")



# ======================================================================= CLI
def main():
    p = argparse.ArgumentParser(description="Weighted Pair-Symbol Encoding over the network")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encode"); e.add_argument("file")
    d = sub.add_parser("decode"); d.add_argument("numbers", nargs="+")
    r = sub.add_parser("receive"); r.add_argument("--port", type=int, default=5050)
    r.add_argument("--out"); r.add_argument("--once", action="store_true")
    s = sub.add_parser("send"); s.add_argument("file"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5050); s.add_argument("--mode", choices=["bcd", "raw"], default="bcd")
    sub.add_parser("selftest")
    a = p.parse_args()
    try:
        if a.cmd == "encode":
            nums, pad = to_numbers(open(a.file, "rb").read())
            print("\n".join(nums))
            if pad:
                print(f"# last block padded with {pad} zero byte(s)", file=sys.stderr)
        elif a.cmd == "decode":
            print(b"".join(decode_block(n) for n in a.numbers).hex())
        elif a.cmd == "receive":
            print(f"listening on port {a.port} ... (Ctrl+C to stop)")
            try:
                serve(a.port, a.out, a.once)
            except KeyboardInterrupt:
                print("stopped")
        elif a.cmd == "send":
            data = open(a.file, "rb").read()
            size, ok = send_data(a.host, a.port, data, a.mode)
            print(f"sent {len(data):,} bytes as {size:,} bytes ({a.mode}) -> {'verified' if ok else 'REJECTED'}")
        elif a.cmd == "selftest":
            selftest()
    except (ValueError, OSError, ConnectionError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
