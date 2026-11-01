// =====================================================================================
// pse_net — Weighted Pair-Symbol Encoding: codec, framing, TCP/TLS transport
// ALL-IN-ONE SOURCE FILE (same code as the repository, combined into one file)
//
// How to build:
//   1. Create a folder with this layout:
//        pse_net/
//          Cargo.toml        <- copy the block below (without the leading "// ")
//          src/main.rs       <- this file
//   2. cargo build --release      (binary: target/release/pse_net)
//      cargo test  --release      (unit tests + loopback network tests)
//
// -------------------------------------------------------------------------------------
//[package]
name = "pse_net"
version = "0.3.0"
edition = "2021"
description = "Weighted Pair-Symbol Encoding: codec, framing and network transport (TCP / TLS)"
license = "MIT"
rust-version = "1.75"
repository = "https://github.com/AlmodinyMk/data-link-pse-net"

[dependencies]
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
rustls-pemfile = "2"

[profile.release]
opt-level = 3
lto = true
// Sections in this file:
//   1. mod codec   — rules R1-R6, ladder table, block numbers, BCD digits
//   2. mod frame   — PSE2 frame, CRC-32, length validation
//   3. mod net     — TCP/TLS, concurrent server, chunked streaming, ACK/retry
//   4. CLI (main)  — encode / decode / send / receive
//   5. mod loopback_tests — network tests on 127.0.0.1
// =====================================================================================

// ============================== 1. CODEC ==============================
mod codec {
    // Weighted pair-symbol codec.
    //
    // byte -> two 4-bit groups -> four 2-bit pairs (weights 00:2 01:3 10:5 11:13)
    // value X.0YY in units of 0.001 (X = relational state 0..9, YY = sum, ladder for repeats)
    // 4 bytes -> "X4X3X2X1.0YY0YY0YY0YY" -> 12 transmitted digits (fixed zeros dropped)

    use std::sync::OnceLock;

    /// R2: pair weights indexed by the 2-bit value.
    pub const WEIGHTS: [u16; 4] = [2, 3, 5, 13];

    #[inline]
    fn pair_hi(g: u8) -> u8 {
        (g >> 2) & 0b11
    }
    #[inline]
    fn pair_lo(g: u8) -> u8 {
        g & 0b11
    }

    /// R4: sum of a 4-bit group.
    pub fn group_sum(g: u8) -> u16 {
        WEIGHTS[pair_hi(g) as usize] + WEIGHTS[pair_lo(g) as usize]
    }

    /// R3: true if the group starts larger (equal counts as "starts smaller").
    pub fn starts_larger(g: u8) -> bool {
        WEIGHTS[pair_hi(g) as usize] > WEIGHTS[pair_lo(g) as usize]
    }

    /// R5: smaller sum is smaller; on equal sums the group that starts larger is larger.
    pub fn first_is_smaller(g1: u8, g2: u8) -> bool {
        let (s1, s2) = (group_sum(g1), group_sum(g2));
        if s1 != s2 {
            s1 < s2
        } else {
            !starts_larger(g1) && starts_larger(g2)
        }
    }

    /// R6: the ten relational states (1..=10).
    pub fn state(g1: u8, g2: u8) -> u8 {
        let (f1, f2) = (starts_larger(g1), starts_larger(g2));
        if g1 == g2 {
            return if f1 { 9 } else { 10 };
        }
        let base = match (f1, f2) {
            (false, false) => 1,
            (true, false) => 3,
            (false, true) => 5,
            (true, true) => 7,
        };
        if first_is_smaller(g1, g2) {
            base
        } else {
            base + 1
        }
    }

    /// State number -> integer digit X (state 10 -> 0).
    pub fn state_value(st: u8) -> u16 {
        if st == 10 {
            0
        } else {
            st as u16
        }
    }

    pub struct Table {
        /// byte -> value in units of 0.001
        pub enc: [u16; 256],
        /// value (0..9999) -> byte, or -1
        pub dec: Vec<i16>,
    }

    fn build() -> Table {
        // per state: list of (sum, smaller-group sum, byte)
        let mut by_state: Vec<Vec<(u16, u16, u8)>> = vec![Vec::new(); 10];
        for b in 0u16..256 {
            let (g1, g2) = ((b >> 4) as u8, (b & 0xF) as u8);
            let x = state_value(state(g1, g2)) as usize;
            let s = group_sum(g1) + group_sum(g2);
            by_state[x].push((s, group_sum(g1).min(group_sum(g2)), b as u8));
        }
        let mut enc = [0u16; 256];
        for (x, cells) in by_state.iter_mut().enumerate() {
            cells.sort(); // by sum, then smaller-group sum
            let mut used: Vec<u16> = cells.iter().map(|c| c.0).collect();
            used.dedup();
            let mut next = *used.iter().max().unwrap_or(&0);
            let mut prev_sum: Option<u16> = None;
            for &(s, _, b) in cells.iter() {
                let yy = if prev_sum != Some(s) {
                    prev_sum = Some(s);
                    s // first cell keeps the sum
                } else {
                    next += 1; // ladder: next free step above the state's max
                    while used.contains(&next) {
                        next += 1;
                    }
                    used.push(next);
                    next
                };
                enc[b as usize] = x as u16 * 1000 + yy;
            }
        }
        let mut dec = vec![-1i16; 10000];
        for (b, &v) in enc.iter().enumerate() {
            assert!(dec[v as usize] == -1, "table is not one-to-one");
            assert!(v % 1000 < 100, "section would need its first digit");
            dec[v as usize] = b as i16;
        }
        Table { enc, dec }
    }

    pub fn table() -> &'static Table {
        static T: OnceLock<Table> = OnceLock::new();
        T.get_or_init(build)
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum CodecError {
        BadNumber(String),
        NotInTable(u16),
        BadDigit,
    }

    impl std::fmt::Display for CodecError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                CodecError::BadNumber(s) => write!(f, "bad number: {s}"),
                CodecError::NotInTable(v) => write!(
                    f,
                    "{}.{:03} is not a value of this system",
                    v / 1000,
                    v % 1000
                ),
                CodecError::BadDigit => write!(f, "invalid BCD digit"),
            }
        }
    }
    impl std::error::Error for CodecError {}

    /// 4 bytes -> "X4X3X2X1.0YY0YY0YY0YY"
    pub fn encode_block(b: [u8; 4]) -> String {
        let t = table();
        let v: Vec<u16> = b.iter().map(|&x| t.enc[x as usize]).collect();
        let mut s = String::with_capacity(17);
        for x in v.iter().rev() {
            s.push(char::from(b'0' + (x / 1000) as u8));
        }
        s.push('.');
        for x in &v {
            s.push_str(&format!("{:03}", x % 1000));
        }
        s
    }

    pub fn decode_block(num: &str) -> Result<[u8; 4], CodecError> {
        let (ip, fp) = num
            .trim()
            .split_once('.')
            .ok_or_else(|| CodecError::BadNumber(num.into()))?;
        if ip.len() != 4 || fp.len() != 12 || !ip.bytes().chain(fp.bytes()).all(|c| c.is_ascii_digit())
        {
            return Err(CodecError::BadNumber(num.into()));
        }
        let (ib, fb) = (ip.as_bytes(), fp.as_bytes());
        let mut out = [0u8; 4];
        for i in 0..4 {
            let x = (ib[3 - i] - b'0') as u16;
            let yyy = (fb[3 * i] - b'0') as u16 * 100
                + (fb[3 * i + 1] - b'0') as u16 * 10
                + (fb[3 * i + 2] - b'0') as u16;
            out[i] = lookup(x * 1000 + yyy)?;
        }
        Ok(out)
    }

    fn lookup(v: u16) -> Result<u8, CodecError> {
        match table().dec.get(v as usize) {
            Some(&b) if b >= 0 => Ok(b as u8),
            _ => Err(CodecError::NotInTable(v)),
        }
    }

    /// Bytes -> transmitted digits (0..9 each), 12 per 4-byte block; the last block is zero-padded.
    pub fn bytes_to_digits(data: &[u8]) -> Vec<u8> {
        let t = table();
        let mut d = Vec::with_capacity(data.len().div_ceil(4) * 12);
        for chunk in data.chunks(4) {
            let mut b = [0u8; 4];
            b[..chunk.len()].copy_from_slice(chunk);
            let v = [
                t.enc[b[0] as usize],
                t.enc[b[1] as usize],
                t.enc[b[2] as usize],
                t.enc[b[3] as usize],
            ];
            for x in v.iter().rev() {
                d.push((x / 1000) as u8);
            } // X4 X3 X2 X1
            for x in &v {
                let yy = x % 1000;
                d.push((yy / 10) as u8);
                d.push((yy % 10) as u8);
            }
        }
        d
    }

    /// Transmitted digits -> bytes (n = original length, used to drop padding).
    pub fn digits_to_bytes(d: &[u8], n: usize) -> Result<Vec<u8>, CodecError> {
        if d.len() % 12 != 0 {
            return Err(CodecError::BadDigit);
        }
        let mut out = Vec::with_capacity(d.len() / 3);
        for blk in d.chunks(12) {
            for i in 0..4 {
                let x = blk[3 - i] as u16;
                let yy = blk[4 + 2 * i] as u16 * 10 + blk[5 + 2 * i] as u16;
                out.push(lookup(x * 1000 + yy)?);
            }
        }
        out.truncate(n);
        Ok(out)
    }

    /// Two digits per byte, high nibble first; an odd count is padded with 0xF.
    pub fn bcd_pack(d: &[u8]) -> Vec<u8> {
        d.chunks(2)
            .map(|p| (p[0] << 4) | if p.len() == 2 { p[1] } else { 0xF })
            .collect()
    }

    pub fn bcd_unpack(b: &[u8], ndigits: usize) -> Result<Vec<u8>, CodecError> {
        let mut d = Vec::with_capacity(ndigits);
        for &x in b {
            d.push(x >> 4);
            d.push(x & 0xF);
        }
        d.truncate(ndigits);
        if d.len() != ndigits || d.iter().any(|&v| v > 9) {
            return Err(CodecError::BadDigit);
        }
        Ok(d)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn table_is_bijective_and_sections_start_with_zero() {
            let t = table();
            let mut v: Vec<u16> = t.enc.to_vec();
            v.sort();
            v.dedup();
            assert_eq!(v.len(), 256);
            assert!(t.enc.iter().all(|x| x % 1000 < 100));
            assert_eq!(*t.enc.iter().max().unwrap(), 9036);
        }

        #[test]
        fn paper_example() {
            let n = encode_block([0xE8, 0xF8, 0xEB, 0x9A]);
            assert_eq!(n, "3468.025033036018");
            assert_eq!(decode_block(&n).unwrap(), [0xE8, 0xF8, 0xEB, 0x9A]);
            let d: String = bytes_to_digits(&[0xE8, 0xF8, 0xEB, 0x9A])
                .iter()
                .map(|x| char::from(b'0' + x))
                .collect();
            assert_eq!(d, "346825333618");
        }

        #[test]
        fn exhaustive_two_byte_round_trip() {
            for a in 0..=255u8 {
                for b in 0..=255u8 {
                    let d = bytes_to_digits(&[a, b]);
                    let p = bcd_pack(&d);
                    let back = digits_to_bytes(&bcd_unpack(&p, d.len()).unwrap(), 2).unwrap();
                    assert_eq!(back, vec![a, b]);
                }
            }
        }
    }
}

// ============================== 2. FRAME ==============================
mod frame {
    // PSE2 frame (big-endian, wire-compatible with pse_net_plain.py):
    //
    // | magic "PSE2" (4) | mode (1) | flags (1) | original length (4) | body length (4) | CRC-32 (4) | body |
    //
    // mode : 1 = bcd (system digits, 6 bytes per 4 data bytes), 2 = raw (data as is)
    // flags: bit0 = encrypted (refused: use TLS), bit1 = STREAM (more frames follow on this
    //        connection), bit2 = LAST (final frame of a stream). Python peers use flags = 0.

    use crate::codec::{self, CodecError};

    pub const MAGIC: &[u8; 4] = b"PSE2";
    pub const HDR_LEN: usize = 18;
    pub const MODE_BCD: u8 = 1;
    pub const MODE_RAW: u8 = 2;
    pub const FLAG_ENC: u8 = 0x01;
    pub const FLAG_STREAM: u8 = 0x02;
    pub const FLAG_LAST: u8 = 0x04;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Mode {
        Bcd,
        Raw,
    }

    #[derive(Debug)]
    pub enum FrameError {
        TooShort,
        BadMagic,
        Truncated,
        Encrypted,
        UnknownMode(u8),
        Crc,
        Codec(CodecError),
    }

    impl std::fmt::Display for FrameError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                FrameError::TooShort => write!(f, "frame too short"),
                FrameError::BadMagic => write!(f, "not a PSE frame"),
                FrameError::Truncated => write!(f, "truncated frame"),
                FrameError::Encrypted => {
                    write!(f, "encrypted frame refused (use TLS transport instead)")
                }
                FrameError::UnknownMode(m) => write!(f, "unknown mode {m}"),
                FrameError::Crc => write!(f, "CRC-32 mismatch: data corrupted in transit"),
                FrameError::Codec(e) => write!(f, "{e}"),
            }
        }
    }
    impl std::error::Error for FrameError {}
    impl From<CodecError> for FrameError {
        fn from(e: CodecError) -> Self {
            FrameError::Codec(e)
        }
    }

    /// CRC-32 (IEEE 802.3, reflected, same as zlib.crc32).
    pub fn crc32(data: &[u8]) -> u32 {
        static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
        let t = TABLE.get_or_init(|| {
            let mut t = [0u32; 256];
            for (i, e) in t.iter_mut().enumerate() {
                let mut c = i as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xEDB8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
                *e = c;
            }
            t
        });
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        c ^ 0xFFFF_FFFF
    }

    pub fn make_frame(data: &[u8], mode: Mode, flags: u8) -> Vec<u8> {
        let (m, body) = match mode {
            Mode::Raw => (MODE_RAW, data.to_vec()),
            Mode::Bcd => (MODE_BCD, codec::bcd_pack(&codec::bytes_to_digits(data))),
        };
        let mut f = Vec::with_capacity(HDR_LEN + body.len());
        f.extend_from_slice(MAGIC);
        f.push(m);
        f.push(flags);
        f.extend_from_slice(&(data.len() as u32).to_be_bytes());
        f.extend_from_slice(&(body.len() as u32).to_be_bytes());
        f.extend_from_slice(&crc32(data).to_be_bytes());
        f.extend_from_slice(&body);
        f
    }

    pub struct Parsed {
        pub data: Vec<u8>,
        pub flags: u8,
        pub mode: Mode,
    }

    pub fn parse_frame(f: &[u8]) -> Result<Parsed, FrameError> {
        if f.len() < HDR_LEN {
            return Err(FrameError::TooShort);
        }
        if &f[0..4] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let (m, flags) = (f[4], f[5]);
        let n = u32::from_be_bytes(f[6..10].try_into().unwrap()) as usize;
        let blen = u32::from_be_bytes(f[10..14].try_into().unwrap()) as usize;
        let crc = u32::from_be_bytes(f[14..18].try_into().unwrap());
        // the frame must contain exactly the header and the declared body
        if f.len() != HDR_LEN + blen {
            return Err(FrameError::Truncated);
        }
        let body = &f[HDR_LEN..];
        if flags & FLAG_ENC != 0 {
            return Err(FrameError::Encrypted);
        }
        let (data, mode) = match m {
            MODE_RAW => {
                if blen != n {
                    return Err(FrameError::Truncated);
                }
                (body.to_vec(), Mode::Raw)
            }
            MODE_BCD => {
                // validate the declared length against the body BEFORE allocating anything from it
                if blen as u64 != (n as u64).div_ceil(4) * 6 {
                    return Err(FrameError::Truncated);
                }
                let ndig = n.div_ceil(4) * 12;
                let digits = codec::bcd_unpack(body, ndig)?;
                (codec::digits_to_bytes(&digits, n)?, Mode::Bcd)
            }
            other => return Err(FrameError::UnknownMode(other)),
        };
        if crc32(&data) != crc {
            return Err(FrameError::Crc);
        }
        Ok(Parsed { data, flags, mode })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn crc_matches_zlib() {
            assert_eq!(crc32(b"123456789"), 0xCBF4_3926); // standard check value
        }

        #[test]
        fn round_trips_and_padding() {
            for n in [0usize, 1, 3, 4, 5, 1000] {
                let d: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
                for mode in [Mode::Bcd, Mode::Raw] {
                    assert_eq!(parse_frame(&make_frame(&d, mode, 0)).unwrap().data, d);
                }
            }
        }

        #[test]
        fn every_single_bit_flip_is_detected() {
            let d: Vec<u8> = (0..64u32).map(|i| (i * 91 % 256) as u8).collect();
            for mode in [Mode::Bcd, Mode::Raw] {
                let f = make_frame(&d, mode, 0);
                for byte in HDR_LEN..f.len() {
                    for bit in 0..8 {
                        let mut g = f.clone();
                        g[byte] ^= 1 << bit;
                        assert!(parse_frame(&g).is_err(), "undetected flip at {byte}:{bit}");
                    }
                }
            }
        }

        #[test]
        fn hostile_length_fields_rejected_without_allocation() {
            // declared original length 4 GiB with a 6-byte body: must be rejected, not allocated
            let mut f = make_frame(&[1, 2, 3, 4], Mode::Bcd, 0);
            f[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(matches!(parse_frame(&f), Err(FrameError::Truncated)));
            // trailing bytes after the declared body
            let mut g = make_frame(&[1, 2, 3, 4], Mode::Raw, 0);
            g.push(0);
            assert!(matches!(parse_frame(&g), Err(FrameError::Truncated)));
            // body length larger than the frame
            let mut h = make_frame(&[1, 2, 3, 4], Mode::Raw, 0);
            h[10..14].copy_from_slice(&1000u32.to_be_bytes());
            assert!(matches!(parse_frame(&h), Err(FrameError::Truncated)));
        }

        #[test]
        fn swapped_bytes_detected() {
            let mut f = make_frame(&[1, 2, 3, 4], Mode::Raw, 0);
            let l = f.len();
            f.swap(l - 4, l - 3);
            assert!(parse_frame(&f).is_err());
        }

        #[test]
        fn malformed_rejected() {
            assert!(matches!(parse_frame(b"PSE2"), Err(FrameError::TooShort)));
            assert!(matches!(parse_frame(&[0u8; 18]), Err(FrameError::BadMagic)));
            let mut f = make_frame(&[1, 2, 3, 4], Mode::Raw, 0);
            f[5] = FLAG_ENC;
            assert!(matches!(parse_frame(&f), Err(FrameError::Encrypted)));
        }
    }
}

// ============================== 3. NET ================================
mod net {
    // Transport layer.
    //
    // Reliability, ordering, retransmission, congestion control and segmentation are provided by
    // TCP and are deliberately not re-implemented here. This layer adds:
    //   * framing with a 4-byte length prefix and a per-frame acknowledgement ("OK" / "ER" / "BY")
    //   * application-level retry of a frame that fails verification (bounded)
    //   * chunked streaming of large files (constant memory) with an atomic write on completion
    //   * a concurrent server with a connection limit, timeouts and size limits
    //   * optional TLS 1.2/1.3 (rustls) for confidentiality, integrity and server authentication

    use crate::frame::{self, Mode, FLAG_LAST, FLAG_STREAM};
    use std::fs::{self, File};
    use std::io::{self, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub const ACK_OK: &[u8; 2] = b"OK";
    pub const ACK_ERR: &[u8; 2] = b"ER";
    pub const ACK_BUSY: &[u8; 2] = b"BY";

    pub trait Stream: Read + Write + Send {}
    impl<T: Read + Write + Send> Stream for T {}

    fn other<E: std::fmt::Display>(e: E) -> io::Error {
        io::Error::other(e.to_string())
    }

    // ------------------------------------------------------------------ TLS setup
    fn load_certs(path: &Path) -> io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
    }

    pub fn tls_server_config(cert: &Path, key: &Path) -> io::Result<Arc<rustls::ServerConfig>> {
        let certs = load_certs(cert)?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
            .ok_or_else(|| other("no private key found"))?;
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(other)?;
        Ok(Arc::new(cfg))
    }

    pub fn tls_client_config(ca: &Path) -> io::Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certs(ca)? {
            roots.add(c).map_err(other)?;
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Arc::new(cfg))
    }

    // ---------------------------------------------------------------- framing I/O
    fn read_exact_vec(s: &mut dyn Stream, n: usize) -> io::Result<Vec<u8>> {
        let mut b = vec![0u8; n];
        s.read_exact(&mut b)?;
        Ok(b)
    }

    /// Read exactly n bytes, failing if the whole read takes longer than `deadline`
    /// (a peer that trickles bytes cannot hold a connection slot indefinitely).
    fn read_exact_deadline(s: &mut dyn Stream, n: usize, deadline: Instant) -> io::Result<Vec<u8>> {
        let mut b = vec![0u8; n];
        let mut got = 0;
        while got < n {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "frame not received in time",
                ));
            }
            let end = (got + 64 * 1024).min(n);
            let k = s.read(&mut b[got..end])?;
            if k == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            got += k;
        }
        Ok(b)
    }

    fn write_frame(s: &mut dyn Stream, f: &[u8]) -> io::Result<()> {
        s.write_all(&(f.len() as u32).to_be_bytes())?;
        s.write_all(f)?;
        s.flush()
    }

    // --------------------------------------------------------------------- client
    pub struct SendOptions {
        pub mode: Mode,
        pub chunk: usize, // bytes of data per frame when streaming
        pub retries: u32, // re-sends of a frame answered with "ER"
    }

    impl Default for SendOptions {
        fn default() -> Self {
            SendOptions {
                mode: Mode::Bcd,
                chunk: 1 << 20,
                retries: 3,
            }
        }
    }

    pub struct SendReport {
        pub data_bytes: u64,
        pub wire_bytes: u64,
        pub frames: u64,
        pub retries: u64,
    }

    pub fn connect(
        host: &str,
        port: u16,
        tls: Option<(Arc<rustls::ClientConfig>, String)>,
    ) -> io::Result<Box<dyn Stream>> {
        let tcp = TcpStream::connect((host, port))?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(60)))?;
        match tls {
            None => Ok(Box::new(tcp)),
            Some((cfg, name)) => {
                let sn = rustls::pki_types::ServerName::try_from(name).map_err(other)?;
                let conn = rustls::ClientConnection::new(cfg, sn).map_err(other)?;
                Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
            }
        }
    }

    /// Send a whole file. Files not larger than one chunk are sent as a single frame (flags = 0,
    /// compatible with the Python implementation); larger files are streamed chunk by chunk.
    pub fn send_file(s: &mut dyn Stream, path: &Path, opt: &SendOptions) -> io::Result<SendReport> {
        let size = fs::metadata(path)?.len();
        let mut f = File::open(path)?;
        let chunk = opt.chunk.max(4) / 4 * 4;
        let mut rep = SendReport {
            data_bytes: 0,
            wire_bytes: 0,
            frames: 0,
            retries: 0,
        };
        let streaming = size > chunk as u64;
        let mut buf = vec![0u8; chunk];
        let mut sent: u64 = 0;
        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 && sent < size {
                return Err(other("file shrank while it was being sent"));
            }
            let last = sent + n as u64 >= size;
            let flags = if streaming {
                FLAG_STREAM | if last { FLAG_LAST } else { 0 }
            } else {
                0
            };
            let fr = frame::make_frame(&buf[..n], opt.mode, flags);
            let mut attempt = 0;
            loop {
                if let Err(e) = write_frame(s, &fr) {
                    // the receiver may have refused the connection with "BY" and closed it
                    let mut ack = [0u8; 2];
                    if s.read_exact(&mut ack).is_ok() && &ack == ACK_BUSY {
                        return Err(other("receiver busy (connection limit reached)"));
                    }
                    return Err(e);
                }
                rep.wire_bytes += 4 + fr.len() as u64;
                let mut ack = [0u8; 2];
                s.read_exact(&mut ack)?;
                if &ack == ACK_OK {
                    break;
                }
                if &ack == ACK_BUSY {
                    return Err(other("receiver busy (connection limit reached)"));
                }
                attempt += 1;
                rep.retries += 1;
                if attempt > opt.retries {
                    return Err(other("frame rejected by receiver after retries"));
                }
            }
            rep.frames += 1;
            sent += n as u64;
            rep.data_bytes = sent;
            if last {
                break;
            }
        }
        Ok(rep)
    }

    fn read_full(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            let k = f.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        Ok(n)
    }

    // --------------------------------------------------------------------- server
    pub struct ServerOptions {
        pub port: u16,
        pub out_dir: PathBuf,
        pub max_clients: usize,
        pub max_frame: usize,
        pub once: bool,
        pub tls: Option<Arc<rustls::ServerConfig>>,
    }

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    struct SlotGuard(Arc<AtomicUsize>);
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn unique_name(dir: &Path) -> PathBuf {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        dir.join(format!(
            "received_{ms}_{}.bin",
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Handle one connection: a single frame, or a stream of frames ending with FLAG_LAST.
    /// Data is written to a ".part" file and renamed only when complete and verified.
    pub fn handle_connection(
        s: &mut dyn Stream,
        out_dir: &Path,
        max_frame: usize,
    ) -> io::Result<(PathBuf, u64)> {
        let final_path = unique_name(out_dir);
        let part = final_path.with_extension("bin.part");
        let mut out = File::create(&part)?;
        let mut total: u64 = 0;
        let result = (|| -> io::Result<()> {
            loop {
                let len = u32::from_be_bytes(read_exact_vec(s, 4)?.try_into().unwrap()) as usize;
                if len > max_frame {
                    s.write_all(ACK_ERR)?;
                    return Err(other(format!(
                        "frame of {len} bytes exceeds limit {max_frame}"
                    )));
                }
                // allow 60 s plus 1 s per MiB for the body to arrive
                let deadline = Instant::now() + Duration::from_secs(60 + (len >> 20) as u64);
                let fr = read_exact_deadline(s, len, deadline)?;
                match frame::parse_frame(&fr) {
                    Ok(p) => {
                        out.write_all(&p.data)?;
                        total += p.data.len() as u64;
                        s.write_all(ACK_OK)?;
                        s.flush()?;
                        let streaming = p.flags & FLAG_STREAM != 0;
                        if !streaming || p.flags & FLAG_LAST != 0 {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        // ask for retransmission of this frame; the sender bounds the number of retries
                        s.write_all(ACK_ERR)?;
                        s.flush()?;
                        eprintln!("  frame rejected: {e}");
                    }
                }
            }
        })();
        drop(out);
        match result {
            Ok(()) => {
                fs::rename(&part, &final_path)?;
                Ok((final_path, total))
            }
            Err(e) => {
                let _ = fs::remove_file(&part);
                Err(e)
            }
        }
    }

    pub fn serve(opt: ServerOptions) -> io::Result<()> {
        fs::create_dir_all(&opt.out_dir)?;
        let listener = TcpListener::bind(("0.0.0.0", opt.port))?;
        let active = Arc::new(AtomicUsize::new(0));
        eprintln!(
            "listening on port {} ({}), up to {} clients, output in {}",
            opt.port,
            if opt.tls.is_some() {
                "TLS"
            } else {
                "plain TCP"
            },
            opt.max_clients,
            opt.out_dir.display()
        );
        for conn in listener.incoming() {
            let tcp = match conn {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("accept error: {e}");
                    continue;
                }
            };
            let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
            let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));
            let max = opt.max_clients;
            if active
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |a| {
                    if a < max {
                        Some(a + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                let mut t = tcp;
                let _ = t.write_all(ACK_BUSY);
                eprintln!("[{peer}] refused: connection limit reached");
                continue;
            }
            let (active2, dir, maxf, tls) = (
                active.clone(),
                opt.out_dir.clone(),
                opt.max_frame,
                opt.tls.clone(),
            );
            let worker = std::thread::spawn(move || {
                let _slot = SlotGuard(active2); // released even if this thread panics
                let res = (|| -> io::Result<(PathBuf, u64)> {
                    let mut stream: Box<dyn Stream> = match tls {
                        None => Box::new(tcp),
                        Some(cfg) => {
                            let conn = rustls::ServerConnection::new(cfg).map_err(other)?;
                            Box::new(rustls::StreamOwned::new(conn, tcp))
                        }
                    };
                    handle_connection(stream.as_mut(), &dir, maxf)
                })();
                match res {
                    Ok((p, n)) => eprintln!(
                        "[{peer}] {n} bytes received and verified -> {}",
                        p.display()
                    ),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => eprintln!(
                        "[{peer}] connection closed before a complete frame (partial data discarded)"
                    ),
                    Err(e) => eprintln!("[{peer}] connection failed: {e}"),
                }
            });
            if opt.once {
                let _ = worker.join();
                return Ok(());
            }
        }
        Ok(())
    }
}

// ============================== 4. CLI ================================
// pse_net — command-line interface.
//
//   pse_net encode  <file>
//   pse_net decode  <number> [<number> ...]
//   pse_net receive --port 5050 --out-dir recv [--max-clients 16] [--max-frame-mb 64] [--once]
//                   [--tls-cert cert.pem --tls-key key.pem]
//   pse_net send    --host 127.0.0.1 --port 5050 <file> [--mode bcd|raw] [--chunk-kb 1024]
//                   [--tls-ca ca.pem --server-name localhost]
use crate::frame::Mode;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage:\n  pse_net encode <file>\n  pse_net decode <number>...\n  \
pse_net receive --port P --out-dir DIR [--max-clients N] [--max-frame-mb N] [--once] [--tls-cert C --tls-key K]\n  \
pse_net send --host H --port P <file> [--mode bcd|raw] [--chunk-kb N] [--tls-ca CA --server-name NAME]");
    ExitCode::from(2)
}

struct Args {
    pos: Vec<String>,
    kv: Vec<(String, String)>,
    flags: Vec<String>,
}

const OPTIONS: &[&str] = &[
    "port",
    "host",
    "out-dir",
    "max-clients",
    "max-frame-mb",
    "tls-cert",
    "tls-key",
    "tls-ca",
    "server-name",
    "mode",
    "chunk-kb",
];

/// Strict parser: unknown or value-less options are errors (a mistyped --tls-ca must not
/// silently fall back to an unencrypted connection).
fn parse(a: &[String]) -> Result<Args, String> {
    let (mut pos, mut kv, mut flags) = (vec![], vec![], vec![]);
    let mut i = 0;
    while i < a.len() {
        if let Some(k) = a[i].strip_prefix("--") {
            if k == "once" {
                flags.push(k.to_string());
            } else if OPTIONS.contains(&k) {
                let v = a
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or(format!("--{k} needs a value"))?;
                kv.push((k.to_string(), v.clone()));
                i += 1;
            } else {
                return Err(format!("unknown option --{k}"));
            }
        } else {
            pos.push(a[i].clone());
        }
        i += 1;
    }
    Ok(Args { pos, kv, flags })
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.kv
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
    }
    fn num(&self, k: &str, d: usize) -> Result<usize, String> {
        self.get(k)
            .map(|v| {
                v.parse::<usize>()
                    .map_err(|_| format!("--{k} must be a number"))
            })
            .unwrap_or(Ok(d))
    }
    fn port(&self) -> Result<u16, String> {
        let p = self.num("port", 5050)?;
        u16::try_from(p)
            .ok()
            .filter(|&p| p != 0)
            .ok_or(format!("--port must be 1..65535, got {p}"))
    }
}

fn run(cmd: &str, a: Args) -> Result<(), String> {
    match cmd {
        "encode" => {
            let data =
                std::fs::read(a.pos.first().ok_or("missing file")?).map_err(|e| e.to_string())?;
            for c in data.chunks(4) {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                println!("{}", codec::encode_block(b));
            }
            if data.len() % 4 != 0 {
                eprintln!(
                    "# last block padded with {} zero byte(s)",
                    4 - data.len() % 4
                );
            }
        }
        "decode" => {
            let mut out = String::new();
            for n in &a.pos {
                for b in codec::decode_block(n).map_err(|e| e.to_string())? {
                    out.push_str(&format!("{b:02x}"));
                }
            }
            println!("{out}");
        }
        "receive" => {
            let tls = match (a.get("tls-cert"), a.get("tls-key")) {
                (Some(c), Some(k)) => Some(
                    net::tls_server_config(c.as_ref(), k.as_ref())
                        .map_err(|e| format!("TLS: {e}"))?,
                ),
                (None, None) => None,
                _ => return Err("--tls-cert and --tls-key must be given together".into()),
            };
            net::serve(net::ServerOptions {
                port: a.port()?,
                out_dir: PathBuf::from(a.get("out-dir").unwrap_or("received")),
                max_clients: a.num("max-clients", 16)?.max(1),
                max_frame: a.num("max-frame-mb", 64)?.clamp(1, 2048) << 20,
                once: a.flags.iter().any(|f| f == "once"),
                tls,
            })
            .map_err(|e| e.to_string())?;
        }
        "send" => {
            let file = PathBuf::from(a.pos.first().ok_or("missing file")?);
            let mode = match a.get("mode").unwrap_or("bcd") {
                "bcd" => Mode::Bcd,
                "raw" => Mode::Raw,
                m => return Err(format!("unknown mode {m}")),
            };
            let tls = match a.get("tls-ca") {
                Some(ca) => Some((
                    net::tls_client_config(ca.as_ref()).map_err(|e| format!("TLS: {e}"))?,
                    a.get("server-name").unwrap_or("localhost").to_string(),
                )),
                None => None,
            };
            let host = a.get("host").unwrap_or("127.0.0.1");
            let chunk_kb = a.num("chunk-kb", 1024)?;
            if !(1..=65536).contains(&chunk_kb) {
                return Err("--chunk-kb must be 1..65536".into());
            }
            let mut s = net::connect(host, a.port()?, tls).map_err(|e| e.to_string())?;
            let opt = net::SendOptions {
                mode,
                chunk: chunk_kb << 10,
                retries: 3,
            };
            let r = net::send_file(s.as_mut(), &file, &opt).map_err(|e| e.to_string())?;
            println!("sent {} bytes in {} frame(s) as {} bytes on the wire ({:?}{}), retries {} -> verified",
                     r.data_bytes, r.frames, r.wire_bytes, mode, if a.get("tls-ca").is_some() { ", TLS" } else { "" }, r.retries);
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        return usage();
    };
    if !["encode", "decode", "receive", "send"].contains(&cmd.as_str()) {
        return usage();
    }
    let args = match parse(&argv[1..]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&cmd, args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}


// ============================== 5. LOOPBACK TESTS =====================
#[cfg(test)]
mod loopback_tests {
    // Cross-platform network tests (Linux, macOS, Windows): plain TCP on 127.0.0.1.
    use crate::frame::Mode;
    use crate::net::{self, SendOptions, ServerOptions};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pse_net_test_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn start_server(port: u16, out: &Path, max_clients: usize) {
        let opt = ServerOptions {
            port,
            out_dir: out.to_path_buf(),
            max_clients,
            max_frame: 64 << 20,
            once: false,
            tls: None,
        };
        thread::spawn(move || net::serve(opt).unwrap());
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                thread::sleep(Duration::from_millis(50));
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("server did not start");
    }

    fn send(port: u16, file: &Path, mode: Mode, chunk: usize) {
        let mut s = net::connect("127.0.0.1", port, None).unwrap();
        net::send_file(
            s.as_mut(),
            file,
            &SendOptions {
                mode,
                chunk,
                retries: 3,
            },
        )
        .unwrap();
    }

    fn received(out: &Path) -> Vec<Vec<u8>> {
        thread::sleep(Duration::from_millis(300));
        let mut v: Vec<Vec<u8>> = std::fs::read_dir(out)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "bin").unwrap_or(false))
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        v.sort_by_key(|d| d.len());
        v
    }

    #[test]
    fn single_frame_and_stream_both_modes() {
        let dir = temp_dir("stream");
        let out = dir.join("out");
        start_server(47101, &out, 8);
        let small = pseudo_random(5_000, 1);
        let big = pseudo_random(3_000_000, 2);
        std::fs::write(dir.join("small.bin"), &small).unwrap();
        std::fs::write(dir.join("big.bin"), &big).unwrap();
        send(47101, &dir.join("small.bin"), Mode::Bcd, 1 << 20);
        send(47101, &dir.join("big.bin"), Mode::Bcd, 64 << 10); // 46 frames
        send(47101, &dir.join("big.bin"), Mode::Raw, 64 << 10);
        let r = received(&out);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], small);
        assert_eq!(r[1], big);
        assert_eq!(r[2], big);
    }

    #[test]
    fn concurrent_clients() {
        let dir = temp_dir("concurrent");
        let out = dir.join("out");
        start_server(47102, &out, 16);
        let data = pseudo_random(500_000, 3);
        std::fs::write(dir.join("d.bin"), &data).unwrap();
        let file = dir.join("d.bin");
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let f = file.clone();
                thread::spawn(move || send(47102, &f, Mode::Bcd, 32 << 10))
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let r = received(&out);
        assert_eq!(r.len(), 8);
        assert!(r.iter().all(|x| *x == data));
    }

    #[test]
    fn hostile_frames_do_not_stop_the_server() {
        let dir = temp_dir("hostile");
        let out = dir.join("out");
        start_server(47103, &out, 8);
        // 1) declared original length of 4 GiB with a 6-byte body
        let mut hdr = b"PSE2".to_vec();
        hdr.extend_from_slice(&[1, 0]);
        hdr.extend_from_slice(&u32::MAX.to_be_bytes());
        hdr.extend_from_slice(&6u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&[0u8; 6]);
        let mut s = TcpStream::connect(("127.0.0.1", 47103)).unwrap();
        s.write_all(&(hdr.len() as u32).to_be_bytes()).unwrap();
        s.write_all(&hdr).unwrap();
        let mut ack = [0u8; 2];
        s.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ER");
        drop(s);
        // 2) oversized length prefix
        let mut s = TcpStream::connect(("127.0.0.1", 47103)).unwrap();
        s.write_all(&(1u32 << 30).to_be_bytes()).unwrap();
        s.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ER");
        drop(s);
        // 3) the server still accepts a valid transfer
        let data = pseudo_random(10_000, 4);
        std::fs::write(dir.join("ok.bin"), &data).unwrap();
        send(47103, &dir.join("ok.bin"), Mode::Bcd, 1 << 20);
        assert_eq!(received(&out), vec![data]);
    }

    #[test]
    fn connection_limit_reports_busy() {
        let dir = temp_dir("busy");
        let out = dir.join("out");
        start_server(47104, &out, 1);
        let _hold = TcpStream::connect(("127.0.0.1", 47104)).unwrap(); // occupies the only slot
        thread::sleep(Duration::from_millis(200));
        std::fs::write(dir.join("x.bin"), [1u8, 2, 3, 4]).unwrap();
        let mut s = net::connect("127.0.0.1", 47104, None).unwrap();
        let e = net::send_file(s.as_mut(), &dir.join("x.bin"), &SendOptions::default())
            .err()
            .expect("should be refused");
        assert!(e.to_string().contains("busy"), "unexpected error: {e}");
    }
}
