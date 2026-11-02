//! End-to-end (black-box) tests of the `pse_net` binary.
//!
//! Every test starts real `pse_net` processes and talks to them over TCP on 127.0.0.1.
//! Runs on Linux, macOS and Windows. Sections:
//!   A. CLI and argument validation
//!   B. Codec through the CLI (encode/decode, exhaustive single bytes, random files)
//!   C. Transfers: single frame, streaming, raw mode, empty and odd-sized files
//!   D. Protocol behaviour: OK / CN (continue) / ER + retransmission / BY (busy)
//!   E. Robustness: hostile, truncated, oversized and fuzzed frames; server keeps running
//!   F. Concurrency
//!   G. TLS: transfer, unknown CA, wrong server name, plaintext to a TLS server
//!   H. Interoperability with the Python reference (skipped if Python is not installed)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_pse_net");

// ------------------------------------------------------------------ helpers
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pse_e2e_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Deterministic pseudo-random bytes (xorshift), so failures are reproducible.
fn prng(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("cannot run pse_net")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A receiver process that is killed when the guard is dropped.
struct Server {
    child: Child,
    port: u16,
    out: PathBuf,
}

impl Server {
    fn start(name: &str, extra: &[&str]) -> Server {
        let port = free_port();
        let out = temp_dir(name).join("out");
        let mut args = vec![
            "receive".to_string(),
            "--port".into(),
            port.to_string(),
            "--out-dir".into(),
            out.to_string_lossy().into_owned(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        let child = Command::new(BIN)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot start receiver");
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "receiver did not start");
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_millis(100)); // let the probe connection close
        Server { child, port, out }
    }

    fn send(&self, file: &Path, extra: &[&str]) -> Output {
        let port = self.port.to_string();
        let mut args = vec!["send", "--port", &port, file.to_str().unwrap()];
        args.extend_from_slice(extra);
        run(&args)
    }

    /// Completed files, sorted by size (".part" files are excluded).
    fn received(&self, expected: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut v: Vec<Vec<u8>> = std::fs::read_dir(&self.out)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| p.extension().map(|x| x == "bin").unwrap_or(false))
                        .filter_map(|p| std::fs::read(p).ok())
                        .collect()
                })
                .unwrap_or_default();
            if v.len() >= expected || Instant::now() > deadline {
                v.sort_by_key(|d| d.len());
                return v;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn part_files(&self) -> usize {
        std::fs::read_dir(&self.out)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().to_string_lossy().ends_with(".part"))
                    .count()
            })
            .unwrap_or(0)
    }

    fn alive(&self) -> bool {
        TcpStream::connect(("127.0.0.1", self.port)).is_ok()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- raw frame construction (independent re-implementation of the wire format)
fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn raw_frame(data: &[u8], flags: u8) -> Vec<u8> {
    let mut f = b"PSE2".to_vec();
    f.push(2); // mode raw
    f.push(flags);
    f.extend_from_slice(&(data.len() as u32).to_be_bytes());
    f.extend_from_slice(&(data.len() as u32).to_be_bytes());
    f.extend_from_slice(&crc32(data).to_be_bytes());
    f.extend_from_slice(data);
    f
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn send_frame(s: &mut TcpStream, frame: &[u8]) -> [u8; 2] {
    s.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    s.write_all(frame).unwrap();
    let mut ack = [0u8; 2];
    s.read_exact(&mut ack).unwrap();
    ack
}

// ============================================================ A. CLI
#[test]
fn a1_usage_and_unknown_command() {
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));
}

#[test]
fn a2_option_validation() {
    let d = temp_dir("a2");
    let f = d.join("x.bin");
    std::fs::write(&f, [1u8, 2, 3]).unwrap();
    let f = f.to_str().unwrap();
    for (args, needle) in [
        (vec!["send", f, "--tls-cA", "x"], "unknown option"), // a typo must not drop TLS
        (vec!["send", f, "--port", "70000"], "--port"),
        (vec!["send", f, "--port", "0"], "--port"),
        (vec!["send", f, "--chunk-kb", "0"], "--chunk-kb"),
        (vec!["send", f, "--mode", "zip"], "unknown mode"),
        (vec!["send", f, "--port"], "needs a value"),
        (vec!["receive", "--tls-cert", "only.pem"], "together"),
    ] {
        let o = run(&args);
        assert!(!o.status.success(), "accepted: {args:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(needle),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

// ======================================================= B. codec via CLI
#[test]
fn b1_paper_example() {
    let d = temp_dir("b1");
    let f = d.join("e.bin");
    std::fs::write(&f, [0xE8, 0xF8, 0xEB, 0x9A]).unwrap();
    assert_eq!(
        ok(&run(&["encode", f.to_str().unwrap()])),
        "3468.025033036018"
    );
    assert_eq!(ok(&run(&["decode", "3468.025033036018"])), "e8f8eb9a");
}

#[test]
fn b2_all_256_bytes_round_trip_and_are_distinct() {
    let d = temp_dir("b2");
    let f = d.join("all.bin");
    std::fs::write(&f, (0..=255u8).collect::<Vec<_>>()).unwrap();
    let nums = ok(&run(&["encode", f.to_str().unwrap()]));
    let nums: Vec<&str> = nums.lines().collect();
    assert_eq!(nums.len(), 64);
    let mut args = vec!["decode"];
    args.extend(nums.iter().copied());
    let hex = ok(&run(&args));
    let expect: String = (0..=255u8).fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    assert_eq!(hex, expect);
    // every section value distinct across the 256 bytes
    let mut vals = std::collections::HashSet::new();
    for n in &nums {
        let (ip, fp) = n.split_once('.').unwrap();
        for i in 0..4 {
            vals.insert(format!("{}{}", &ip[3 - i..4 - i], &fp[3 * i..3 * i + 3]));
        }
    }
    assert_eq!(vals.len(), 256);
}

#[test]
fn b3_decode_rejects_invalid_numbers() {
    for bad in [
        "3468.02503303601",
        "34a8.025033036018",
        "9999.999999999999",
        "3468025033036018",
    ] {
        assert!(!run(&["decode", bad]).status.success(), "accepted {bad}");
    }
}

// ===================================================== C. transfers
#[test]
fn c1_single_frame_streaming_raw_and_edge_sizes() {
    let srv = Server::start("c1", &[]);
    let d = temp_dir("c1src");
    let files: Vec<(PathBuf, Vec<u8>, Vec<&str>)> = vec![
        (d.join("empty.bin"), vec![], vec![]),
        (d.join("one.bin"), vec![0xFF], vec![]),
        (d.join("odd.bin"), prng(1_001, 1), vec![]),
        (
            d.join("stream_bcd.bin"),
            prng(2_500_000, 2),
            vec!["--chunk-kb", "64"],
        ),
        (
            d.join("stream_raw.bin"),
            prng(2_600_000, 3),
            vec!["--chunk-kb", "64", "--mode", "raw"],
        ),
        (
            d.join("tiny_chunks.bin"),
            prng(10_000, 4),
            vec!["--chunk-kb", "1"],
        ),
    ];
    for (p, data, args) in &files {
        std::fs::write(p, data).unwrap();
        let out = ok(&srv.send(p, args));
        assert!(out.contains("verified"), "{out}");
    }
    let mut expected: Vec<Vec<u8>> = files.iter().map(|f| f.1.clone()).collect();
    expected.sort_by_key(|d| d.len());
    assert_eq!(srv.received(files.len()), expected);
    assert_eq!(srv.part_files(), 0);
}

#[test]
fn c2_wire_size_matches_the_paper() {
    let srv = Server::start("c2", &[]);
    let d = temp_dir("c2src");
    let p = d.join("d.bin");
    std::fs::write(&p, prng(100_000, 5)).unwrap();
    let bcd = ok(&srv.send(&p, &[]));
    let raw = ok(&srv.send(&p, &["--mode", "raw"]));
    // 4-byte length prefix + 18-byte header + body
    assert!(bcd.contains("as 150022 bytes"), "{bcd}");
    assert!(raw.contains("as 100022 bytes"), "{raw}");
}

// ============================================== D. protocol behaviour
#[test]
fn d1_corrupted_frame_gets_er_then_retransmission_succeeds() {
    let srv = Server::start("d1", &[]);
    let data = prng(5_000, 6);
    let good = raw_frame(&data, 0);
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01; // payload no longer matches CRC-32
    let mut s = connect(srv.port);
    assert_eq!(&send_frame(&mut s, &bad), b"ER");
    assert_eq!(&send_frame(&mut s, &good), b"OK"); // same connection, re-sent frame
    assert_eq!(srv.received(1), vec![data]);
}

#[test]
fn d2_stream_frames_are_acknowledged_and_assembled_in_order() {
    let srv = Server::start("d2", &[]);
    let parts = [prng(1_000, 7), prng(2_000, 8), prng(3_000, 9)];
    let mut s = connect(srv.port);
    for (i, p) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let flags = 0x02 | if last { 0x04 } else { 0 };
        let expected: &[u8; 2] = if last { b"OK" } else { b"CN" };
        assert_eq!(&send_frame(&mut s, &raw_frame(p, flags)), expected);
    }
    assert_eq!(srv.received(1), vec![parts.concat()]);
}

#[test]
fn d3_interrupted_stream_leaves_no_file() {
    let srv = Server::start("d3", &[]);
    {
        let mut s = connect(srv.port);
        assert_eq!(
            &send_frame(&mut s, &raw_frame(&prng(1_000, 10), 0x02)),
            b"CN"
        );
        // connection dropped before the LAST frame
    }
    thread::sleep(Duration::from_millis(500));
    assert!(srv.received(0).is_empty());
    assert_eq!(srv.part_files(), 0, "partial data must be discarded");
}

#[test]
fn d4_connection_limit_answers_busy() {
    let srv = Server::start("d4", &["--max-clients", "1"]);
    let _hold = connect(srv.port); // occupies the only slot
    thread::sleep(Duration::from_millis(300));
    let d = temp_dir("d4src");
    let p = d.join("x.bin");
    std::fs::write(&p, [1u8, 2, 3, 4]).unwrap();
    let o = srv.send(&p, &[]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("busy"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

// =================================================== E. robustness
#[test]
fn e1_hostile_frames_are_rejected_and_server_survives() {
    let srv = Server::start("e1", &[]);
    let mut huge_len = raw_frame(&[1, 2, 3, 4], 0);
    huge_len[4] = 1; // bcd mode
    huge_len[6..10].copy_from_slice(&u32::MAX.to_be_bytes()); // declares 4 GiB of data
    let mut encrypted = raw_frame(&[1, 2, 3, 4], 0);
    encrypted[5] = 0x01;
    let mut bad_mode = raw_frame(&[1, 2, 3, 4], 0);
    bad_mode[4] = 9;
    let mut trailing = raw_frame(&[1, 2, 3, 4], 0);
    trailing.push(0);
    let mut undefined_flag = raw_frame(&[1, 2, 3, 4], 0);
    undefined_flag[5] = 0x40;
    let mut last_without_stream = raw_frame(&[1, 2, 3, 4], 0);
    last_without_stream[5] = 0x04;
    for (name, frame) in [
        ("short", b"PSE2".to_vec()),
        (
            "bad magic",
            b"XXXX".iter().copied().chain([0u8; 14]).collect(),
        ),
        ("4 GiB declared length", huge_len),
        ("encrypted flag", encrypted),
        ("unknown mode", bad_mode),
        ("trailing bytes", trailing),
        ("undefined flag bit", undefined_flag),
        ("LAST without STREAM", last_without_stream),
    ] {
        let mut s = connect(srv.port);
        assert_eq!(&send_frame(&mut s, &frame), b"ER", "{name}");
    }
    // oversized length prefix: refused before the body is read
    let mut s = connect(srv.port);
    s.write_all(&(1u32 << 30).to_be_bytes()).unwrap();
    let mut ack = [0u8; 2];
    s.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"ER");
    // truncated frame, then disconnect
    let mut s = connect(srv.port);
    s.write_all(&100u32.to_be_bytes()).unwrap();
    s.write_all(b"PSE2").unwrap();
    drop(s);
    thread::sleep(Duration::from_millis(300));
    assert!(srv.alive());
    let d = temp_dir("e1src");
    let p = d.join("ok.bin");
    std::fs::write(&p, prng(4_096, 11)).unwrap();
    ok(&srv.send(&p, &[]));
    assert_eq!(srv.received(1).len(), 1);
}

#[test]
fn e2_fuzz_300_random_corruptions() {
    let srv = Server::start("e2", &[]);
    let data = prng(256, 12);
    let good = raw_frame(&data, 0);
    let noise = prng(600, 13);
    for i in 0..300 {
        let mut f = good.clone();
        let pos = 4 + (noise[2 * i] as usize * 7 + noise[2 * i + 1] as usize) % (f.len() - 4);
        f[pos] ^= 1 << (noise[i] % 8);
        if f == good {
            continue;
        }
        let mut s = connect(srv.port);
        let reply = send_frame(&mut s, &f);
        // "ER": rejected. "CN": the STREAM flag (frame byte 5) was flipped; the receiver
        // waits for more frames and a sender expecting "OK" detects the mismatch.
        // A corrupted frame must never be answered with "OK".
        assert!(
            &reply == b"ER" || (&reply == b"CN" && pos == 5),
            "corruption at frame byte {pos} answered {:?}",
            String::from_utf8_lossy(&reply)
        );
    }
    assert!(
        srv.received(0).is_empty(),
        "a corrupted frame was written to disk"
    );
    assert!(srv.alive());
}

// ==================================================== F. concurrency
#[test]
fn f1_twelve_concurrent_clients() {
    let srv = Server::start("f1", &["--max-clients", "16"]);
    let d = temp_dir("f1src");
    let paths: Vec<PathBuf> = (0..12)
        .map(|i| {
            let p = d.join(format!("c{i}.bin"));
            std::fs::write(&p, prng(200_000 + i * 1_000, 100 + i as u64)).unwrap();
            p
        })
        .collect();
    let port = srv.port.to_string();
    let handles: Vec<_> = paths
        .iter()
        .cloned()
        .map(|p| {
            let port = port.clone();
            thread::spawn(move || {
                run(&[
                    "send",
                    "--port",
                    &port,
                    p.to_str().unwrap(),
                    "--chunk-kb",
                    "16",
                ])
            })
        })
        .collect();
    for h in handles {
        ok(&h.join().unwrap());
    }
    let mut expected: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
    expected.sort_by_key(|d| d.len());
    assert_eq!(srv.received(12), expected);
}

// =========================================================== G. TLS
fn tls_server(name: &str) -> Server {
    let fx = fixtures();
    Server::start(
        name,
        &[
            "--tls-cert",
            fx.join("server.pem").to_str().unwrap(),
            "--tls-key",
            fx.join("server.key").to_str().unwrap(),
        ],
    )
}

#[test]
fn g1_tls_transfer() {
    let srv = tls_server("g1");
    let d = temp_dir("g1src");
    let p = d.join("t.bin");
    let data = prng(3_000_000, 14);
    std::fs::write(&p, &data).unwrap();
    let ca = fixtures().join("ca.pem");
    let out = ok(&srv.send(
        &p,
        &[
            "--tls-ca",
            ca.to_str().unwrap(),
            "--server-name",
            "localhost",
            "--chunk-kb",
            "256",
        ],
    ));
    assert!(out.contains("TLS"), "{out}");
    assert_eq!(srv.received(1), vec![data]);
}

#[test]
fn g2_tls_rejections() {
    let srv = tls_server("g2");
    let d = temp_dir("g2src");
    let p = d.join("t.bin");
    std::fs::write(&p, prng(1_000, 15)).unwrap();
    let ca = fixtures().join("ca.pem");
    let other = fixtures().join("other_ca.pem");
    // untrusted CA
    assert!(!srv
        .send(
            &p,
            &[
                "--tls-ca",
                other.to_str().unwrap(),
                "--server-name",
                "localhost"
            ]
        )
        .status
        .success());
    // certificate does not match the requested name
    assert!(!srv
        .send(
            &p,
            &[
                "--tls-ca",
                ca.to_str().unwrap(),
                "--server-name",
                "example.com"
            ]
        )
        .status
        .success());
    // plaintext client to a TLS server
    assert!(!srv.send(&p, &[]).status.success());
    thread::sleep(Duration::from_millis(300));
    assert!(srv.received(0).is_empty());
    assert!(srv.alive());
}

// ============================================ H. Python interoperability
fn python() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|p| {
        Command::new(p)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

#[test]
fn h1_python_to_rust_and_rust_to_python() {
    let py_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("pse_net_plain.py");
    let Some(py) = python() else {
        eprintln!("skipped: Python not installed");
        return;
    };
    if !py_file.exists() {
        eprintln!("skipped: pse_net_plain.py not found");
        return;
    }
    let py_file = py_file.to_str().unwrap();
    let d = temp_dir("h1");
    let p = d.join("d.bin");
    let data = prng(50_000, 16);
    std::fs::write(&p, &data).unwrap();

    // Python sender -> Rust receiver, both modes
    let srv = Server::start("h1rust", &[]);
    for mode in ["bcd", "raw"] {
        let o = Command::new(py)
            .args([
                py_file,
                "send",
                "--port",
                &srv.port.to_string(),
                "--mode",
                mode,
                p.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        ok(&o);
    }
    assert_eq!(srv.received(2), vec![data.clone(), data.clone()]);

    // Rust sender -> Python receiver
    let port = free_port();
    let out = d.join("py.bin");
    let mut child = Command::new(py)
        .args([
            py_file,
            "receive",
            "--port",
            &port.to_string(),
            "--out",
            out.to_str().unwrap(),
            "--once",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "python receiver did not start");
        thread::sleep(Duration::from_millis(50));
    }
    // the probe above was accepted by "--once"; restart it cleanly
    let _ = child.wait();
    let mut child = Command::new(py)
        .args([
            py_file,
            "receive",
            "--port",
            &port.to_string(),
            "--out",
            out.to_str().unwrap(),
            "--once",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(800));
    ok(&run(&[
        "send",
        "--port",
        &port.to_string(),
        p.to_str().unwrap(),
        "--chunk-kb",
        "4096",
    ]));
    let _ = child.wait();
    assert_eq!(std::fs::read(&out).unwrap(), data);
}
