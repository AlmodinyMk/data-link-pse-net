//! Robustness tests of the `pse_net` binary (Linux, macOS, Windows).
//!
//!   R1. 3,000 hostile inputs (random bytes, random headers, corrupted valid frames)
//!   R2. Fragmented delivery with random delays between fragments (jitter)
//!   R3. 30,000 frames: one 30,000-frame stream, and 30,000 frames over 300 connections
//!   R4. Damaged network: a proxy that drops, duplicates and reorders packets after TCP;
//!       no corrupted file may ever be accepted, and no partial file may be left behind
//!
//! Loss, duplication and reordering on a real network are handled by TCP; R4 deliberately
//! damages the byte stream *above* TCP to check that the protocol detects it.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_pse_net");

// ------------------------------------------------------------------ helpers
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 1_000_000.0 < p
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pse_rob_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
    out: PathBuf,
}

impl Server {
    fn start(name: &str) -> Server {
        let port = free_port();
        let out = temp_dir(name).join("out");
        let child = Command::new(BIN)
            .args([
                "receive",
                "--port",
                &port.to_string(),
                "--out-dir",
                out.to_str().unwrap(),
                "--max-clients",
                "64",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "receiver did not start");
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_millis(100));
        Server { child, port, out }
    }
    fn files(&self, ext: &str) -> Vec<PathBuf> {
        std::fs::read_dir(&self.out)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.to_string_lossy().ends_with(ext))
                    .collect()
            })
            .unwrap_or_default()
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
    f.extend_from_slice(&[2, flags]);
    f.extend_from_slice(&(data.len() as u32).to_be_bytes());
    f.extend_from_slice(&(data.len() as u32).to_be_bytes());
    f.extend_from_slice(&crc32(data).to_be_bytes());
    f.extend_from_slice(data);
    f
}

fn with_prefix(frame: &[u8]) -> Vec<u8> {
    let mut m = (frame.len() as u32).to_be_bytes().to_vec();
    m.extend_from_slice(frame);
    m
}

/// Send raw bytes, half-close, and return the 2-byte reply ("" if the connection closed).
fn exchange(port: u16, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    if s.write_all(bytes).is_err() {
        return vec![];
    }
    let _ = s.shutdown(Shutdown::Write);
    let mut r = Vec::new();
    let _ = s.take(2).read_to_end(&mut r);
    r
}

// =================================================================== R1
#[test]
fn r1_three_thousand_hostile_inputs() {
    let srv = Server::start("r1");
    let mut rng = Rng(42);
    let (mut rejected, mut closed) = (0, 0);
    for i in 0..3000 {
        let msg = match i % 3 {
            0 => {
                // random bytes, random length prefix
                let body = {
                    let n = (rng.below(200)) as usize;
                    rng.bytes(n)
                };
                let mut m = (rng.below(body.len() as u64 + 10) as u32)
                    .to_be_bytes()
                    .to_vec();
                m.extend_from_slice(&body);
                m
            }
            1 => {
                // valid magic, random header and body
                let mut f = b"PSE2".to_vec();
                f.extend({
                    let n = (rng.below(120)) as usize;
                    rng.bytes(n)
                });
                with_prefix(&f)
            }
            _ => {
                // valid frame with 1-8 damaged bytes
                let d = {
                    let n = (rng.below(100)) as usize;
                    rng.bytes(n)
                };
                let mut f = raw_frame(&d, 0);
                for _ in 0..1 + rng.below(8) {
                    let j = rng.below(f.len() as u64) as usize;
                    let x = 1 + rng.below(255) as u8;
                    f[j] ^= x;
                }
                with_prefix(&f)
            }
        };
        match exchange(srv.port, &msg).as_slice() {
            b"ER" => rejected += 1,
            b"" => closed += 1,
            other => panic!(
                "hostile input #{i} answered {:?}",
                String::from_utf8_lossy(other)
            ),
        }
    }
    assert_eq!(rejected + closed, 3000);
    thread::sleep(Duration::from_millis(300));
    assert!(srv.alive(), "receiver stopped");
    assert!(
        srv.files(".bin").is_empty(),
        "a hostile input was written to disk"
    );
}

// =================================================================== R2
#[test]
fn r2_fragmented_delivery_with_jitter() {
    let srv = Server::start("r2");
    let mut rng = Rng(7);
    let mut sent = Vec::new();
    for _ in 0..20 {
        let d = {
            let n = (1 + rng.below(20_000)) as usize;
            rng.bytes(n)
        };
        let msg = with_prefix(&raw_frame(&d, 0));
        let mut s = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.set_nodelay(true).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut i = 0;
        while i < msg.len() {
            // 1..700-byte pieces, 0..20 ms apart
            let k = (1 + rng.below(700) as usize).min(msg.len() - i);
            s.write_all(&msg[i..i + k]).unwrap();
            i += k;
            thread::sleep(Duration::from_millis(rng.below(20)));
        }
        let mut ack = [0u8; 2];
        s.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"OK");
        sent.push(d);
    }
    thread::sleep(Duration::from_millis(300));
    let mut got: Vec<Vec<u8>> = srv
        .files(".bin")
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    got.sort();
    sent.sort();
    assert_eq!(got, sent);
}

// =================================================================== R3
#[test]
fn r3_thirty_thousand_frames_without_loss() {
    let srv = Server::start("r3");
    let dir = temp_dir("r3src");
    // (a) one stream of 30,000 frames of 1 KiB
    let mut rng = Rng(3);
    let data = rng.bytes(30_000 * 1024);
    let file = dir.join("d.bin");
    std::fs::write(&file, &data).unwrap();
    let o = Command::new(BIN)
        .args([
            "send",
            "--port",
            &srv.port.to_string(),
            file.to_str().unwrap(),
            "--chunk-kb",
            "1",
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("in 30000 frame(s)"));
    // (b) 30,000 single frames over 300 connections (100 streamed frames each)
    let mut acks = 0;
    for c in 0..300 {
        let mut s = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut whole = Vec::new();
        for k in 0..100 {
            let part = {
                let n = (rng.below(64)) as usize;
                rng.bytes(n)
            };
            let last = k == 99;
            let flags = 0x02 | if last { 0x04 } else { 0 };
            s.write_all(&with_prefix(&raw_frame(&part, flags))).unwrap();
            let mut ack = [0u8; 2];
            s.read_exact(&mut ack).unwrap();
            assert_eq!(
                &ack,
                if last { b"OK" } else { b"CN" },
                "connection {c}, frame {k}"
            );
            acks += 1;
            whole.extend(part);
        }
        let _ = whole;
    }
    assert_eq!(acks, 30_000);
    thread::sleep(Duration::from_millis(500));
    let files = srv.files(".bin");
    assert_eq!(files.len(), 301);
    assert!(
        files.iter().any(|p| std::fs::read(p).unwrap() == data),
        "30,000-frame file differs"
    );
}

// =================================================================== R4
/// Proxy that forwards client -> server in packets of up to 1,400 bytes and drops,
/// duplicates or swaps packets with the given probabilities. Replies pass unchanged.
/// After damage, a stalled connection is shut down on both sides.
fn damaging_proxy(target: u16, p: f64, seed: u64, stop: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let rng = Arc::new(Mutex::new(Rng(seed)));
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Ok((cli, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(5));
                continue;
            };
            cli.set_nonblocking(false).unwrap();
            let rng = rng.clone();
            thread::spawn(move || {
                let Ok(srv) = TcpStream::connect(("127.0.0.1", target)) else {
                    return;
                };
                let (mut srv_r, mut cli_w) = (srv.try_clone().unwrap(), cli.try_clone().unwrap());
                thread::spawn(move || {
                    // replies: server -> client, unchanged
                    let mut b = [0u8; 4096];
                    while let Ok(n) = srv_r.read(&mut b) {
                        if n == 0 || cli_w.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = cli_w.shutdown(Shutdown::Both);
                });
                let (mut cli_r, mut srv_w) = (cli, srv);
                cli_r
                    .set_read_timeout(Some(Duration::from_millis(300)))
                    .unwrap();
                let (mut held, mut damaged) = (None::<Vec<u8>>, false);
                let mut b = [0u8; 1400];
                loop {
                    let n = match cli_r.read(&mut b) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) if damaged => break, // stalled after damage
                        Err(_) => continue,
                    };
                    let pkt = b[..n].to_vec();
                    let r = {
                        let mut g = rng.lock().unwrap();
                        (g.chance(p), g.chance(p), g.chance(p))
                    };
                    let mut out = Vec::new();
                    if r.0 {
                        damaged = true;
                    }
                    // drop
                    else if r.1 {
                        damaged = true;
                        out.push(pkt.clone());
                        out.push(pkt);
                    }
                    // duplicate
                    else if r.2 && held.is_none() {
                        damaged = true;
                        held = Some(pkt);
                        continue;
                    }
                    // reorder
                    else {
                        out.push(pkt);
                    }
                    if !out.is_empty() {
                        if let Some(h) = held.take() {
                            out.push(h);
                        }
                    }
                    for x in out {
                        if srv_w.write_all(&x).is_err() {
                            break;
                        }
                    }
                }
                let _ = srv_w.shutdown(Shutdown::Both);
                let _ = cli_r.shutdown(Shutdown::Both);
            });
        }
    });
    port
}

#[test]
fn r4_damaged_network_never_yields_corrupted_files() {
    let srv = Server::start("r4");
    let stop = Arc::new(AtomicBool::new(false));
    let proxy = damaging_proxy(srv.port, 0.02, 11, stop.clone());
    let dir = temp_dir("r4src");
    let mut rng = Rng(5);
    let mut originals = Vec::new();
    let (mut ok, mut failed) = (0, 0);
    for i in 0..40 {
        let d = {
            let n = (10_000 + rng.below(20_000)) as usize;
            rng.bytes(n)
        };
        let f = dir.join(format!("f{i}.bin"));
        std::fs::write(&f, &d).unwrap();
        originals.push(d);
        let o = Command::new(BIN)
            .args([
                "send",
                "--port",
                &proxy.to_string(),
                f.to_str().unwrap(),
                "--chunk-kb",
                "4",
            ])
            .output()
            .unwrap();
        if o.status.success() {
            ok += 1
        } else {
            failed += 1
        }
    }
    stop.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_secs(2));
    eprintln!("damaged network: {ok} transfers succeeded, {failed} failed and were detected");
    // every completed file must be byte-identical to one of the originals
    for p in srv.files(".bin") {
        let got = std::fs::read(&p).unwrap();
        assert!(
            originals.contains(&got),
            "corrupted file accepted: {}",
            p.display()
        );
    }
    assert!(
        srv.files(".bin").len() >= ok,
        "a verified transfer is missing on the receiver"
    );
    assert!(
        srv.files(".part").is_empty(),
        "partial files were left behind"
    );
    assert!(srv.alive());
    let _ = Path::new("");
}
