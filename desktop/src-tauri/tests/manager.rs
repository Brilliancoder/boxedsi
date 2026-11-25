//! The sidecar manager against a fake sidecar. This file is its own test runner (`harness = false`) because the fake sidecar
//! is this very executable started with `--fake-sidecar`: the standard harness prints to stdout, which would corrupt frames.
//!
//! Real processes, real pipes, real exit codes. Timings are tiny but every check is a lower bound, or an upper bound with
//! seconds to spare, so a loaded machine slows the tests down without failing them.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use boxed_desktop_lib::commands;
use boxed_desktop_lib::manager::{Config, Sidecar, SidecarError, REQUEST_TIMEOUT};
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------------------------------------------------
// the fake sidecar

mod fake {
    use std::fs::OpenOptions;
    use std::io::{self, Read, Write};
    use std::process::{self, Stdio};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::{json, Value};

    /// Written by hand on purpose: a second, independent implementation of the frame format.
    fn read_request(input: &mut impl Read) -> Option<Value> {
        let mut header = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match input.read(&mut header[got..]) {
                Ok(0) => return None,
                Ok(n) => got += n,
                Err(_) => return None,
            }
        }
        let mut body = vec![0u8; u32::from_le_bytes(header) as usize];
        input.read_exact(&mut body).ok()?;
        serde_json::from_slice(&body).ok()
    }

    fn write_raw(bytes: &[u8]) {
        let mut out = io::stdout().lock();
        out.write_all(bytes).unwrap();
        out.flush().unwrap();
    }

    fn write_reply(reply: &Value) {
        let body = serde_json::to_vec(reply).unwrap();
        let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&body);
        write_raw(&bytes);
    }

    fn append(path: &str, line: &str) {
        let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(file, "{line}").unwrap();
    }

    #[cfg(unix)]
    fn group() -> u64 {
        unsafe { libc::getpgrp() as u64 }
    }

    #[cfg(not(unix))]
    fn group() -> u64 {
        0
    }

    fn forever() -> ! {
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }

    pub fn main(args: &[String]) -> ! {
        let mut marker = None;
        let mut record = None;
        let mut die_at_start: Option<(u32, String)> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--no-read" => {
                    // a sidecar stuck before it ever reads its input: whatever is written to it piles up in the pipe
                    forever();
                }
                "--marker" => marker = Some(args[i + 1].clone()),
                "--record-start" => record = Some(args[i + 1].clone()),
                "--die-at-start" => die_at_start = Some((args[i + 1].parse().unwrap(), args[i + 2].clone())),
                other => panic!("unknown fake option {other}"),
            }
            i += if args[i] == "--die-at-start" { 3 } else { 2 };
        }

        if let Some(path) = &record {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            append(path, &format!("{} {nanos}", process::id()));
        }
        eprintln!("fake: started");
        if std::env::var_os("FAKE_HANG").is_some() {
            forever(); // never reads its input: the end of input cannot end it, like a sidecar that is busy or hung
        }
        if let Some((limit, counter)) = &die_at_start {
            let seen: u32 = std::fs::read_to_string(counter).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0) + 1;
            std::fs::write(counter, seen.to_string()).unwrap();
            if seen <= *limit {
                eprintln!("fake: dying");
                process::exit(1);
            }
        }

        let mut input = io::stdin().lock();
        loop {
            let Some(request) = read_request(&mut input) else {
                if let Some(path) = &marker {
                    append(path, "eof");
                }
                process::exit(0);
            };
            let id = request["id"].clone();
            match request["cmd"].as_str().unwrap_or("") {
                "ping" => write_reply(&json!({"id": id, "ok": true, "version": "fake", "pid": process::id(), "pgid": group(), "ner_env": std::env::var("BOXED_SERVE_NER").ok()})),
                "echo" => {
                    let mut echoed = request.as_object().unwrap().clone();
                    echoed.remove("id");
                    echoed.remove("cmd");
                    write_reply(&json!({"id": id, "ok": true, "echo": echoed, "pid": process::id()}));
                }
                "error" => write_reply(&json!({"id": id, "ok": false, "error": "bad request"})),
                "sleep" => {
                    thread::sleep(Duration::from_millis(request["ms"].as_u64().unwrap()));
                    write_reply(&json!({"id": id, "ok": true}));
                }
                "big" => {
                    let text = "x".repeat(request["kb"].as_u64().unwrap() as usize * 1024);
                    write_reply(&json!({"id": id, "ok": true, "text": text}));
                }
                "stderr" => {
                    let noise = vec![b'e'; 300 * 1024];
                    io::stderr().write_all(&noise).unwrap();
                    write_reply(&json!({"id": id, "ok": true}));
                }
                "stale" => {
                    write_reply(&json!({"id": id.as_u64().unwrap() - 1, "ok": true, "stale": true}));
                    write_reply(&json!({"id": id, "ok": true, "stale": false}));
                }
                "no-id" => write_reply(&json!({"ok": true})),
                "null-id" => write_reply(&json!({"id": null, "ok": false, "error": "bad request"})),
                "no-ok" => write_reply(&json!({"id": id})),
                "garbage" => {
                    write_raw(b"this is not a frame at all, only text");
                    forever();
                }
                "oversize" => {
                    write_raw(&(17u32 * 1024 * 1024).to_le_bytes());
                    forever();
                }
                "hang" => forever(),
                "spawn-child" => {
                    // a process of its own that outlives a plain kill of this one: it sleeps, and its pid goes into the file
                    let child = process::Command::new("sleep").arg("600").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
                    std::fs::write(request["file"].as_str().unwrap(), child.id().to_string()).unwrap();
                    forever();
                }
                "stderr-lines" => {
                    let width = request["width"].as_u64().unwrap_or(0) as usize;
                    for n in 0..request["n"].as_u64().unwrap() {
                        eprintln!("fake line {n} {}", "x".repeat(width));
                    }
                    write_reply(&json!({"id": id, "ok": true}));
                }
                "crash" => process::exit(1),
                "exit0" => process::exit(0),
                "reply-then-crash" => {
                    write_reply(&json!({"id": id, "ok": true}));
                    process::exit(1);
                }
                "reply-then-exit0" => {
                    write_reply(&json!({"id": id, "ok": true}));
                    process::exit(0);
                }
                "reply-then-exit0-slow" => {
                    write_reply(&json!({"id": id, "ok": true}));
                    thread::sleep(Duration::from_millis(300));
                    process::exit(0);
                }
                other => panic!("unknown fake command {other}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// helpers

fn fields(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("fields must be an object"),
    }
}

/// A folder for one test under the target folder, emptied at the start and removed at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("manager-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn file(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }

    /// (pid, unix nanoseconds) of every start the fake recorded with `--record-start starts`.
    fn starts(&self) -> Vec<(u32, u128)> {
        let text = fs::read_to_string(self.0.join("starts")).unwrap_or_default();
        text.lines()
            .map(|line| {
                let (pid, nanos) = line.split_once(' ').unwrap();
                (pid.parse().unwrap(), nanos.parse().unwrap())
            })
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Fast timings; the 120 s of production is checked separately (`defaults`).
fn config(fake_args: &[&str]) -> Config {
    let mut args = vec![OsString::from("--fake-sidecar")];
    args.extend(fake_args.iter().map(OsString::from));
    let mut config = Config::new(env::current_exe().unwrap(), args);
    config.request_timeout = Duration::from_secs(20);
    config.backoff = [0, 40, 80, 160].map(Duration::from_millis).to_vec();
    config.stop_grace = Duration::from_secs(3);
    config
}

fn sidecar(fake_args: &[&str]) -> Sidecar {
    Sidecar::start(config(fake_args))
}

fn ping(sidecar: &Sidecar) -> Result<Map<String, Value>, SidecarError> {
    sidecar.request("ping", Map::new())
}

fn eventually(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < within, "gave up waiting for: {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stderr(process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}


#[cfg(unix)]
fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The parent of a process, from ps; None when there is no such process.
#[cfg(unix)]
fn parent_of(pid: u32) -> Option<u32> {
    let out = process::Command::new("ps").args(["-o", "ppid=", "-p", &pid.to_string()]).output().ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

/// Starts `program args` in the background from a shell that then ends, so that the parent of the process is pid 1: what is
/// left of a sidecar when its app is killed.
#[cfg(unix)]
fn orphan(env: &[(&str, &str)], program: &str, args: &[&str]) -> u32 {
    let setting: String = env.iter().map(|(name, value)| format!("{name}={value} ")).collect();
    let line = format!("{setting}'{program}' {} >/dev/null 2>&1 </dev/null & echo $!", args.join(" "));
    let out = process::Command::new("/bin/sh").arg("-c").arg(line).output().unwrap();
    let pid: u32 = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
    eventually("the shell to be gone", Duration::from_secs(5), || parent_of(pid) == Some(1));
    pid
}

#[cfg(unix)]
fn kill(pid: u32) {
    let _ = process::Command::new("kill").arg("-9").arg(pid.to_string()).stderr(Stdio::null()).status();
}

#[cfg(unix)]
fn with_pid_dir(scratch: &Scratch) -> Config {
    let mut config = config(&[]);
    config.pid_dir = Some(scratch.0.clone());
    config
}

// ---------------------------------------------------------------------------------------------------------------------
// the tests

fn defaults() {
    let config = Config::new("boxed", vec![OsString::from("serve")]);
    assert_eq!(config.request_timeout, Duration::from_secs(120));
    assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(120));
    let seconds: Vec<f64> = config.backoff.iter().map(Duration::as_secs_f64).collect();
    assert_eq!(seconds, [0.0, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 30.0]);
    assert!(config.stop_grace >= Duration::from_secs(1));
}

fn ping_round_trip() {
    let sidecar = sidecar(&[]);
    let reply = ping(&sidecar).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["version"], "fake");
    assert!(!reply.contains_key("id"), "the id is the manager's business, not the caller's");
    sidecar.shutdown();
}

fn the_first_sidecar_starts_at_launch_not_with_the_first_request() {
    let scratch = Scratch::new("launch");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    eventually("the first start", Duration::from_secs(5), || scratch.starts().len() == 1);
    sidecar.shutdown();
}

fn fields_reach_the_sidecar_and_text_survives_unchanged() {
    let sidecar = sidecar(&[]);
    let text = "Привет, [CLIENT_1]! \u{1F4E6} line\nbreak \"quoted\" \\ tab\t";
    let reply = sidecar.request("echo", fields(json!({"text": text, "level": 3, "scope": null}))).unwrap();
    assert_eq!(reply["echo"], json!({"text": text, "level": 3, "scope": null}));
    sidecar.shutdown();
}

fn requests_from_many_threads_each_get_their_own_reply() {
    let sidecar = sidecar(&[]);
    let workers: Vec<_> = (0..8)
        .map(|n| {
            let sidecar = sidecar.clone();
            thread::spawn(move || {
                for round in 0..5 {
                    let tag = format!("{n}-{round}");
                    let reply = sidecar.request("echo", fields(json!({"tag": tag}))).unwrap();
                    assert_eq!(reply["echo"]["tag"], tag.as_str());
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    sidecar.shutdown();
}

fn a_reply_that_belongs_to_another_request_is_skipped() {
    let sidecar = sidecar(&[]);
    let reply = sidecar.request("stale", Map::new()).unwrap();
    assert_eq!(reply["stale"], false, "the stale reply was delivered instead of the real one");
    assert!(ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn an_error_reply_of_the_sidecar_is_a_reply_not_a_failure() {
    let sidecar = sidecar(&[]);
    let reply = sidecar.request("error", Map::new()).unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"], "bad request");
    sidecar.shutdown();
}

fn a_reply_without_id_ok_or_with_a_null_id_is_a_protocol_error_and_the_sidecar_is_replaced() {
    for bad in ["no-id", "no-ok", "null-id"] {
        let scratch = Scratch::new("bad-reply");
        let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
        assert_eq!(sidecar.request(bad, Map::new()), Err(SidecarError::Protocol), "{bad}");
        eventually("the replacement answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
        assert_eq!(scratch.starts().len(), 2, "{bad}: the sidecar that broke the protocol must be replaced");
        sidecar.shutdown();
    }
}

fn garbage_bytes_and_an_oversize_header_are_protocol_errors_and_the_sidecar_is_killed_and_replaced() {
    for bad in ["garbage", "oversize"] {
        let scratch = Scratch::new("garbage");
        let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
        let first_pid = ping(&sidecar).unwrap()["pid"].as_u64().unwrap() as u32;
        assert_eq!(sidecar.request(bad, Map::new()), Err(SidecarError::Protocol), "{bad}");
        eventually("the replacement answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
        assert_eq!(scratch.starts().len(), 2, "{bad}");
        #[cfg(unix)]
        assert!(!alive(first_pid), "{bad}: the broken sidecar is still running");
        let _ = first_pid;
        sidecar.shutdown();
    }
}

fn a_crash_in_the_middle_of_a_request_fails_that_request_and_the_next_one_works() {
    let scratch = Scratch::new("crash");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    assert!(ping(&sidecar).is_ok());
    assert_eq!(sidecar.request("crash", Map::new()), Err(SidecarError::Unavailable));
    eventually("the restarted sidecar answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(scratch.starts().len(), 2);
    sidecar.shutdown();
}

fn a_crash_while_idle_is_repaired_without_waiting_for_a_request() {
    let scratch = Scratch::new("idle-crash");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    assert!(sidecar.request("reply-then-crash", Map::new()).is_ok());
    eventually("a second start with no request made", Duration::from_secs(10), || scratch.starts().len() == 2);
    assert!(ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn a_sidecar_that_ends_itself_after_a_reply_is_started_again_without_counting_it_as_a_failure() {
    let scratch = Scratch::new("exit0");
    let mut slow = config(&["--record-start", &scratch.file("starts")]);
    slow.backoff = vec![Duration::ZERO, Duration::from_secs(30)]; // a second failure in a row would wait 30 s
    let sidecar = Sidecar::start(slow);
    let started = Instant::now();
    for _ in 0..5 {
        assert!(sidecar.request("reply-then-exit0", Map::new()).is_ok());
    }
    assert!(ping(&sidecar).is_ok());
    assert!(started.elapsed() < Duration::from_secs(25), "a clean exit must not be punished with a backoff");
    assert!(scratch.starts().len() >= 6);
    sidecar.shutdown();
}

fn a_request_written_to_a_sidecar_that_was_about_to_end_itself_is_sent_again() {
    let scratch = Scratch::new("exit0-slow");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    assert!(sidecar.request("reply-then-exit0-slow", Map::new()).is_ok());
    // the sidecar sleeps before it leaves; this request goes into its pipe and is never read
    let reply = sidecar.request("echo", fields(json!({"tag": "second"}))).unwrap();
    assert_eq!(reply["echo"]["tag"], "second");
    assert_eq!(scratch.starts().len(), 2);
    sidecar.shutdown();
}

fn a_sidecar_that_keeps_ending_itself_without_answering_is_given_up_on() {
    let scratch = Scratch::new("exit0-always");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    assert_eq!(sidecar.request("exit0", Map::new()), Err(SidecarError::Unavailable));
    assert!(scratch.starts().len() <= 3, "one retry, not a loop");
    sidecar.shutdown();
}

fn restarts_wait_longer_after_each_failed_run() {
    let scratch = Scratch::new("backoff");
    let mut config = config(&["--record-start", &scratch.file("starts"), "--die-at-start", "3", &scratch.file("counter")]);
    config.backoff = vec![Duration::ZERO, Duration::from_millis(150), Duration::from_millis(300)];
    config.max_failures = 10; // this test is about the waits; giving up is tested on its own
    let sidecar = Sidecar::start(config);
    eventually("four starts", Duration::from_secs(10), || scratch.starts().len() >= 4);
    let at: Vec<u128> = scratch.starts().iter().map(|(_, nanos)| nanos / 1_000_000).collect();
    assert!(at[2] - at[1] >= 140, "second restart came after {} ms", at[2] - at[1]);
    assert!(at[3] - at[2] >= 290, "third restart came after {} ms", at[3] - at[2]);
    eventually("the fourth sidecar answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(scratch.starts().len(), 4, "no more starts than needed");
    sidecar.shutdown();
}

fn a_good_answer_wipes_the_memory_of_earlier_failures() {
    let scratch = Scratch::new("backoff-reset");
    let mut config = config(&["--record-start", &scratch.file("starts"), "--die-at-start", "1", &scratch.file("counter")]);
    config.backoff = vec![Duration::ZERO, Duration::from_secs(3)];
    let sidecar = Sidecar::start(config);
    eventually("the second sidecar answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(sidecar.request("crash", Map::new()), Err(SidecarError::Unavailable));
    let started = Instant::now();
    eventually("the third sidecar answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert!(started.elapsed() < Duration::from_millis(2500), "the old failure still counted: {:?}", started.elapsed());
    sidecar.shutdown();
}

fn requests_fail_at_once_while_a_restart_is_waiting_and_succeed_after_it() {
    let scratch = Scratch::new("waiting");
    let mut config = config(&["--record-start", &scratch.file("starts"), "--die-at-start", "2", &scratch.file("counter")]);
    config.backoff = vec![Duration::ZERO, Duration::from_millis(1500)];
    let sidecar = Sidecar::start(config);
    eventually("two starts", Duration::from_secs(10), || scratch.starts().len() == 2);
    let started = Instant::now();
    assert_eq!(ping(&sidecar), Err(SidecarError::Unavailable));
    assert!(started.elapsed() < Duration::from_millis(1000), "waited {:?} for a restart that is not due", started.elapsed());
    eventually("the third sidecar answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn a_program_that_does_not_exist_gives_unavailable_and_is_picked_up_when_it_appears() {
    let scratch = Scratch::new("missing");
    let program = scratch.0.join("bin").join("boxed");
    let mut config = Config::new(&program, vec![OsString::from("--fake-sidecar")]);
    config.backoff = vec![Duration::ZERO, Duration::from_millis(50)];
    config.max_failures = 1000; // it is tried again and again until the program is there
    let sidecar = Sidecar::start(config);
    assert_eq!(ping(&sidecar), Err(SidecarError::Unavailable));
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::copy(env::current_exe().unwrap(), &program).unwrap();
    eventually("the installed program answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn a_hung_sidecar_is_given_up_on_killed_and_replaced() {
    let scratch = Scratch::new("hang");
    let mut config = config(&["--record-start", &scratch.file("starts")]);
    config.request_timeout = Duration::from_millis(1000);
    let sidecar = Sidecar::start(config);
    let first_pid = ping(&sidecar).unwrap()["pid"].as_u64().unwrap() as u32;
    let started = Instant::now();
    assert_eq!(sidecar.request("hang", Map::new()), Err(SidecarError::Timeout));
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(950), "gave up after only {waited:?}");
    assert!(waited < Duration::from_secs(5), "gave up after {waited:?}");
    eventually("the replacement answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(scratch.starts().len(), 2);
    #[cfg(unix)]
    assert!(!alive(first_pid), "the hung sidecar is still running");
    let _ = first_pid;
    sidecar.shutdown();
}

fn a_sidecar_that_never_reads_cannot_stall_the_shell() {
    let mut config = config(&["--no-read"]);
    config.request_timeout = Duration::from_millis(800);
    let sidecar = Sidecar::start(config);
    // far more than a pipe holds: the write blocks, and the deadline must fire all the same
    let text = "x".repeat(900_000);
    let started = Instant::now();
    assert_eq!(sidecar.request("echo", fields(json!({"text": text}))), Err(SidecarError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5), "gave up after {:?}", started.elapsed());
    let started = Instant::now();
    sidecar.shutdown();
    assert!(started.elapsed() < Duration::from_secs(10), "shutdown took {:?}", started.elapsed());
}

fn a_slow_sidecar_that_answers_in_time_is_not_cut_off() {
    let mut config = config(&[]);
    config.request_timeout = Duration::from_secs(5);
    let sidecar = Sidecar::start(config);
    assert!(sidecar.request("sleep", fields(json!({"ms": 600}))).is_ok());
    sidecar.shutdown();
}

fn the_time_limit_counts_from_the_request_so_a_waiting_request_shares_it() {
    let mut config = config(&[]);
    config.request_timeout = Duration::from_millis(1500);
    let sidecar = Sidecar::start(config);
    assert!(ping(&sidecar).is_ok());
    let first = {
        let sidecar = sidecar.clone();
        thread::spawn(move || sidecar.request("sleep", fields(json!({"ms": 900}))))
    };
    thread::sleep(Duration::from_millis(100)); // the first request is on its way
    let second = sidecar.request("sleep", fields(json!({"ms": 900})));
    assert!(first.join().unwrap().is_ok());
    assert_eq!(second, Err(SidecarError::Timeout), "900 ms of waiting plus 900 ms of work is over 1500 ms");
    sidecar.shutdown();
}

fn a_request_over_the_frame_cap_is_refused_without_touching_the_sidecar() {
    let scratch = Scratch::new("too-large");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts")]);
    assert!(ping(&sidecar).is_ok());
    let text = "x".repeat(1024 * 1024);
    assert_eq!(sidecar.request("echo", fields(json!({"text": text}))), Err(SidecarError::TooLarge));
    assert!(ping(&sidecar).is_ok());
    assert_eq!(scratch.starts().len(), 1, "a request that never left the shell must not restart the sidecar");
    sidecar.shutdown();
}

fn a_request_close_to_the_cap_and_a_large_reply_go_through() {
    let sidecar = sidecar(&[]);
    let text = "я".repeat(400_000); // 800 000 bytes of UTF-8
    let reply = sidecar.request("echo", fields(json!({"text": text}))).unwrap();
    assert_eq!(reply["echo"]["text"].as_str().unwrap().len(), 800_000);
    let reply = sidecar.request("big", fields(json!({"kb": 3000}))).unwrap();
    assert_eq!(reply["text"].as_str().unwrap().len(), 3000 * 1024);
    sidecar.shutdown();
}

fn a_request_may_not_carry_its_own_id_or_command() {
    let sidecar = sidecar(&[]);
    assert_eq!(sidecar.request("echo", fields(json!({"id": 5}))), Err(SidecarError::BadRequest));
    assert_eq!(sidecar.request("echo", fields(json!({"cmd": "crash"}))), Err(SidecarError::BadRequest));
    assert_eq!(sidecar.request("", Map::new()), Err(SidecarError::BadRequest));
    assert!(ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn noise_on_the_sidecars_error_stream_is_discarded_and_never_blocks_it() {
    let sidecar = sidecar(&[]);
    assert!(sidecar.request("stderr", Map::new()).is_ok());
    assert!(ping(&sidecar).is_ok());
    sidecar.shutdown();
}

fn shutdown_closes_the_input_so_the_sidecar_leaves_by_itself() {
    let scratch = Scratch::new("shutdown");
    let sidecar = sidecar(&["--marker", &scratch.file("marker")]);
    let pid = ping(&sidecar).unwrap()["pid"].as_u64().unwrap() as u32;
    sidecar.shutdown();
    assert_eq!(fs::read_to_string(scratch.0.join("marker")).unwrap().trim(), "eof", "it was killed instead of asked to leave");
    #[cfg(unix)]
    assert!(!alive(pid));
    let _ = pid;
    assert_eq!(ping(&sidecar), Err(SidecarError::Stopped));
    sidecar.shutdown(); // twice is fine
}

fn shutdown_kills_a_sidecar_that_does_not_leave_and_stops_the_request_waiting_for_it() {
    let mut config = config(&[]);
    config.stop_grace = Duration::from_millis(300);
    let sidecar = Sidecar::start(config);
    let pid = ping(&sidecar).unwrap()["pid"].as_u64().unwrap() as u32;
    let waiting = {
        let sidecar = sidecar.clone();
        thread::spawn(move || sidecar.request("hang", Map::new()))
    };
    thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    sidecar.shutdown();
    assert!(started.elapsed() < Duration::from_secs(5), "shutdown took {:?}", started.elapsed());
    assert_eq!(waiting.join().unwrap(), Err(SidecarError::Stopped));
    #[cfg(unix)]
    assert!(!alive(pid));
    let _ = pid;
}

fn dropping_the_last_handle_stops_the_sidecar() {
    let scratch = Scratch::new("drop");
    let sidecar = sidecar(&["--marker", &scratch.file("marker")]);
    assert!(ping(&sidecar).is_ok());
    drop(sidecar);
    eventually("the sidecar leaves", Duration::from_secs(10), || fs::read_to_string(scratch.0.join("marker")).is_ok());
}

fn the_front_end_command_hands_the_reply_over_without_the_id() {
    let sidecar = sidecar(&[]);
    let reply = commands::dispatch(&sidecar, "ping", Map::new());
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["version"], "fake");
    assert!(reply.get("id").is_none());
    sidecar.shutdown();
}

#[cfg(unix)]
fn the_sidecar_leads_its_own_process_group_and_a_timeout_ends_the_whole_group() {
    let scratch = Scratch::new("group");
    let mut config = config(&[]);
    config.request_timeout = Duration::from_millis(2500);
    let sidecar = Sidecar::start(config);
    let reply = ping(&sidecar).unwrap();
    assert_eq!(reply["pgid"], reply["pid"], "the sidecar leads a process group of its own");
    let file = scratch.file("child.pid");
    assert_eq!(sidecar.request("spawn-child", fields(json!({"file": file}))), Err(SidecarError::Timeout));
    let child = read_pid(&scratch.0.join("child.pid")).expect("the sidecar started a process of its own");
    eventually("the process the sidecar started is gone", Duration::from_secs(5), || !alive(child));
    sidecar.shutdown();
}

#[cfg(unix)]
fn shutdown_ends_the_whole_group_of_a_sidecar_that_does_not_leave() {
    let scratch = Scratch::new("group-stop");
    let mut config = config(&[]);
    config.stop_grace = Duration::from_millis(300);
    let sidecar = Sidecar::start(config);
    assert!(ping(&sidecar).is_ok());
    let file = scratch.file("child.pid");
    let waiting = {
        let sidecar = sidecar.clone();
        thread::spawn(move || sidecar.request("spawn-child", fields(json!({"file": file}))))
    };
    let child = {
        let path = scratch.0.join("child.pid");
        let mut found = None;
        eventually("the sidecar to start its process", Duration::from_secs(5), || {
            found = read_pid(&path);
            found.is_some()
        });
        found.unwrap()
    };
    sidecar.shutdown();
    assert_eq!(waiting.join().unwrap(), Err(SidecarError::Stopped));
    eventually("the process the sidecar started is gone", Duration::from_secs(5), || !alive(child));
}

#[cfg(unix)]
fn a_leftover_sidecar_of_a_dead_app_is_ended_when_the_manager_starts() {
    let scratch = Scratch::new("leftover");
    let exe = env::current_exe().unwrap();
    // busy or hung: it never reads its input, so the end of input that closed with its app did not end it
    let leftover = orphan(&[("FAKE_HANG", "1")], exe.to_str().unwrap(), &["--fake-sidecar"]);
    fs::write(scratch.0.join("sidecar-1.pid"), leftover.to_string()).unwrap(); // the file of the app that is gone
    assert!(alive(leftover));
    let sidecar = Sidecar::start(with_pid_dir(&scratch));
    assert!(ping(&sidecar).is_ok());
    eventually("the leftover to be gone", Duration::from_secs(5), || !alive(leftover));
    assert!(!scratch.0.join("sidecar-1.pid").exists(), "its file goes with it");
    sidecar.shutdown();
}

#[cfg(unix)]
fn a_leftover_is_found_although_the_path_of_the_app_names_no_folder() {
    // an app started from the Finder has a short PATH, and a program started by a script, as in the smoke test, may have none
    let scratch = Scratch::new("leftover-no-path");
    let exe = env::current_exe().unwrap();
    let leftover = orphan(&[("FAKE_HANG", "1")], exe.to_str().unwrap(), &["--fake-sidecar"]);
    fs::write(scratch.0.join("sidecar-1.pid"), leftover.to_string()).unwrap();
    let path = env::var_os("PATH");
    env::set_var("PATH", "");
    let sidecar = Sidecar::start(with_pid_dir(&scratch));
    let answered = ping(&sidecar).is_ok();
    sidecar.shutdown();
    match path {
        Some(path) => env::set_var("PATH", path),
        None => env::remove_var("PATH"),
    }
    assert!(answered);
    eventually("the leftover to be gone", Duration::from_secs(5), || !alive(leftover));
}

#[cfg(unix)]
fn a_sidecar_that_still_has_its_app_is_left_alone() {
    let scratch = Scratch::new("not-a-leftover");
    let mut running = process::Command::new(env::current_exe().unwrap())
        .arg("--fake-sidecar")
        .env("FAKE_HANG", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap(); // its parent is this test, not pid 1
    fs::write(scratch.0.join("sidecar-1.pid"), running.id().to_string()).unwrap();
    let sidecar = Sidecar::start(with_pid_dir(&scratch));
    assert!(ping(&sidecar).is_ok());
    assert!(alive(running.id()), "the sidecar of another running app was ended");
    assert!(scratch.0.join("sidecar-1.pid").exists(), "its app still needs its file");
    sidecar.shutdown();
    let _ = running.kill();
    let _ = running.wait();
}

#[cfg(unix)]
fn a_pid_file_that_names_another_program_does_not_end_it() {
    let scratch = Scratch::new("other-program");
    let other = orphan(&[], "/bin/sleep", &["600"]); // an orphan too, but not our sidecar: the pid was reused
    fs::write(scratch.0.join("sidecar-1.pid"), other.to_string()).unwrap();
    let sidecar = Sidecar::start(with_pid_dir(&scratch));
    assert!(ping(&sidecar).is_ok());
    assert!(alive(other), "a program that is not the sidecar of this app was ended");
    assert!(!scratch.0.join("sidecar-1.pid").exists(), "the record is stale and goes");
    sidecar.shutdown();
    kill(other);
}

#[cfg(unix)]
fn the_pid_file_names_the_running_sidecar_and_goes_with_a_clean_shutdown() {
    let scratch = Scratch::new("pid-file");
    let file = scratch.0.join(format!("sidecar-{}.pid", process::id()));
    let sidecar = Sidecar::start(with_pid_dir(&scratch));
    let first = ping(&sidecar).unwrap()["pid"].as_u64().unwrap() as u32;
    assert_eq!(read_pid(&file), Some(first));
    assert_eq!(sidecar.request("crash", Map::new()), Err(SidecarError::Unavailable));
    let mut second = first;
    eventually("the restarted sidecar answers", Duration::from_secs(10), || {
        second = ping(&sidecar).map(|reply| reply["pid"].as_u64().unwrap() as u32).unwrap_or(first);
        second != first
    });
    assert_eq!(read_pid(&file), Some(second), "the file follows the restart");
    sidecar.shutdown();
    assert!(!file.exists(), "a clean end leaves no file behind");
}

fn a_sidecar_that_keeps_failing_is_given_up_on_after_three_failures_in_a_minute() {
    let scratch = Scratch::new("give-up");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts"), "--die-at-start", "100", &scratch.file("counter")]);
    eventually("the manager to give up", Duration::from_secs(10), || ping(&sidecar) == Err(SidecarError::GaveUp));
    assert_eq!(scratch.starts().len(), 3, "three runs, and no more");
    thread::sleep(Duration::from_millis(600));
    assert_eq!(scratch.starts().len(), 3, "it does not start the sidecar again by itself");
    let started = Instant::now();
    assert_eq!(ping(&sidecar), Err(SidecarError::GaveUp));
    assert!(started.elapsed() < Duration::from_secs(1), "a request is answered at once, not kept waiting");
    let report = sidecar.diagnostics();
    assert!(report.gave_up);
    assert_eq!(report.restarts, 2);
    assert_eq!(report.last_exit_code, Some(1));
    eventually("the last words of the sidecar", Duration::from_secs(5), || {
        let tail = sidecar.diagnostics().stderr_tail;
        tail.contains(&"fake: dying".to_string()) && tail.contains(&"fake: started".to_string())
    });
    sidecar.shutdown();
}

fn retry_starts_the_sidecar_again_once_the_cause_is_gone() {
    let scratch = Scratch::new("retry");
    let sidecar = sidecar(&["--record-start", &scratch.file("starts"), "--die-at-start", "3", &scratch.file("counter")]);
    eventually("the manager to give up", Duration::from_secs(10), || ping(&sidecar) == Err(SidecarError::GaveUp));
    sidecar.retry();
    eventually("the sidecar to answer", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(scratch.starts().len(), 4);
    let report = sidecar.diagnostics();
    assert!(!report.gave_up);
    assert_eq!(report.restarts, 3);
    sidecar.shutdown();
}

fn failures_that_are_far_apart_do_not_add_up() {
    let scratch = Scratch::new("far-apart");
    let mut config = config(&["--record-start", &scratch.file("starts"), "--die-at-start", "4", &scratch.file("counter")]);
    config.backoff = vec![Duration::ZERO, Duration::from_millis(400)];
    config.failure_window = Duration::from_millis(300);
    let sidecar = Sidecar::start(config);
    eventually("the fifth sidecar answers", Duration::from_secs(20), || ping(&sidecar).is_ok());
    assert!(!sidecar.diagnostics().gave_up);
    assert_eq!(scratch.starts().len(), 5);
    sidecar.shutdown();
}

fn timeouts_count_as_failures_too() {
    let mut config = config(&[]);
    config.request_timeout = Duration::from_millis(400);
    config.max_failures = 2;
    let sidecar = Sidecar::start(config);
    assert_eq!(sidecar.request("hang", Map::new()), Err(SidecarError::Timeout));
    assert_eq!(sidecar.request("hang", Map::new()), Err(SidecarError::Timeout));
    assert_eq!(ping(&sidecar), Err(SidecarError::GaveUp), "two hung requests in a row: the manager stops replacing the sidecar");
    sidecar.shutdown();
}

fn the_last_error_lines_are_kept_short_and_in_memory_only() {
    let sidecar = sidecar(&[]);
    assert!(sidecar.request("stderr-lines", fields(json!({"n": 100, "width": 500}))).is_ok());
    eventually("the lines to be read", Duration::from_secs(5), || sidecar.diagnostics().stderr_tail.last().is_some_and(|line| line.starts_with("fake line 99 ")));
    let tail = sidecar.diagnostics().stderr_tail;
    assert_eq!(tail.len(), 20, "only the last lines are kept");
    assert!(tail.iter().all(|line| line.len() <= 200), "a long line is cut");
    sidecar.shutdown();
}

#[cfg(unix)]
fn the_diagnostics_say_how_the_last_run_ended() {
    let mut config = config(&[]);
    config.request_timeout = Duration::from_millis(1000);
    let sidecar = Sidecar::start(config);
    assert!(ping(&sidecar).is_ok());
    assert_eq!(sidecar.request("crash", Map::new()), Err(SidecarError::Unavailable));
    eventually("the exit code", Duration::from_secs(5), || sidecar.diagnostics().last_exit_code == Some(1));
    eventually("the sidecar that replaced it answers", Duration::from_secs(10), || ping(&sidecar).is_ok());
    assert_eq!(sidecar.request("hang", Map::new()), Err(SidecarError::Timeout));
    eventually("the signal that ended the hung sidecar", Duration::from_secs(5), || {
        let report = sidecar.diagnostics();
        report.last_signal == Some(9) && report.last_exit_code.is_none()
    });
    sidecar.shutdown();
}

fn the_environment_of_the_config_reaches_the_sidecar_and_nothing_else_is_added() {
    let plain = sidecar(&[]);
    assert_eq!(ping(&plain).unwrap()["ner_env"], Value::Null);
    plain.shutdown();
    let mut config = config(&[]);
    config.env = vec![(OsString::from("BOXED_SERVE_NER"), OsString::from("ru"))];
    let switched = Sidecar::start(config);
    assert_eq!(ping(&switched).unwrap()["ner_env"], "ru");
    switched.shutdown();
}

fn error_texts_are_fixed_sentences_with_codes() {
    let all = [
        (SidecarError::Unavailable, "unavailable"),
        (SidecarError::GaveUp, "gave-up"),
        (SidecarError::Timeout, "timeout"),
        (SidecarError::Protocol, "protocol"),
        (SidecarError::TooLarge, "too-large"),
        (SidecarError::BadRequest, "bad-request"),
        (SidecarError::Stopped, "stopped"),
    ];
    let mut seen = Vec::new();
    for (error, code) in all {
        assert_eq!(error.code(), code);
        let message = error.message();
        assert!(message.len() > 20 && message.ends_with('.'), "{message}");
        assert!(!message.contains('\u{2014}') && !message.contains('\u{2013}'), "no dashes in product texts: {message}");
        assert!(!seen.contains(&message), "two errors share the text: {message}");
        seen.push(message);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the runner

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--fake-sidecar") {
        fake::main(&args[1..]);
    }
    let filter: Vec<&String> = args.iter().filter(|arg| !arg.starts_with("--")).collect();

    let tests: &[(&str, fn())] = &[
        ("defaults", defaults),
        ("ping_round_trip", ping_round_trip),
        ("the_first_sidecar_starts_at_launch", the_first_sidecar_starts_at_launch_not_with_the_first_request),
        ("fields_and_text_survive", fields_reach_the_sidecar_and_text_survives_unchanged),
        ("many_threads", requests_from_many_threads_each_get_their_own_reply),
        ("stale_reply_skipped", a_reply_that_belongs_to_another_request_is_skipped),
        ("error_reply_passes_through", an_error_reply_of_the_sidecar_is_a_reply_not_a_failure),
        ("bad_reply_is_protocol_error", a_reply_without_id_ok_or_with_a_null_id_is_a_protocol_error_and_the_sidecar_is_replaced),
        ("garbage_and_oversize", garbage_bytes_and_an_oversize_header_are_protocol_errors_and_the_sidecar_is_killed_and_replaced),
        ("crash_mid_request", a_crash_in_the_middle_of_a_request_fails_that_request_and_the_next_one_works),
        ("crash_while_idle", a_crash_while_idle_is_repaired_without_waiting_for_a_request),
        ("clean_exit_after_reply", a_sidecar_that_ends_itself_after_a_reply_is_started_again_without_counting_it_as_a_failure),
        ("request_sent_again_after_clean_exit", a_request_written_to_a_sidecar_that_was_about_to_end_itself_is_sent_again),
        ("clean_exit_without_answer", a_sidecar_that_keeps_ending_itself_without_answering_is_given_up_on),
        ("backoff_grows", restarts_wait_longer_after_each_failed_run),
        ("backoff_resets", a_good_answer_wipes_the_memory_of_earlier_failures),
        ("fail_fast_while_waiting", requests_fail_at_once_while_a_restart_is_waiting_and_succeed_after_it),
        ("missing_program", a_program_that_does_not_exist_gives_unavailable_and_is_picked_up_when_it_appears),
        ("hang_times_out", a_hung_sidecar_is_given_up_on_killed_and_replaced),
        ("never_reads", a_sidecar_that_never_reads_cannot_stall_the_shell),
        ("slow_but_in_time", a_slow_sidecar_that_answers_in_time_is_not_cut_off),
        ("deadline_from_the_request", the_time_limit_counts_from_the_request_so_a_waiting_request_shares_it),
        ("request_over_the_cap", a_request_over_the_frame_cap_is_refused_without_touching_the_sidecar),
        ("large_frames", a_request_close_to_the_cap_and_a_large_reply_go_through),
        ("id_and_cmd_reserved", a_request_may_not_carry_its_own_id_or_command),
        ("stderr_noise", noise_on_the_sidecars_error_stream_is_discarded_and_never_blocks_it),
        ("shutdown_by_eof", shutdown_closes_the_input_so_the_sidecar_leaves_by_itself),
        ("shutdown_kills_after_grace", shutdown_kills_a_sidecar_that_does_not_leave_and_stops_the_request_waiting_for_it),
        ("drop_stops_the_sidecar", dropping_the_last_handle_stops_the_sidecar),
        ("front_end_command", the_front_end_command_hands_the_reply_over_without_the_id),
        #[cfg(unix)]
        ("group_kill_on_timeout", the_sidecar_leads_its_own_process_group_and_a_timeout_ends_the_whole_group),
        #[cfg(unix)]
        ("group_kill_on_shutdown", shutdown_ends_the_whole_group_of_a_sidecar_that_does_not_leave),
        #[cfg(unix)]
        ("leftover_is_ended", a_leftover_sidecar_of_a_dead_app_is_ended_when_the_manager_starts),
        #[cfg(unix)]
        ("leftover_without_a_path", a_leftover_is_found_although_the_path_of_the_app_names_no_folder),
        #[cfg(unix)]
        ("live_sidecar_is_left_alone", a_sidecar_that_still_has_its_app_is_left_alone),
        #[cfg(unix)]
        ("other_program_is_left_alone", a_pid_file_that_names_another_program_does_not_end_it),
        #[cfg(unix)]
        ("pid_file_lifecycle", the_pid_file_names_the_running_sidecar_and_goes_with_a_clean_shutdown),
        ("environment", the_environment_of_the_config_reaches_the_sidecar_and_nothing_else_is_added),
        ("gives_up", a_sidecar_that_keeps_failing_is_given_up_on_after_three_failures_in_a_minute),
        ("retry", retry_starts_the_sidecar_again_once_the_cause_is_gone),
        ("failures_far_apart", failures_that_are_far_apart_do_not_add_up),
        ("timeouts_count", timeouts_count_as_failures_too),
        ("stderr_tail", the_last_error_lines_are_kept_short_and_in_memory_only),
        #[cfg(unix)]
        ("diagnostics_exit", the_diagnostics_say_how_the_last_run_ended),
        ("error_texts", error_texts_are_fixed_sentences_with_codes),
    ];

    let mut failed = Vec::new();
    let mut passed = 0;
    for (name, test) in tests {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let outcome = std::panic::catch_unwind(test);
            let _ = done_tx.send(outcome.is_ok());
        });
        // a test that hangs would hang `cargo test`: stop everything after a minute
        match done_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(true) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Ok(false) => {
                println!("test {name} ... FAILED");
                failed.push(*name);
            }
            Err(_) => {
                println!("test {name} ... HUNG for 60 s");
                process::exit(2);
            }
        }
        let _ = worker.join();
    }
    println!("\ntest result: {}. {passed} passed; {} failed", if failed.is_empty() { "ok" } else { "FAILED" }, failed.len());
    if !failed.is_empty() {
        println!("failed: {}", failed.join(", "));
        process::exit(1);
    }
}
