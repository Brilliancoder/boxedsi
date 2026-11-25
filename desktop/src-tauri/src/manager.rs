//! The sidecar manager: starts `boxed serve` once, frames requests, matches replies by id, restarts the process after a
//! crash with a growing delay and gives up on a request after 120 seconds.
//!
//! One supervisor thread owns all the state and reacts to events (a request, a frame, the process gone, a deadline), so
//! there are no locks around it. Each sidecar process gets a reader thread (frames in) and a writer thread (frames out), so
//! a sidecar that stops reading cannot stall the supervisor and a deadline always fires.
//!
//! What the person is told is a fixed sentence per [`SidecarError`]; no error carries a piece of a request or a reply, and
//! nothing is logged. The sidecar's error stream is read, so that it never blocks the sidecar, and its last lines are kept in
//! memory with the exit code and the number of restarts ([`Diagnostics`]): for support only, never shown and never written, since a
//! traceback can quote the text it was working on. After a few failures in a short time the manager stops restarting the sidecar
//! and says so, until `retry`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::framing::{self, FrameError, MAX_REPLY, MAX_REQUEST};
use crate::processes;

/// How long a request may take, counted from the moment it is made.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a sidecar that has closed its output, or broke the protocol, is given to leave before it is killed.
const REAP_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Config {
    /// The sidecar executable and the arguments it is started with (`serve`).
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub request_timeout: Duration,
    /// Wait before restart number n after n failed runs in a row; the last value repeats.
    pub backoff: Vec<Duration>,
    /// On shutdown: how long a sidecar may take to leave after its input is closed, before it is killed.
    pub stop_grace: Duration,
    /// Where the pid file of the running sidecar is kept, in the app's own data folder; None: no file, and no search for leftovers.
    pub pid_dir: Option<PathBuf>,
    /// This many failed runs within `failure_window` and the manager stops restarting the sidecar, until `retry` is called.
    pub max_failures: u32,
    pub failure_window: Duration,
    /// Variables added to the environment the sidecar inherits (a switch of the core, for example).
    pub env: Vec<(OsString, OsString)>,
}

impl Config {
    pub fn new(program: impl Into<PathBuf>, args: Vec<OsString>) -> Config {
        Config {
            program: program.into(),
            args,
            request_timeout: REQUEST_TIMEOUT,
            backoff: [0, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000].map(Duration::from_millis).to_vec(),
            stop_grace: Duration::from_secs(3),
            pid_dir: None,
            max_failures: 3,
            failure_window: Duration::from_secs(60),
            env: Vec::new(),
        }
    }

    fn delay(&self, failures: u32) -> Duration {
        let index = (failures.max(1) - 1) as usize;
        self.backoff.get(index).or(self.backoff.last()).copied().unwrap_or(Duration::from_millis(500))
    }
}

/// What the shell knows about how the sidecar has been doing. It is for support: it goes to no page and to no log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    /// How many times the sidecar was started again after its first start.
    pub restarts: u32,
    /// How the last run ended: by its exit code, or by a signal (both None while it runs, or before there was a run).
    pub last_exit_code: Option<i32>,
    pub last_signal: Option<i32>,
    /// The last lines of the error stream of the last run, each cut short. In memory only: never shown, never logged.
    pub stderr_tail: Vec<String>,
    /// The manager stopped restarting the sidecar after repeated failures and waits for `retry`.
    pub gave_up: bool,
}

/// Why a request got no answer from the sidecar. The texts are fixed: they never carry a piece of a request or a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarError {
    /// The sidecar is not running (it crashed, cannot be started, or a restart is waiting).
    Unavailable,
    /// The sidecar kept failing and is not started again until `retry` is called.
    GaveUp,
    /// No answer within the request timeout.
    Timeout,
    /// The sidecar sent something that is not a valid reply.
    Protocol,
    /// The request does not fit in one frame.
    TooLarge,
    /// The request is malformed (empty command, or fields that clash with the frame's own).
    BadRequest,
    /// The shell is closing.
    Stopped,
}

impl SidecarError {
    pub fn code(self) -> &'static str {
        match self {
            SidecarError::Unavailable => "unavailable",
            SidecarError::GaveUp => "gave-up",
            SidecarError::Timeout => "timeout",
            SidecarError::Protocol => "protocol",
            SidecarError::TooLarge => "too-large",
            SidecarError::BadRequest => "bad-request",
            SidecarError::Stopped => "stopped",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            SidecarError::Unavailable => "The masking engine is not running. It is restarting, please try again in a moment.",
            SidecarError::GaveUp => "The masking engine keeps stopping, so it was not started again. Press Try again.",
            SidecarError::Timeout => "The request took too long and was stopped. Please try again.",
            SidecarError::Protocol => "The masking engine gave an unexpected answer and was restarted. Please try again.",
            SidecarError::TooLarge => "The text is too large to send in one piece. Please send a smaller part.",
            SidecarError::BadRequest => "The request could not be sent.",
            SidecarError::Stopped => "The program is closing.",
        }
    }
}

type Reply = Result<Map<String, Value>, SidecarError>;

/// A request on its way. It is dropped, and with it the text, when it is answered or fails.
struct Job {
    id: u64,
    frame: Arc<Vec<u8>>,
    deadline: Instant,
    reply: Sender<Reply>,
    /// How many times it has been written to a sidecar.
    attempts: u32,
}

impl Job {
    fn finish(self, reply: Reply) {
        let _ = self.reply.send(reply); // the caller may have gone; nothing to do then
    }
}

enum Event {
    Request(Job),
    Frame { generation: u64, value: Value },
    Gone { generation: u64, how: Gone },
    Retry,
    Shutdown(Sender<()>),
}

/// The diagnostics, shared by the supervisor, which fills in how the runs end, and the readers of the error streams.
type Shared = Arc<Mutex<Diagnostics>>;

fn notes(shared: &Shared) -> MutexGuard<'_, Diagnostics> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

/// Error lines kept, and the bytes of each: the sidecar writes none of its requests there, and only the end of a run matters.
const TAIL_LINES: usize = 20;
const TAIL_WIDTH: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gone {
    /// The output ended, or the input could not be written: the process is leaving or has left.
    Closed,
    /// The output is not a valid frame: the stream cannot be trusted any more.
    Broken,
}

struct Inner {
    events: Sender<Event>,
    next_id: AtomicU64,
    timeout: Duration,
    notes: Shared,
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl Inner {
    fn stop(&self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.events.send(Event::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.recv();
        }
        if let Some(supervisor) = self.supervisor.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = supervisor.join();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
pub struct Sidecar {
    inner: Arc<Inner>,
}

impl Sidecar {
    /// Starts the supervisor and, with it, the first sidecar process.
    pub fn start(config: Config) -> Sidecar {
        let (events, inbox) = mpsc::channel();
        let timeout = config.request_timeout;
        let notes: Shared = Arc::default();
        let supervisor = Supervisor::new(config, events.clone(), inbox, notes.clone());
        let handle = thread::Builder::new()
            .name("boxed-sidecar".into())
            .spawn(move || supervisor.run())
            .expect("cannot start the sidecar supervisor");
        Sidecar {
            inner: Arc::new(Inner { events, next_id: AtomicU64::new(1), timeout, notes, supervisor: Mutex::new(Some(handle)) }),
        }
    }

    /// The reply of the sidecar without its `id`; an `ok: false` reply is a reply, not an error.
    pub fn request(&self, cmd: &str, mut fields: Map<String, Value>) -> Result<Map<String, Value>, SidecarError> {
        if cmd.is_empty() || fields.contains_key("id") || fields.contains_key("cmd") {
            return Err(SidecarError::BadRequest);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        fields.insert("id".into(), id.into());
        fields.insert("cmd".into(), cmd.into());
        let frame = framing::encode(&Value::Object(fields), MAX_REQUEST).map_err(|e| match e {
            FrameError::TooLarge => SidecarError::TooLarge,
            _ => SidecarError::BadRequest,
        })?;
        let (reply, answer) = mpsc::channel();
        let job = Job { id, frame: Arc::new(frame), deadline: Instant::now() + self.inner.timeout, reply, attempts: 0 };
        self.inner.events.send(Event::Request(job)).map_err(|_| SidecarError::Stopped)?;
        answer.recv().unwrap_or(Err(SidecarError::Stopped)) // the supervisor ended without an answer: it is shutting down
    }

    /// Closes the sidecar's input, waits for it to leave, kills it after the grace time. Idempotent.
    pub fn shutdown(&self) {
        self.inner.stop();
    }

    /// Forgets the failures and starts the sidecar again, also after the manager gave up on it.
    pub fn retry(&self) {
        let _ = self.inner.events.send(Event::Retry);
    }

    pub fn diagnostics(&self) -> Diagnostics {
        notes(&self.inner.notes).clone()
    }
}

struct Running {
    generation: u64,
    child: Child,
    writer: Sender<Arc<Vec<u8>>>,
    /// Replies received from this process.
    served: u64,
}

struct Supervisor {
    config: Config,
    events: Sender<Event>,
    inbox: Receiver<Event>,
    queue: VecDeque<Job>,
    in_flight: Option<Job>,
    running: Option<Running>,
    generation: u64,
    /// Sidecars started so far; the first is not a restart.
    launched: u32,
    /// Runs that ended badly in a row, since the last good answer: it sets the wait before the next start.
    failures: u32,
    /// When the last failures were, within `failure_window`: enough of them and the manager gives up.
    recent: VecDeque<Instant>,
    gave_up: bool,
    /// While no sidecar runs: the earliest moment to start one.
    next_spawn_at: Instant,
    notes: Shared,
}

impl Supervisor {
    fn new(config: Config, events: Sender<Event>, inbox: Receiver<Event>, notes: Shared) -> Supervisor {
        Supervisor {
            config,
            events,
            inbox,
            queue: VecDeque::new(),
            in_flight: None,
            running: None,
            generation: 0,
            launched: 0,
            failures: 0,
            recent: VecDeque::new(),
            gave_up: false,
            next_spawn_at: Instant::now(),
            notes,
        }
    }

    fn run(mut self) {
        if let Some(dir) = &self.config.pid_dir {
            let args: Vec<String> = self.config.args.iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
            processes::end_leftovers(dir, &format!("{} {}", self.config.program.display(), args.join(" ")));
        }
        self.tick();
        loop {
            let event = match self.next_wake() {
                Some(at) => match self.inbox.recv_timeout(at.saturating_duration_since(Instant::now())) {
                    Ok(event) => Some(event),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => return,
                },
                None => match self.inbox.recv() {
                    Ok(event) => Some(event),
                    Err(_) => return,
                },
            };
            match event {
                Some(Event::Request(job)) => self.queue.push_back(job),
                Some(Event::Frame { generation, value }) => self.on_frame(generation, value),
                Some(Event::Gone { generation, how }) => {
                    if self.running.as_ref().is_some_and(|r| r.generation == generation) {
                        self.child_gone(how);
                    }
                }
                Some(Event::Retry) => {
                    self.gave_up = false;
                    self.failures = 0;
                    self.recent.clear();
                    self.next_spawn_at = Instant::now();
                    notes(&self.notes).gave_up = false;
                }
                Some(Event::Shutdown(ack)) => {
                    self.stop();
                    let _ = ack.send(());
                    return;
                }
                None => {}
            }
            self.tick();
        }
    }

    /// The next moment something must happen without an event: a deadline, or a restart that is due.
    fn next_wake(&self) -> Option<Instant> {
        let deadline = self.in_flight.as_ref().map(|job| job.deadline);
        let restart = (self.running.is_none() && !self.gave_up).then_some(self.next_spawn_at);
        [deadline, restart].into_iter().flatten().min()
    }

    fn tick(&mut self) {
        if self.in_flight.as_ref().is_some_and(|job| Instant::now() >= job.deadline) {
            self.give_up_on_the_request();
        }
        if self.running.is_none() && !self.gave_up && Instant::now() >= self.next_spawn_at {
            self.spawn();
        }
        self.pump();
    }

    /// What a request is told when there is no sidecar to send it to: that a restart is on its way, or that there will be none.
    fn unavailable(&self) -> SidecarError {
        if self.gave_up {
            SidecarError::GaveUp
        } else {
            SidecarError::Unavailable
        }
    }

    /// Sends the next waiting request, unless one is already out. A request that cannot be sent now fails at once: the person
    /// gets a sentence, not a spinner for as long as a restart is waiting.
    fn pump(&mut self) {
        while self.in_flight.is_none() {
            let Some(job) = self.queue.pop_front() else { return };
            if Instant::now() >= job.deadline {
                job.finish(Err(SidecarError::Timeout));
            } else if self.running.is_none() && (self.gave_up || !(Instant::now() >= self.next_spawn_at && self.spawn())) {
                let error = self.unavailable();
                job.finish(Err(error));
            } else {
                self.dispatch(job);
            }
        }
    }

    fn dispatch(&mut self, mut job: Job) {
        job.attempts += 1;
        let sent = self.running.as_ref().is_some_and(|running| running.writer.send(job.frame.clone()).is_ok());
        self.in_flight = Some(job);
        if !sent {
            self.child_gone(Gone::Closed); // the writer is gone: the process is on its way out
        }
    }

    fn on_frame(&mut self, generation: u64, value: Value) {
        if self.running.as_ref().is_none_or(|r| r.generation != generation) {
            return; // from a process that has been given up on
        }
        let Value::Object(mut reply) = value else { return self.child_gone(Gone::Broken) };
        let Some(id) = reply.get("id").and_then(Value::as_u64) else { return self.child_gone(Gone::Broken) };
        if self.in_flight.as_ref().is_none_or(|job| job.id != id) {
            return; // an answer to a request that was given up on, or nobody asked for: skipped
        }
        if !reply.get("ok").is_some_and(Value::is_boolean) {
            return self.child_gone(Gone::Broken);
        }
        reply.remove("id");
        if let Some(running) = self.running.as_mut() {
            running.served += 1;
        }
        self.failures = 0;
        if let Some(job) = self.in_flight.take() {
            job.finish(Ok(reply));
        }
    }

    /// The process is gone, or cannot be trusted: reap it, settle the request that was out, and plan the restart.
    fn child_gone(&mut self, how: Gone) {
        let Some(mut running) = self.running.take() else { return };
        let status = reap(&mut running.child, how == Gone::Broken);
        self.note_exit(status);
        let clean = status.is_some_and(|status| status.success());
        let had_served = running.served > 0;
        drop(running); // the writer channel closes with it
        match self.in_flight.take() {
            Some(job) if how == Gone::Broken => {
                self.record_failure();
                job.finish(Err(if self.gave_up { SidecarError::GaveUp } else { SidecarError::Protocol }));
            }
            // The sidecar may end itself right after a reply (exit code 0), before it reads what comes next. A request
            // written to it then was never started: send it again, once, to a new process.
            Some(job) if clean && job.attempts < 2 => {
                self.queue.push_front(job);
                self.after_clean_exit(had_served);
            }
            Some(job) => {
                self.record_failure();
                let error = self.unavailable();
                job.finish(Err(error));
            }
            None if how == Gone::Broken => self.record_failure(),
            None => self.after_clean_exit(clean && had_served),
        }
    }

    /// A run that ended with exit code 0. After at least one reply that is the sidecar's own decision and not a failure:
    /// start the next one at once. Without any reply it is a failure like a crash.
    fn after_clean_exit(&mut self, planned: bool) {
        if planned {
            self.failures = 0;
            self.next_spawn_at = Instant::now();
        } else {
            self.record_failure();
        }
    }

    /// A run that ended badly, or could not be started: the next start waits longer each time, and a few of them in a short
    /// time are the end of restarting.
    fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.next_spawn_at = Instant::now() + self.config.delay(self.failures);
        self.count_in_the_window();
    }

    fn count_in_the_window(&mut self) {
        let now = Instant::now();
        self.recent.push_back(now);
        while self.recent.front().is_some_and(|at| now.duration_since(*at) > self.config.failure_window) {
            self.recent.pop_front();
        }
        if self.recent.len() as u32 >= self.config.max_failures {
            self.gave_up = true;
            notes(&self.notes).gave_up = true;
        }
    }

    /// How the last run ended, for the diagnostics.
    fn note_exit(&self, status: Option<ExitStatus>) {
        let mut notes = notes(&self.notes);
        notes.last_exit_code = status.and_then(|status| status.code());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            notes.last_signal = status.and_then(|status| status.signal());
        }
    }

    /// No answer in time: the sidecar may be hung, and a late answer would only be in the way. Replace it, at once, with no wait
    /// (a request that is merely slow is not the sidecar's fault), but count it among the failures: a sidecar that hangs again
    /// and again is not replaced for ever.
    fn give_up_on_the_request(&mut self) {
        if let Some(job) = self.in_flight.take() {
            job.finish(Err(SidecarError::Timeout));
        }
        if let Some(mut running) = self.running.take() {
            let status = reap(&mut running.child, true);
            self.note_exit(status);
        }
        self.failures = 0;
        self.next_spawn_at = Instant::now();
        self.count_in_the_window();
    }

    fn spawn(&mut self) -> bool {
        self.generation += 1;
        match launch(&self.config, self.generation, &self.events, &self.notes) {
            Ok((child, writer)) => {
                if let Some(dir) = &self.config.pid_dir {
                    processes::write_pid_file(dir, child.id());
                }
                self.launched += 1;
                notes(&self.notes).restarts = self.launched - 1;
                self.running = Some(Running { generation: self.generation, child, writer, served: 0 });
                true
            }
            Err(_) => {
                self.record_failure();
                false
            }
        }
    }

    fn stop(&mut self) {
        let waiting = self.in_flight.take().into_iter().chain(self.queue.drain(..));
        for job in waiting {
            job.finish(Err(SidecarError::Stopped));
        }
        if let Some(Running { mut child, writer, .. }) = self.running.take() {
            // Dropping the writer closes the sidecar's input; `boxed serve` leaves after the request it is working on.
            drop(writer);
            reap_within(&mut child, self.config.stop_grace);
        }
        if let Some(dir) = &self.config.pid_dir {
            processes::remove_pid_file(dir);
        }
    }
}

/// Starts the sidecar with a reader and a writer thread, and a third thread that keeps the last lines of its error stream.
fn launch(config: &Config, generation: u64, events: &Sender<Event>, shared: &Shared) -> io::Result<(Child, Sender<Arc<Vec<u8>>>)> {
    let mut command = Command::new(&config.program);
    command.args(&config.args).envs(config.env.iter().map(|(name, value)| (name, value)));
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0); // its own group: what it starts goes with it, and one signal ends them all
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flashes up for the sidecar
    }
    let mut child = command.spawn()?;
    let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("sidecar pipes missing"));
    };
    let (writer, frames) = mpsc::channel();
    let started = spawn_reader(generation, stdout, events.clone())
        .and_then(|_| spawn_writer(generation, stdin, frames, events.clone()))
        .and_then(|_| spawn_error_reader(stderr, shared.clone()));
    if let Err(e) = started {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok((child, writer))
}

fn spawn_reader(generation: u64, mut stdout: ChildStdout, events: Sender<Event>) -> io::Result<()> {
    thread::Builder::new().name("boxed-sidecar-out".into()).spawn(move || loop {
        let event = match framing::read_frame(&mut stdout, MAX_REPLY) {
            Ok(Some(value)) => Event::Frame { generation, value },
            Ok(None) | Err(FrameError::Truncated) | Err(FrameError::Io(_)) => Event::Gone { generation, how: Gone::Closed },
            Err(FrameError::TooLarge) | Err(FrameError::BadJson) => Event::Gone { generation, how: Gone::Broken },
        };
        let last = matches!(event, Event::Gone { .. });
        if events.send(event).is_err() || last {
            return;
        }
    })?;
    Ok(())
}

fn spawn_writer(generation: u64, mut stdin: ChildStdin, frames: Receiver<Arc<Vec<u8>>>, events: Sender<Event>) -> io::Result<()> {
    thread::Builder::new().name("boxed-sidecar-in".into()).spawn(move || {
        while let Ok(frame) = frames.recv() {
            if stdin.write_all(&frame).and_then(|_| stdin.flush()).is_err() {
                let _ = events.send(Event::Gone { generation, how: Gone::Closed });
                return;
            }
        }
        // the channel is closed: stdin is dropped here, which is the end of input the sidecar waits for
    })?;
    Ok(())
}

/// Reads the sidecar's error stream so that it never fills up and blocks it, and keeps the last lines of it in memory, each cut
/// short. They are for support (`Sidecar::diagnostics`): nothing shows them to the person or writes them anywhere.
fn spawn_error_reader(mut stderr: ChildStderr, shared: Shared) -> io::Result<()> {
    fn keep(shared: &Shared, line: &[u8]) {
        let mut notes = notes(shared);
        notes.stderr_tail.push(String::from_utf8_lossy(line).into_owned());
        if notes.stderr_tail.len() > TAIL_LINES {
            notes.stderr_tail.remove(0);
        }
    }

    thread::Builder::new().name("boxed-sidecar-err".into()).spawn(move || {
        let mut chunk = [0u8; 4096];
        let mut line: Vec<u8> = Vec::new();
        loop {
            let got = match stderr.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(got) => got,
            };
            for &byte in &chunk[..got] {
                if byte == b'\n' {
                    keep(&shared, &line);
                    line.clear();
                } else if line.len() < TAIL_WIDTH {
                    line.push(byte); // the rest of a long line is dropped
                }
            }
        }
        if !line.is_empty() {
            keep(&shared, &line);
        }
    })?;
    Ok(())
}

/// Makes sure the process is gone and collected: at once if `kill_now`, else after `REAP_GRACE` for it to leave by itself.
fn reap(child: &mut Child, kill_now: bool) -> Option<ExitStatus> {
    if kill_now {
        end(child);
        return child.wait().ok();
    }
    reap_within(child, REAP_GRACE)
}

fn reap_within(child: &mut Child, grace: Duration) -> Option<ExitStatus> {
    let until = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(5)),
            _ => {
                end(child);
                return child.wait().ok();
            }
        }
    }
}

/// Ends the sidecar and everything it started: its process group, since it leads one.
fn end(child: &mut Child) {
    #[cfg(unix)]
    processes::end_group(child.id());
    let _ = child.kill();
}
