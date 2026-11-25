//! The one thing the front end may ask of the shell: send a request to the sidecar.

use serde_json::{json, Map, Value};

use crate::manager::{Sidecar, SidecarError};

/// What the front end may ask for. `ping`, `mask` and `restore` go to the sidecar; `restart` is the shell's own verb, for the
/// "Try again" button: it forgets the failures and starts the sidecar again. A later screen adds its verbs here, on purpose.
pub const ALLOWED: &[&str] = &["ping", "mask", "restore", "restart"];

/// What the front end gets when the shell itself fails: not a reply of the sidecar, and no detail.
pub const INTERNAL_ERROR: &str = "The program hit an internal error. Please try again.";

/// Always a JSON object with a boolean `ok`: the sidecar's reply without its `id`, or `{ok: false, error, code}` with a
/// fixed sentence when the shell could not get one.
pub fn dispatch(sidecar: &Sidecar, cmd: &str, fields: Map<String, Value>) -> Value {
    if !ALLOWED.contains(&cmd) {
        return failure(sidecar, SidecarError::BadRequest);
    }
    if cmd == "restart" {
        sidecar.retry();
        return json!({"ok": true});
    }
    match sidecar.request(cmd, fields) {
        Ok(reply) => Value::Object(reply),
        Err(error) => failure(sidecar, error),
    }
}

/// A fixed sentence and its code. When the sidecar is not there the numbers of the diagnostics go with it, so that the window can
/// say how often it was restarted and how it last ended; the lines of its error stream never do.
fn failure(sidecar: &Sidecar, error: SidecarError) -> Value {
    let mut value = json!({"ok": false, "error": error.message(), "code": error.code()});
    if matches!(error, SidecarError::Unavailable | SidecarError::GaveUp) {
        let report = sidecar.diagnostics();
        value["restarts"] = report.restarts.into();
        if let Some(code) = report.last_exit_code {
            value["exit_code"] = code.into();
        }
        if let Some(signal) = report.last_signal {
            value["signal"] = signal.into();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::Config;
    use std::time::{Duration, Instant};

    /// A sidecar that cannot start: any request that reaches it fails as unavailable.
    fn dead_sidecar() -> Sidecar {
        let mut config = Config::new("/nonexistent/boxed", vec!["serve".into()]);
        config.backoff = vec![Duration::from_secs(60)];
        Sidecar::start(config)
    }

    /// A sidecar that cannot start and is tried again at once, so that the manager gives up on it in a moment.
    fn given_up_sidecar() -> Sidecar {
        let mut config = Config::new("/nonexistent/boxed", vec!["serve".into()]);
        config.backoff = vec![Duration::ZERO];
        config.max_failures = 2;
        Sidecar::start(config)
    }

    #[test]
    fn only_the_commands_of_the_first_screen_are_allowed() {
        assert_eq!(ALLOWED, ["ping", "mask", "restore", "restart"]);
    }

    #[test]
    fn restart_is_the_shells_own_verb_and_never_goes_to_the_sidecar() {
        let sidecar = dead_sidecar();
        assert_eq!(dispatch(&sidecar, "restart", Map::new()), json!({"ok": true}));
    }

    #[test]
    fn a_sidecar_that_was_given_up_on_says_so_in_a_fixed_sentence_with_numbers_only() {
        let sidecar = given_up_sidecar();
        let started = Instant::now();
        let reply = loop {
            let reply = dispatch(&sidecar, "ping", Map::new());
            if reply["code"] == "gave-up" {
                break reply;
            }
            assert!(started.elapsed() < Duration::from_secs(10), "the manager never gave up: {reply}");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(reply, json!({"ok": false, "error": SidecarError::GaveUp.message(), "code": "gave-up", "restarts": 0}));
    }

    #[test]
    fn a_command_outside_the_list_is_refused_before_it_reaches_the_sidecar() {
        let sidecar = dead_sidecar();
        for cmd in ["key-set", "key-remove", "journal-export", "ask", "mask-file", "Mask", "", "mask ", "mask\0"] {
            let reply = dispatch(&sidecar, cmd, Map::new());
            assert_eq!(reply["ok"], false, "{cmd:?}");
            assert_eq!(reply["code"], SidecarError::BadRequest.code(), "{cmd:?} reached the sidecar");
        }
    }

    #[test]
    fn a_failure_of_the_shell_is_a_fixed_sentence_with_a_code_and_nothing_else() {
        let sidecar = dead_sidecar();
        let secret = "ivan.petrov@example.com";
        let fields = match json!({"text": secret, "level": 2}) {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        let reply = dispatch(&sidecar, "mask", fields);
        assert_eq!(
            reply,
            json!({"ok": false, "error": SidecarError::Unavailable.message(), "code": "unavailable", "restarts": 0}),
        );
        assert!(!reply.to_string().contains(secret));
    }
}
