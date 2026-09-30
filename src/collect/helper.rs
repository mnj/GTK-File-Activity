// SPDX-License-Identifier: MIT

//! Privilege separation. The window never runs as root. Rates come from a
//! helper process, `gtk-file-activity --helper`, started through pkexec. It
//! loads the probes, drops to the few capabilities the sampling loop needs
//! (see `privs`), then streams one JSON `Snapshot` per line on stdout. The
//! window sends its settings as JSON lines on stdin. The helper exits when
//! stdin closes, so it cannot outlive the window.

use super::{is_root, privs, Control, Sampler};
use crate::model::Snapshot;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command as Process, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
struct Settings {
    interval_ms: u64,
    paused: bool,
    show_idle: bool,
}

/// `--helper`: the privileged side. Returns the process exit code.
pub fn run() -> i32 {
    if !is_root() {
        eprintln!("the helper must run as root; start it through pkexec");
        return 1;
    }
    let mut sampler = Sampler::new();
    if sampler.loaded.is_none() {
        eprintln!("{}", sampler.problem);
        return 1;
    }
    if !std::env::args().any(|arg| arg == "--keep-privileges") {
        if let Err(err) = privs::drop_to_sampling() {
            eprintln!("could not drop privileges: {err}");
            return 1;
        }
    }

    let ctrl = Control::new(Duration::from_secs(1), false);
    {
        let ctrl = ctrl.clone();
        thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines().map_while(Result::ok) {
                if let Ok(settings) = serde_json::from_str::<Settings>(&line) {
                    ctrl.set_interval(Duration::from_millis(settings.interval_ms.clamp(100, 60_000)));
                    ctrl.set_paused(settings.paused);
                    ctrl.set_show_idle(settings.show_idle);
                }
            }
            ctrl.stop();
        });
    }

    let mut out = std::io::stdout().lock();
    while !ctrl.stopped() {
        let Some(snap) = sampler.tick(&ctrl) else {
            continue;
        };
        let Ok(mut line) = serde_json::to_vec(&snap) else {
            continue;
        };
        line.push(b'\n');
        if out.write_all(&line).and_then(|_| out.flush()).is_err() {
            break;
        }
    }
    0
}

/// The window's end of the helper: one running child.
pub struct Remote {
    child: Child,
    stdin: Option<ChildStdin>,
    ready: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    sent: Option<Settings>,
}

impl Remote {
    pub fn spawn(
        tx: async_channel::Sender<Snapshot>,
        ctrl: Arc<Control>,
    ) -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let mut child = Process::new("pkexec")
            .arg(exe)
            .arg("--helper")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let ready = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        {
            let (ready, done) = (ready.clone(), done.clone());
            thread::spawn(move || {
                if let Some(stdout) = stdout {
                    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                        if let Ok(snap) = serde_json::from_str::<Snapshot>(&line) {
                            ready.store(true, Ordering::SeqCst);
                            let _ = tx.try_send(snap);
                        }
                    }
                }
                done.store(true, Ordering::SeqCst);
                ctrl.notify();
            });
        }
        Ok(Self {
            child,
            stdin,
            ready,
            done,
            sent: None,
        })
    }

    /// True once the helper has produced a snapshot, so its numbers are live.
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Pass the window's settings on when they change.
    pub fn sync(&mut self, ctrl: &Control) {
        let want = Settings {
            interval_ms: ctrl.interval().as_millis() as u64,
            paused: ctrl.paused(),
            show_idle: ctrl.show_idle(),
        };
        if self.sent == Some(want) {
            return;
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return;
        };
        let Ok(mut line) = serde_json::to_vec(&want) else {
            return;
        };
        line.push(b'\n');
        if stdin.write_all(&line).and_then(|_| stdin.flush()).is_ok() {
            self.sent = Some(want);
        }
    }

    /// Why the helper ended, once its output has closed.
    pub fn reap(mut self) -> String {
        match self.child.wait().ok().and_then(|status| status.code()) {
            Some(126) => "Authentication was cancelled.".into(),
            Some(127) => "Not authorized to start the helper.".into(),
            Some(0) => "The helper stopped.".into(),
            code => format!(
                "The helper exited ({code:?}). Run `sudo gtk-file-activity --dump` to see why."
            ),
        }
    }

    /// Closing stdin is what stops the helper.
    pub fn shutdown(mut self) {
        self.stdin.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FileSnapshot, GraphPoint, ProcSnapshot};

    #[test]
    fn snapshots_survive_the_pipe() {
        let snap = Snapshot {
            files: vec![FileSnapshot {
                dev: 37,
                ino: 9,
                path: "/tmp/a b\"c".into(),
                read_bps: 1.5,
                write_bps: 0.0,
                reads: 2,
                writes: 0,
                summary: "x (1)".into(),
                haystack: "x".into(),
                processes: vec![ProcSnapshot {
                    tgid: 1,
                    comm: "x".into(),
                    read_bps: 1.5,
                    write_bps: 0.0,
                    reads: 2,
                    writes: 0,
                    fds: vec![3],
                    path: "/tmp/a b\"c".into(),
                    did_io: true,
                    still_open: true,
                }],
            }],
            total_read_bps: 1.5,
            total_write_bps: 0.0,
            graph: vec![GraphPoint {
                age: 0.0,
                read_bps: 1.5,
                write_bps: 0.0,
            }],
            attached: 18,
            expected: 18,
            failed: vec![],
            needs_auth: false,
        };
        let line = serde_json::to_string(&snap).unwrap();
        assert!(!line.contains('\n'));
        let back: Snapshot = serde_json::from_str(&line).unwrap();
        assert_eq!(back.files[0].path, "/tmp/a b\"c");
        assert_eq!(back.attached, 18);
    }

    #[test]
    fn settings_round_trip() {
        let want = Settings {
            interval_ms: 500,
            paused: true,
            show_idle: false,
        };
        let line = serde_json::to_string(&want).unwrap();
        assert_eq!(serde_json::from_str::<Settings>(&line).unwrap(), want);
    }
}
