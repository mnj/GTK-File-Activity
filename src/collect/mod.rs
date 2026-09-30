// SPDX-License-Identifier: MIT

//! Sampling: reads the eBPF counters, fills in paths from /proc, and feeds the model.

mod bpf;
mod control;
mod helper;
mod privs;
mod procfs;

pub use control::Control;
pub use helper::run as run_helper;
use helper::Remote;

use crate::model::{format_rate, Model, RawStat, Snapshot, HOLD};
use bpf::{Loaded, EXPECTED_PROBES};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// One sampling pipeline: probes, rate model and path resolution.
struct Sampler {
    loaded: Option<Loaded>,
    problem: String,
    model: Model,
    /// When the counters were last read. Rates divide by the gap between
    /// reads, which includes the /proc scan, not just the sleep.
    last_read: Instant,
    /// Per-process activity totals, to tell which processes did I/O.
    totals: HashMap<u32, u64>,
    recent: HashMap<u32, Instant>,
    was_paused: bool,
}

impl Sampler {
    fn new() -> Self {
        let (loaded, problem) = if is_root() {
            match Loaded::open() {
                Ok(loaded) => (Some(loaded), String::new()),
                Err(err) => (None, err),
            }
        } else {
            (None, String::new())
        };
        let mut sampler = Self {
            loaded,
            problem,
            model: Model::new(),
            last_read: Instant::now(),
            totals: HashMap::new(),
            recent: HashMap::new(),
            was_paused: false,
        };
        sampler.rebase();
        sampler
    }

    fn attached(&self) -> usize {
        self.loaded.as_ref().map_or(0, |loaded| loaded.attached)
    }

    /// Forget activity accumulated while nobody was looking.
    fn rebase(&mut self) {
        if let Some(loaded) = &self.loaded {
            self.model.rebase(&loaded.read_stats());
        }
        self.last_read = Instant::now();
    }

    fn sample(&mut self, show_idle: bool) -> Snapshot {
        let (stats, hints, failed) = match &self.loaded {
            Some(loaded) => (
                loaded.read_stats(),
                loaded.read_hints(),
                loaded.failed.clone(),
            ),
            None => (
                Vec::new(),
                HashMap::new(),
                if self.problem.is_empty() {
                    Vec::new()
                } else {
                    vec![self.problem.clone()]
                },
            ),
        };
        let read_at = Instant::now();
        let elapsed = read_at.duration_since(self.last_read).as_secs_f64();
        self.last_read = read_at;

        let fds = if show_idle {
            procfs::scan(None)
        } else {
            procfs::scan(Some(&self.active_tgids(&stats, read_at)))
        };
        let (files, total_read_bps, total_write_bps, graph) =
            self.model
                .ingest(Instant::now(), elapsed, &stats, &hints, &fds, show_idle);
        Snapshot {
            files,
            total_read_bps,
            total_write_bps,
            graph,
            attached: self.attached(),
            expected: EXPECTED_PROBES,
            failed,
            needs_auth: self.loaded.is_none() && !is_root(),
        }
    }

    /// Waits one interval and samples. `None` while paused or interrupted.
    fn tick(&mut self, ctrl: &Control) -> Option<Snapshot> {
        if ctrl.paused() {
            self.was_paused = true;
            ctrl.wait(Duration::from_millis(200));
            return None;
        }
        if self.was_paused {
            self.was_paused = false;
            self.rebase();
        }
        ctrl.wait(ctrl.interval());
        if ctrl.stopped() || ctrl.paused() {
            return None;
        }
        Some(self.sample(ctrl.show_idle()))
    }

    /// Processes that did I/O since the last sample or within the hold window.
    fn active_tgids(&mut self, stats: &[RawStat], now: Instant) -> HashSet<u32> {
        let mut totals: HashMap<u32, u64> = HashMap::new();
        for stat in stats {
            let slot = totals.entry(stat.tgid).or_default();
            *slot = slot
                .wrapping_add(stat.rbytes)
                .wrapping_add(stat.wbytes)
                .wrapping_add(stat.reads)
                .wrapping_add(stat.writes);
        }
        for (tgid, total) in &totals {
            if self.totals.get(tgid) != Some(total) {
                self.recent.insert(*tgid, now);
            }
        }
        self.totals = totals;
        self.recent
            .retain(|_, at| now.saturating_duration_since(*at) <= HOLD);
        self.recent.keys().copied().collect()
    }
}

pub fn spawn(tx: async_channel::Sender<Snapshot>, ctrl: Arc<Control>) -> JoinHandle<()> {
    thread::spawn(move || collector(tx, ctrl))
}

fn collector(tx: async_channel::Sender<Snapshot>, ctrl: Arc<Control>) {
    let mut local = Sampler::new();
    let mut remote: Option<Remote> = None;
    if local.loaded.is_none() {
        let _ = tx.try_send(local.sample(ctrl.show_idle()));
    }

    while !ctrl.stopped() {
        if ctrl.take_helper_request() && remote.is_none() && local.loaded.is_none() {
            match Remote::spawn(tx.clone(), ctrl.clone()) {
                Ok(helper) => remote = Some(helper),
                Err(err) => {
                    local.problem = format!("Could not start pkexec: {err}");
                    let _ = tx.try_send(local.sample(ctrl.show_idle()));
                }
            }
        }
        if let Some(helper) = remote.as_mut() {
            if helper.done() {
                local.problem = remote.take().map(Remote::reap).unwrap_or_default();
                let _ = tx.try_send(local.sample(ctrl.show_idle()));
                continue;
            }
            helper.sync(&ctrl);
            if helper.ready() {
                // The helper's snapshots go straight to the window.
                ctrl.wait(Duration::from_millis(250));
                continue;
            }
        }
        if let Some(snap) = local.tick(&ctrl) {
            let _ = tx.try_send(snap);
        }
    }
    if let Some(helper) = remote {
        helper.shutdown();
    }
}

/// `--dump`: print the busiest files once a second, without the UI.
pub fn run_dump() -> i32 {
    if !is_root() {
        eprintln!("file rates need root; re-run with sudo or pkexec");
        return 1;
    }
    let mut sampler = Sampler::new();
    if sampler.loaded.is_none() {
        eprintln!("{}", sampler.problem);
        return 1;
    }
    eprintln!("probes {}/{}", sampler.attached(), EXPECTED_PROBES);
    if let Some(loaded) = &sampler.loaded {
        for failure in &loaded.failed {
            eprintln!("not attached: {failure}");
        }
    }
    if sampler.attached() == 0 {
        return 1;
    }
    let mut tick = 0u32;
    loop {
        thread::sleep(Duration::from_secs(1));
        let snap = sampler.sample(false);
        tick += 1;
        if tick % 5 == 1 {
            if let Some(loaded) = &sampler.loaded {
                let hits: Vec<String> = loaded
                    .read_hits()
                    .into_iter()
                    .filter(|(_, n)| *n > 0)
                    .map(|(name, n)| format!("{name}={n}"))
                    .collect();
                eprintln!("hook hits: {}", hits.join(" "));
            }
        }
        println!(
            "{} read  {} write  {} files",
            format_rate(snap.total_read_bps),
            format_rate(snap.total_write_bps),
            snap.files
                .iter()
                .filter(|f| f.read_bps + f.write_bps > 0.0)
                .count()
        );
        for file in snap.files.iter().take(30) {
            if file.read_bps + file.write_bps <= 0.0 {
                continue;
            }
            println!(
                "  {:>12} read {:>12} write  {:>6} ops  {:<18} {}",
                format_rate(file.read_bps),
                format_rate(file.write_bps),
                file.reads + file.writes,
                file.summary,
                file.path
            );
        }
    }
}
