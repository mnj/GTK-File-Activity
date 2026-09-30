// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const HOLD: Duration = Duration::from_secs(3);
const GRAPH_WINDOW: Duration = Duration::from_secs(60);
const MAX_ROWS: usize = 4000;

#[derive(Clone, Debug)]
pub struct RawStat {
    pub dev: u64,
    pub ino: u64,
    pub tgid: u32,
    pub rbytes: u64,
    pub wbytes: u64,
    pub reads: u64,
    pub writes: u64,
    pub comm: String,
}

#[derive(Clone, Debug)]
pub struct Holder {
    pub tgid: u32,
    pub comm: String,
    pub fds: Vec<i32>,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct FdIndex {
    pub paths: HashMap<(u64, u64), String>,
    pub holders: HashMap<(u64, u64), Vec<Holder>>,
    /// Full executable path from `/proc/<tgid>/exe`, when that process is still alive.
    pub exes: HashMap<u32, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcSnapshot {
    pub tgid: u32,
    pub comm: String,
    pub read_bps: f64,
    pub write_bps: f64,
    pub reads: u64,
    pub writes: u64,
    pub fds: Vec<i32>,
    pub did_io: bool,
    pub still_open: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub dev: u64,
    pub ino: u64,
    pub path: String,
    pub read_bps: f64,
    pub write_bps: f64,
    pub reads: u64,
    pub writes: u64,
    pub summary: String,
    pub haystack: String,
    pub processes: Vec<ProcSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphPoint {
    pub age: f64,
    pub read_bps: f64,
    pub write_bps: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub files: Vec<FileSnapshot>,
    pub total_read_bps: f64,
    pub total_write_bps: f64,
    pub graph: Vec<GraphPoint>,
    pub attached: usize,
    pub expected: usize,
    pub failed: Vec<String>,
    /// True when this process cannot load the probes and could ask for them.
    pub needs_auth: bool,
}

#[derive(Clone, Copy, Default)]
struct Counts {
    rbytes: u64,
    wbytes: u64,
    reads: u64,
    writes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CounterKey {
    dev: u64,
    ino: u64,
    tgid: u32,
}

struct Live {
    last_active: Instant,
}

#[derive(Default)]
pub struct Model {
    prev: HashMap<CounterKey, Counts>,
    live: HashMap<(u64, u64), Live>,
    graph: VecDeque<(Instant, f64, f64)>,
}

struct Delta {
    tgid: u32,
    comm: String,
    rbytes: u64,
    wbytes: u64,
    reads: u64,
    writes: u64,
}

impl Model {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget activity accumulated while the view was paused.
    pub fn rebase(&mut self, stats: &[RawStat]) {
        self.prev.clear();
        for stat in stats {
            self.prev.insert(key_of(stat), counts_of(stat));
        }
    }

    pub fn ingest(
        &mut self,
        now: Instant,
        elapsed: f64,
        stats: &[RawStat],
        hints: &HashMap<(u64, u64), String>,
        fds: &FdIndex,
        show_idle: bool,
    ) -> (Vec<FileSnapshot>, f64, f64, Vec<GraphPoint>) {
        let elapsed = elapsed.max(0.001);
        let mut seen = HashSet::new();
        let mut grouped: HashMap<(u64, u64), Vec<Delta>> = HashMap::new();

        for stat in stats {
            let key = key_of(stat);
            seen.insert(key);
            let prev = self.prev.get(&key).copied().unwrap_or_default();
            let cur = counts_of(stat);
            self.prev.insert(key, cur);
            let delta = Delta {
                tgid: stat.tgid,
                comm: stat.comm.clone(),
                rbytes: forward_delta(cur.rbytes, prev.rbytes),
                wbytes: forward_delta(cur.wbytes, prev.wbytes),
                reads: forward_delta(cur.reads, prev.reads),
                writes: forward_delta(cur.writes, prev.writes),
            };
            if delta.rbytes + delta.wbytes + delta.reads + delta.writes == 0 {
                continue;
            }
            grouped.entry((stat.dev, stat.ino)).or_default().push(delta);
        }
        self.prev.retain(|key, _| seen.contains(key));

        let mut files = Vec::new();
        let mut emitted = HashSet::new();

        for ((dev, ino), deltas) in &grouped {
            let row = build_row(*dev, *ino, deltas, elapsed, fds, hints);
            self.live.insert((*dev, *ino), Live { last_active: now });
            emitted.insert((*dev, *ino));
            files.push(row);
        }

        self.live.retain(|id, live| {
            if emitted.contains(id) {
                return true;
            }
            now.saturating_duration_since(live.last_active) <= HOLD
        });
        for &(dev, ino) in self.live.keys() {
            if emitted.contains(&(dev, ino)) {
                continue;
            }
            let row = build_row(dev, ino, &[], elapsed, fds, hints);
            emitted.insert((dev, ino));
            files.push(row);
        }

        if show_idle {
            for &(dev, ino) in fds.holders.keys() {
                if emitted.contains(&(dev, ino)) || files.len() >= MAX_ROWS {
                    continue;
                }
                files.push(build_row(dev, ino, &[], elapsed, fds, hints));
                emitted.insert((dev, ino));
            }
        }

        let total_read_bps: f64 = files.iter().map(|f| f.read_bps).sum();
        let total_write_bps: f64 = files.iter().map(|f| f.write_bps).sum();
        self.graph
            .push_back((now, total_read_bps, total_write_bps));
        while self
            .graph
            .front()
            .is_some_and(|(t, _, _)| now.saturating_duration_since(*t) > GRAPH_WINDOW)
        {
            self.graph.pop_front();
        }
        let graph = self
            .graph
            .iter()
            .map(|(t, r, w)| GraphPoint {
                age: now.saturating_duration_since(*t).as_secs_f64(),
                read_bps: *r,
                write_bps: *w,
            })
            .collect();

        files.sort_by(|a, b| {
            (b.read_bps + b.write_bps)
                .partial_cmp(&(a.read_bps + a.write_bps))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.path.cmp(&b.path))
        });
        if files.len() > MAX_ROWS {
            files.truncate(MAX_ROWS);
        }
        (files, total_read_bps, total_write_bps, graph)
    }
}

fn key_of(stat: &RawStat) -> CounterKey {
    CounterKey {
        dev: stat.dev,
        ino: stat.ino,
        tgid: stat.tgid,
    }
}

fn counts_of(stat: &RawStat) -> Counts {
    Counts {
        rbytes: stat.rbytes,
        wbytes: stat.wbytes,
        reads: stat.reads,
        writes: stat.writes,
    }
}

fn forward_delta(cur: u64, prev: u64) -> u64 {
    if cur < prev {
        cur
    } else {
        cur - prev
    }
}

fn build_row(
    dev: u64,
    ino: u64,
    deltas: &[Delta],
    elapsed: f64,
    fds: &FdIndex,
    hints: &HashMap<(u64, u64), String>,
) -> FileSnapshot {
    let mut procs: HashMap<u32, ProcSnapshot> = HashMap::new();
    let mut reads = 0u64;
    let mut writes = 0u64;
    let mut read_bps = 0.0;
    let mut write_bps = 0.0;
    for delta in deltas {
        let rb = delta.rbytes as f64 / elapsed;
        let wb = delta.wbytes as f64 / elapsed;
        reads += delta.reads;
        writes += delta.writes;
        read_bps += rb;
        write_bps += wb;
        procs.insert(
            delta.tgid,
            ProcSnapshot {
                tgid: delta.tgid,
                comm: delta.comm.clone(),
                read_bps: rb,
                write_bps: wb,
                reads: delta.reads,
                writes: delta.writes,
                fds: Vec::new(),
                did_io: true,
                still_open: false,
            },
        );
    }
    if let Some(holders) = fds.holders.get(&(dev, ino)) {
        for holder in holders {
            let entry = procs.entry(holder.tgid).or_insert_with(|| ProcSnapshot {
                tgid: holder.tgid,
                comm: holder.comm.clone(),
                read_bps: 0.0,
                write_bps: 0.0,
                reads: 0,
                writes: 0,
                fds: Vec::new(),
                did_io: false,
                still_open: false,
            });
            entry.still_open = true;
            entry.fds.clone_from(&holder.fds);
            if entry.comm.is_empty() {
                entry.comm.clone_from(&holder.comm);
            }
        }
    }
    let mut processes: Vec<_> = procs.into_values().collect();
    for proc in &mut processes {
        if let Some(exe) = fds.exes.get(&proc.tgid).filter(|exe| !exe.is_empty()) {
            proc.comm.clone_from(exe);
        }
    }
    processes.sort_by(|a, b| {
        (b.read_bps + b.write_bps)
            .partial_cmp(&(a.read_bps + a.write_bps))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.tgid.cmp(&b.tgid))
    });
    let path = choose_path(dev, ino, fds, hints);
    let summary = process_summary(&processes);
    let mut haystack = format!("{path} {summary}");
    for proc in &processes {
        haystack.push(' ');
        haystack.push_str(&proc.comm);
    }
    FileSnapshot {
        dev,
        ino,
        path,
        read_bps,
        write_bps,
        reads,
        writes,
        summary,
        haystack: haystack.to_lowercase(),
        processes,
    }
}

pub fn process_summary(procs: &[ProcSnapshot]) -> String {
    let mut ranked: Vec<&ProcSnapshot> = procs.iter().filter(|p| p.did_io).collect();
    if ranked.is_empty() {
        ranked = procs.iter().filter(|p| p.still_open).collect();
    }
    if ranked.is_empty() {
        return String::new();
    }
    ranked.sort_by(|a, b| {
        (b.read_bps + b.write_bps)
            .partial_cmp(&(a.read_bps + a.write_bps))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.tgid.cmp(&b.tgid))
    });
    if ranked.len() == 1 {
        format!("{} ({})", ranked[0].comm, ranked[0].tgid)
    } else {
        format!("{} +{}", ranked[0].comm, ranked.len() - 1)
    }
}

/// The probe's path is taken from the initial mount namespace, so it is the
/// real location even for a container's files. `/proc/<pid>/fd` links are
/// relative to that process's root (`/input/...` inside a container), so they
/// are the fallback for files the probe has not named.
pub fn choose_path(
    dev: u64,
    ino: u64,
    fds: &FdIndex,
    hints: &HashMap<(u64, u64), String>,
) -> String {
    if let Some(path) = hints.get(&(dev, ino)) {
        let path = path.trim_end_matches('\0');
        if !path.is_empty() {
            return path.to_string();
        }
    }
    if let Some(holders) = fds.holders.get(&(dev, ino)) {
        let mut best: Option<&str> = None;
        for holder in holders {
            if holder.path.is_empty() {
                continue;
            }
            best = Some(match best {
                None => holder.path.as_str(),
                Some(cur) if path_preferred(&holder.path, cur) => holder.path.as_str(),
                Some(cur) => cur,
            });
        }
        if let Some(path) = best {
            return path.to_string();
        }
    }
    if let Some(path) = fds.paths.get(&(dev, ino)) {
        if !path.is_empty() {
            return path.clone();
        }
    }
    dev_ino_label(dev, ino)
}

fn path_preferred(candidate: &str, current: &str) -> bool {
    let cand_dead = candidate.contains(" (deleted)");
    let cur_dead = current.contains(" (deleted)");
    if cur_dead && !cand_dead {
        return true;
    }
    if cand_dead && !cur_dead {
        return false;
    }
    candidate.len() < current.len()
}

pub fn dev_ino_label(dev: u64, ino: u64) -> String {
    format!("{}:{} inode {ino}", major(dev), minor(dev))
}

fn major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)
}

fn minor(dev: u64) -> u64 {
    (dev & 0xff) | ((dev >> 12) & !0xff)
}

pub fn format_rate(bps: f64) -> String {
    let n = bps.abs();
    if n < 1024.0 {
        format!("{bps:.0} B/s")
    } else if n < 1024.0 * 1024.0 {
        format!("{:.1} KiB/s", bps / 1024.0)
    } else if n < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MiB/s", bps / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB/s", bps / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(dev: u64, ino: u64, tgid: u32, rbytes: u64, wbytes: u64, comm: &str) -> RawStat {
        RawStat {
            dev,
            ino,
            tgid,
            rbytes,
            wbytes,
            reads: if rbytes > 0 { 1 } else { 0 },
            writes: if wbytes > 0 { 1 } else { 0 },
            comm: comm.to_string(),
        }
    }

    #[test]
    fn folds_processes_into_one_file() {
        let mut model = Model::new();
        let t0 = Instant::now();
        let stats = vec![
            stat(1, 9, 10, 1000, 0, "alpha"),
            stat(1, 9, 11, 500, 250, "beta"),
        ];
        let (files, read, write, _) = model.ingest(t0, 1.0, &stats, &HashMap::new(), &FdIndex::default(), false);
        assert_eq!(files.len(), 1);
        assert!((read - 1500.0).abs() < 0.1);
        assert!((write - 250.0).abs() < 0.1);
        assert_eq!(files[0].processes.len(), 2);
        assert_eq!(files[0].summary, "alpha +1");
        assert!((files[0].read_bps - 1500.0).abs() < 0.1);
    }

    #[test]
    fn exe_path_replaces_the_short_comm() {
        let mut fds = FdIndex::default();
        fds.exes.insert(10, "/usr/lib/firefox/firefox".into());
        fds.exes.insert(11, "/usr/lib/postgresql/bin/postgres".into());
        let mut model = Model::new();
        let stats = vec![
            stat(1, 9, 10, 1000, 0, "firefox"),
            stat(1, 9, 11, 100, 0, "postgres"),
        ];
        let (files, _, _, _) =
            model.ingest(Instant::now(), 1.0, &stats, &HashMap::new(), &fds, false);
        assert_eq!(files[0].summary, "/usr/lib/firefox/firefox +1");
        assert_eq!(files[0].processes[0].comm, "/usr/lib/firefox/firefox");
        assert_eq!(
            files[0].processes[1].comm,
            "/usr/lib/postgresql/bin/postgres"
        );
        assert!(files[0].haystack.contains("/usr/lib/firefox/firefox"));
    }

    #[test]
    fn second_sample_is_a_delta() {
        let mut model = Model::new();
        let t0 = Instant::now();
        let first = vec![stat(1, 1, 4, 100, 0, "dd")];
        model.ingest(t0, 1.0, &first, &HashMap::new(), &FdIndex::default(), false);
        let second = vec![stat(1, 1, 4, 100, 0, "dd")];
        let (files, read, _, _) =
            model.ingest(t0 + Duration::from_secs(1), 1.0, &second, &HashMap::new(), &FdIndex::default(), false);
        assert!(read.abs() < 0.1);
        assert_eq!(files.len(), 1, "idle row is held");
        assert!(files[0].read_bps.abs() < 0.1);
    }

    #[test]
    fn hold_expires() {
        let mut model = Model::new();
        let t0 = Instant::now();
        model.ingest(
            t0,
            1.0,
            &[stat(1, 1, 4, 50, 0, "dd")],
            &HashMap::new(),
            &FdIndex::default(),
            false,
        );
        let (held, _, _, _) = model.ingest(
            t0 + Duration::from_secs(2),
            1.0,
            &[stat(1, 1, 4, 50, 0, "dd")],
            &HashMap::new(),
            &FdIndex::default(),
            false,
        );
        assert_eq!(held.len(), 1);
        let (gone, _, _, _) = model.ingest(
            t0 + Duration::from_secs(6),
            1.0,
            &[stat(1, 1, 4, 50, 0, "dd")],
            &HashMap::new(),
            &FdIndex::default(),
            false,
        );
        assert!(gone.is_empty());
    }

    #[test]
    fn counter_reset_does_not_wrap() {
        let mut model = Model::new();
        let t0 = Instant::now();
        model.ingest(
            t0,
            1.0,
            &[stat(1, 1, 4, 5_000, 0, "dd")],
            &HashMap::new(),
            &FdIndex::default(),
            false,
        );
        let (files, _, _, _) = model.ingest(
            t0 + Duration::from_secs(1),
            1.0,
            &[stat(1, 1, 4, 40, 0, "dd")],
            &HashMap::new(),
            &FdIndex::default(),
            false,
        );
        assert!((files[0].read_bps - 40.0).abs() < 0.1);
    }

    #[test]
    fn idle_files_need_the_toggle() {
        let mut fds = FdIndex::default();
        fds.holders.insert(
            (8, 8),
            vec![Holder {
                tgid: 3,
                comm: "cat".into(),
                fds: vec![5],
                path: "/tmp/idle".into(),
            }],
        );
        let mut model = Model::new();
        let (hidden, _, _, _) =
            model.ingest(Instant::now(), 1.0, &[], &HashMap::new(), &fds, false);
        assert!(hidden.is_empty());
        let (shown, _, _, _) =
            model.ingest(Instant::now(), 1.0, &[], &HashMap::new(), &fds, true);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].path, "/tmp/idle");
        assert_eq!(shown[0].summary, "cat (3)");
        assert!(shown[0].read_bps.abs() < 0.1);
    }

    #[test]
    fn prefers_the_probe_path_then_a_live_fd_path() {
        let mut fds = FdIndex::default();
        fds.holders.insert(
            (1, 2),
            vec![Holder {
                tgid: 1,
                comm: "a".into(),
                fds: vec![3],
                path: "/tmp/old (deleted)".into(),
            }],
        );
        fds.paths.insert((1, 2), "/tmp/from-scan".into());
        let mut hints = HashMap::new();
        hints.insert((1, 2), "/tmp/from-bpf".into());
        fds.holders.get_mut(&(1, 2)).unwrap().push(Holder {
            tgid: 2,
            comm: "b".into(),
            fds: vec![4],
            path: "/tmp/live".into(),
        });
        assert_eq!(choose_path(1, 2, &fds, &hints), "/tmp/from-bpf");
        hints.remove(&(1, 2));
        assert_eq!(choose_path(1, 2, &fds, &hints), "/tmp/live");
        assert_eq!(
            choose_path(9, 9, &FdIndex::default(), &hints),
            dev_ino_label(9, 9)
        );
        hints.insert((9, 9), "/only/hint".into());
        assert_eq!(
            choose_path(9, 9, &FdIndex::default(), &hints),
            "/only/hint"
        );
    }

    #[test]
    fn formats_rates() {
        assert_eq!(format_rate(12.0), "12 B/s");
        assert_eq!(format_rate(2048.0), "2.0 KiB/s");
        assert_eq!(format_rate(1.5 * 1024.0 * 1024.0), "1.5 MiB/s");
    }
}
