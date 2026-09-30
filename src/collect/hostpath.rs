// SPDX-License-Identifier: MIT

//! Translates paths seen inside a container to paths on the host.
//!
//! The probe records a path as the touching process sees it, so a file bind
//! mounted at `/input` in a container comes back as `/input/...`. Every mount
//! has a filesystem (its `major:minor`) and a root inside that filesystem, and
//! both namespaces report them in `mountinfo`. So the container path becomes a
//! path inside the filesystem, and the host mount of the same filesystem turns
//! that back into a host path.

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

const MOUNTINFO_TTL: Duration = Duration::from_secs(10);
const MISS_TTL: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq)]
pub struct MountEntry {
    /// Directory inside the filesystem that is mounted here.
    pub root: String,
    pub point: String,
    /// `major:minor` of the filesystem.
    pub dev: String,
}

pub struct HostPaths {
    host_ns: u64,
    host: Option<(Instant, Vec<MountEntry>)>,
    by_ns: HashMap<u64, (Instant, Vec<MountEntry>)>,
    /// Result and when it was worked out. Failures are retried after `MISS_TTL`.
    translated: HashMap<(u64, u64), (Instant, Option<String>)>,
}

impl HostPaths {
    pub fn new() -> Self {
        Self {
            host_ns: ns_inode("self").unwrap_or(0),
            host: None,
            by_ns: HashMap::new(),
            translated: HashMap::new(),
        }
    }

    /// Turns each hint into a host path where it can. `tgids` lists, per file,
    /// the processes that touched it, to find one living in the hint's namespace.
    pub fn resolve(
        &mut self,
        hints: &HashMap<(u64, u64), (u64, String)>,
        tgids: &HashMap<(u64, u64), Vec<u32>>,
    ) -> HashMap<(u64, u64), String> {
        let now = Instant::now();
        self.translated.retain(|id, _| hints.contains_key(id));
        let mut out = HashMap::new();
        for (id, (ns, path)) in hints {
            if *ns == self.host_ns || *ns == 0 {
                out.insert(*id, path.clone());
                continue;
            }
            if let Some((at, host)) = self.translated.get(id) {
                match host {
                    Some(host) => {
                        out.insert(*id, host.clone());
                        continue;
                    }
                    None if now.duration_since(*at) < MISS_TTL => {
                        out.insert(*id, path.clone());
                        continue;
                    }
                    None => {}
                }
            }
            let host = tgids
                .get(id)
                .and_then(|pids| self.translate(*ns, path, pids, now));
            self.translated.insert(*id, (now, host.clone()));
            // Without a translation the container path is still better than an inode.
            out.insert(*id, host.unwrap_or_else(|| path.clone()));
        }
        out
    }

    fn translate(&mut self, ns: u64, path: &str, pids: &[u32], now: Instant) -> Option<String> {
        let pid = pids.iter().find(|pid| ns_inode(&pid.to_string()) == Some(ns))?;
        let stale = |entry: &Option<&(Instant, Vec<MountEntry>)>| {
            entry.is_none_or(|(at, _)| now.duration_since(*at) > MOUNTINFO_TTL)
        };
        if stale(&self.by_ns.get(&ns)) {
            let text = fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
            self.by_ns.insert(ns, (now, parse_mountinfo(&text)));
        }
        if stale(&self.host.as_ref()) {
            let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
            self.host = Some((now, parse_mountinfo(&text)));
        }
        let theirs = &self.by_ns.get(&ns)?.1;
        let ours = &self.host.as_ref()?.1;
        to_host(path, theirs, ours)
    }
}

fn ns_inode(pid: &str) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()?;
    let link = link.to_string_lossy();
    link.strip_prefix("mnt:[")?.strip_suffix(']')?.parse().ok()
}

/// A path inside `ns_mounts`' namespace, as a path in the `host_mounts` one.
pub fn to_host(path: &str, ns_mounts: &[MountEntry], host_mounts: &[MountEntry]) -> Option<String> {
    let inner = ns_mounts
        .iter()
        .filter(|m| under(path, &m.point))
        .max_by_key(|m| m.point.len())?;
    let in_fs = join(&inner.root, strip(path, &inner.point));
    let outer = host_mounts
        .iter()
        .filter(|m| m.dev == inner.dev && under(&in_fs, &m.root))
        .max_by_key(|m| m.root.len())?;
    Some(join(&outer.point, strip(&in_fs, &outer.root)))
}

/// Whether `path` is `dir` or inside it, by whole path components.
fn under(path: &str, dir: &str) -> bool {
    dir == "/" || path == dir || path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
}

fn strip<'a>(path: &'a str, dir: &str) -> &'a str {
    if dir == "/" {
        path
    } else {
        path.strip_prefix(dir).unwrap_or(path)
    }
}

fn join(base: &str, rest: &str) -> String {
    let rest = rest.trim_start_matches('/');
    match (base.trim_end_matches('/'), rest.is_empty()) {
        ("", true) => "/".into(),
        (base, true) => base.into(),
        (base, false) => format!("{base}/{rest}"),
    }
}

pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let (pre, _) = line.split_once(" - ")?;
            let mut fields = pre.split_whitespace();
            let dev = fields.nth(2)?.to_string();
            let root = unescape(fields.next()?);
            let point = unescape(fields.next()?);
            Some(MountEntry { root, point, dev })
        })
        .collect()
}

fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match (bytes[i], octal) {
            (b'\\', Some(d)) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "\
36 1 0:35 /@ / rw - btrfs /dev/x rw,subvol=/@
40 36 0:151 / /run/media/mnj/Backup3 rw - btrfs /dev/y rw,subvolid=5
41 36 8:1 / /mnt/ext\\040disk rw - ext4 /dev/sda1 rw
";
    const CONTAINER: &str = "\
500 400 0:200 / / rw - overlay overlay rw
501 500 0:151 /DustinRaw/jira/jira /input ro - btrfs /dev/y rw,subvolid=5
502 500 0:151 /out /output rw - btrfs /dev/y rw,subvolid=5
";

    #[test]
    fn maps_a_bind_mount_back_to_the_host_path() {
        let host = parse_mountinfo(HOST);
        let ct = parse_mountinfo(CONTAINER);
        assert_eq!(
            to_host("/input/attachments/TS/a.iso", &ct, &host).as_deref(),
            Some("/run/media/mnj/Backup3/DustinRaw/jira/jira/attachments/TS/a.iso")
        );
        assert_eq!(
            to_host("/output/tmp/x", &ct, &host).as_deref(),
            Some("/run/media/mnj/Backup3/out/tmp/x")
        );
    }

    #[test]
    fn unknown_filesystems_are_left_alone() {
        let host = parse_mountinfo(HOST);
        let ct = parse_mountinfo(CONTAINER);
        assert_eq!(to_host("/etc/hosts", &ct, &host), None);
    }

    #[test]
    fn matches_whole_components_and_unescapes() {
        assert!(under("/input/a", "/input"));
        assert!(!under("/inputs/a", "/input"));
        assert_eq!(parse_mountinfo(HOST)[2].point, "/mnt/ext disk");
        assert_eq!(join("/", "a/b"), "/a/b");
        assert_eq!(join("/mnt", ""), "/mnt");
    }
}
