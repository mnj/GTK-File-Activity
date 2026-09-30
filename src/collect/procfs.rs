// SPDX-License-Identifier: MIT

use crate::model::{FdIndex, Holder};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;

/// Every process, or only `only` when the caller needs a few. Walking every
/// fd of every process costs a few syscalls each, so the sampler limits the
/// scan to recently active processes unless idle files are shown.
pub fn scan(only: Option<&HashSet<u32>>) -> FdIndex {
    let mut index = FdIndex::default();
    let pids: Vec<u32> = match only {
        Some(set) => set.iter().copied().collect(),
        None => match fs::read_dir("/proc") {
            Ok(entries) => entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
                .collect(),
            Err(_) => return index,
        },
    };
    for pid in pids {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if let Some(exe) = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
            .filter(|path| !path.is_empty())
        {
            index.exes.insert(pid, exe);
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd_ent in fds.flatten() {
            let Ok(fd_num) = fd_ent.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let fd_path = fd_ent.path();
            // Sockets, pipes and anon inodes read as "socket:[1]" and so on.
            // Only file paths start with a slash, which saves a stat on those.
            let link = fs::read_link(&fd_path)
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !link.starts_with('/') {
                continue;
            }
            let Ok(meta) = fs::metadata(&fd_path) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let id = (meta.dev(), meta.ino());
            let holders = index.holders.entry(id).or_default();
            if let Some(existing) = holders.iter_mut().find(|h| h.tgid == pid) {
                existing.fds.push(fd_num);
                if path_rank(&link) > path_rank(&existing.path) {
                    existing.path = link;
                }
            } else {
                holders.push(Holder {
                    tgid: pid,
                    comm: comm.clone(),
                    fds: vec![fd_num],
                    path: link,
                });
            }
        }
    }
    for (id, holders) in &index.holders {
        if let Some(best) = holders.iter().max_by(|a, b| path_rank(&a.path).cmp(&path_rank(&b.path)))
        {
            index.paths.insert(*id, best.path.clone());
        }
    }
    index
}

fn path_rank(path: &str) -> (u8, i64) {
    let live = if path.contains(" (deleted)") { 0 } else { 1 };
    (live, -(path.len() as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_records_our_executable() {
        let index = scan(None);
        let exe = index
            .exes
            .get(&std::process::id())
            .expect("this process is visible in /proc");
        assert!(exe.starts_with('/'), "{exe}");
    }
}
