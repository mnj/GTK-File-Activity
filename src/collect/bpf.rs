// SPDX-License-Identifier: MIT

//! Loads the eBPF object and reads its maps.

use crate::model::RawStat;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};
use std::collections::HashMap;
use std::mem::MaybeUninit;

include!(concat!(env!("OUT_DIR"), "/filemon.skel.rs"));

pub const EXPECTED_PROBES: usize = 16;

pub struct Loaded {
    _links: Vec<libbpf_rs::Link>,
    skel: FilemonSkel<'static>,
    pub attached: usize,
    pub failed: Vec<String>,
}

impl Loaded {
    pub fn open() -> Result<Self, String> {
        // libbpf-rs 0.24 borrows the loaded object from caller-owned storage for the skeleton lifetime.
        let storage = Box::leak(Box::new(MaybeUninit::uninit()));
        let open = FilemonSkelBuilder::default()
            .open(storage)
            .map_err(|err| format!("open probes: {err}"))?;
        let skel = open
            .load()
            .map_err(|err| format!("load probes: {err}"))?;

        let mut failed = Vec::new();
        let mut links = Vec::new();
        macro_rules! attach {
            ($prog:ident) => {
                match skel.progs.$prog.attach() {
                    Ok(link) => links.push(link),
                    Err(err) => failed.push(format!("{}: {err}", stringify!($prog))),
                }
            };
        }
        attach!(on_sys_read);
        attach!(on_sys_pread64);
        attach!(on_sys_readv);
        attach!(on_sys_preadv);
        attach!(on_sys_preadv2);
        attach!(on_sys_write);
        attach!(on_sys_pwrite64);
        attach!(on_sys_writev);
        attach!(on_sys_pwritev);
        attach!(on_sys_pwritev2);
        attach!(on_sys_sendfile64);
        attach!(on_sys_splice);
        attach!(on_sys_copy_file_range);
        attach!(on_kiocb_done);
        attach!(on_io_complete_rw);
        attach!(on_io_complete_rw_iopoll);

        let attached = links.len();
        Ok(Self {
            _links: links,
            skel,
            attached,
            failed,
        })
    }

    pub fn read_stats(&self) -> Vec<RawStat> {
        let mut out = Vec::new();
        for key in map_keys(&self.skel.maps.stats) {
            let Some(val) = map_lookup(&self.skel.maps.stats, &key) else {
                continue;
            };
            let Some(key) = pod::<FileKey>(&key) else {
                continue;
            };
            let Some(val) = pod::<FileStat>(&val) else {
                continue;
            };
            out.push(RawStat {
                dev: key.dev,
                ino: key.ino,
                tgid: key.tgid,
                rbytes: val.rbytes,
                wbytes: val.wbytes,
                reads: val.reads,
                writes: val.writes,
                comm: cstr(&val.comm),
            });
        }
        out
    }

    pub fn read_hints(&self) -> HashMap<(u64, u64), String> {
        let mut out = HashMap::new();
        for key in map_keys(&self.skel.maps.paths) {
            let Some(val) = map_lookup(&self.skel.maps.paths, &key) else {
                continue;
            };
            let Some(key) = pod::<PathKey>(&key) else {
                continue;
            };
            let path = cstr(&val);
            if !path.is_empty() {
                out.insert((key.dev, key.ino), path);
            }
        }
        out
    }

    /// How often each hook fired, summed over CPUs, in the order of the C `enum hook`.
    pub fn read_hits(&self) -> Vec<(&'static str, u64)> {
        HOOK_NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let key = (i as u32).to_ne_bytes();
                let total = self
                    .skel
                    .maps
                    .hits
                    .lookup_percpu(&key, MapFlags::ANY)
                    .ok()
                    .flatten()
                    .map(|cpus| {
                        cpus.iter()
                            .filter_map(|bytes| pod::<u64>(bytes))
                            .fold(0u64, u64::wrapping_add)
                    })
                    .unwrap_or(0);
                (*name, total)
            })
            .collect()
    }
}

/// Must match `enum hook` in bpf/filemon.bpf.c.
const HOOK_NAMES: [&str; 19] = [
    "read",
    "pread64",
    "readv",
    "preadv",
    "preadv2",
    "write",
    "pwrite64",
    "writev",
    "pwritev",
    "pwritev2",
    "sendfile",
    "splice",
    "copy_file_range",
    "io_uring",
    "io_uring (queued)",
    "io_uring (iopoll)",
    "path ok",
    "path truncated",
    "path empty",
];

#[repr(C)]
#[derive(Clone, Copy)]
struct FileKey {
    dev: u64,
    ino: u64,
    tgid: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FileStat {
    rbytes: u64,
    wbytes: u64,
    reads: u64,
    writes: u64,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PathKey {
    dev: u64,
    ino: u64,
}

fn pod<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn map_keys(map: &impl MapCore) -> Vec<Vec<u8>> {
    map.keys().collect()
}

fn map_lookup(map: &impl MapCore, key: &[u8]) -> Option<Vec<u8>> {
    map.lookup(key, MapFlags::ANY).ok().flatten()
}

