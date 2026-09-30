// SPDX-License-Identifier: MIT

//! Shrinks the helper's privileges once the probes are loaded.
//!
//! Loading and attaching the eBPF programs needs CAP_BPF and CAP_PERFMON (and
//! is the only reason the helper starts as root). After that the map file
//! descriptors keep working with no capabilities: only BPF_MAP_CREATE and
//! BPF_PROG_LOAD are capability-gated. The sampling loop still needs one:
//!
//! * CAP_SYS_PTRACE: read `/proc/<pid>/fd` and `/proc/<pid>/exe` of other users.

use std::io;

const CAP_SYS_PTRACE: u32 = 19;
const KEEP: [u32; 1] = [CAP_SYS_PTRACE];
const LAST_CAP: u32 = 63;
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn drop_to_sampling() -> io::Result<()> {
    let check = |rc: libc::c_long| {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    unsafe {
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as libc::c_long)?;
        // Other processes must not be able to ptrace or read the helper's memory.
        check(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) as libc::c_long)?;
        for cap in 0..=LAST_CAP {
            if KEEP.contains(&cap) {
                continue;
            }
            // EINVAL past the last capability this kernel knows about.
            libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        }
        let mut mask = [Data::default(); 2];
        for cap in KEEP {
            let word = (cap / 32) as usize;
            mask[word].effective |= 1 << (cap % 32);
            mask[word].permitted |= 1 << (cap % 32);
        }
        let header = Header {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        check(libc::syscall(libc::SYS_capset, &header, mask.as_ptr()))?;
    }
    Ok(())
}
