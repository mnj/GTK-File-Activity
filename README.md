# GTK File Activity

Per-file read and write rates for Linux, in the style of Windows Resource
Monitor. A small eBPF program counts bytes per `(file, process)` in the kernel;
a GTK 4 / libadwaita window shows them as live rates, with a 60 second history
and the processes behind each file.

## Running

```sh
cargo build --release
./target/release/gtk-file-activity               # click "Enable Rates" for the probes
sudo ./target/release/gtk-file-activity --dump   # terminal output, prints hook hit counts
```

The window never runs as root. "Enable Rates" starts
`gtk-file-activity --helper` through `pkexec`. The helper loads the eBPF probes,
then drops every capability except `CAP_SYS_PTRACE` (reading other users'
`/proc/<pid>/fd`). It sends
one JSON snapshot per line to the window and exits when the window closes.
Without the helper the window still lists open files.

To install, put the binary at `/usr/bin/gtk-file-activity` and
`data/local.gtk.FileActivity.policy` in `/usr/share/polkit-1/actions/`. That
gives a proper authentication prompt that is remembered for the session.
Without it pkexec still works and uses its generic prompt.

Build needs `clang`, `bpftool`, libbpf headers, GTK 4.14+ and libadwaita 1.7+.
Runtime needs a kernel with BTF (`/sys/kernel/btf/vmlinux`) and fentry support,
on x86_64 or arm64. The probes target Linux 7.2. Hooks that do not exist on
another kernel fail to attach and are reported in the window.

Keys: `Ctrl+F` search, `Ctrl+P` pause, `F1` about.

## Layout

| Path | What |
| --- | --- |
| `bpf/filemon.bpf.c` | eBPF program (GPL-2.0-only) |
| `build.rs` | Compiles the eBPF object and generates the Rust skeleton |
| `src/collect/` | Sampling: `mod.rs` (sampler, thread), `bpf.rs` (maps), `helper.rs` (pkexec helper and protocol), `privs.rs` (capability drop), `procfs.rs` (fd scan), `control.rs` (UI settings) |
| `src/model.rs` | Turns counters into rates, per-file rows and history |
| `src/ui/` | `mod.rs` (window), `table.rs` (file list), `detail.rs` (sidebar), `graph.rs`, `row.rs`, `style.css` |
| `data/` | Desktop entry, polkit policy |

## What is counted

Logical bytes passed to `read`/`write` (and the `v`, `p` and `p*2` variants,
`copy_file_range`, `sendfile`, `splice` and io_uring), including page cache hits.
They are counted at the syscall entry points (`__x64_sys_*`), not in the VFS
functions beneath: on LTO/AutoFDO kernels (CachyOS) `vfs_read` and friends are
inlined into their callers, which silently removes the probe site.
Not counted: memory-mapped access, `kernel_read` callers such as `exec`, and
classic AIO.

## License

The application is MIT (see `LICENSE`). The eBPF program in `bpf/` is
GPL-2.0-only (see `bpf/LICENSE`), as the kernel requires for GPL-only helpers.
The compiled eBPF object is embedded in the binary, so a distributed binary
must be accompanied by the source for that program, which this repository is.
