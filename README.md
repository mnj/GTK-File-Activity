# GTK File Activity

[![CI](https://github.com/mnj/GTK-File-Activity/actions/workflows/ci.yml/badge.svg)](https://github.com/mnj/GTK-File-Activity/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mnj/GTK-File-Activity)](https://github.com/mnj/GTK-File-Activity/releases/latest)

See which files your programs are reading and writing, and how fast. A
Resource Monitor style viewer for Linux: one row per file, live read and write
speeds, a 60 second history, and the processes behind each file.

Website: <https://mnj.github.io/GTK-File-Activity/>

A small eBPF program counts bytes per file and process inside the kernel. A
GTK 4 / libadwaita window shows them.

## Install

Requires Linux on x86_64 with GTK 4.14+ and libadwaita 1.7+. The probes target
Linux 7.2 and need a kernel with BTF (`/sys/kernel/btf/vmlinux`) and fentry
support.

From a [release](https://github.com/mnj/GTK-File-Activity/releases/latest):

```sh
tar xf gtk-file-activity-*-x86_64-linux.tar.gz
cd gtk-file-activity-*/
sudo PREFIX=/usr ./install.sh
```

`PREFIX=/usr` also installs the polkit policy, which gives a proper
authentication prompt that is remembered for the session. With the default
`/usr/local` prefix pkexec uses its generic prompt.

Every merge to `main` publishes a new release, tagged
`v<major>.<minor>.<commit count>`.

### From source

Needs Rust, `clang`, `make`, `pkg-config`, libelf and zlib headers, and the
GTK 4 and libadwaita development files.

```sh
cargo build --release
./target/release/gtk-file-activity
```

The eBPF program is compiled against a checked-in kernel type header
(`bpf/vmlinux-x86_64.h.gz`, from Linux 7.2), so the build does not depend on
the kernel you build on. Set `VMLINUX_H=/path/to/vmlinux.h` to use another. On
other architectures the build dumps the running kernel's BTF with `bpftool`.

## Using it

Start the app and click **Start Monitoring**. Until then it lists the files
programs have open, without speeds.

| Key | Action |
| --- | --- |
| `Ctrl+F` (or just type) | Search by file or program |
| `Ctrl+P` | Pause |
| `F1` | About |

The menu sets the refresh interval and whether idle open files are listed.

### Permissions

The window never runs as root. **Start Monitoring** runs
`gtk-file-activity --helper` through `pkexec`. The helper loads the eBPF
probes, then drops every capability except `CAP_SYS_PTRACE` (needed to read
other users' `/proc/<pid>/fd`). It sends one JSON snapshot per line to the
window on stdout, takes settings on stdin, and exits when the window closes.

### Troubleshooting

`sudo gtk-file-activity --dump` runs the sampler in the terminal and prints how
often each hook fired. A hook that never fires on your kernel is the first
thing to check when numbers look low or files show as `0:55 inode 1234`.

## What is counted

Logical bytes passed to `read`/`write` (and the `p`, `v` and `p…v2` variants),
`copy_file_range`, `sendfile`, `splice` and io_uring, including page cache hits.

They are counted at the syscall entry points (`__x64_sys_*`), not in the VFS
functions beneath. On LTO/AutoFDO kernels (CachyOS) `vfs_read` and friends are
inlined into their callers, which silently removes the probe site. Paths are
rebuilt by walking dentries and mounts the first time a file is counted, for
the same reason: the hooks `bpf_d_path` is allowed in are inlined away too.

Not counted: memory-mapped access, `kernel_read` callers such as `exec`, and
classic AIO.

## Layout

| Path | What |
| --- | --- |
| `bpf/filemon.bpf.c` | The eBPF program (GPL-2.0-only) |
| `bpf/vmlinux-x86_64.h.gz` | Kernel types the program is compiled against |
| `build.rs` | Compiles the eBPF object and generates the Rust skeleton |
| `src/collect/` | Sampling: `mod.rs` (sampler and thread), `bpf.rs` (maps), `helper.rs` (pkexec helper and protocol), `privs.rs` (capability drop), `procfs.rs` (fd scan), `control.rs` (settings shared with the UI) |
| `src/model.rs` | Turns counters into rates, per-file rows and history |
| `src/ui/` | `mod.rs` (window), `table.rs` (file list), `detail.rs` (sidebar), `graph.rs`, `row.rs`, `style.css` |
| `data/` | Desktop entry and polkit policy |
| `scripts/install.sh` | Installer used by the release archive |
| `docs/` | The website, published with GitHub Pages |
| `.github/workflows/` | CI, releases and Pages |

## Contributing

Open a pull request against `main`. CI builds, runs the tests and runs clippy
with warnings denied (`cargo clippy --all-targets -- -D warnings`). When it
merges, a release is published automatically.

## License

The application is MIT (see `LICENSE`). The eBPF program in `bpf/`, and the
kernel header it is built against, are GPL-2.0-only (see `bpf/LICENSE`), as the
kernel requires for GPL-only helpers. The compiled eBPF object is embedded in
the binary, so a distributed binary must be accompanied by the source for that
program, which this repository is. Release archives include both licenses.
