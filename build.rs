// SPDX-License-Identifier: MIT

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let vmlinux = out_dir.join("vmlinux.h");

    write_vmlinux(&vmlinux);

    let skel = out_dir.join("filemon.skel.rs");
    SkeletonBuilder::new()
        .source("bpf/filemon.bpf.c")
        .clang_args([format!("-I{}", out_dir.display())])
        .build_and_generate(&skel)
        .expect("compile filemon.bpf.c");
    // libbpf 1.8 repeats deprecated enum names with the same value. Rust
    // rejects that, and nothing in this program uses the deprecated names.
    let generated = std::fs::read_to_string(&skel).expect("read skeleton");
    let generated = generated
        .lines()
        .filter(|line| !line.contains("_DEPRECATED"))
        .filter(|line| !line.contains("use libbpf_rs::MapCore as _;"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&skel, generated).expect("write skeleton");

    println!("cargo:rerun-if-changed=bpf/filemon.bpf.c");
    println!("cargo:rerun-if-changed=bpf/vmlinux-x86_64.h.gz");
    println!("cargo:rerun-if-env-changed=VMLINUX_H");
}

/// The kernel type definitions the eBPF program is compiled against.
///
/// CO-RE relocates field offsets at load time, so one header is enough for
/// every kernel that has the types the program uses. The default is a checked
/// in header (from Linux 7.2) so builds do not depend on the build machine's
/// kernel, which matters in CI. `VMLINUX_H=/path/to/vmlinux.h` overrides it,
/// and other architectures dump the running kernel's BTF with bpftool.
fn write_vmlinux(dest: &Path) {
    if let Ok(path) = env::var("VMLINUX_H") {
        std::fs::copy(&path, dest).unwrap_or_else(|err| panic!("copy {path}: {err}"));
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let bundled = Path::new("bpf/vmlinux-x86_64.h.gz");
    let dump = if arch == "x86_64" && bundled.exists() {
        Command::new("gzip").arg("-dc").arg(bundled).output()
    } else {
        Command::new("bpftool")
            .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .output()
    }
    .expect("run gzip or bpftool to produce vmlinux.h");
    if !dump.status.success() {
        panic!(
            "producing vmlinux.h failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        );
    }
    std::fs::write(dest, &dump.stdout).expect("write vmlinux.h");
}
