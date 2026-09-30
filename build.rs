// SPDX-License-Identifier: MIT

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let vmlinux = out_dir.join("vmlinux.h");

    let dump = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("run bpftool to generate vmlinux.h");
    if !dump.status.success() {
        panic!(
            "bpftool btf dump failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        );
    }
    std::fs::write(&vmlinux, &dump.stdout).expect("write vmlinux.h");

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
    println!("cargo:rerun-if-changed=/sys/kernel/btf/vmlinux");
}
