// Compiles the tc classifier with clang -target bpf. The resulting
// object is embedded in the binary (include_bytes! in main.rs), so the
// deployed guard is a single file with no runtime asset paths.
//
// Set SHIELD_GUARD_BPF_OBJ to a prebuilt object to skip compilation
// (for packaging on hosts without clang).

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=bpf/shield_guard.bpf.c");
    println!("cargo:rerun-if-env-changed=SHIELD_GUARD_BPF_OBJ");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("shield_guard.bpf.o");

    if let Ok(prebuilt) = env::var("SHIELD_GUARD_BPF_OBJ") {
        std::fs::copy(&prebuilt, &out)
            .unwrap_or_else(|e| panic!("cannot copy SHIELD_GUARD_BPF_OBJ {prebuilt}: {e}"));
        return;
    }

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    // -g is required: the BTF it emits is what carries the map
    // definitions the loader (and the kernel) rely on.
    let mut cmd = Command::new(&clang);
    cmd.args([
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-Wall",
        "-Werror",
        "-c",
        "bpf/shield_guard.bpf.c",
        "-o",
    ])
    .arg(&out);

    // linux/bpf.h pulls in asm/types.h, which Debian and Ubuntu keep in
    // a multiarch directory that clang does not search when targeting
    // BPF (the target triple is "bpf", not the host's). Add it when
    // present; distributions with a unified /usr/include (Fedora,
    // Alpine) need nothing, and a host with gcc-multilib installed
    // happens to work either way — which is exactly why this was easy
    // to miss locally.
    for dir in multiarch_include_dirs() {
        if dir.is_dir() {
            cmd.arg(format!("-I{}", dir.display()));
        }
    }

    let status = cmd.status().unwrap_or_else(|e| {
        panic!("failed to run {clang} (install clang, or set CLANG / SHIELD_GUARD_BPF_OBJ): {e}")
    });
    assert!(
        status.success(),
        "clang failed to build the BPF object. On Debian/Ubuntu this usually means the kernel \
         headers are missing: apt install linux-libc-dev"
    );
}

fn multiarch_include_dirs() -> Vec<PathBuf> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let triples: &[&str] = match arch.as_str() {
        // 32-bit ARM ships under two possible triples depending on ABI.
        "arm" => &["arm-linux-gnueabihf", "arm-linux-gnueabi"],
        "x86_64" => &["x86_64-linux-gnu"],
        "aarch64" => &["aarch64-linux-gnu"],
        "riscv64" => &["riscv64-linux-gnu"],
        "powerpc64" => &["powerpc64le-linux-gnu"],
        _ => &[],
    };
    triples
        .iter()
        .map(|t| PathBuf::from("/usr/include").join(t))
        .collect()
}
