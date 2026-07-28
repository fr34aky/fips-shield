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
    let status = Command::new(&clang)
        .args([
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
        .arg(&out)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run {clang} (install clang, or set CLANG / SHIELD_GUARD_BPF_OBJ): {e}"
            )
        });
    assert!(status.success(), "clang failed to build the BPF object");
}
