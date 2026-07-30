// Compiles the tc classifier with clang -target bpf. The resulting
// object is embedded in the binary (include_bytes! in main.rs), so the
// deployed guard is a single file with no runtime asset paths.
//
// Set SHIELD_GUARD_BPF_OBJ to a prebuilt object to skip compilation
// (for packaging on hosts without clang).

use std::{
    env,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    println!("cargo:rerun-if-changed=bpf/shield_guard.bpf.c");
    println!("cargo:rerun-if-env-changed=SHIELD_GUARD_BPF_OBJ");
    println!("cargo:rerun-if-env-changed=CLANG");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("shield_guard.bpf.o");

    if let Ok(prebuilt) = env::var("SHIELD_GUARD_BPF_OBJ") {
        std::fs::copy(&prebuilt, &out)
            .unwrap_or_else(|e| panic!("cannot copy SHIELD_GUARD_BPF_OBJ {prebuilt}: {e}"));
        return;
    }

    // Debian and Ubuntu install the LLVM apt packages as clang-19,
    // clang-18, ... with no unversioned symlink unless the `clang` meta
    // package or an update-alternatives entry is also present. Probe
    // "clang" first, then the highest version found on PATH, so a host
    // with only clang-19 builds without being told about it. An explicit
    // CLANG is used verbatim: if the operator names a compiler, a
    // silent fallback to a different one would be worse than failing.
    let candidates = match env::var("CLANG") {
        Ok(explicit) => vec![explicit],
        Err(_) => clang_candidates(),
    };

    let clang = pick_clang(&candidates);

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
        panic!("failed to run {clang} (set CLANG or SHIELD_GUARD_BPF_OBJ): {e}")
    });
    assert!(
        status.success(),
        "{clang} failed to build the BPF object. On Debian/Ubuntu this usually means the kernel \
         headers are missing: apt install linux-libc-dev"
    );
}

/// Compilers to try, best first: plain `clang`, then every `clang-<N>`
/// on PATH from the highest version down.
fn clang_candidates() -> Vec<String> {
    let mut versioned: Vec<(u32, String)> = Vec::new();
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                // "clang-19" qualifies; "clang-cpp-19", "clang-tidy"
                // and "clang-scan-deps-19" do not, because the suffix
                // has to parse as a bare version number.
                let Some(version) = name
                    .strip_prefix("clang-")
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                if !versioned.iter().any(|(_, seen)| *seen == name) {
                    versioned.push((version, name));
                }
            }
        }
    }
    versioned.sort_by_key(|(version, _)| std::cmp::Reverse(*version));

    let mut out = vec!["clang".to_string()];
    out.extend(versioned.into_iter().map(|(_, name)| name));
    out
}

/// First candidate that actually runs. Probing with `--version` keeps a
/// dangling symlink or a half-removed package from being selected.
fn pick_clang(candidates: &[String]) -> String {
    for candidate in candidates {
        let runs = Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if runs {
            return candidate.clone();
        }
    }
    panic!(
        "no working clang found (tried: {}). Install it (Debian/Ubuntu: \
         apt install clang linux-libc-dev), or set CLANG to a versioned \
         binary such as clang-19, or point SHIELD_GUARD_BPF_OBJ at a \
         prebuilt object — see guard/README.md.",
        candidates.join(", ")
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
