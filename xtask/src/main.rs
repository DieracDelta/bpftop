use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the CO-RE eBPF object (bpftop-ebpf-c/target/bpftop.bpf.o)
    BuildEbpf {
        /// clang to compile with (must support -target bpf; use an
        /// unwrapped clang, not a hardening cc-wrapper)
        #[clap(long, default_value = "clang")]
        clang: String,
    },
    /// Build the eBPF object and userspace, then run bpftop with sudo
    Run {
        /// Build in release mode
        #[clap(long)]
        release: bool,
        /// clang to compile the eBPF object with
        #[clap(long, default_value = "clang")]
        clang: String,
        /// Arguments to pass to the binary
        #[clap(last = true)]
        run_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::BuildEbpf { clang } => build_ebpf(&clang),
        Cli::Run { release, clang, run_args } => {
            build_ebpf(&clang)?;
            run(release, &run_args)
        }
    }
}

/// Same invocation as the flake's buildPhase. Field offsets are relocated
/// by Aya at load time from the running kernel's BTF, so the object isn't
/// tied to a kernel version.
fn build_ebpf(clang: &str) -> Result<()> {
    let root = workspace_root();
    let src_dir = root.join("bpftop-ebpf-c");
    let out_dir = src_dir.join("target");
    std::fs::create_dir_all(&out_dir).context("creating bpftop-ebpf-c/target")?;

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => bail!("unsupported architecture: {other}"),
    };

    let mut cmd = Command::new(clang);
    cmd.args(["-target", "bpf", &format!("-D__TARGET_ARCH_{arch}"), "-g", "-O2", "-Wall", "-Werror"])
        .arg("-I")
        .arg(&src_dir);
    if let Some(include) = libbpf_include() {
        cmd.arg("-I").arg(include);
    }
    cmd.arg("-c")
        .arg(src_dir.join("bpftop.bpf.c"))
        .arg("-o")
        .arg(out_dir.join("bpftop.bpf.o"));

    let status = cmd
        .status()
        .with_context(|| format!("failed to run {clang}"))?;
    if !status.success() {
        bail!("eBPF build failed with status: {}", status);
    }
    Ok(())
}

/// Directory containing <bpf/bpf_helpers.h>: $LIBBPF_INCLUDE, else
/// pkg-config, else the compiler's default search path.
fn libbpf_include() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("LIBBPF_INCLUDE") {
        return Some(dir.into());
    }
    let out = Command::new("pkg-config")
        .args(["--variable=includedir", "libbpf"])
        .output()
        .ok()?;
    let dir = String::from_utf8(out.stdout).ok()?;
    let dir = Path::new(dir.trim());
    (out.status.success() && dir.join("bpf/bpf_helpers.h").exists()).then(|| dir.to_path_buf())
}

fn run(release: bool, run_args: &[String]) -> Result<()> {
    let workspace_root = workspace_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .args(["build", "--package", "bpftop"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build userspace binary")?;
    if !status.success() {
        bail!("userspace build failed with status: {}", status);
    }

    let profile = if release { "release" } else { "debug" };
    let bin = workspace_root
        .join("target")
        .join(profile)
        .join("bpftop");

    let mut cmd = Command::new("sudo");
    cmd.arg(bin);
    cmd.args(run_args);

    let status = cmd.status().context("failed to run bpftop")?;
    if !status.success() {
        bail!("bpftop exited with status: {}", status);
    }

    Ok(())
}

fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("failed to run cargo metadata");

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failed to parse cargo metadata");

    PathBuf::from(
        metadata["workspace_root"]
            .as_str()
            .expect("workspace_root not found"),
    )
}
