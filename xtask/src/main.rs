use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs
    BuildEbpf {
        /// Set the endianness of the BPF target
        #[clap(default_value = "bpfel-unknown-none", long)]
        target: String,
        /// Build in release mode
        #[clap(long)]
        release: bool,
    },
    /// Build eBPF programs and run the userspace binary
    Run {
        /// Build in release mode
        #[clap(long)]
        release: bool,
        /// Arguments to pass to the binary
        #[clap(last = true)]
        run_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { target, release } => build_ebpf(&target, release),
        Cli::Run { release, run_args } => {
            build_ebpf("bpfel-unknown-none", release)?;
            run(release, &run_args)
        }
    }
}

fn build_ebpf(target: &str, release: bool) -> Result<()> {
    let workspace_root = workspace_root();
    let ebpf_dir = workspace_root.join("bpftop-ebpf");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "+nightly",
            "build",
            "--target",
            target,
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build eBPF programs")?;
    if !status.success() {
        bail!("eBPF build failed with status: {}", status);
    }

    Ok(())
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
