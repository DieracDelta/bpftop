# What is this

An eBPF-powered interactive process monitor. Think `htop` but using BPF iterators and perf events to get per-process stats with no per-process syscall scaling. Ratatui TUI.

- Container awareness (Docker, podman — see which container each process belongs to)
- GPU awareness (NVIDIA via NVML)
- Systemd service/unit awareness (see which `.service`, `.slice`, or `.scope` owns a process)
- Cgroup v2 freeze/thaw (freeze entire services or containers without SIGSTOP)
- Statically linked target with MUSL so it can be run on any linux machine (assuming the linux is new enough)

![demo](demo.gif)

# Why not htop?

htop gives you a flat list of processes sorted by CPU or memory. That's fine until you need to answer questions like:

- **"What's eating my CPU?"** — htop shows you 30 individual worker threads. Are they from the same service? The same container? You have to cross-reference PIDs with `systemctl status`, `docker ps`, `cat /proc/PID/cgroup` manually.
- **"Which container is misbehaving?"** — htop has no concept of containers. You see PIDs and have to mentally map them to container names.
- **"Which systemd service is responsible?"** — htop shows process names like `python3` or `node`. Useless when you have 15 services all running python. bpftop shows the systemd unit directly in the process table (e.g. `myapp.service`, `docker-abc123.scope`).
- **"I want to pause this service while I debug something else"** — htop can send SIGSTOP to one process at a time. If the service has 20 worker processes, you're sending 20 signals and hoping nothing forks in between. And SIGSTOP is visible to the process (see below).

bpftop resolves all of this by showing container names, systemd units, and cgroup paths inline. You can filter by user, search by service name, and act on entire cgroups at once.

# Why cgroup freeze over SIGSTOP?

Traditional process monitors (htop, top) pause processes with `SIGSTOP`. This has real problems:

- **Not transparent.** The process can detect it was stopped. Parent processes see `SIGCHLD` with `WIFSTOPPED`. Supervisors like systemd may restart the service or log errors. Monitoring tools flag the state change.
- **Not atomic across a group.** If a service has 20 processes and you SIGSTOP them one by one, processes can fork new children between signals. You're racing against the workload.
- **Single-process only.** You have to find and signal every PID individually. Miss one and it keeps running.
- **SIGCONT from anywhere.** Any process with the right UID can send SIGCONT, accidentally or intentionally unfreezing what you paused.

Cgroup v2 freeze (`cgroup.freeze`) solves all of these:

- **Transparent.** The kernel simply stops scheduling tasks in the cgroup. The processes don't receive a signal — they have no idea they're frozen. No SIGCHLD, no state change visible to the application.
- **Atomic.** Writing `1` to `cgroup.freeze` freezes every process in the cgroup in one operation. No race window.
- **Group-level.** Freeze an entire systemd service or container with a single write. Any new processes forked into the cgroup are born frozen.
- **Controlled.** Only someone with write access to the cgroupfs can thaw. No accidental SIGCONT.

In bpftop: select a process, press `f`, confirm the dialog showing all affected PIDs in that cgroup, done. Press `u` to thaw with confirmation, or `U` to thaw instantly. Frozen processes show up in a distinct color in the process table.

# Disclaimer

I worked with claude when writing this. Claude has touched many parts of this codebase.

# How to install

There's a nix flake. Two package outputs: dynamically linked (default) and a fully static musl binary.

## NixOS

Add the flake input and enable the module. This installs bpftop with Linux capabilities (`cap_bpf`, `cap_perfmon`, `cap_sys_resource`, `cap_dac_override`, `cap_sys_admin`) so it runs without sudo.

```nix
# flake.nix
{
  inputs.bpftop.url = "github:DieracDelta/bpftop";

  outputs = { self, nixpkgs, bpftop, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        bpftop.nixosModules.default
        {
          programs.bpftop.enable = true;
        }
      ];
    };
  };
}
```

Then `bpftop` is available at `/run/wrappers/bin/bpftop` and works without sudo.

## Non-NixOS with Nix

```bash
# dynamic binary
nix build github:DieracDelta/bpftop
sudo ./result/bin/bpftop

# static binary (no runtime deps, copy it wherever)
nix build github:DieracDelta/bpftop#static
sudo ./result/bin/bpftop
```

## Non-Nix Linux

Grab the static binary from the releases or build it yourself. You need nightly rust, `rust-src`, and `bpf-linker`.

```bash
# build the eBPF object first (use arch-aarch64 on arm64)
cd bpftop-ebpf
cargo build --target bpfel-unknown-none -Z build-std=core --release --features arch-x86_64
cd ..

# then the userspace binary
cargo build --release --bin bpftop

# run it
sudo ./target/release/bpftop
```

## Avoiding sudo

bpftop needs `cap_bpf`, `cap_perfmon`, and `cap_sys_resource` capabilities for core functionality. On NixOS, the module handles this automatically. Otherwise, set them manually:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=eip ./target/release/bpftop
./bpftop  # no sudo needed
```

The cgroup freeze/thaw feature (`f`/`u`/`U` keys) additionally requires `cap_dac_override` and `cap_sys_admin` to write to cgroupfs files and migrate processes between cgroups. The NixOS module includes these. For manual setcap:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_dac_override,cap_sys_admin=eip ./target/release/bpftop
```

# Usage

```bash
bpftop                     # default 1s refresh
bpftop -d 500              # 500ms refresh rate
bpftop -t                  # start in tree view
bpftop -u jrestivo         # filter by user
```

# Development

```bash
nix develop
# bpf-linker is installed via cargo install bpf-linker in the devshell
cd bpftop-ebpf && cargo build --target bpfel-unknown-none -Z build-std=core --release --features arch-x86_64 && cd ..
cargo build --release --bin bpftop
sudo ./target/release/bpftop
```

# Build details

The build is two-phase. Phase 1 compiles the eBPF program (`bpftop-ebpf`) for the `bpfel-unknown-none` target using `-Z build-std=core`. Phase 2 compiles the userspace binary which embeds the eBPF object at compile time via `include_bytes_aligned!`. The eBPF crate is excluded from the cargo workspace because it targets a completely different architecture.

The nix package builds bpf-linker v0.10.1 from source against LLVM 22 to match the nightly rust toolchain's LLVM version. nixpkgs ships bpf-linker 0.9.15 with LLVM 21 which can't read object files produced by the newer LLVM.

# Supported Systems

Tested on two NixOS machines only — one aarch64-linux and one x86_64-linux.

# Limitations

Kernel struct field offsets (e.g. `task_struct`, `mm_struct`) are hardcoded per architecture at compile time. This means the eBPF program must be built with the correct `--features arch-x86_64` or `--features arch-aarch64` flag, and may break across kernel versions if struct layouts change.

Ideally we'd use CO-RE (Compile Once, Run Everywhere) to resolve offsets at load time from the target kernel's BTF. Aya's loader fully supports CO-RE relocations, but aya-ebpf (the BPF-side Rust SDK) can't emit them because rustc doesn't expose LLVM's `__builtin_preserve_access_index` intrinsic. This is tracked at https://github.com/aya-rs/aya/issues/349.

# Acknowledgements

htop was the inspiration for this project. It's too resource heavy! bpftop is much faster — see the benchmarks below

psc was also an inspiration for this project. I didn't realize bpf was this far along until I saw that project.

# Performance

bpftop uses a BPF task iterator to walk the kernel's task list in a single pass, plus 4 constant `/proc` reads for system-wide stats (`/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime`). htop opens and reads ~4 files per process per refresh (`/proc/PID/stat`, `status`, `cmdline`, `cgroup`), so its syscall count grows linearly with process count.

**Syscall scaling** — At each process count (100–10,000), dummy `sleep` processes are spawned and both tools are run under `strace -f -c` to count total syscalls. htop scales linearly; bpftop stays flat.

![Syscall Scaling](bench/results/syscall_scaling.png)

**Collection time** — Each tool is benchmarked with `hyperfine` at each scale point. bpftop runs `bench --iterations 1 --warmup 0` (one BPF iterator walk + 4 `/proc` reads). htop runs `htop -d 1 -n 5` under `script` for a pseudo-tty. Shaded bands show stddev.

![Collection Time](bench/results/collection_time.png)

**Syscall breakdown at N=5000** — Per-syscall counts from `strace -f -c` showing htop dominated by `read`/`openat`/`close` (per-PID `/proc` scraping) while bpftop's counts are near zero on the log scale.

![Syscall Breakdown](bench/results/syscall_breakdown.png)

## Reproducing

```bash
# Build the bench binary
cargo build --release --bin bench

# Enter the devshell (provides hyperfine, strace, htop, matplotlib)
nix develop

# Run benchmarks (needs root for BPF)
sudo bash bench/run.sh

# Generate graphs
python3 bench/plot.py
```

See `bench/` for the full methodology. Timing uses [hyperfine](https://github.com/sharkdp/hyperfine) for statistically rigorous measurements. Syscall counts use `strace -c`.
