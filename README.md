
# BPFTOP: An extremely *B*espoke*PF* process monitor

Ever craved the rush of racing a ferrari, but couldn't justify taking out a second mortgage? 9/10 race car drivers say BPFtop is so fast that they feel *more* of a rush than that time they went supersonic on the track.

BPFtop is htop, but eBPF. We use BPF iterators to walk the kernel task list directly instead of scraping `/proc/PID/*` for every process.

htop does ~4 file reads per process *per* refresh cycle. It scales linearly -- O(n)! So, you're screwed if you have a lot of PIDs, and keep opening htop willy nilly and forget to close them. Htop ends up as one of the things eating up many instructions. As AFAIU the other process monitors like btm or btop also have this issue.

BUT life doesn't HAVE to be this way in the year of 2026! bpftop does one BPF iterator walk + 4 constant `/proc` reads regardless of process count. So, O(1) syscall count. Fast as fuck! BIG MONEY!!!

Here's a (somewhat dated) demo.

![demo](demo.gif)

# DISCLAIMER:

I worked closely with claude-code while building this. Claude has touched many parts of this codebase.

# THE BESPOKE ASF FEATURES

- BLAZINGLY FAST because the heavy lifting is done kernel-sid3
- Container aware (docker+podman) for each process
- Shows which systemd unit (`.service`, `.slice`, `.scope`) owns a process — useful when you have 15 things all named `python3`
- Per-process network I/O tracking via kprobes on tcp/udp send/recv (`N` to toggle). Still in eBPF land, so no syscall overhead here either!
- NVIDIA GPU usage per process (VRAM+%used)
- Cgroup v2 freeze/thaw — freeze entire services or containers atomically (press `f`). This is OP!!
- Vim keybindings, folding, visual mode, first class support for yank to clipboard that works in tmux
- Statically linked MUSL targets uploaded to CI so you can run onto any linux box
- CROSS PLATFORM: I got the bpf reading for both ARM and x86_64 working.
- zram aware! htop isn't zram aware. My RAM always reads wrong... The bar is full but the ram number is not...
- htop is prettyCoolTM. We have htop feature parity, so that's pretty cool too

# Okay, WTF is freezing?

I always felt so powerless in htop. Picture this: you're about to OOM and be subjected to the OOM killer. Some process keeps on allocating more memory. You figure out the problematic pid, but you're like "NOOO" because that pid is important and been running for 30 minutes and you really don't want to kill it. So what do you do? Kill something else? But you have 5s before you max out your RAM! So you sit there, watching, crying, knowing the OOM killer will kill the process and maybe some other stuff. You're frozen in despair. Maybe the process is maxxing out your CPU too, you don't know about niceness, and htop is SLOW because you have 100k pids. Turns out you aren't frozen by choice. Nope. You're frozen by circumstance.

Maybe you think "what if I suspend and resume"? Suspend/resume works by sending SIGTSTP/SIGCONT. These signals are visible to the process and its parents (SIGCHLD). The signals can have some handler that can ignore them. Talk about mixed signals! Forks, children, and parents of a children might keep going. So, it's deadass fucked and not at all clean if you SIGTSTP the process so you can figure out your RAM situation. What's worse, you'll get unintuitive racy behavior like if you SIGTSTP right before a child spins up and then the child doesn't get the signal and then gets upset because the parent is stoped.

This has ALWAYS bothered me. And now with cgroups v2 + bpftop we have a solution!

`cgroup.freeze` stops scheduling everything in the cgroup atomically. The processes have no idea. New forks are born frozen. Only someone with cgroupfs write access can thaw. The only thing is the system clock continues. So, maybe the time traveling process is a little confused. But this is still a massive improvement!

You can use this for fun and profit in bpftop! `f` to freeze, `u` to thaw with a confirmation dialog, `U` to thaw instantly. Frozen processes are clearly marked in bpftop.

# How to install

There's a nix flake with two outputs: dynamically linked and fully static musl binary. Statically linked is built and hosted on CI.

## NixOS

```nix
# flake.nix
{
  inputs.bpftop.url = "github:DieracDelta/bpftop";

  outputs = { self, nixpkgs, bpftop, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        bpftop.nixosModules.default
        { programs.bpftop.enable = true; }
      ];
    };
  };
}
```

The module sets up capabilities (`cap_bpf`, `cap_perfmon`, `cap_sys_resource`, `cap_dac_override`, `cap_sys_admin`) so it works without sudo. Yes, you'll need extra perms. With great power comes great perms. At the end of the day, the binary ends up at `/run/wrappers/bin/bpftop`.

## Non-NixOS with Nix

```bash
nix build github:DieracDelta/bpftop
sudo ./result/bin/bpftop

# or static (no runtime deps, copy it wherever)
nix build github:DieracDelta/bpftop#static
sudo ./result/bin/bpftop
```

## Non-Nix Linux

You need nightly rust, `rust-src`, and `bpf-linker`.

```bash
# eBPF object first (use arch-aarch64 on arm64 instead of arch-x86_64)
cd bpftop-ebpf
cargo build --target bpfel-unknown-none -Z build-std=core --release --features arch-x86_64
cd ..

# userspace binary
cargo build --release --bin bpftop
sudo ./target/release/bpftop
```

## Avoiding sudo

```bash
# core functionality
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=eip ./target/release/bpftop

# extra capabilities needed for cgroup freeze/thaw
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
cd bpftop-ebpf && cargo build --target bpfel-unknown-none -Z build-std=core --release --features arch-x86_64 && cd ..
cargo build --release --bin bpftop
sudo ./target/release/bpftop
```

# Build details

We have a two-phase build. The eBPF program compiles for `bpfel-unknown-none` with `-Z build-std=core`, then the userspace binary embeds it at compile time via `include_bytes_aligned!`. The eBPF crate is excluded from the workspace because it targets a different architecture, and cargo doesn't provide a "nice" way to handle this AFAIU.

The nix package builds bpf-linker v0.10.1 from source against LLVM 22. nixpkgs ships 0.9.15 with LLVM 21 which can't read objects produced by the newer LLVM.

# Limitations

Kernel struct offsets (`task_struct`, `mm_struct`, `sock`, etc.) are hardcoded per architecture. Build with `--features arch-x86_64` or `--features arch-aarch64`. May break across kernel versions if layouts change.

The right fix is CO-RE (resolve offsets from the target kernel's BTF at load time). Aya's loader supports CO-RE relocations but aya-ebpf can't emit them — rustc doesn't expose `__builtin_preserve_access_index`. Tracked at https://github.com/aya-rs/aya/issues/349.

Network stats (NET/s, NET TOT) are cumulative since bpftop was started, not since process start. There's no kernel-level per-process network accounting, so we use kprobes on tcp/udp send/recv. A daemon that runs at boot would give lifetime stats, but that's a different tool.

# Tested on

Two NixOS machines — one aarch64-linux, one x86_64-linux.

# Acknowledgements

htop inspired this.

[psc](https://github.com/dpc/psc) pushed my imagination in this direction. I didn't realize BPF was this far along until I saw that project. Such power!!

# Performance

bpftop does one BPF iterator walk + 4 `/proc` reads per cycle. htop does ~4 file reads per process. And so, syscall count scales linearly with process count for htop, but stays flat for bpftop.

![Syscall Scaling](bench/results/syscall_scaling.png)

![Collection Time](bench/results/collection_time.png)

![Syscall Breakdown](bench/results/syscall_breakdown.png)

## Reproducing the benchmarks

```bash
cargo build --release --bin bench
nix develop
sudo bash bench/run.sh
python3 bench/plot.py
```

See `bench/` for full methodology. I used [hyperfine](https://github.com/sharkdp/hyperfine) for timing, `strace -c` for syscall counts.
