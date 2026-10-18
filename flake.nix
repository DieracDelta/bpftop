{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, fenix }:
    let
      forAllSystems = fn:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: fn {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
            inherit system;
          });
      # Single LLVM for the BPF object in both the package and the dev shell.
      llvmFor = pkgs: pkgs.llvmPackages_23;
    in {
      packages = forAllSystems ({ pkgs, system }:
        let
          rustToolchain = pkgs.rust-bin.stable.latest.default;

          workspaceVendor = pkgs.rustPlatform.fetchCargoVendor {
            src = ./.;
            hash = "sha256-85fpj96ncyt/S9ybbIctkogrZ71k+Pl1wjrODFeeUHs=";
          };

          mkBpftop = { pname, rustToolchain, cargoTarget ? null, extraNativeBuildInputs ? [], env ? {}, bins ? [ "bpftop" ] }:
            let
              targetFlag = if cargoTarget != null then "--target ${cargoTarget}" else "";
              outputDir = if cargoTarget != null then "target/${cargoTarget}/release" else "target/release";
              bpfTargetArch = {
                "x86_64-linux" = "x86";
                "aarch64-linux" = "arm64";
              }.${system};
            in pkgs.stdenv.mkDerivation ({
              inherit pname;
              version = "0.1.0";
              src = ./.;

              nativeBuildInputs = [
                rustToolchain
                (llvmFor pkgs).clang-unwrapped
                (llvmFor pkgs).llvm
                pkgs.libbpf
                pkgs.pkg-config
              ] ++ extraNativeBuildInputs;

              buildInputs = [ pkgs.elfutils ];

              configurePhase = ''
                runHook preConfigure

                export HOME=$(mktemp -d)

                # Vendor workspace deps (substitute @vendor@ placeholder)
                mkdir -p .cargo
                substitute ${workspaceVendor}/.cargo/config.toml .cargo/config.toml \
                  --subst-var-by vendor ${workspaceVendor}
                echo '[alias]' >> .cargo/config.toml
                echo 'xtask = "run --package xtask --"' >> .cargo/config.toml

                runHook postConfigure
              '';

              buildPhase = ''
                runHook preBuild

                # Phase 1: Build CO-RE eBPF object. Field offsets are relocated
                # by Aya at load time from the running kernel's BTF.
                mkdir -p bpftop-ebpf-c/target
                clang -target bpf -D__TARGET_ARCH_${bpfTargetArch} -g -O2 -Wall -Werror \
                  -I bpftop-ebpf-c \
                  -I ${pkgs.libbpf}/include \
                  -c bpftop-ebpf-c/bpftop.bpf.c \
                  -o bpftop-ebpf-c/target/bpftop.bpf.o

                # Phase 2: Build userspace (embeds eBPF via include_bytes_aligned!)
                cargo build --release ${pkgs.lib.concatMapStringsSep " " (b: "--bin ${b}") bins} ${targetFlag}

                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/bin
                cp ${pkgs.lib.concatMapStringsSep " " (b: "${outputDir}/${b}") bins} $out/bin/
                runHook postInstall
              '';
            } // env);

          muslTarget = {
            "x86_64-linux" = "x86_64-unknown-linux-musl";
            "aarch64-linux" = "aarch64-unknown-linux-musl";
          }.${system};

          muslCC = {
            "x86_64-linux" = pkgs.pkgsCross.musl64.stdenv.cc;
            "aarch64-linux" = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;
          }.${system};

          cargoTargetEnvVar =
            "CARGO_TARGET_${builtins.replaceStrings ["-"] ["_"] (pkgs.lib.toUpper muslTarget)}_LINKER";

        in {
          default = mkBpftop {
            pname = "bpftop";
            inherit rustToolchain;
          };

          # bpftop plus the headless collection benchmark.
          bench = mkBpftop {
            pname = "bpftop-bench";
            inherit rustToolchain;
            bins = [ "bpftop" "bench" ];
          };

          static = mkBpftop {
            pname = "bpftop-static";
            rustToolchain = pkgs.rust-bin.stable.latest.default.override {
              targets = [ muslTarget ];
            };
            cargoTarget = muslTarget;
            extraNativeBuildInputs = [ muslCC ];
            env = {
              ${cargoTargetEnvVar} = "${muslCC}/bin/${muslTarget}-cc";
            };
          };
        }
      );

      # Root-in-a-VM collection benchmark: `nix build .#checks.x86_64-linux.bench-vm`
      # Results (bench JSON + strace syscall counts) land in ./result/results.
      checks = forAllSystems ({ pkgs, system }:
        let
          netbench = pkgs.runCommandCC "netbench" { } ''
            mkdir -p $out/bin
            $CC -O2 -Wall -o $out/bin/netbench ${./bench/netbench.c}
          '';
        in {
        bench-vm = pkgs.testers.runNixOSTest {
          name = "bpftop-bench-vm";
          nodes.machine = { pkgs, ... }: {
            boot.kernelPackages = pkgs.linuxPackages_latest;
            virtualisation.memorySize = 4096;
            virtualisation.cores = 4;
            users.users = builtins.listToAttrs (map (i: {
              name = "bench${toString i}";
              value = { isSystemUser = true; group = "nogroup"; };
            }) (pkgs.lib.range 1 20));
            environment.systemPackages = [
              self.packages.${system}.bench
              pkgs.strace
              pkgs.python3
              pkgs.htop
              netbench
            ];
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")

            # 40 units x 50 procs spread over 20 users. Half the procs touch
            # UDP first so NET_STATS has entries, then exec into sleep (same pid).
            for i in range(40):
                net = "echo x > /dev/udp/127.0.0.1/9 2>/dev/null;" if i % 2 == 0 else ""
                machine.succeed(
                    f"systemd-run --unit=load{i} --uid=bench{i % 20 + 1} ${pkgs.bash}/bin/bash -c "
                    f"'for j in {{1..50}}; do ${pkgs.bash}/bin/bash -c \"{net} exec ${pkgs.coreutils}/bin/sleep infinity\" & done; wait'"
                )
            # Multithreaded processes: 10 x 100 threads.
            for i in range(10):
                machine.succeed(
                    f"systemd-run --unit=threads{i} ${pkgs.python3}/bin/python3 -c "
                    "'import threading,time; [threading.Thread(target=time.sleep,args=(1e9,)).start() for _ in range(100)]; time.sleep(1e9)'"
                )
            machine.wait_until_succeeds("test $(ls -d /proc/[0-9]* | wc -l) -gt 2000", timeout=900)
            machine.succeed("sleep 2")
            print(machine.succeed("echo procs=$(ls -d /proc/[0-9]* | wc -l) tasks=$(ls -d /proc/[0-9]*/task/* | wc -l) cgroups=$(find /sys/fs/cgroup -type d | wc -l)"))

            machine.succeed("mkdir -p /tmp/results")
            machine.succeed("echo procs=$(ls -d /proc/[0-9]* | wc -l) tasks=$(ls -d /proc/[0-9]*/task/* | wc -l) cgroups=$(find /sys/fs/cgroup -type d | wc -l) > /tmp/results/workload.txt")
            machine.succeed("bench --iterations 10 --warmup 2 --json > /tmp/results/bench.json")
            # Syscalls per cycle = (6-cycle run - 1-cycle run) / 5.
            machine.succeed("strace -f -c -S calls -o /tmp/results/strace_1.txt bench --iterations 1 --warmup 0")
            machine.succeed("strace -f -c -S calls -o /tmp/results/strace_6.txt bench --iterations 6 --warmup 0")
            print(machine.succeed("cat /tmp/results/workload.txt; head -c 1500 /tmp/results/bench.json | tail -c 600; head -20 /tmp/results/strace_6.txt"))

            # ── Functional checks of the collected data ──────────────
            # Spawns and reaps a thread (and sends UDP) every 200ms, so thread
            # exits happen while BPF is loaded; the cmdline must survive them.
            machine.succeed(
                "systemd-run --unit=threadexit --uid=bench3 ${pkgs.python3}/bin/python3 -c "
                "'#marker-threadexit\n"
                "import socket,threading,time\n"
                "r=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); r.bind((\"127.0.0.1\",0))\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(r.getsockname())\n"
                "while True:\n"
                " t=threading.Thread(target=lambda:None); t.start(); t.join()\n"
                " s.send(b\"x\"*100); r.recv(200); time.sleep(0.2)'"
            )
            # All CPU on a worker thread; the leader only sleeps.
            machine.succeed(
                "systemd-run --unit=busythread ${pkgs.python3}/bin/python3 -c "
                "'import threading,time\n"
                "threading.Thread(target=lambda: any(iter(int, 1)), daemon=True).start()\n"
                "time.sleep(1e9)' marker-busythread"
            )
            # IPv6 UDP: native ::1 traffic plus a v4-mapped send from a v6
            # socket (udpv6_sendmsg delegates to udp_sendmsg), which must be
            # counted once: tx stays within one iteration of rx.
            machine.succeed(
                "systemd-run --unit=udp6 ${pkgs.python3}/bin/python3 -c "
                "'#marker-udp6\n"
                "import socket,time\n"
                "r6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); r6.bind((\"::1\",0))\n"
                "r4=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); r4.bind((\"127.0.0.1\",0))\n"
                "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
                "m=(\"::ffff:127.0.0.1\",r4.getsockname()[1])\n"
                "while True:\n"
                " s.sendto(b\"x\"*100,r6.getsockname()); r6.recv(200)\n"
                " s.sendto(b\"y\"*100,m); r4.recv(200); time.sleep(0.2)'"
            )
            # Storage writes (fsync'd) and write syscalls from one process.
            machine.succeed(
                "systemd-run --unit=diskio ${pkgs.python3}/bin/python3 -c "
                "'#marker-diskio\n"
                "import os,time\n"
                "f=os.open(\"/var/tmp/bpftop-io\",os.O_WRONLY|os.O_CREAT)\n"
                "while True:\n"
                " os.pwrite(f,b\"x\"*65536,0); os.fsync(f); time.sleep(0.05)'"
            )
            # Process states: a stopped process and an unreaped (zombie) child.
            machine.succeed("systemd-run --unit=stopme ${pkgs.coreutils}/bin/sleep 100003")
            machine.succeed(
                "systemd-run --unit=zombieparent ${pkgs.python3}/bin/python3 -c "
                "'import os,time\n"
                "os.fork() or os._exit(0)\n"
                "time.sleep(1e9)' marker-zombieparent"
            )
            # Longer than a CMDLINE_MAP entry (255 bytes); seeded from /proc.
            machine.succeed(
                "systemd-run --unit=longcmd ${pkgs.python3}/bin/python3 -c \"import time; time.sleep(1e9)\" "
                + "a" * 300 + " marker-longseed"
            )
            machine.succeed("systemd-run --unit=freezeme ${pkgs.coreutils}/bin/sleep 100001")
            machine.wait_until_succeeds("systemctl is-active freezeme threadexit udp6 diskio stopme zombieparent longcmd")
            machine.succeed("systemctl kill --signal=STOP stopme")
            machine.succeed("echo 1 > /sys/fs/cgroup/system.slice/freezeme.service/cgroup.freeze")
            # Execs after BPF loads (during --settle-ms): cmdline comes from the
            # exec tracepoint, and is also longer than a map entry.
            machine.succeed(
                "systemd-run --unit=execer ${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/sleep 10; "
                "exec ${pkgs.python3}/bin/python3 -c \"import time; time.sleep(1e9)\" " + "b" * 300 + " marker-exec'"
            )
            dump = machine.succeed("bench --dump --settle-ms 15000 --warmup 1 --iterations 1 --interval-ms 1000 | tee /tmp/results/dump.tsv")
            def parse(dump):
                lines = dump.splitlines()
                header = lines[0].split("\t")
                n = len(header) - 1
                return [dict(zip(header, l.split("\t", n))) for l in lines[1:] if l.count("\t") >= n]
            def find(rows, marker):
                hits = [r for r in rows if marker in r["cmdline"] and r["thread"] == "0"]
                assert hits, f"no process with cmdline containing {marker!r}"
                return hits[0]
            def check_net(rows, mode):
                r = find(rows, "marker-threadexit")
                assert int(r["net_tx"]) > 0 and int(r["net_rx"]) > 0 and r["net_if"] == "lo", f"net ({mode}): {r}"
                r = find(rows, "marker-udp6")
                tx, rx = int(r["net_tx"]), int(r["net_rx"])
                assert tx >= 1000 and abs(tx - rx) <= 200, f"udp6 ({mode}): {r}"
            rows = parse(dump)
            assert find(rows, "marker-threadexit")["user"] == "bench3"
            check_net(rows, "fexit")
            assert find(rows, "sleep 100001")["frozen"] == "1", "freezeme should be frozen"
            assert sum(r["frozen"] == "1" for r in rows) == 1, "only freezeme is frozen"
            # CPU% must include non-leader threads (was leader-only).
            r = find(rows, "marker-busythread")
            assert float(r["cpu"]) > 50 and r["kthread"] == "0", r
            # Full cmdlines past the 255-byte map entry, seeded and exec'd.
            assert find(rows, "marker-longseed")["cmdline"].endswith("a" * 300 + " marker-longseed")
            r = find(rows, "marker-exec")
            assert ("b" * 300) in r["cmdline"] and r["frozen"] == "0", r
            # Process states, decoded like the kernel's /proc.
            assert find(rows, "sleep 100003")["state"] == "T", find(rows, "sleep 100003")
            parent = find(rows, "marker-zombieparent")
            zombies = [r for r in rows if r["ppid"] == parent["pid"]]
            assert [z["state"] for z in zombies] == ["Z"], zombies
            unknown = [r for r in rows if r["state"] == "?"]
            assert not unknown, unknown
            kthreads = [r for r in rows if r["kthread"] == "1"]
            assert any(r["comm"] == "kthreadd" for r in kthreads), "kthreadd should be a kthread"
            assert any(r["state"] == "I" for r in kthreads), "idle kworkers should be I"
            # Disk I/O columns.
            r = find(rows, "marker-diskio")
            assert float(r["io_write"]) > 0 and float(r["iops"]) > 0, r
            # Thread rows (H): each python pool lists its 100 threads, and the
            # busy worker thread carries its own CPU.
            tdump = machine.succeed("bench --dump --threads --warmup 1 --iterations 1 --interval-ms 1000 | tee /tmp/results/dump_threads.tsv")
            trows = parse(tdump)
            busy = find(trows, "marker-busythread")
            workers = [r for r in trows if r["thread"] == "1" and r["ppid"] == busy["pid"]]
            assert len(workers) == 1 and float(workers[0]["cpu"]) > 50, workers
            pools = [r for r in trows if r["thread"] == "0" and "range(100)" in r["cmdline"]]
            assert len(pools) == 10, len(pools)
            for p in pools:
                n = sum(1 for r in trows if r["thread"] == "1" and r["ppid"] == p["pid"])
                assert n == 100, (p["pid"], n)
            # Same accounting through the kprobe fallback.
            kdump = machine.succeed("BPFTOP_NET_PROBES=kprobe bench --dump --settle-ms 5000 --warmup 0 --iterations 1 | tee /tmp/results/dump_kprobe.tsv")
            check_net(parse(kdump), "kprobe")
            machine.succeed("echo 0 > /sys/fs/cgroup/system.slice/freezeme.service/cgroup.freeze")
            machine.succeed("systemctl kill --signal=CONT stopme")

            # ── Network probe overhead on other processes ────────────
            def netbench(tag):
                machine.succeed(f"for i in 1 2 3 4 5; do netbench 50000; done > /tmp/results/net_{tag}.txt")
            netbench("none")
            for mode in ["kprobe", "fexit"]:
                env = "--setenv=BPFTOP_NET_PROBES=kprobe" if mode == "kprobe" else ""
                machine.succeed(f"systemd-run --unit=hold-{mode} {env} $(command -v bench) --hold 600")
                machine.wait_until_succeeds(f"journalctl -u hold-{mode} | grep -q holding")
                line = machine.succeed(f"journalctl -u hold-{mode} | grep holding")
                print(line)
                assert ("FExit" if mode == "fexit" else "KProbe") in line, line
                netbench(mode)
                machine.succeed(f"systemctl stop hold-{mode}")
            netbench("none2")
            print(machine.succeed("grep -H . /tmp/results/net_*.txt"))

            # ── bench/run.sh end to end at one small scale ───────────
            machine.succeed(
                "SCALES=100 K=5 REPS=2 BENCH_BIN=$(command -v bench) RESULTS_DIR=/tmp/results/runsh "
                "bash ${./bench}/run.sh >&2"
            )
            print(machine.succeed("cd /tmp/results/runsh && ls && cat meta_100.json *_cpu_100.txt"))

            machine.copy_from_machine("/tmp/results", "")
          '';
        };
      });

      devShells = forAllSystems ({ pkgs, system }: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Stable Rust via oxalica; rust-src for rust-analyzer.
            (rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
            })
            # rust-analyzer via fenix
            fenix.packages.${system}.rust-analyzer
            # eBPF tooling. Unwrapped clang: the cc-wrapper injects hardening
            # flags (-fzero-call-used-regs, -fstack-protector) that the bpf
            # target rejects.
            (llvmFor pkgs).clang-unwrapped
            (llvmFor pkgs).llvm
            libbpf
            bpftools
            # Build deps
            pkg-config
            elfutils
            # Benchmarking
            hyperfine
            strace
            htop
            (python3.withPackages (ps: [ ps.matplotlib ps.numpy ]))
            # Demo recording
            asciinema
            agg
          ];

          # For `cargo xtask build-ebpf`.
          LIBBPF_INCLUDE = "${pkgs.libbpf}/include";
        };
      });

      nixosModules.default = { config, lib, pkgs, ... }: {
        options.programs.bpftop.enable = lib.mkEnableOption "bpftop process monitor";

        config = lib.mkIf config.programs.bpftop.enable {
          security.wrappers.bpftop = {
            source = "${self.packages.${pkgs.system}.default}/bin/bpftop";
            owner = "root";
            group = "root";
            capabilities = "cap_bpf,cap_perfmon,cap_sys_resource,cap_dac_override,cap_sys_admin=eip";
          };
        };
      };
    };
}
