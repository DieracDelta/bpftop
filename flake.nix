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
    in {
      packages = forAllSystems ({ pkgs, system }:
        let
          rustNightly = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [ "rust-src" ];
          };

          workspaceVendor = pkgs.rustPlatform.fetchCargoVendor {
            src = ./.;
            hash = "sha256-ECV4yHAsu/QX9YwT0jwV7lity0xtPnE+frc1CjHdSH4=";
          };

          mkBpftop = { pname, rustToolchain, cargoTarget ? null, extraNativeBuildInputs ? [], env ? {} }:
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
                pkgs.llvmPackages_22.clang-unwrapped
                pkgs.llvmPackages_22.llvm
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
                cargo build --release --bin bpftop ${targetFlag}

                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/bin
                cp ${outputDir}/bpftop $out/bin/
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
            rustToolchain = rustNightly;
          };

          static = mkBpftop {
            pname = "bpftop-static";
            rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
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

      devShells = forAllSystems ({ pkgs, system }: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain via oxalica (nightly required for aya-bpf)
            # bpfel-unknown-none is a built-in target (not a rustup target),
            # so we just need rust-src for -Z build-std to work.
            (rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
            })
            # rust-analyzer via fenix
            fenix.packages.${system}.rust-analyzer
            # eBPF tooling
            llvmPackages.clang
            llvmPackages.llvm
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

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            # bpf-linker is installed via: cargo install bpf-linker
            export PATH="$HOME/.cargo/bin:$PATH"
          '';
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
