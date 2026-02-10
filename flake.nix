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
            hash = "sha256-Nycj6xfkJTsDESy0P5EvqV9iI/bAmYUGS9Xa41Pyp/o=";
          };

          # Combined LLVM 22 (dev + lib outputs merged for bpf-linker's build script)
          llvm22 = pkgs.symlinkJoin {
            name = "llvm-22-combined";
            paths = [ pkgs.llvmPackages_22.llvm.dev pkgs.llvmPackages_22.llvm.lib ];
          };

          # bpf-linker v0.10.1 with LLVM 22 (matches nightly Rust's LLVM)
          bpfLinker = pkgs.rustPlatform.buildRustPackage rec {
            pname = "bpf-linker";
            version = "0.10.1";
            src = pkgs.fetchFromGitHub {
              owner = "aya-rs";
              repo = "bpf-linker";
              tag = "v${version}";
              hash = "sha256-WFMQlaM18v5FsrsjmAl1nPGNMnBW3pjXmkfOfv3Izq0=";
            };
            cargoHash = "sha256-m/mlN1EL5jYxprNXvMbuVzBsewdIOFX0ebNQWfByEHQ=";
            buildNoDefaultFeatures = true;
            buildFeatures = [ "llvm-${pkgs.lib.versions.major pkgs.llvmPackages_22.llvm.version}" ];
            LLVM_PREFIX = "${llvm22}";
            nativeBuildInputs = [ llvm22 ];
            buildInputs = [ pkgs.zlib pkgs.libxml2 ];
            doCheck = false;
          };

          # Custom FOD: vendors eBPF deps + std library deps (needed for -Z build-std=core)
          ebpfVendor = pkgs.stdenvNoCC.mkDerivation {
            name = "bpftop-ebpf-vendor";
            src = ./.;
            postUnpack = "sourceRoot=$sourceRoot/bpftop-ebpf";
            nativeBuildInputs = [ rustNightly pkgs.cacert ];
            dontBuild = true;
            dontFixup = true;
            installPhase = ''
              mkdir -p $out/.cargo
              sysroot=$(rustc --print sysroot)
              HOME=$(mktemp -d) cargo vendor \
                --locked \
                --sync "$sysroot/lib/rustlib/src/rust/library/Cargo.toml" \
                $out 2>/dev/null > vendor-config.toml
              sed "s|$out|@vendor@|g" vendor-config.toml > $out/.cargo/config.toml
            '';
            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "sha256-J7H0kMUUfLr0sesuIih9Dm5VOOd0w9u5nfwNjT+QDqI=";
          };
          mkBpftop = { pname, rustToolchain, cargoTarget ? null, extraNativeBuildInputs ? [], env ? {} }:
            let
              targetFlag = if cargoTarget != null then "--target ${cargoTarget}" else "";
              outputDir = if cargoTarget != null then "target/${cargoTarget}/release" else "target/release";
            in pkgs.stdenv.mkDerivation ({
              inherit pname;
              version = "0.1.0";
              src = ./.;

              nativeBuildInputs = [
                rustToolchain
                bpfLinker
                pkgs.llvmPackages_22.clang
                pkgs.llvmPackages_22.llvm
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

                # Vendor eBPF deps + linker config
                mkdir -p bpftop-ebpf/.cargo
                substitute ${ebpfVendor}/.cargo/config.toml bpftop-ebpf/.cargo/config.toml \
                  --subst-var-by vendor ${ebpfVendor}
                echo '[target.bpfel-unknown-none]' >> bpftop-ebpf/.cargo/config.toml
                echo 'linker = "bpf-linker"' >> bpftop-ebpf/.cargo/config.toml
                echo 'rustflags = ["-Clink-arg=--btf"]' >> bpftop-ebpf/.cargo/config.toml

                runHook postConfigure
              '';

              buildPhase = let
                archFeature = {
                  "x86_64-linux" = "arch-x86_64";
                  "aarch64-linux" = "arch-aarch64";
                }.${system};
              in ''
                runHook preBuild

                # Phase 1: Build eBPF object
                pushd bpftop-ebpf
                cargo build --target bpfel-unknown-none -Z build-std=core --release --features ${archFeature}
                popd

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

          muslCC = pkgs.pkgsCross.musl64.stdenv.cc;

        in {
          default = mkBpftop {
            pname = "bpftop";
            rustToolchain = rustNightly;
          };

          static = mkBpftop {
            pname = "bpftop-static";
            rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            };
            cargoTarget = "x86_64-unknown-linux-musl";
            extraNativeBuildInputs = [ muslCC ];
            env = {
              CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
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
            bpftools
            # Build deps
            pkg-config
            elfutils
            # Benchmarking
            hyperfine
            strace
            htop
            (python3.withPackages (ps: [ ps.matplotlib ps.numpy ]))
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
            setuid = true;
            owner = "root";
            group = "root";
          };
        };
      };
    };
}
