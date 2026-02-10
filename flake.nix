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
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            # bpf-linker is installed via: cargo install bpf-linker
            export PATH="$HOME/.cargo/bin:$PATH"
          '';
        };
      });
    };
}
