{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [
    (pkgs.python3.withPackages (ps: [ ps.matplotlib ps.numpy ]))
    pkgs.strace
    pkgs.htop
    pkgs.hyperfine
  ];
}
