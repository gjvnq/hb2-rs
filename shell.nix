{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustc
    rustfmt
    pkg-config
    openssl.dev
    e2fsprogs.dev
    libclang.lib
  ];
}