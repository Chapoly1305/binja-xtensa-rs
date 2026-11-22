#!/bin/sh
# Run a command in the Ubuntu 24.04 build image (same glibc as typical BN
# deployments) against a local Binary Ninja install.
#   BN_DIR    Binary Ninja install directory (default: $HOME/binaryninja)
#   BXR_CACHE cargo registry/git/target cache (default: $HOME/.cache/bxr)
set -e
BN_DIR=${BN_DIR:-$HOME/binaryninja}
BXR_CACHE=${BXR_CACHE:-$HOME/.cache/bxr}
mkdir -p "$BXR_CACHE/registry" "$BXR_CACHE/git" "$BXR_CACHE/target"
exec docker run --rm -e BINARYNINJADIR=/root/binaryninja -e CARGO_TARGET_DIR=/target \
  -v "$PWD":/src -v "$BN_DIR":/root/binaryninja:ro \
  -v "$BXR_CACHE/registry":/opt/cargo/registry -v "$BXR_CACHE/git":/opt/cargo/git \
  -v "$BXR_CACHE/target":/target -w /src binja-xtensa-rs-build:1 "$@"
