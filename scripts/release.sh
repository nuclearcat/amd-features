#!/bin/sh
# Build release artifacts into dist/:
#   - GUI+CLI binary built in a Debian bookworm container (needs glibc >= 2.35)
#   - .deb and .rpm packages of that binary
#   - fully static CLI-only musl binary
#   - tarballs and SHA256SUMS
# Requires: docker, cargo-deb, cargo-generate-rpm, the x86_64-unknown-linux-musl target.
set -eu
cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
arch=x86_64
rm -rf dist
mkdir -p dist

docker run --rm --user "$(id -u):$(id -g)" \
    -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/src/target/bookworm \
    -v "$PWD":/src -w /src rust:1-bookworm cargo build --release --locked
# cargo-deb and cargo-generate-rpm package target/release/amd-features.
mkdir -p target/release
cp target/bookworm/release/amd-features target/release/amd-features

cargo build --release --locked --no-default-features --target x86_64-unknown-linux-musl

cargo deb --no-build
cargo generate-rpm
cp target/debian/amd-features_"$version"-*_amd64.deb dist/
cp target/generate-rpm/amd-features-"$version"-*."$arch".rpm dist/

tarball() {
    name=$1 binary=$2
    stage=target/stage/$name
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$binary" README.md TRADEMARKS.md "$stage"/
    tar -C target/stage -czf dist/"$name".tar.gz "$name"
}
tarball amd-features-"$version"-"$arch"-linux-gnu target/release/amd-features
tarball amd-features-"$version"-"$arch"-linux-musl-cli \
    target/x86_64-unknown-linux-musl/release/amd-features

(cd dist && sha256sum -- * > SHA256SUMS)
ls -l dist
