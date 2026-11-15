#!/bin/sh
# Build the static Linux binaries and the deb/rpm packages of one architecture
# (used by the CI and release workflows; docs/install.md "Building the packages").
#
#   packaging/build-packages.sh <version> <rust target> [output directory]
#   packaging/build-packages.sh 0.1.0 x86_64-unknown-linux-musl dist
#
# Needs: cargo-zigbuild with zig (`pip install cargo-zigbuild ziglang`), the Rust target
# (`rustup target add <target>`) and nfpm (https://nfpm.goreleaser.com).
set -eu

VERSION="${1:?version, e.g. 0.1.0}"
TARGET="${2:?rust target, e.g. x86_64-unknown-linux-musl}"
OUT="${3:-dist}"

case "$TARGET" in
    x86_64-unknown-linux-musl) ARCH=amd64 ;;
    aarch64-unknown-linux-musl) ARCH=arm64 ;;
    *) echo "unsupported target $TARGET" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
mkdir -p "$OUT"

# Static binaries: one build serves every distribution of the architecture.
CARGO_INCREMENTAL=0 cargo zigbuild --release --locked --target "$TARGET" \
    -p delbert-agent -p delbert-core -p delbert-proxy -p delbert-pki -p delbert-wire

export VERSION ARCH
export BIN_DIR="target/$TARGET/release"
export MAINTAINER="${MAINTAINER:-Delbert maintainers <delbert@example.com>}"

# nfpm expands environment variables in some fields only (not in `contents.src`), so the four
# placeholders are filled in here and nfpm reads a plain file.
RENDERED="$(mktemp -d)"
for package in agent core proxy tools; do
    sed -e "s|\${VERSION}|$VERSION|g" -e "s|\${ARCH}|$ARCH|g" -e "s|\${BIN_DIR}|$BIN_DIR|g" -e "s|\${MAINTAINER}|$MAINTAINER|g" \
        "packaging/nfpm/$package.yaml" >"$RENDERED/$package.yaml"
    if grep -q '\${' "$RENDERED/$package.yaml"; then
        echo "unfilled placeholder in packaging/nfpm/$package.yaml" >&2
        exit 1
    fi
    for format in deb rpm; do
        nfpm package --config "$RENDERED/$package.yaml" --packager "$format" --target "$OUT/"
    done
done
rm -rf "$RENDERED"

# The same binaries without a package manager.
# The agent's aliases are symlinks, so they are staged with the binaries.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp "$BIN_DIR"/delbert-agent "$BIN_DIR"/delbert-core "$BIN_DIR"/delbert-proxy "$BIN_DIR"/delbert-pki "$BIN_DIR"/delbert-sign "$STAGE/"
for alias in delbert dg overlook; do ln -s delbert-agent "$STAGE/$alias"; done
tar -C "$STAGE" -czf "$OUT/delbert-$VERSION-linux-$ARCH.tar.gz" \
    delbert-agent delbert dg overlook delbert-core delbert-proxy delbert-pki delbert-sign

ls -l "$OUT"
