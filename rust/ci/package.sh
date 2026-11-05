#!/usr/bin/env bash
# Puts a built binary and the licence in one archive, then proves the archive holds a binary that runs.
# usage: package.sh TARGET OUT_DIR
set -euo pipefail

target=$1
out=$2
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
binary=eureka-daemon
case "$target" in *windows*) binary=eureka-daemon.exe ;; esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
staging=$(mktemp -d)
check=$(mktemp -d)
trap 'rm -rf "$staging" "$check"' EXIT

cp "$root/rust/target/$target/release/$binary" "$root/LICENSE" "$staging/"
case "$target" in
  *windows*)
    archive="$out/eureka-daemon-$target.zip"
    (cd "$staging" && pwsh -NoProfile -Command "Compress-Archive -Path * -DestinationPath '$(cygpath -w "$archive")' -Force")
    (cd "$check" && pwsh -NoProfile -Command "Expand-Archive -Path '$(cygpath -w "$archive")' -DestinationPath .")
    ;;
  *)
    archive="$out/eureka-daemon-$target.tar.gz"
    tar -czf "$archive" -C "$staging" "$binary" LICENSE
    tar -xzf "$archive" -C "$check"
    ;;
esac

"$check/$binary" --version
echo "packaged $archive"
