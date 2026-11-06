#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Fails if the docs show something that belongs on one person's machine: a home folder, a LAN address other
# than the placeholders, or a secret. It looks for patterns and lists no one's real names, since this file is public.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

files=$(git ls-files '*.md' 'deploy/*' 'demo.sh' 'rust/ci/release-notes.md')
found=0
check() {
  # grep exits 1 for no match and 2 for an error, which must fail the scan and not pass it.
  # shellcheck disable=SC2086
  matches=$(grep -n -I -E -e "$2" $files) || [ $? -eq 1 ]
  matches=$(printf '%s\n' "$matches" | grep -v -E -e "${3:-^$}") || true
  if [ -n "$matches" ]; then
    echo "$1:"
    echo "$matches"
    found=1
  fi
}

check "a home folder" '/Users/[A-Za-z0-9_]|[A-Za-z]:\\Users\\|/home/[A-Za-z0-9_]' '/home/(operator|you)/'
check "a LAN address that is not a placeholder" '\b(192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+)\b' '192\.168\.0\.[0-9]+'
check "something that looks like a secret" '-----BEGIN [A-Z ]*PRIVATE KEY|Bearer [A-Za-z0-9_-]{20,}|webhook_authorization"? *[:=]'

if [ "$found" -ne 0 ]; then
  echo "scan-docs: replace these with placeholders"
  exit 1
fi
echo "scan-docs: clean"
