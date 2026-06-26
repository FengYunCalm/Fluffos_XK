#!/usr/bin/env bash
set -euo pipefail

case "${TMPDIR:-}" in
  "" | /mnt/*) export TMPDIR=/tmp ;;
esac

case "${TEMP:-}" in
  "" | /mnt/*) export TEMP="$TMPDIR" ;;
esac

case "${TMP:-}" in
  "" | /mnt/*) export TMP="$TMPDIR" ;;
esac

exec cmake --build "$@"
