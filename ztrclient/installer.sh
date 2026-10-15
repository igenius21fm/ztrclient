#!/usr/bin/env bash
# One installer for every supported system. It works out which one you're on
# and runs installer-linux.sh or installer-macos.sh with the same arguments, so
# the instructions are the same everywhere:
#
#   ./installer.sh                      install the wrappers (it asks about the rest)
#   ./installer.sh --with-ferry         every option of the installer for your system works here
#   ./installer.sh --help               the full list of options
#
# Linux runs installer-linux.sh; macOS runs installer-macos.sh. You can still
# run either of those directly.
set -euo pipefail

# Follow symlinks back to the folder this really lives in.
SELF="${BASH_SOURCE[0]}"
while [[ -L "$SELF" ]]; do
  LINK="$(readlink "$SELF")"
  case "$LINK" in
    /*) SELF="$LINK" ;;
    *) SELF="$(dirname "$SELF")/$LINK" ;;
  esac
done
HERE="$(cd "$(dirname "$SELF")" && pwd)"

if [[ -t 2 ]]; then
  C_ERR=$'\033[0;31m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
  C_ERR=""; C_DIM=""; C_RESET=""
fi

case "$(uname -s)" in
  Linux)  TARGET="installer-linux.sh"; SYSTEM="Linux" ;;
  Darwin) TARGET="installer-macos.sh"; SYSTEM="macOS" ;;
  *)
    echo "${C_ERR}[installer] $(uname -s) isn't supported — ztrclient installs on Linux and macOS.${C_RESET}" >&2
    exit 1
    ;;
esac

if [[ ! -f "$HERE/$TARGET" ]]; then
  echo "${C_ERR}[installer] $TARGET is missing from $HERE — this folder looks incomplete. Download ztrclient again.${C_RESET}" >&2
  exit 1
fi

echo "${C_DIM}[installer] $SYSTEM detected — running $TARGET${C_RESET}" >&2
exec bash "$HERE/$TARGET" "$@"
