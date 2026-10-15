#!/usr/bin/env bash
# One installer for every supported system. It works out which one you're on
# and runs installer-linux.sh or installer-macos.sh with the same arguments, so
# the instructions are the same everywhere:
#
#   ./installer.sh                      install the wrappers (it asks about the rest)
#   ./installer.sh --with-ferry         every option of the installer for your system works here
#   ./installer.sh --help               the full list of options
#   ./installer.sh --gui                the same installation in a window: pick what you want, watch it happen
#
# Linux runs installer-linux.sh; macOS runs installer-macos.sh. You can still
# run either of those directly. The window needs Python's tkinter (on a Mac, a
# Python with Tk 8.6 or newer); --gui and the other options aren't combined —
# the window asks for everything itself.
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

# --gui: the same installation in a window (installer_gui.py, which runs the installer below for you).
if [[ "${1:-}" == "--gui" ]]; then
  shift
  GUI="$HERE/installer_gui.py"
  if [[ ! -f "$GUI" ]]; then
    echo "${C_ERR}[installer] installer_gui.py is missing from $HERE — this folder looks incomplete. Download ztrclient again.${C_RESET}" >&2
    exit 1
  fi
  # A Python whose Tk can draw a window. A Mac's default python3 often has none (Apple's is Tk 8.5, Homebrew's
  # comes without Tk), so look at the usual places for one that does.
  has_tk() { "$1" -c 'import sys, tkinter; sys.exit(0 if tkinter.TkVersion >= 8.6 else 1)' >/dev/null 2>&1; }
  GUI_PY=""
  for candidate in "${ZTR_PYTHON:-}" python3 python3.14 python3.13 python3.12 \
      /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
      /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 \
      /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    [[ -n "$candidate" ]] || continue
    found="$(command -v "$candidate" 2>/dev/null || true)"
    [[ -n "$found" ]] || continue
    # Without the Xcode command line tools /usr/bin/python3 on a Mac is a stub that pops up an install dialog.
    if [[ "$(uname -s)" == "Darwin" && "$found" == /usr/bin/python3 ]] && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    if has_tk "$found"; then
      GUI_PY="$found"
      break
    fi
  done
  if [[ -z "$GUI_PY" ]]; then
    echo "${C_ERR}[installer] The window needs a Python with Tk (8.6 or newer), and none was found.${C_RESET}" >&2
    if [[ "$(uname -s)" == "Darwin" ]]; then
      echo "  With Homebrew: brew install python-tk@3.13   (or install Python from python.org, which includes Tk)" >&2
    else
      echo "  On Debian/Ubuntu/Raspberry Pi OS: sudo apt install python3-tk" >&2
    fi
    echo "  Or run the installer in the terminal instead: ./installer.sh" >&2
    exit 1
  fi
  # Started from a plain ssh login on Linux there's no display; try the desktop's usual one.
  if [[ "$(uname -s)" != "Darwin" && -z "${DISPLAY:-}" ]]; then
    export DISPLAY=:0
  fi
  exec "$GUI_PY" "$GUI" "$@"
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

for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    echo "installer.sh --gui opens the installer in a window (it takes no other options)."
    echo
    break
  fi
done

echo "${C_DIM}[installer] $SYSTEM detected — running $TARGET${C_RESET}" >&2
exec bash "$HERE/$TARGET" "$@"
