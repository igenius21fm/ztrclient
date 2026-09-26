#!/usr/bin/env bash
# Bootstraps the one thing you need before a route.ztr exists at all: your
# own keypair, so you can hand its public half to whoever issues routes and
# get one back. launcher.py needs pycryptodome to generate that keypair,
# but installer-linux.sh (which normally sets up ztr's venv) expects a
# route already in place before it's worth running — so this creates that
# same venv on its own, installs just the one dependency launcher.py
# actually needs, and runs it. installer-linux.sh reuses this exact venv
# afterward instead of creating a second one.
#
#   ./launcher.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/ztr/venv}"

if [[ -t 1 ]]; then
  C_INFO=$'\033[0;36m'; C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'; C_RESET=$'\033[0m'
else
  C_INFO=""; C_OK=""; C_ERR=""; C_RESET=""
fi
log_info() { echo "${C_INFO}[launcher]${C_RESET} $*"; }
log_ok()   { echo "${C_OK}[launcher]${C_RESET} $*"; }
log_err()  { echo "${C_ERR}[launcher] $*${C_RESET}" >&2; }

if ! command -v python3 >/dev/null 2>&1; then
  log_err "python3 not found — install it first."
  exit 1
fi

VENV_PY="$VENV_DIR/bin/python3"
if [[ -x "$VENV_PY" ]]; then
  log_ok "ztr venv already exists at $VENV_DIR."
else
  log_info "creating ztr's venv at $VENV_DIR ..."
  mkdir -p "$(dirname "$VENV_DIR")"
  # --copies, not the default symlink-to-system-python3 — same reasoning as
  # installer-linux.sh's own venv setup, which reuses this exact venv
  # later: --with-dashboard's setcap needs a real interpreter file, not a
  # symlink to the system one.
  if ! python3 -m venv --copies "$VENV_DIR"; then
    log_err "couldn't create the venv — on Debian/Ubuntu you likely need: sudo apt install python3-venv"
    exit 1
  fi
  log_ok "venv created."
fi

if "$VENV_PY" -c "import Crypto" >/dev/null 2>&1; then
  log_ok "pycryptodome already installed in the venv."
else
  log_info "installing pycryptodome into the venv ..."
  "$VENV_PY" -m pip install --quiet --upgrade pip pycryptodome
  log_ok "pycryptodome installed."
fi

exec "$VENV_PY" "$SCRIPT_DIR/launcher.py" "$@"
