#!/usr/bin/env bash
# macOS installer for the ZTRelay plugin wrappers (ztr_ssh, ztr_forward,
# ztr_pg) so they run from anywhere, without a manual shell alias per
# docs/ztrclient's "Alias it" sections. Does NOT touch the platform or
# ztrClient.py itself — this is scoped to plugins/ only (which is also
# where ztr_tunnel_lp.py and ztr_dashboard.py live).
# On Linux? Use installer-linux.sh instead — this one assumes launchd
# and `ifconfig`, neither of which exist there.
#
#   ./installer-macos.sh                       install wrappers into ~/.local/bin
#   ./installer-macos.sh --prefix DIR          install into DIR instead
#   ./installer-macos.sh --venv-dir DIR        put ztr's own Python venv at DIR instead of ~/.local/share/ztr/venv
#   ./installer-macos.sh --with-service        also set up ztr_tunnel_lp.py as a launchd agent
#   ./installer-macos.sh --with-dashboard      also set up ztr_dashboard.py as a launchd agent
#   ./installer-macos.sh --with-local-ip       also set up a dedicated loopback alias for tunneled sessions
#   ./installer-macos.sh --local-ip IP         use IP instead of the default 10.10.15.10
#   ./installer-macos.sh --uninstall           remove the installed wrappers (agents, venv, and loopback alias, if present)
#
# Run with no flags in an actual terminal and it just asks: whether to set
# up each agent, and (if either one, or if --with-local-ip was passed) what
# IP to use. --with-service/--with-dashboard/--with-local-ip/--local-ip
# above are for skipping those prompts — non-interactive runs (CI,
# provisioning scripts, piped input) skip them automatically and just take
# the flags/defaults given.
#
# What it actually does:
#   1. Makes plugins/{ztr_ssh,ztr_forward,ztr_pg} executable — a zip
#      download doesn't reliably preserve the executable bit, so this
#      isn't just belt-and-suspenders.
#   2. Checks that python3 exists, then creates a dedicated venv for ztr
#      (default ~/.local/share/ztr/venv) if one isn't already there, and
#      installs pycryptodome into it — ztr_tunnel_lp.py imports RelayClient
#      from ztrClient.py, which needs it. Keeping this in its own venv
#      instead of --user/system site-packages means it can't clash with
#      whatever else is installed on your system python3. Both launchd
#      agents (--with-service, --with-dashboard) run using this venv's
#      interpreter. With --with-dashboard, also offers to install scapy
#      into it — only needed for the dashboard's live traffic panel.
#   3. Symlinks the three wrappers into --prefix (default ~/.local/bin),
#      so `ztr_ssh`/`ztr_forward`/`ztr_pg` work from any shell, not just
#      one with a hand-edited rc file. Re-running just refreshes the links.
#   4. With --with-local-ip: adds --local-ip (default 10.10.15.10) as a
#      loopback alias (`ifconfig lo0 alias ...`), so ztr_tunnel_lp.py's
#      per-session listeners (and the dashboard, if you set it up) bind to
#      a dedicated address instead of the generic 127.0.0.1 — needs sudo,
#      requires you to run this yourself, and doesn't persist across
#      reboot on its own (see the note this step prints).
#   5. With --with-service: installs ztr_tunnel_lp.py as a per-user
#      launchd agent (~/Library/LaunchAgents), prompting for your .ztr
#      config path. Restarts on crash, starts at login — the launchd
#      equivalent of installer-linux.sh's systemd unit.
#   6. With --with-dashboard: installs ztr_dashboard.py as a launchd agent
#      the same way — reuses the .ztr config from --with-service above if
#      you set both up together, otherwise prompts for its own (or none,
#      if you just want the tunnel/error panels).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS_DIR="$SCRIPT_DIR/plugins"
WRAPPERS=(ztr_ssh ztr_forward ztr_pg)

PREFIX="${PREFIX:-$HOME/.local/bin}"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/ztr/venv}"
LOCAL_IP="${LOCAL_IP:-10.10.15.10}"
LOCAL_IP_SET_BY_USER=0
WITH_SERVICE=0
WITH_SERVICE_SET_BY_USER=0
WITH_DASHBOARD=0
WITH_DASHBOARD_SET_BY_USER=0
WITH_LOCAL_IP=0
UNINSTALL=0

if [[ -t 1 ]]; then
  C_INFO=$'\033[0;36m'; C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'
  C_WARN=$'\033[0;33m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
  C_INFO=""; C_OK=""; C_ERR=""; C_WARN=""; C_DIM=""; C_RESET=""
fi
log_info() { echo "${C_INFO}[installer]${C_RESET} $*"; }
log_ok()   { echo "${C_OK}[installer]${C_RESET} $*"; }
log_warn() { echo "${C_WARN}[installer]${C_RESET} $*"; }
log_err()  { echo "${C_ERR}[installer] $*${C_RESET}" >&2; }

usage() {
  sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="$2"
      shift 2
      ;;
    --with-service)
      WITH_SERVICE=1
      WITH_SERVICE_SET_BY_USER=1
      shift
      ;;
    --with-dashboard)
      WITH_DASHBOARD=1
      WITH_DASHBOARD_SET_BY_USER=1
      shift
      ;;
    --with-local-ip)
      WITH_LOCAL_IP=1
      shift
      ;;
    --local-ip)
      LOCAL_IP="$2"
      LOCAL_IP_SET_BY_USER=1
      shift 2
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_err "unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

AGENT_LABEL="com.ztrelay.tunnel-lp"
AGENT_PLIST="$HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"
AGENT_LOG_OUT="$HOME/Library/Logs/ztr-tunnel-lp.log"
AGENT_LOG_ERR="$HOME/Library/Logs/ztr-tunnel-lp.err.log"

DASHBOARD_AGENT_LABEL="com.ztrelay.dashboard"
DASHBOARD_AGENT_PLIST="$HOME/Library/LaunchAgents/${DASHBOARD_AGENT_LABEL}.plist"
DASHBOARD_AGENT_LOG_OUT="$HOME/Library/Logs/ztr-dashboard.log"
DASHBOARD_AGENT_LOG_ERR="$HOME/Library/Logs/ztr-dashboard.err.log"

# Ask up front rather than requiring you to already know the flag exists —
# only when you didn't already say one way or the other with --with-service,
# and only when actually running interactively (skip in scripts/CI, and
# skip entirely for --uninstall, which doesn't need this).
if [[ "$WITH_SERVICE_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_tunnel_lp.py as a persistent launchd agent? [y/N]: " WITH_SERVICE_ANSWER
  case "$WITH_SERVICE_ANSWER" in
    [yY]*) WITH_SERVICE=1 ;;
  esac
fi

# Same idea, asked separately — the dashboard doesn't need the tunnel
# agent (or vice versa), so answering one shouldn't silently decide the
# other.
if [[ "$WITH_DASHBOARD_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_dashboard.py as a persistent launchd agent? [y/N]: " WITH_DASHBOARD_ANSWER
  case "$WITH_DASHBOARD_ANSWER" in
    [yY]*) WITH_DASHBOARD=1 ;;
  esac
fi

# The agent is useless without somewhere to bind its per-session
# listeners — without the dummy interface, every session fails to start
# the moment the agent is actually up. So --with-service (flag or the
# prompt above) implies --with-local-ip, not just the "what IP" prompt
# below — this is what actually creates the interface later on.
if [[ "$WITH_SERVICE" -eq 1 ]]; then
  WITH_LOCAL_IP=1
fi

# Ask rather than silently defaulting — this address matters (it's what
# ztr_tunnel_lp.py binds to and every wrapper connects through), so
# anyone with a reason to pick their own subnet should get the chance
# before it's baked into a launchd agent. Only asks if --local-ip wasn't
# already given, and only when actually running interactively (skip in
# scripts/CI, where stdin isn't a terminal — reading from it there would
# either hang or consume unrelated piped input).
if [[ "$LOCAL_IP_SET_BY_USER" -eq 0 && ( "$WITH_LOCAL_IP" -eq 1 || "$WITH_SERVICE" -eq 1 ) && -t 0 ]]; then
  read -r -p "Dummy IP for tunneled sessions to bind to [$LOCAL_IP]: " LOCAL_IP_INPUT
  if [[ -n "$LOCAL_IP_INPUT" ]]; then
    LOCAL_IP="$LOCAL_IP_INPUT"
  fi
fi

# ---------------------------------------------------------------------------
# Loopback-alias helpers — doesn't persist across reboot on its own; see
# the --with-local-ip block's own note.

local_ip_present() {
  ifconfig lo0 2>/dev/null | grep -q "inet ${LOCAL_IP} "
}

remove_local_ip() {
  sudo ifconfig lo0 -alias "$LOCAL_IP" >/dev/null 2>&1 || true
}

# zsh -> ~/.zshrc (the macOS default since Catalina); bash -> ~/.bash_profile
# (what Terminal.app's login shell actually sources, not ~/.bashrc).
# Defined up here (not just near where it's used) so uninstall() — which
# runs and exits before the rest of the script — can use it too.
detect_rc_file() {
  case "$(basename "${SHELL:-}")" in
    zsh) echo "$HOME/.zshrc" ;;
    bash) echo "$HOME/.bash_profile" ;;
    *) echo "$HOME/.profile" ;;
  esac
}

# ---------------------------------------------------------------------------
uninstall() {
  log_info "removing wrappers from $PREFIX ..."
  local removed=0
  for name in "${WRAPPERS[@]}"; do
    local link="$PREFIX/$name"
    # Only remove it if it's actually our symlink — never clobber some
    # unrelated file that happens to share the name.
    if [[ -L "$link" ]] && [[ "$(readlink "$link")" == "$PLUGINS_DIR/$name" ]]; then
      rm -f "$link"
      removed=1
    fi
  done
  [[ "$removed" -eq 1 ]] && log_ok "wrappers removed." || log_warn "no installed wrappers found in $PREFIX."

  if [[ -f "$AGENT_PLIST" ]]; then
    log_info "stopping and removing the $AGENT_LABEL launchd agent ..."
    launchctl unload -w "$AGENT_PLIST" >/dev/null 2>&1 || true
    rm -f "$AGENT_PLIST"
    log_ok "agent removed."
  fi

  if [[ -f "$DASHBOARD_AGENT_PLIST" ]]; then
    log_info "stopping and removing the $DASHBOARD_AGENT_LABEL launchd agent ..."
    launchctl unload -w "$DASHBOARD_AGENT_PLIST" >/dev/null 2>&1 || true
    rm -f "$DASHBOARD_AGENT_PLIST"
    log_ok "agent removed."
  fi

  if [[ -d "$VENV_DIR" ]]; then
    log_info "removing ztr's venv at $VENV_DIR ..."
    rm -rf "$VENV_DIR"
    log_ok "venv removed."
  fi

  local rc_file
  rc_file="$(detect_rc_file)"
  local path_line="export PATH=\"$PREFIX:\$PATH\"  # added by ztrclient installer"
  if [[ -f "$rc_file" ]] && grep -qF "# added by ztrclient installer" "$rc_file" 2>/dev/null; then
    log_info "removing the PATH export and aliases we added to $rc_file ..."
    local tmp_rc
    tmp_rc="$(mktemp)"
    grep -vxF "$path_line" "$rc_file" > "$tmp_rc"
    for name in "${WRAPPERS[@]}"; do
      local alias_line="alias $name=\"$PLUGINS_DIR/$name\"  # added by ztrclient installer"
      grep -vxF "$alias_line" "$tmp_rc" > "$tmp_rc.next" && mv "$tmp_rc.next" "$tmp_rc"
    done
    mv "$tmp_rc" "$rc_file"
    log_ok "removed from $rc_file."
  fi

  if local_ip_present; then
    log_info "removing the $LOCAL_IP loopback alias (needs sudo) ..."
    if remove_local_ip && ! local_ip_present; then
      log_ok "$LOCAL_IP removed."
    else
      log_warn "couldn't confirm $LOCAL_IP was removed — remove it yourself if it's still there."
    fi
  fi
  exit 0
}
[[ "$UNINSTALL" -eq 1 ]] && uninstall

# ---------------------------------------------------------------------------
log_info "checking prerequisites ..."

if ! command -v python3 >/dev/null 2>&1; then
  log_err "python3 not found — required by every plugin wrapper and by ztr_tunnel_lp.py itself."
  log_err "install it via Homebrew (brew install python3) or python.org, then re-run this installer."
  exit 1
fi
log_ok "python3 found ($(command -v python3))."

VENV_PY="$VENV_DIR/bin/python3"
if [[ -x "$VENV_PY" ]]; then
  log_ok "ztr venv already exists at $VENV_DIR."
else
  log_info "creating ztr's venv at $VENV_DIR ..."
  mkdir -p "$(dirname "$VENV_DIR")"
  if ! python3 -m venv "$VENV_DIR"; then
    log_err "couldn't create the venv — check the python3 -m venv output above."
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

# Only needed for the dashboard's live traffic panel — best-effort, since
# that panel is optional and everything else works fine without it.
if [[ "$WITH_DASHBOARD" -eq 1 ]]; then
  if "$VENV_PY" -c "import scapy" >/dev/null 2>&1; then
    log_ok "scapy already installed in the venv."
  elif "$VENV_PY" -m pip install --quiet scapy; then
    log_ok "scapy installed — live traffic capture available (needs root or the access_bpf group to actually run)."
  else
    log_warn "couldn't install scapy — the dashboard's live traffic panel will stay off, everything else still works."
  fi
fi

# ---------------------------------------------------------------------------
# ztrClient.py (RelayConfig) always resolves --config-file inside this
# folder — create it up front so it's there the moment you want to drop a
# .ztr config in, whether or not you're using --with-service.
mkdir -p "$SCRIPT_DIR/routes"

log_info "installing wrappers into $PREFIX ..."
mkdir -p "$PREFIX"

for name in "${WRAPPERS[@]}"; do
  chmod +x "$PLUGINS_DIR/$name"
  target="$PREFIX/$name"
  # Only overwrite what's already ours (a symlink to this plugins dir, or
  # nothing at all) — never clobber some unrelated file that happens to
  # share the name.
  if [[ -e "$target" || -L "$target" ]] && [[ "$(readlink "$target" 2>/dev/null)" != "$PLUGINS_DIR/$name" ]]; then
    log_warn "$target already exists and isn't one of ours — skipping (remove it yourself and re-run to install here)."
    continue
  fi
  ln -sf "$PLUGINS_DIR/$name" "$target"
  log_ok "$name -> $target"
done

case ":$PATH:" in
  *":$PREFIX:"*)
    log_ok "$PREFIX is already on your PATH."
    ;;
  *)
    RC_FILE="$(detect_rc_file)"
    PATH_LINE="export PATH=\"$PREFIX:\$PATH\"  # added by ztrclient installer"
    ADD_TO_RC=0
    if [[ -t 0 ]]; then
      read -r -p "$PREFIX isn't on your PATH yet — add PATH + shell aliases for ztr_ssh/ztr_forward/ztr_pg to $RC_FILE? [y/N]: " ADD_TO_RC_ANSWER
      case "$ADD_TO_RC_ANSWER" in
        [yY]*) ADD_TO_RC=1 ;;
      esac
    fi
    if [[ "$ADD_TO_RC" -eq 1 ]]; then
      if grep -qxF "$PATH_LINE" "$RC_FILE" 2>/dev/null; then
        log_ok "$RC_FILE already has this PATH export."
      else
        { echo ""; echo "$PATH_LINE"; } >> "$RC_FILE"
      fi
      for name in "${WRAPPERS[@]}"; do
        alias_line="alias $name=\"$PLUGINS_DIR/$name\"  # added by ztrclient installer"
        if ! grep -qxF "$alias_line" "$RC_FILE" 2>/dev/null; then
          echo "$alias_line" >> "$RC_FILE"
        fi
      done
      log_ok "added PATH + aliases to $RC_FILE — open a new shell (or run: source $RC_FILE) to pick it up."
    else
      log_warn "$PREFIX is not on your PATH yet — add this to your shell rc file:"
      echo "${C_DIM}    $PATH_LINE${C_RESET}"
      for name in "${WRAPPERS[@]}"; do
        echo "${C_DIM}    alias $name=\"$PLUGINS_DIR/$name\"${C_RESET}"
      done
    fi
    ;;
esac

# ---------------------------------------------------------------------------
if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
  log_info "setting up $LOCAL_IP as a dedicated loopback alias (needs sudo) ..."

  if local_ip_present; then
    log_ok "$LOCAL_IP is already configured — nothing to do."
  else
    # A /32-equivalent host alias (255.255.255.255) — just this one
    # address reachable via lo0, not a whole subnet.
    sudo ifconfig lo0 alias "$LOCAL_IP" 255.255.255.255
    if local_ip_present; then
      log_ok "$LOCAL_IP configured."
    else
      log_err "couldn't confirm $LOCAL_IP was added — check the sudo command's output above."
    fi
  fi

  log_warn "this doesn't survive a reboot on its own. To make it permanent, add a LaunchDaemon"
  log_warn "that runs the same command at boot:"
  echo "${C_DIM}    ifconfig lo0 alias $LOCAL_IP 255.255.255.255${C_RESET}"
  echo "${C_DIM}    Or just re-run './installer-macos.sh --with-local-ip' after each reboot.${C_RESET}"
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_SERVICE" -eq 1 ]]; then
  log_info "setting up ztr_tunnel_lp.py as a launchd agent ..."

  read -r -p "Path to your downloaded .ztr route config: " ZTR_CONFIG_SRC
  if [[ ! -f "$ZTR_CONFIG_SRC" ]]; then
    log_err "no file at $ZTR_CONFIG_SRC — skipping agent setup. Re-run with --with-service once it's in place."
  else
    # ztrClient.py (RelayConfig) always resolves --config-file inside
    # routes/, next to itself — never a path you hand it directly. Copy
    # whatever you pointed at in there under its own name, so every .ztr
    # config ends up in one place regardless of where it was downloaded to.
    mkdir -p "$SCRIPT_DIR/routes"
    ZTR_CONFIG_NAME="$(basename "$ZTR_CONFIG_SRC")"
    ZTR_CONFIG_DEST="$SCRIPT_DIR/routes/$ZTR_CONFIG_NAME"
    ZTR_CONFIG_SRC_ABS="$(cd "$(dirname "$ZTR_CONFIG_SRC")" && pwd)/$ZTR_CONFIG_NAME"
    if [[ "$ZTR_CONFIG_SRC_ABS" != "$ZTR_CONFIG_DEST" ]]; then
      cp "$ZTR_CONFIG_SRC" "$ZTR_CONFIG_DEST"
      log_ok "copied to $ZTR_CONFIG_DEST"
    fi

    if ! local_ip_present; then
      log_warn "$LOCAL_IP isn't configured on this machine yet — sessions will fail to bind until you"
      log_warn "run './installer-macos.sh --with-local-ip' (or restart the agent with --local-ip 127.0.0.1)."
    fi

    mkdir -p "$(dirname "$AGENT_PLIST")" "$(dirname "$AGENT_LOG_OUT")"
    cat > "$AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV_PY</string>
    <string>$SCRIPT_DIR/plugins/ztr_tunnel_lp.py</string>
    <string>--config-file</string>
    <string>$ZTR_CONFIG_NAME</string>
    <string>--local-ip</string>
    <string>$LOCAL_IP</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$SCRIPT_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>$AGENT_LOG_OUT</string>
  <key>StandardErrorPath</key>
  <string>$AGENT_LOG_ERR</string>
</dict>
</plist>
EOF
    # Unload first in case this is a re-run with a changed config — load
    # on an already-loaded label is a no-op rather than a reload.
    launchctl unload -w "$AGENT_PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$AGENT_PLIST"
    log_ok "agent installed and started: $AGENT_LABEL"
    echo "${C_DIM}    launchctl list | grep $AGENT_LABEL${C_RESET}"
    echo "${C_DIM}    tail -f $AGENT_LOG_OUT${C_RESET}"
  fi
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_DASHBOARD" -eq 1 ]]; then
  log_info "setting up ztr_dashboard.py as a launchd agent ..."

  # The tunnel agent's config, if this run also set one up, works just as
  # well for the dashboard (same route) — offer it as the default instead
  # of asking you to type the same path twice.
  DASHBOARD_CONFIG_PROMPT="Path to a .ztr route config for the dashboard to diagram (blank for none)"
  if [[ -n "${ZTR_CONFIG_NAME:-}" ]]; then
    read -r -p "$DASHBOARD_CONFIG_PROMPT [$ZTR_CONFIG_NAME]: " ZTR_DASHBOARD_CONFIG_SRC
    ZTR_DASHBOARD_CONFIG_SRC="${ZTR_DASHBOARD_CONFIG_SRC:-$ZTR_CONFIG_NAME}"
  else
    read -r -p "$DASHBOARD_CONFIG_PROMPT: " ZTR_DASHBOARD_CONFIG_SRC
  fi

  DASHBOARD_CONFIG_ARGS=""
  if [[ -n "$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
    # Same as --with-service above: whatever it points at ends up as its
    # own file directly inside routes/, since that's the only place
    # ztrClient.py (RelayConfig) will ever look for it.
    if [[ -f "$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
      mkdir -p "$SCRIPT_DIR/routes"
      ZTR_DASHBOARD_CONFIG_NAME="$(basename "$ZTR_DASHBOARD_CONFIG_SRC")"
      ZTR_DASHBOARD_CONFIG_DEST="$SCRIPT_DIR/routes/$ZTR_DASHBOARD_CONFIG_NAME"
      ZTR_DASHBOARD_CONFIG_SRC_ABS="$(cd "$(dirname "$ZTR_DASHBOARD_CONFIG_SRC")" && pwd)/$ZTR_DASHBOARD_CONFIG_NAME"
      if [[ "$ZTR_DASHBOARD_CONFIG_SRC_ABS" != "$ZTR_DASHBOARD_CONFIG_DEST" ]]; then
        cp "$ZTR_DASHBOARD_CONFIG_SRC" "$ZTR_DASHBOARD_CONFIG_DEST"
        log_ok "copied to $ZTR_DASHBOARD_CONFIG_DEST"
      fi
      DASHBOARD_CONFIG_ARGS="    <string>--config-file</string>
    <string>$ZTR_DASHBOARD_CONFIG_NAME</string>"
    elif [[ -f "$SCRIPT_DIR/routes/$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
      # Already just a name sitting in routes/ (e.g. reused from
      # --with-service above, which already copied it there).
      DASHBOARD_CONFIG_ARGS="    <string>--config-file</string>
    <string>$ZTR_DASHBOARD_CONFIG_SRC</string>"
    else
      log_warn "no file at $ZTR_DASHBOARD_CONFIG_SRC — starting the dashboard without a config (tunnel/error panels only)."
    fi
  fi

  mkdir -p "$(dirname "$DASHBOARD_AGENT_PLIST")" "$(dirname "$DASHBOARD_AGENT_LOG_OUT")"
  cat > "$DASHBOARD_AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$DASHBOARD_AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV_PY</string>
    <string>$SCRIPT_DIR/plugins/ztr_dashboard.py</string>
$DASHBOARD_CONFIG_ARGS
  </array>
  <key>WorkingDirectory</key>
  <string>$SCRIPT_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>$DASHBOARD_AGENT_LOG_OUT</string>
  <key>StandardErrorPath</key>
  <string>$DASHBOARD_AGENT_LOG_ERR</string>
</dict>
</plist>
EOF
  launchctl unload -w "$DASHBOARD_AGENT_PLIST" >/dev/null 2>&1 || true
  launchctl load -w "$DASHBOARD_AGENT_PLIST"
  log_ok "agent installed and started: $DASHBOARD_AGENT_LABEL"
  echo "${C_DIM}    launchctl list | grep $DASHBOARD_AGENT_LABEL${C_RESET}"
  echo "${C_DIM}    tail -f $DASHBOARD_AGENT_LOG_OUT${C_RESET}"
  log_warn "live traffic capture (if scapy is installed) still needs root or the access_bpf group to actually"
  log_warn "capture packets — a plain launchd agent won't have raw-socket privileges on its own."
fi

echo
log_ok "done. Try: ztr_ssh --rh \"example._ztr\" --rp 22"
